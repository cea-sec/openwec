use anyhow::Result;
use common::{
    database::Db,
    subscription::{SubscriptionData, SubscriptionOutput},
};
use itertools::Itertools;
use log::{debug, info, warn};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    time,
};

use crate::{
    formatter::Format,
    output::Output,
    outputs::{file::OutputFile, kafka::OutputKafka, tcp::OutputTcp, unix::OutputUnixDatagram},
};

use crate::outputs::redis::OutputRedis;

pub struct Subscription {
    data: SubscriptionData,
    outputs: Vec<Arc<Box<dyn Output + Send + Sync>>>,
    formats: HashSet<Format>,
}

impl TryFrom<SubscriptionData> for Subscription {
    type Error = anyhow::Error;
    fn try_from(data: SubscriptionData) -> Result<Self, Self::Error> {
        let mut formats: HashSet<Format> = HashSet::new();
        for output in data.outputs() {
            formats.insert(output.format().into());
        }
        let mut subscription = Subscription {
            data,
            outputs: Vec::new(),
            formats,
        };
        subscription.init()?;
        Ok(subscription)
    }
}

impl Subscription {
    /// Get a reference to the subscription's uuid.
    pub fn uuid(&self) -> &str {
        self.data.uuid()
    }

    /// Get a reference to the subscription's version.
    pub fn version(&self) -> &str {
        self.data.version()
    }

    /// Get a reference to the subscription's outputs.
    pub fn outputs(&self) -> &[Arc<Box<dyn Output + Send + Sync>>] {
        self.outputs.as_ref()
    }

    fn init(&mut self) -> Result<()> {
        // Initialize outputs
        for output_data in self.data.outputs() {
            if output_data.is_enabled() {
                self.outputs.push(match output_data {
                    SubscriptionOutput::Files(format, config, _) => {
                        Arc::new(Box::new(OutputFile::new(Format::from(format), config)))
                    }
                    SubscriptionOutput::Kafka(format, config, _) => {
                        Arc::new(Box::new(OutputKafka::new(Format::from(format), config)?))
                    }
                    SubscriptionOutput::Tcp(format, config, _) => {
                        Arc::new(Box::new(OutputTcp::new(Format::from(format), config)?))
                    }
                    SubscriptionOutput::Redis(format, config, _) => {
                        Arc::new(Box::new(OutputRedis::new(Format::from(format), config)?))
                    }
                    SubscriptionOutput::UnixDatagram(format, config, _) => {
                        Arc::new(Box::new(OutputUnixDatagram::new(Format::from(format), config)?))
                    }
                });
            }
        }
        Ok(())
    }

    pub fn data(&self) -> &SubscriptionData {
        &self.data
    }

    pub fn formats(&self) -> &HashSet<Format> {
        &self.formats
    }
}

pub type Subscriptions = Arc<RwLock<HashMap<String, Arc<Subscription>>>>;

pub async fn reload_subscriptions_task(db: Db, subscriptions: Subscriptions, interval: u64) {
    info!("reload_subscriptions task started");
    let mut interval = time::interval(Duration::from_secs(interval));
    let mut sighup = signal(SignalKind::hangup()).expect("Could not listen to SIGHUP");

    loop {
        tokio::select! {
            _ = interval.tick() => {
                debug!("Update subscriptions from db (interval tick)");
                if let Err(e) = reload_subscriptions(db.clone(), subscriptions.clone(), true).await {
                    warn!("Failed to update subscriptions on interval tick: {:?}", e);
                    continue;
                }
            },
            _ = sighup.recv() => {
                info!("Update subscriptions from db (signal)");
                if let Err(e) = reload_subscriptions(db.clone(), subscriptions.clone(), false).await {
                    warn!("Failed to update subscriptions on SIGHUP: {:?}", e);
                    continue;
                }
            }
        }
    }
}

async fn reload_subscriptions(
    db: Db,
    mem_subscriptions: Subscriptions,
    keep_already_existing: bool,
) -> Result<()> {
    let db_subscriptions = db.get_subscriptions().await?;

    let mut active_subscriptions: HashSet<String> = HashSet::with_capacity(db_subscriptions.len());

    // Take a write lock on subscriptions
    // It will be released at the end of the function
    let mut mem_subscriptions = mem_subscriptions.write().unwrap();

    if !keep_already_existing {
        mem_subscriptions.clear();
    }

    for subscription_data in db_subscriptions {
        let version = subscription_data.version();

        if !subscription_data.is_active() {
            debug!(
                "Subscription {} is disabled or have no enabled outputs",
                subscription_data.uuid()
            );
            continue;
        }

        active_subscriptions.insert(version.to_string());

        // Update the in memory representation of this subscription if necessary
        match mem_subscriptions.get(version) {
            Some(_) => {
                // This subscription has not been changed. Nothing to do
            }
            None => {
                debug!(
                    "Subscription version {} not found in the in memory subscriptions",
                    version
                );
                // The version of this subscription does not exist in the in-memory
                // subscriptions HashMap. This may happen in 2 situations:
                // 1. This is a new subscription. We must add it to the in-memory subscriptions.
                // 2. The subscription has been updated. We must remove the old subscription and add the new one to the
                //      in memory subscriptions.

                // `subscription.uuid()` stays the same after an update
                let old_subscription = {
                    mem_subscriptions
                        .values()
                        .find(|old_subscription| {
                            subscription_data.uuid() == old_subscription.uuid()
                        })
                        .cloned()
                };

                if let Some(old_subscription) = old_subscription {
                    info!("Subscription {} has been updated", subscription_data.uuid());
                    mem_subscriptions.remove(old_subscription.version());
                } else {
                    info!("Subscription {} has been created", subscription_data.uuid());
                }

                // Initialize the new subscription and add it to in-memory subscriptions
                let new_subscription = Arc::new(Subscription::try_from(subscription_data.clone())?);
                mem_subscriptions.insert(version.to_owned(), new_subscription);
            }
        }
    }

    debug!("Active subscriptions are: {:?}", active_subscriptions);

    // Make a list of subscriptions that need to be removed from in-memory subscriptions
    // These subscriptions have been disabled or deleted
    let mut to_delete = HashSet::new();
    for version in mem_subscriptions.keys() {
        if !active_subscriptions.contains(version) {
            debug!("Mark {} as 'to delete'", version);
            to_delete.insert(version.to_string());
        }
    }

    // Remove listed subscriptions
    for version in to_delete {
        info!(
            "Remove subscription {} from in memory subscriptions",
            version
        );
        mem_subscriptions.remove(&version);
    }

    if mem_subscriptions.is_empty() {
        warn!("There are no active subscriptions!");
    } else {
        debug!(
            "Active subscriptions are: {}",
            mem_subscriptions
                .iter()
                .map(|(_, subscription)| format!(
                    "\"{}\" ({})",
                    subscription.data.name(),
                    subscription.data.uuid()
                ))
                .join(", ")
        );
    }

    Ok(())
}
