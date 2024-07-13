use anyhow::{Context, Result};
use common::{
    database::Db,
    settings::Outputs,
    subscription::{
        InternalVersion, PublicVersion, SubscriptionData, SubscriptionOutputFormat,
        SubscriptionUuid,
    },
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

use crate::output::{Output, OutputDriversContext};

pub struct Subscription {
    data: SubscriptionData,
    // Subscription public version is a bit expensive to compute, so we
    // store the result in memory
    public_version: PublicVersion,
    outputs: Vec<Output>,
    formats: HashSet<SubscriptionOutputFormat>,
}

impl Subscription {
    /// Get a reference to the subscription's uuid.
    pub fn uuid_string(&self) -> String {
        self.data.uuid_string()
    }

    /// Get a reference to the subscription's public version.
    pub fn public_version_string(&self) -> String {
        self.public_version.to_string().to_uppercase()
    }

    pub fn data(&self) -> &SubscriptionData {
        &self.data
    }

    pub fn formats(&self) -> &HashSet<SubscriptionOutputFormat> {
        &self.formats
    }

    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    fn create_outputs(
        data: &SubscriptionData,
        context: &mut OutputDriversContext,
    ) -> Result<Vec<Output>> {
        let mut outputs = Vec::new();
        for output_data in data.outputs() {
            if output_data.enabled() {
                outputs.push(Output::new(
                    output_data.format(),
                    output_data.driver(),
                    context,
                )?);
            }
        }
        Ok(outputs)
    }

    pub fn from_data(data: SubscriptionData, context: &mut OutputDriversContext) -> Result<Self> {
        let mut formats: HashSet<SubscriptionOutputFormat> = HashSet::new();
        for output in data.outputs() {
            formats.insert(output.format().clone());
        }
        let outputs = Self::create_outputs(&data, context)?;
        let subscription = Subscription {
            public_version: data.public_version()?,
            data,
            outputs,
            formats,
        };

        Ok(subscription)
    }
}

/// In-memory map of currently active subscriptions
/// <subscription_uuid> => <subscription>
pub type Subscriptions = Arc<RwLock<HashMap<SubscriptionUuid, Arc<Subscription>>>>;

pub async fn reload_subscriptions_task(
    db: Db,
    subscriptions: Subscriptions,
    reload_interval: u64,
    outputs_settings: Outputs,
) {
    info!("reload_subscriptions task started");
    let mut reload = time::interval(Duration::from_secs(reload_interval));
    let mut garbage_collect =
        time::interval(Duration::from_secs(outputs_settings.garbage_collect_interval()));
    let mut sighup = signal(SignalKind::hangup()).expect("Could not listen to SIGHUP");

    let mut context = OutputDriversContext::new(&outputs_settings);

    // Don't call garbage_collect immediatly
    garbage_collect.reset();

    loop {
        tokio::select! {
            // First tick happens instantly
            _ = reload.tick() => {
                debug!("Update subscriptions from db (interval tick)");
                if let Err(e) = reload_subscriptions(db.clone(), subscriptions.clone(), &mut context, true).await {
                    warn!("Failed to update subscriptions on interval tick: {:?}", e);
                    continue;
                }
            },
            _ = garbage_collect.tick() => {
                debug!("Garbage collect output drivers context"); // FIXME
                if let Err(e) = context.garbage_collect(&outputs_settings) {
                    warn!("Failed to garbage collect output drivers: {:?}", e);
                    continue;
                }
            },
            _ = sighup.recv() => {
                info!("Update subscriptions from db (signal)");
                if let Err(e) = reload_subscriptions(db.clone(), subscriptions.clone(), &mut context, false).await {
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
    context: &mut OutputDriversContext,
    keep_already_existing: bool,
) -> Result<()> {
    let db_subscriptions = db.get_subscriptions().await?;

    // Make sure that the context is initialized for every active output drivers
    context.initialize_missing(&db_subscriptions).context("Failed to initialize output drivers context")?;

    let mut active_subscriptions: HashSet<InternalVersion> =
        HashSet::with_capacity(db_subscriptions.len());

    // Take a write lock on subscriptions
    // It will be released at the end of the function
    let mut mem_subscriptions = mem_subscriptions.write().unwrap();

    if !keep_already_existing {
        mem_subscriptions.clear();
        context.clear();
    }

    // mem_subscriptions is indexed on "public version"
    // To know whether something has changed, we must rely "on internal version"
    let mem_subscriptions_internal_version: HashSet<InternalVersion> = mem_subscriptions
        .iter()
        .map(|(_, subscription)| subscription.data().internal_version())
        .collect();

    for subscription_data in db_subscriptions {
        if !subscription_data.is_active() {
            debug!(
                "Subscription {} is disabled or have no enabled outputs",
                subscription_data.name(),
            );
            continue;
        }

        let internal_version = subscription_data.internal_version();

        active_subscriptions.insert(internal_version);

        // Update the in memory representation of this subscription if necessary
        match mem_subscriptions_internal_version.get(&internal_version) {
            Some(_) => {
                // This subscription has not been changed. Nothing to do
            }
            None => {
                debug!(
                    "Subscription internal version {} not found in the in memory subscriptions",
                    internal_version
                );
                // The internal version of this subscription does not exist in the in-memory
                // subscriptions HashMap. This may happen in 2 situations:
                // 1. This is a new subscription. We must add it to the in-memory subscriptions.
                // 2. The subscription has been updated. We must remove the old subscription and add the new one to the
                //      in memory subscriptions.

                // `subscription.uuid()` stays the same after an update
                let old_subscription: Option<Arc<Subscription>> = {
                    mem_subscriptions
                        .values()
                        .find(|old_subscription| {
                            subscription_data.uuid() == old_subscription.data().uuid()
                        })
                        .cloned()
                };

                if let Some(old_subscription) = old_subscription {
                    info!("Subscription {} has been updated", subscription_data.name());
                    mem_subscriptions.remove(old_subscription.data().uuid());
                } else {
                    info!("Subscription {} has been created", subscription_data.name());
                }

                // Initialize the new subscription and add it to in-memory subscriptions
                let new_subscription =
                    Arc::new(Subscription::from_data(subscription_data.clone(), context)?);
                // mem_subscriptions is indexed on public version
                mem_subscriptions.insert(*new_subscription.data().uuid(), new_subscription);
            }
        }
    }

    debug!(
        "Active subscriptions internal versions are: {:?}",
        active_subscriptions
    );

    // Make a list of subscriptions that need to be removed from in-memory subscriptions
    // These subscriptions have been disabled or deleted
    let mut to_delete: HashSet<SubscriptionUuid> = HashSet::new();
    for subscription in mem_subscriptions.values() {
        if !active_subscriptions.contains(&subscription.data().internal_version()) {
            debug!(
                "Mark subscription {} as 'to delete' (public version: {})",
                subscription.data().name(),
                subscription.public_version
            );
            to_delete.insert(*subscription.data().uuid());
        }
    }

    // Remove listed subscriptions
    for subscription_uuid in to_delete {
        info!(
            "Remove subscription uuid {} from in memory subscriptions",
            subscription_uuid
        );
        mem_subscriptions.remove(&subscription_uuid);
    }

    if mem_subscriptions.is_empty() {
        warn!("There are no active subscriptions!");
    } else {
        debug!(
            "Active subscriptions are: {}",
            mem_subscriptions
                .iter()
                .map(|(_, subscription)| format!(
                    "\"{}\" (uuid:{}, internal_version:{}, public_version:{})",
                    subscription.data.name(),
                    subscription.data.uuid(),
                    subscription.data().internal_version(),
                    subscription.public_version,
                ))
                .join(", ")
        );
    }

    Ok(())
}
