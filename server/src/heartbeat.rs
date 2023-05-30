use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use common::{
    database::Db,
    heartbeat::{HeartbeatKey, HeartbeatValue, HeartbeatsCache},
};
use log::{debug, error, info};
use tokio::{
    select,
    sync::{mpsc, oneshot},
    time,
};

pub async fn store_heartbeat(
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    machine: &str,
    ip: String,
    subscription: &str,
    is_event: bool,
) -> Result<()> {
    if is_event {
        debug!(
            "Store event heartbeat for {} ({}) with subscription {}",
            machine, ip, subscription
        )
    } else {
        debug!(
            "Store heartbeat for {} ({}) with subscription {}",
            machine, ip, subscription
        )
    }
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    heartbeat_tx
        .send(WriteHeartbeatMessage {
            machine: machine.to_owned(),
            ip,
            subscription: subscription.to_owned(),
            timestamp: now,
            is_event,
        })
        .await
        .context("Failed to send WriteHeartbeatMessage")?;
    Ok(())
}

#[derive(Debug)]
pub struct WriteHeartbeatMessage {
    pub machine: String,
    pub ip: String,
    pub subscription: String,
    pub timestamp: u64,
    pub is_event: bool,
}

pub async fn heartbeat_task(
    db: Db,
    interval: u64,
    mut task_rx: mpsc::Receiver<WriteHeartbeatMessage>,
    mut task_exit_rx: oneshot::Receiver<oneshot::Sender<()>>,
) {
    info!("Heartbeat task started");
    let mut interval = time::interval(Duration::from_secs(interval));
    let mut heartbeats: HeartbeatsCache = HashMap::new();

    loop {
        select! {
            Some(heartbeat) = task_rx.recv() => {
                // Store heartbeat in cache storage

                let key = HeartbeatKey {
                    machine: heartbeat.machine.clone(),
                    subscription: heartbeat.subscription.clone()
                };

                let value = if !heartbeat.is_event {
                    // If we just received a heartbeat, we just want to
                    // update "last_seen" value.

                    let mut value = HeartbeatValue {
                        ip: heartbeat.ip.clone(),
                        last_seen: heartbeat.timestamp,
                        last_event_seen: None
                    };
                    let old_opt = heartbeats.get(&key);
                    if let Some(old) = old_opt {
                        value.last_event_seen = old.last_event_seen;
                    }
                    value
                } else {
                    HeartbeatValue {
                        ip: heartbeat.ip.clone(),
                        last_seen: heartbeat.timestamp,
                        last_event_seen: Some(heartbeat.timestamp),
                    }
                };
                debug!(
                    "Cache heartbeat for {} ({}) with subscription {}. last_seen = {}, last_event_seen = {:?}",
                    key.machine, value.ip, key.subscription, value.last_seen, value.last_event_seen
                );
                heartbeats.insert(key, value);
            },
            _ = interval.tick() => {
                if !heartbeats.is_empty() {
                    info!("Flush heartbeat cache");
                    if let Err(e) = db.store_heartbeats(&heartbeats).await {
                        error!("Could not store heartbeats in database: {:?}", e);
                    }

                    // Clear the cache to be ready to accept new heartbeats
                    heartbeats.clear();
                    info!("Heartbeat cache flushed and cleared");
                }
            },
            sender = &mut task_exit_rx => {
                if !heartbeats.is_empty() {
                    info!("Flush heartbeat cache before killing the task");
                    if let Err(e) = db.store_heartbeats(&heartbeats).await {
                        error!("Could not store heartbeats in database: {:?}", e);
                    }
                }

                match sender {
                    Ok(sender) => {
                        if let Err(e) = sender.send(()) {
                            error!("Failed to respond to kill order: {:?}", e);
                        }
                    },
                    Err(e) => {
                        error!("Could not respond to kill order: {:?}", e);
                    }
                }
                break;
            }
        }
    }
}
