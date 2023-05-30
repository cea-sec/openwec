use std::time::SystemTime;

use anyhow::Result;
use clap::ArgMatches;
use common::{database::Db, subscription::SubscriptionData, utils::timestamp_to_local_date};
use serde_json::json;

use crate::utils;

pub async fn run(db: &Db, matches: &ArgMatches) -> Result<()> {
    let subscriptions = utils::find_subscriptions(db, matches, "subscription").await?;
    let interval = matches.get_one::<u32>("interval").cloned();
    match matches.get_one::<String>("format") {
        Some(fmt) if fmt == "text" => stats_text(db, &subscriptions, interval).await?,
        Some(fmt) if fmt == "json" => stats_json(db, &subscriptions, interval).await?,
        x => eprintln!("Invalid format {:?}", x),
    }
    Ok(())
}

pub async fn stats_text(
    db: &Db,
    subscriptions: &[SubscriptionData],
    interval: Option<u32>,
) -> Result<()> {
    for subscription in subscriptions {
        let uri_text = match subscription.uri() {
            Some(uri) => uri,
            None => "*",
        };
        println!(
            "Subscription {} ({}) - {}",
            subscription.name(),
            subscription.uuid(),
            uri_text
        );
        let now: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .try_into()?;
        let interval = interval.unwrap_or_else(|| subscription.heartbeat_interval()) as i64;
        let start_heartbeat_interval = now - interval;
        let stats = db
            .get_stats(subscription.uuid(), start_heartbeat_interval)
            .await?;

        let start_heartbeat_interval_date = timestamp_to_local_date(start_heartbeat_interval)?;
        println!("- {} machines ever seen", stats.total_machines_count());
        println!(
            "- {} active machines (event received since {})",
            stats.active_machines_count(),
            start_heartbeat_interval_date.to_rfc3339(),
        );
        println!(
            "- {} alive machines (heartbeat received since {} but no events)",
            stats.alive_machines_count(),
            start_heartbeat_interval_date.to_rfc3339(),
        );
        println!(
            "- {} dead machines (no heartbeats nor events since {})",
            stats.dead_machines_count(),
            start_heartbeat_interval_date.to_rfc3339(),
        );
    }
    Ok(())
}

pub async fn stats_json(
    db: &Db,
    subscriptions: &[SubscriptionData],
    interval: Option<u32>,
) -> Result<()> {
    let mut stats_vec = Vec::new();
    for subscription in subscriptions {
        let now: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .try_into()?;
        let interval = interval.unwrap_or_else(|| subscription.heartbeat_interval()) as i64;
        let start_heartbeat_interval = now - interval;
        let stats = db
            .get_stats(subscription.uuid(), start_heartbeat_interval)
            .await?;

        let start_heartbeat_interval_date = timestamp_to_local_date(start_heartbeat_interval)?;

        stats_vec.push(json!({
            "subscription_name": subscription.name(),
            "subscription_uuid": subscription.uuid(),
            "subscription_uri": subscription.uri(),
            "since": start_heartbeat_interval_date.to_rfc3339(),
            "total_machines_count": stats.total_machines_count(),
            "alive_machines_count": stats.alive_machines_count(),
            "active_machines_count": stats.active_machines_count(),
            "dead_machines_count": stats.dead_machines_count(),
        }));
    }
    println!("{}", serde_json::to_string(&stats_vec)?);
    Ok(())
}
