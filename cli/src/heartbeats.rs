use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use common::{
    database::Db, heartbeat::HeartbeatData, subscription::SubscriptionData,
    utils::timestamp_to_local_date,
};

use crate::utils;

async fn find_subscription(db: &Db, matches: &ArgMatches) -> Result<Option<SubscriptionData>> {
    if let Some(identifier) = matches.get_one::<String>("subscription") {
        Ok(Some(
            utils::find_subscription(db, identifier)
                .await
                .with_context(|| {
                    format!("Failed to find subscription with identifier {}", identifier)
                })?
                .ok_or_else(|| {
                    anyhow!("Subscription {} could not be found in database", identifier)
                })?,
        ))
    } else {
        Ok(None)
    }
}

pub async fn run(db: &Db, matches: &ArgMatches) -> Result<()> {
    let subscription = find_subscription(db, matches).await?;
    let subscription_uuid = subscription.map(|sub| sub.uuid_string());

    let heartbeats = if let Some(machine) = matches.get_one::<String>("machine") {
        db.get_heartbeats_by_machine(machine, subscription_uuid.as_deref())
            .await?
    } else if let Some(address) = matches.get_one::<String>("address") {
        db.get_heartbeats_by_ip(address, subscription_uuid.as_deref())
            .await?
    } else if let Some(uuid) = subscription_uuid {
        db.get_heartbeats_by_subscription(&uuid).await?
    } else {
        db.get_heartbeats().await?
    };

    match matches.get_one::<String>("format") {
        Some(fmt) if fmt == "text" => format_text(&heartbeats)?,
        Some(fmt) if fmt == "json" => format_json(&heartbeats)?,
        x => eprintln!("Invalid format {:?}", x),
    }
    Ok(())
}

fn format_text(heartbeats: &Vec<HeartbeatData>) -> Result<()> {
    for heartbeat in heartbeats {
        let first_seen = timestamp_to_local_date(heartbeat.first_seen())?;
        let last_seen = timestamp_to_local_date(heartbeat.last_seen())?;
        let last_event_seen_sentence = if let Some(last_event_seen) = heartbeat.last_event_seen() {
            format!(
                "Last event received on {}",
                timestamp_to_local_date(last_event_seen)?.to_rfc3339()
            )
        } else {
            "No events have ever been received.".to_string()
        };
        println!(
            "For subscription \"{}\" ({}), {} ({}) last heartbeat was sent on {}. First seen on {}. {}",
            heartbeat.subscription().name(),
            heartbeat.subscription().uuid(),
            heartbeat.machine(),
            heartbeat.ip(),
            last_seen.to_rfc3339(),
            first_seen.to_rfc3339(),
            last_event_seen_sentence
        );
    }
    Ok(())
}

fn format_json(heartbeats: &Vec<HeartbeatData>) -> Result<()> {
    println!("{}", serde_json::to_string(heartbeats)?);
    Ok(())
}
