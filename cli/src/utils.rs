use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use common::database::Db;
use common::subscription::SubscriptionData;
use std::io;
use std::io::Write;

pub fn confirm(message: &str) -> bool {
    for _ in 0..3 {
        print!("{} [y/n] ", message);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(2) => return input.to_ascii_lowercase().trim() == "y",
            _ => (),
        };
    }
    false
}

pub async fn find_subscription(db: &Db, identifier: &str) -> Result<Option<SubscriptionData>> {
    db.get_subscription_by_identifier(identifier)
        .await
        .with_context(|| format!("Failed to find subscription with identifier {}", identifier))
}

pub async fn find_subscriptions(
    db: &Db,
    matches: &ArgMatches,
    field: &str,
) -> Result<Vec<SubscriptionData>> {
    if let Some(identifier) = matches.get_one::<String>(field) {
        Ok(vec![find_subscription(db, identifier)
            .await
            .with_context(|| format!("Failed to find subscription with identifier {}", identifier))?
            .ok_or_else(|| {
                anyhow!("Subscription {} could not be found in database", identifier)
            })?])
    } else {
        Ok(db.get_subscriptions().await?)
    }
}
