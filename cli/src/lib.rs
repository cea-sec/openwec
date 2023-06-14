use clap::builder::StyledStr;
use common::database::schema_is_up_to_date;
use common::{database::db_from_settings, settings::Settings};

use clap::ArgMatches;

use anyhow::{anyhow, bail, Context, Result};

mod bookmarks;
mod db;
mod heartbeats;
mod stats;
mod subscriptions;
mod utils;

pub async fn run(matches: ArgMatches, help_str: StyledStr) -> Result<()> {
    let settings = Settings::new(matches.get_one::<String>("config"))
        .map_err(|e| anyhow!("Failed to retrieve configuration: {}", e))?;
    let db = db_from_settings(&settings)
        .await
        .context("Failed to retrieve a Database instance")?;

    if let Some(matches) = matches.subcommand_matches("db") {
        db::run(&db, matches).await?;
        return Ok(());
    }

    // Check that database schema is up to date
    match schema_is_up_to_date(db.clone()).await.context("Failed to check schema version") {
        Ok(true) => (),
        Ok(false) => bail!("Schema needs to be updated. Please read the changelog and then run `openwec db upgrade`"),
        Err(err) => bail!("{:?}.\nHelp: You may need to run `openwec db init` to setup your database.", err),
    };

    if let Some(matches) = matches.subcommand_matches("subscriptions") {
        subscriptions::run(&db, matches).await?;
    } else if let Some(matches) = matches.subcommand_matches("heartbeats") {
        heartbeats::run(&db, matches).await?;
    } else if let Some(matches) = matches.subcommand_matches("stats") {
        stats::run(&db, matches).await?;
    } else if let Some(matches) = matches.subcommand_matches("bookmarks") {
        bookmarks::run(&db, matches).await?;
    } else {
        println!("{}", help_str);
    }
    Ok(())
}
