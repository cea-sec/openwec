use anyhow::{anyhow, bail, Result};
use clap::ArgMatches;
use common::database::Db;

use crate::utils;

pub async fn run(db: &Db, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("show", matches)) => {
            show(db, matches).await?;
        }
        Some(("delete", matches)) => {
            delete(db, matches).await?;
        }
        Some(("copy", matches)) => {
            copy(db, matches).await?;
        }
        _ => {
            bail!("Invalid subcommand")
        }
    };
    Ok(())
}

async fn show(db: &Db, matches: &ArgMatches) -> Result<()> {
    let machine = matches.get_one::<String>("machine").cloned();
    let subscription_identifier = matches
        .get_one::<String>("subscription")
        .expect("Required by clap")
        .to_string();

    let subscription = utils::find_subscription(db, &subscription_identifier)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "Could not find subscription with identifier {}",
                subscription_identifier
            )
        })?;

    if let Some(machine) = machine {
        let bookmark = db.get_bookmark(&machine, &subscription.uuid_string()).await?;
        match bookmark {
            Some(str) => {
                println!("{}", str)
            }
            None => bail!(
                "No bookmarks found for {} within subscription \"{}\"",
                machine,
                subscription.name()
            ),
        };
    } else {
        for data in db.get_bookmarks(&subscription.uuid_string()).await? {
            println!("{}:{}", data.machine, data.bookmark);
        }
    }

    Ok(())
}

async fn delete(db: &Db, matches: &ArgMatches) -> Result<()> {
    let machine = matches.get_one::<String>("machine").cloned();
    let subscription_identifier = matches.get_one::<String>("subscription").cloned();

    let subscription = match subscription_identifier {
        Some(identifier) => Some(
            utils::find_subscription(db, &identifier)
                .await?
                .ok_or_else(|| {
                    anyhow!("Could not find subscription with identifier {}", identifier)
                })?,
        ),
        None => None,
    };

    let message = match (&machine, &subscription) {
        (Some(machine), Some(subscription)) => format!("You are about to delete the bookmark of {} within subscription \"{}\".\nWARNING: You may lose logs!\nAre you sure?", machine, subscription.name()),
        (Some(machine), None) => format!("You are about to delete all bookmarks stored for {}.\nWARNING: You may lose logs!\nAre you sure?", machine),
        (None, Some(subscription)) => format!("You are about to delete all bookmarks stored for subscription \"{}\".\nWARNING: You may lose logs!\nAre you sure?", subscription.name()),
        (None, None) => "You are about to delete all stored bookmarks.\nWARNING: You may lose logs!\nAre you sure?".to_string(),
    };

    if utils::confirm(&message) {
        let uuid_opt = subscription.map(|x| x.uuid_string());
        db.delete_bookmarks(machine.as_deref(), uuid_opt.as_deref())
            .await?;
        println!("Done");
    } else {
        println!("Aborted");
    }

    Ok(())
}

async fn copy(db: &Db, matches: &ArgMatches) -> Result<()> {
    let machine = matches.get_one::<String>("machine").cloned();
    let source_id = matches
        .get_one::<String>("source")
        .expect("Required by clap")
        .to_string();
    let dest_id = matches
        .get_one::<String>("destination")
        .expect("Required by clap")
        .to_string();

    if source_id == dest_id {
        bail!("Source and destination are equal");
    }

    let source = utils::find_subscription(db, &source_id)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "Could not find source subscription with identifier \"{}\"",
                source_id
            )
        })?;
    let destination = utils::find_subscription(db, &dest_id)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "Could not find destination subscription with identifier \"{}\"",
                dest_id
            )
        })?;

    if let Some(machine) = machine {
        let existing_bookmark = db.get_bookmark(&machine, &destination.uuid_string()).await?;
        if existing_bookmark.is_some() {
            println!(
                "WARNING: A bookmark for {} already exists within subscription \"{}\"",
                machine,
                destination.name()
            )
        }

        let bookmark = db
            .get_bookmark(&machine, &source.uuid_string())
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "Could not find bookmark for {} in \"{}\"",
                    machine,
                    source.name()
                )
            })?;

        if !utils::confirm(format!("You are about to copy bookmark for {} in \"{}\" to \"{}\".\nWARNING: You may lose logs!\nAre you sure?", machine, source.name(), destination.name()).as_str()) {
            println!("Aborted");
            return Ok(());
        }

        db.store_bookmark(&machine, &destination.uuid_string(), &bookmark)
            .await?;
        println!("1 bookmark copied");
    } else {
        if !utils::confirm(format!("You are about to copy all bookmarks of subscription \"{}\" to \"{}\".\nWARNING: You may lose logs!\nAre you sure?", source.name(), destination.name()).as_str()) {
            println!("Aborted");
            return Ok(())
        };

        let mut counter: usize = 0;
        for data in db.get_bookmarks(&source.uuid_string()).await? {
            db.store_bookmark(&data.machine, &destination.uuid_string(), &data.bookmark)
                .await?;
            counter += 1;
        }
        println!("{} bookmarks copied", counter);
    };

    Ok(())
}
