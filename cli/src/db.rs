use anyhow::{Context, Result};
use clap::ArgMatches;
use common::database::{
    schema::{Migrator, Version},
    Db,
};

use crate::utils::confirm;

enum Direction {
    Up,
    Down,
}
pub async fn run(db: &Db, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("init", _matches)) => {
            init(db).await?;
        }
        Some(("upgrade", matches)) => {
            upgrade(db, matches).await?;
        }
        Some(("downgrade", matches)) => {
            downgrade(db, matches).await?;
        }
        _ => {
            report(db, Direction::Up, None).await?;
        }
    }

    Ok(())
}

async fn init(db: &Db) -> Result<()> {
    db.setup_schema().await.context("Failed to setup schema")?;
    let migrator = Migrator::new(db.clone());
    migrator
        .up(None, false)
        .await
        .context("Failed to apply migrations")?;
    Ok(())
}

async fn upgrade(db: &Db, matches: &ArgMatches) -> Result<()> {
    let to = matches.get_one::<i64>("to").copied();
    let work_to_do = report(db, Direction::Up, to)
        .await
        .context("Failed to print migrations report")?;
    if !work_to_do {
        return Ok(());
    }
    let migrator = Migrator::new(db.clone());
    if confirm("Are you sure that you want to apply these migrations?") {
        migrator
            .up(to, false)
            .await
            .context("Failed to apply migrations")?;
    }
    Ok(())
}

async fn downgrade(db: &Db, matches: &ArgMatches) -> Result<()> {
    let to = if let Some(version) = matches.get_one::<i64>("to") {
        Some(*version)
    } else {
        let migrations = db.migrations().await;
        let migrated_versions = db
            .migrated_versions()
            .await
            .context("Failed to retrieve applied migrations")?;
        let mut migrations = migrations
            .iter()
            // Rollback migrations from latest to oldest:
            .rev()
            // Rollback only the migrations that are actually already migrated (in the case that
            // some intermediary migrations were never executed).
            .filter(|&(v, _)| migrated_versions.contains(v))
            .skip(1);
        // Exclude last migration
        migrations.next().map(|(version, _)| version).copied()
    };

    let work_to_do = report(db, Direction::Down, to)
        .await
        .context("Failed to print migrations report")?;
    if !work_to_do {
        return Ok(());
    }

    let migrator = Migrator::new(db.clone());
    if confirm("Are you sure that you want to downgrade these migrations?") {
        migrator
            .down(to, false)
            .await
            .context("Failed to remove migrations")?;
    }
    Ok(())
}

async fn report(db: &Db, direction: Direction, to: Option<Version>) -> Result<bool> {
    let migrations = db.migrations().await;
    println!("Knowned migrations:");
    for (version, migration) in migrations.iter() {
        println!("{}: {}", version, migration.description());
    }

    let migrated_versions = db
        .migrated_versions()
        .await
        .context("Failed to retrieve applied migrations")?;
    if migrated_versions.is_empty() {
        println!("No migrations already applied");
    } else {
        println!("Applied migrations:");
        for version in migrated_versions {
            println!(
                "{}: {}",
                version,
                migrations
                    .get(&version)
                    .map(|migration| migration.description())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
    }

    let migrator = Migrator::new(db.clone());

    let changes = match direction {
        Direction::Up => migrator.up(to, true).await,
        Direction::Down => migrator.down(to, true).await,
    }
    .context("Failed to simulate migrations")?;
    if changes.is_empty() {
        println!("Nothing to do");
        return Ok(false);
    } else {
        match direction {
            Direction::Up => println!("Migrations to apply:"),
            Direction::Down => println!("Migrations to remove:"),
        };
        for version in changes {
            println!(
                "{}: {}",
                version,
                migrations
                    .get(&version)
                    .map(|migration| migration.description())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
    }
    Ok(true)
}
