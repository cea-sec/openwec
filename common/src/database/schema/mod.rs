// A lot of the following code comes from
// https://github.com/SkylerLipthay/schemamama. It was not used directly has
// some parts needed to be modify to be integrated to OpenWEC. As stated by its
// license (MIT), we include below its copyright notice and permission notice:
// 
//       The MIT License (MIT)
//       
//       Copyright (c) 2015 Skyler Lipthay
//       
//       Permission is hereby granted, free of charge, to any person obtaining a copy
//       of this software and associated documentation files (the "Software"), to deal
//       in the Software without restriction, including without limitation the rights
//       to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//       copies of the Software, and to permit persons to whom the Software is
//       furnished to do so, subject to the following conditions:
//       
//       The above copyright notice and this permission notice shall be included in all
//       copies or substantial portions of the Software.
//       
//       THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//       IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//       FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//       AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//       LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//       OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//       SOFTWARE.
//
//
use anyhow::Result;
use log::info;
use std::{collections::BTreeSet, sync::Arc};

use super::Database;

pub mod postgres;
pub mod sqlite;
pub mod redis;

/// The version type alias used to uniquely reference migrations.
pub type Version = i64;

/// All migrations will implement this trait, and a migration trait specific to the chosen adapter.
/// This trait defines the metadata for tracking migration sequence and for human reference.
pub trait Migration {
    /// An ordered (but not necessarily sequential), unique identifier for this migration.
    /// Registered migrations will be applied in ascending order by version.
    fn version(&self) -> Version;

    /// A message describing the effects of this migration.
    fn description(&self) -> String;
}

pub struct MigrationBase {
    version: Version,
    description: String,
}
impl MigrationBase {
    pub fn new(version: Version, description: String) -> Self {
        MigrationBase {
            version,
            description,
        }
    }
}
impl Migration for MigrationBase {
    fn version(&self) -> Version {
        self.version
    }

    fn description(&self) -> String {
        self.description.clone()
    }
}

#[macro_export]
macro_rules! migration {
    ($ty:ident, $version:expr, $description:expr) => {
        impl $crate::database::schema::Migration for $ty {
            fn version(&self) -> $crate::database::schema::Version {
                $version
            }
            fn description(&self) -> String {
                $description.into()
            }
        }
    };
}

/// Maintains an ordered collection of migrations to utilize.
pub struct Migrator {
    db: Arc<dyn Database>,
}

impl Migrator {
    /// Create a migrator with a given adapter.
    pub fn new(db: Arc<dyn Database>) -> Self {
        Migrator { db }
    }

    /// Rollback to the specified version (exclusive), or rollback to the state before any
    /// registered migrations were applied if `None` is specified.
    pub async fn down(&self, to: Option<Version>, no_op: bool) -> Result<BTreeSet<i64>> {
        let mut rollbacked_migrations = BTreeSet::new();
        let from = self.db.current_version().await?;
        if from.is_none() {
            return Ok(rollbacked_migrations);
        }

        let migrated_versions = self.db.migrated_versions().await?;
        let migrations = self.db.migrations().await;
        let targets = migrations
            .iter()
            // Rollback migrations from latest to oldest:
            .rev()
            // Rollback the current version, and all versions downwards until the specified version
            // (exclusive):
            .filter(|&(&v, _)| within_range(v, to, from))
            // Rollback only the migrations that are actually already migrated (in the case that
            // some intermediary migrations were never executed).
            .filter(|&(v, _)| migrated_versions.contains(v));

        for (version, migration) in targets {
            let description = migration.description();
            rollbacked_migrations.insert(*version);
            if !no_op {
                info!("Reverting migration {:?}: {}", version, description);
                self.db.revert_migration(*version).await?;
            }
        }

        Ok(rollbacked_migrations)
    }

    /// Migrate to the specified version (inclusive).
    pub async fn up(&self, to: Option<Version>, no_op: bool) -> Result<BTreeSet<i64>> {
        let migrated_versions = self.db.migrated_versions().await?;
        let migrations = self.db.migrations().await;
        let targets = migrations
            .iter()
            // Execute all versions upwards until the specified version (inclusive):
            .filter(|&(&v, _)| within_range(v, None, to))
            // Execute only the migrations that are actually not already migrated (in the case that
            // some intermediary migrations were previously executed).
            .filter(|&(v, _)| !migrated_versions.contains(v));

        let mut applied_migrations = BTreeSet::new();
        for (version, migration) in targets {
            let description = migration.description();
            applied_migrations.insert(*version);
            if !no_op {
                info!("Applying migration {:?}: {}", version, description);
                self.db.apply_migration(*version).await?
            }
        }

        Ok(applied_migrations)
    }
}

// Tests whether a `Version` is within a range defined by the exclusive `low` and the inclusive
// `high` bounds.
fn within_range(version: Version, low: Option<Version>, high: Option<Version>) -> bool {
    match (low, high) {
        (None, None) => true,
        (Some(low), None) => version > low,
        (None, Some(high)) => version <= high,
        (Some(low), Some(high)) => version > low && version <= high,
    }
}

#[test]
fn test_within_range() {
    // no lower or upper bound
    assert!(within_range(0, None, None));
    assert!(within_range(42, None, None));
    assert!(within_range(100000, None, None));

    // both lower and upper bounds
    assert!(!within_range(1, Some(2), Some(5)));
    assert!(!within_range(2, Some(2), Some(5)));
    assert!(within_range(3, Some(2), Some(5)));
    assert!(within_range(5, Some(2), Some(5)));
    assert!(!within_range(6, Some(2), Some(5)));

    // lower bound only
    assert!(!within_range(0, Some(5), None));
    assert!(!within_range(4, Some(5), None));
    assert!(!within_range(5, Some(5), None));
    assert!(within_range(6, Some(5), None));
    assert!(within_range(60, Some(5), None));

    // upper bound only
    assert!(within_range(0, None, Some(5)));
    assert!(within_range(5, None, Some(5)));
    assert!(!within_range(6, None, Some(5)));
}
