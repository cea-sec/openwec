// Some of the following code is inspired from
// https://github.com/SkylerLipthay/schemamama_postgres. As stated by its
// license (MIT), we include below its copyright notice and permission notice:
//
//       The MIT License (MIT)
//
//       Copyright (c) 2024 Axoflow
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
#![allow(unused_imports)]
use anyhow::{anyhow, ensure, Context, Error, Result};
use async_trait::async_trait;
use deadpool_redis::redis::{self, RedisError};
use deadpool_redis::redis::{pipe, AsyncCommands, Pipeline};
use deadpool_redis::{Config, Connection, Pool, Runtime};
use log::warn;
use serde::de::value;
use uuid::Uuid;
use std::borrow::Borrow;
use std::collections::btree_map::Entry::Vacant;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::bookmark::{self, BookmarkData};
use crate::database::Database;
use crate::heartbeat::{self, HeartbeatData, HeartbeatKey, HeartbeatValue, HeartbeatsCache};
use crate::subscription::{
    self, ContentFormat, InternalVersion, PrincsFilter, SubscriptionData, SubscriptionMachine, SubscriptionMachineState, SubscriptionStatsCounters, SubscriptionUuid
};
use crate::transformers::output_files_use_path::new;

use super::schema::{Migration, MigrationBase, Version};

#[async_trait]
pub trait RedisMigration: Migration {
    /// Called when this migration is to be executed.
    async fn up(&self, conn: &mut Connection) -> Result<()>;

    /// Called when this migration is to be reversed.
    async fn down(&self, conn: &mut Connection) -> Result<()>;

    fn to_base(&self) -> Arc<dyn Migration + Send + Sync> {
        Arc::new(MigrationBase::new(self.version(), self.description()))
    }
}

#[allow(unused)]
pub struct RedisDatabase {
    pool: Pool,
    migrations: BTreeMap<Version, Arc<dyn RedisMigration + Send + Sync>>,
}

impl RedisDatabase {
    pub async fn new(connection_url: &str) -> Result<RedisDatabase> {
        let config = Config::from_url(connection_url);
        let pool = config.create_pool(Some(Runtime::Tokio1))?;
        let db = RedisDatabase {
            pool,
            migrations: BTreeMap::new(),
        };

        Ok(db)
    }
}

#[allow(unused)]
#[async_trait]
impl Database for RedisDatabase {
    async fn get_bookmark(&self, machine: &str, subscription: &str) -> Result<Option<String>> {
        todo!()
    }

    async fn get_bookmarks(&self, subscription: &str) -> Result<Vec<BookmarkData>> {
        todo!()
    }

    async fn store_bookmark(
        &self,
        machine: &str,
        subscription: &str,
        bookmark: &str,
    ) -> Result<()> {
        todo!()
    }

    async fn delete_bookmarks(
        &self,
        machine: Option<&str>,
        subscription: Option<&str>,
    ) -> Result<()> {
        todo!()
    }

    async fn get_heartbeats_by_machine(
        &self,
        machine: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        todo!()
    }

    async fn get_heartbeats_by_ip(
        &self,
        ip: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        todo!()
    }

    async fn get_heartbeats(&self) -> Result<Vec<HeartbeatData>> {
        todo!()
    }

    async fn get_heartbeats_by_subscription(
        &self,
        subscription: &str,
    ) -> Result<Vec<HeartbeatData>> {
        todo!()
    }

    async fn store_heartbeat(
        &self,
        machine: &str,
        ip: String,
        subscription: &str,
        is_event: bool,
    ) -> Result<()> {
        todo!()
    }

    async fn store_heartbeats(&self, heartbeats: &HeartbeatsCache) -> Result<()> {
        todo!()
    }

    async fn get_subscriptions(&self) -> Result<Vec<SubscriptionData>> {
        todo!()
    }

    async fn get_subscription_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<SubscriptionData>> {
        todo!()
    }

    async fn store_subscription(&self, subscription: &SubscriptionData) -> Result<()> {
        todo!()
    }

    async fn delete_subscription(&self, uuid: &str) -> Result<()> {
        todo!()
    }

    async fn current_version(&self) -> Result<Option<Version>> {
        todo!()
    }

    async fn migrated_versions(&self) -> Result<BTreeSet<Version>> {
        todo!()
    }

    async fn apply_migration(&self, version: Version) -> Result<()> {
        todo!()
    }

    async fn revert_migration(&self, version: Version) -> Result<()> {
        todo!()
    }

    async fn setup_schema(&self) -> Result<()> {
        todo!()
    }

    async fn migrations(&self) -> BTreeMap<Version, Arc<dyn Migration + Send + Sync>> {
        todo!()
    }

    async fn get_stats(
        &self,
        subscription: &str,
        start_time: i64,
    ) -> Result<SubscriptionStatsCounters> {
        todo!()
    }

    async fn get_machines(
        &self,
        subscription: &str,
        start_time: i64,
        stat_type: Option<SubscriptionMachineState>,
    ) -> Result<Vec<SubscriptionMachine>> {
        todo!()
    }
}
