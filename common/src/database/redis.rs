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

use super::redisdomain::RedisDomain;
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

enum MachineStatusFilter {
    Alive,
    Active,
    Dead,
}

impl MachineStatusFilter {
    fn is_match(&self, last_seen: &i64, last_event_seen: &Option<i64>, start_time: i64) -> bool {
        match self {
            MachineStatusFilter::Alive => {
                *last_seen > start_time && last_event_seen.map_or(true, |event_time| event_time <= start_time)
            },
            MachineStatusFilter::Active => {
                last_event_seen.map_or(false, |event_time| event_time > start_time)
            },
            MachineStatusFilter::Dead => {
                *last_seen <= start_time && last_event_seen.map_or(true, |event_time| event_time <= start_time)
            }
        }
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

async fn list_keys(con: &mut Connection, key: &str) -> Result<Vec<String>>
{
    let res = con.keys(key).await.context("Unable to list keys")?;
    Ok(res)
}

async fn list_keys_with_fallback(con: &mut Connection, key: &str, fallback: &str) -> Result<Vec<String>>
{
    let keys:Vec<String> = con.keys(key).await?;
    if keys.is_empty() {
        let fallback_keys: Vec<String> = con.keys(fallback).await?;
        return Ok(fallback_keys);
    }

    Ok(keys)
}

#[allow(unused)]
#[async_trait]
impl Database for RedisDatabase {
    async fn get_bookmark(&self, machine: &str, subscription: &str) -> Result<Option<String>> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("{}:{}:{}", RedisDomain::BookMark, subscription.to_uppercase(), machine);
        let bookmark_data : HashMap<String,String> = conn.hgetall(&key).await.context("Failed to get bookmark data")?;
        Ok(bookmark_data.get(RedisDomain::BookMark.as_str()).cloned())
    }

    async fn get_bookmarks(&self, subscription: &str) -> Result<Vec<BookmarkData>> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("{}:{}:{}", RedisDomain::BookMark, subscription.to_uppercase(), RedisDomain::Any);
        let keys = list_keys(&mut conn, &key).await?;
        let mut bookmarks = Vec::<BookmarkData>::new();

        for key in keys {
            let bookmark_data : HashMap<String,String> = conn.hgetall(&key).await.context("Failed to get bookmark data")?;
            if !bookmark_data.is_empty() {
                bookmarks.push(BookmarkData {
                    subscription: bookmark_data[RedisDomain::Subscription.as_str()].clone(),
                    machine: bookmark_data[RedisDomain::Machine.as_str()].clone(),
                    bookmark: bookmark_data[RedisDomain::BookMark.as_str()].clone(),
                });
            } else {
                log::warn!("No bookmard found for key: {}", key);
            }
        }

        Ok(bookmarks)
    }

    async fn store_bookmark(
        &self,
        machine: &str,
        subscription: &str,
        bookmark: &str,
    ) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("{}:{}:{}", RedisDomain::BookMark, subscription.to_uppercase(), machine);

        let mut pipe = Pipeline::new();
        pipe.hset(&key, RedisDomain::Subscription, subscription.to_uppercase());
        pipe.hset(&key, RedisDomain::Machine, machine);
        pipe.hset(&key, RedisDomain::BookMark, bookmark);

        let _: Vec<usize> = pipe.query_async(&mut conn).await.context("Failed to store bookmark data")?;

        Ok(())
    }

    async fn delete_bookmarks(
        &self,
        machine: Option<&str>,
        subscription: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let compose_key = |subscription: &str, machine: &str| -> String {
            format!("{}:{}:{}", RedisDomain::BookMark, subscription.to_uppercase(), machine)
        };
        let key : String = match (subscription, machine) {
            (Some(subscription), Some(machine)) => {
                compose_key(subscription, machine)
            },
            (Some(subscription), None) => {
                compose_key(subscription, RedisDomain::Any.as_str())
            },
            (None, Some(machine)) => {
                compose_key(RedisDomain::Any.as_str(), machine)
            },
            (None, None) => {
                compose_key(RedisDomain::Any.as_str(), RedisDomain::Any.as_str())
            }
        };

        let keys = list_keys(&mut conn, &key).await?;
        let mut pipe = Pipeline::new();
        for key in keys.iter() {
            pipe.del(key);
        }
        let _ : Vec<usize> = pipe.query_async(&mut conn).await.context("Failed to delete bookmark data")?;

        Ok(())
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
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;

        let key = format!("{}:{}:{}", RedisDomain::Subscription, RedisDomain::Any, RedisDomain::Any);

        let keys = list_keys(&mut conn, &key).await?;

        let mut subscriptions = Vec::new();

        for key in keys {
            let subscription_json: Option<String> = conn.get(&key).await.context("Failed to get subscription data")?;

            if let Some(subscription_json) = subscription_json {
                match serde_json::from_str::<SubscriptionData>(&subscription_json) {
                    Ok(subscription) => subscriptions.push(subscription),
                    Err(err) => {
                        log::warn!("Failed to deserialize subscription data for key {}: {}", key, err);
                    }
                }
            } else {
                log::warn!("No subscription found for key: {}", key);
            }
        }

        Ok(subscriptions)
    }

    async fn get_subscription_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<SubscriptionData>> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let first_pass_key = format!("{}:{}:{}", RedisDomain::Subscription, identifier, RedisDomain::Any);
        let second_pass_key = format!("{}:{}:{}", RedisDomain::Subscription, RedisDomain::Any, identifier);

        let keys = list_keys_with_fallback(&mut conn, &first_pass_key, &second_pass_key).await?;

        if !keys.is_empty() {
            let result: Option<String> = conn.get(&keys[0]).await.context("Failed to get subscription data")?;
            if result.is_some() {
                let subscription: SubscriptionData = serde_json::from_str(&result.unwrap()).context("Failed to deserialize subscription data")?;
                return Ok(Some(subscription));
            }
        }
        Ok(None)
    }

    async fn store_subscription(&self, subscription: &SubscriptionData) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;

        let key_filter = format!("{}:{}:{}",RedisDomain::Subscription, subscription.uuid().to_string().to_uppercase(), RedisDomain::Any);
        let keys = list_keys(&mut conn, &key_filter).await?;
        if (!keys.is_empty()) {
            let _:() = conn.del(keys).await?;
        }

        let key = format!("{}:{}:{}", RedisDomain::Subscription, subscription.uuid().to_string().to_uppercase(), subscription.name());
        let value = serde_json::to_string(subscription).context("Failed to serialize subscription data")?;
        let _ : String = conn.set(key, value).await.context("Failed to store subscription data")?;
        Ok(())
    }

    async fn delete_subscription(&self, uuid: &str) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let first_pass_key = format!("{}:{}:{}", RedisDomain::Subscription, uuid.to_uppercase(), RedisDomain::Any);
        let second_pass_key = format!("{}:{}:{}", RedisDomain::Subscription, RedisDomain::Any, uuid);

        let keys = list_keys_with_fallback(&mut conn, &first_pass_key, &second_pass_key).await?;

        self.delete_bookmarks(None, Some(uuid)).await.context("Failed to delete subscription releated bookmark data")?;
        if !keys.is_empty() {
            let _: () = conn.del(keys).await.context("Failed to delete subscription data")?;
        }
        Ok(())
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
