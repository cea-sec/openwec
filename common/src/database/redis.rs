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
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use deadpool_redis::redis::{AsyncCommands, Pipeline};
use deadpool_redis::{Config, Connection, Pool, Runtime};
use log::warn;
use std::collections::btree_map::Entry::Vacant;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::SystemTime;

use crate::bookmark::BookmarkData;
use super::redisdomain::RedisDomain;
use crate::database::Database;
use crate::heartbeat::{HeartbeatData, HeartbeatKey, HeartbeatValue, HeartbeatsCache};
use crate::subscription::{
    SubscriptionData, SubscriptionMachine, SubscriptionMachineState, SubscriptionStatsCounters
};
use futures_util::stream::StreamExt;

use super::schema::{Migration, MigrationBase, Version};

const MIGRATION_TABLE_NAME: &str = "__schema_migrations";

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

fn get_value_or_default<'a>(
    fields: &'a HashMap<RedisDomain, String>,
    key: RedisDomain,
) -> &'a str {
    fields.get(&key).map(move |s| s.as_str()).unwrap_or_else(|| RedisDomain::Any.as_str())
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

    /// Register a migration. If a migration with the same version is already registered, a warning
    /// is logged and the registration fails.
    pub fn register_migration(&mut self, migration: Arc<dyn RedisMigration + Send + Sync>) {
        let version = migration.version();
        if let Vacant(e) = self.migrations.entry(version) {
            e.insert(migration);
        } else {
            warn!("Migration with version {:?} is already registered", version);
        }
    }

    async fn get_heartbeats_by_field(
        &self,
        fields: HashMap<RedisDomain, String>
    ) -> Result<Vec<HeartbeatData>> {

        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;

        let key = format!("{}:{}:{}", RedisDomain::Heartbeat,
        get_value_or_default(&fields, RedisDomain::Subscription),
        get_value_or_default(&fields, RedisDomain::Machine));

        let keys = list_keys(&mut conn, &key).await?;
        let mut heartbeats = Vec::<HeartbeatData>::new();

        let mut subscriptions_cache = HashMap::<String, SubscriptionData>::new();

        for key in keys {
            let heartbeat_data : HashMap<String,String> = conn.hgetall(&key).await.context("Failed to get heartbeat data")?;
            if !heartbeat_data.is_empty() {

                // cache subs
                let subscription_uuid = heartbeat_data[RedisDomain::Subscription.as_str()].clone();
                let cached_data = subscriptions_cache.get(&subscription_uuid).cloned();

                let subscription_data_opt = if cached_data.is_none() {
                    let fetched_data = self.get_subscription_by_identifier(&subscription_uuid).await?;
                    if let Some(fetched_subscription) = fetched_data.clone() {
                        subscriptions_cache.insert(subscription_uuid.clone(), fetched_subscription);
                    }
                    fetched_data
                } else {
                    cached_data
                };

                if subscription_data_opt.is_none() {
                    return Ok(Vec::<HeartbeatData>::new());
                }

                let subscription_data = subscription_data_opt.ok_or_else(|| {
                    anyhow::anyhow!("Subscription data not found for UUID: {}", subscription_uuid)
                })?;

                let expected_ip = fields.get(&RedisDomain::Ip);
                if expected_ip.is_some() && heartbeat_data.get(RedisDomain::Ip.as_str()) != expected_ip {
                    continue;
                }

                let hb = HeartbeatData::new(
                    heartbeat_data[RedisDomain::Machine.as_str()].clone(),
                    heartbeat_data[RedisDomain::Ip.as_str()].clone(),
                    subscription_data,
                    heartbeat_data.get(RedisDomain::FistSeen.as_str())
                        .and_then(|value| value.parse::<i64>().ok())
                        .context(format!("Failed to parse integer for field '{}'", RedisDomain::FistSeen))?,
                    heartbeat_data.get(RedisDomain::LastSeen.as_str())
                    .and_then(|value| value.parse::<i64>().ok())
                    .context(format!("Failed to parse integer for field '{}'", RedisDomain::LastSeen))?,
                    heartbeat_data.get(RedisDomain::LastEventSeen.as_str())
                    .and_then(|value| value.parse::<i64>().ok()),
                );
                heartbeats.push(hb);
            } else {
                log::warn!("No bookmard found for key: {}", key);
            }
        }

        Ok(heartbeats)
    }

}

async fn list_keys(con: &mut Connection, key: &str) -> Result<Vec<String>> {
    let mut res = Vec::new();
    let mut iter = con.scan_match::<&str, String>(key).await.context("Unable to list keys")?;

    while let Some(key) = iter.next().await {
        res.push(key);
    }

    Ok(res)
}

async fn list_keys_with_fallback(con: &mut Connection, key: &str, fallback: &str) -> Result<Vec<String>>
{
    let keys:Vec<String> = list_keys(con, key).await?;
    if keys.is_empty() {
        let fallback_keys: Vec<String> = list_keys(con, fallback).await?;
        return Ok(fallback_keys);
    }

    Ok(keys)
}

async fn set_heartbeat_inner(conn: &mut Connection, subscription: &str, machine: &str, value: &HeartbeatValue) -> Result<()> {
    let redis_key = format!("{}:{}:{}", RedisDomain::Heartbeat, subscription.to_uppercase(), machine);
    let key_exists = conn.exists(&redis_key).await.unwrap_or(true);
    let mut pipe = Pipeline::new();
    pipe.hset(&redis_key, RedisDomain::Subscription, subscription.to_uppercase());
    pipe.hset(&redis_key, RedisDomain::Machine, machine);
    pipe.hset(&redis_key, RedisDomain::Ip, value.ip.clone());
    if !key_exists {
        pipe.hset(&redis_key, RedisDomain::FistSeen, value.last_seen);
    }
    pipe.hset(&redis_key, RedisDomain::LastSeen, value.last_seen);

    if let Some(last_event_seen) = value.last_event_seen {
        pipe.hset(&redis_key, RedisDomain::LastEventSeen, last_event_seen);
    }

    let _ : Vec<usize> = pipe.query_async(conn.as_mut()).await.context("Failed to set heartbeat data")?;
    Ok(())
}

async fn set_heartbeat(conn: &mut Connection, key: &HeartbeatKey, value: &HeartbeatValue) -> Result<()> {
    set_heartbeat_inner(conn, &key.subscription, &key.machine, value).await
}

fn option_to_result<T, E>(option: Option<&T>, err: E) -> Result<T, E>
where
    T: Clone,
{
    option
        .map(|value| value.clone())
        .ok_or(err)
}

#[allow(unused)]
#[async_trait]
impl Database for RedisDatabase {
    async fn get_bookmark(&self, machine: &str, subscription: &str) -> Result<Option<String>> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("{}:{}:{}", RedisDomain::BookMark, subscription.to_uppercase(), machine);
        Ok(conn.hget(&key, RedisDomain::BookMark.as_str()).await.context("Failed to get bookmark data")?)
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
                    subscription: option_to_result(
                        bookmark_data.get(RedisDomain::Subscription.as_str()),
                        anyhow!("RedisError: No Bookmark/{} present!", RedisDomain::Subscription.as_str()))?.clone(),
                    machine: option_to_result(
                        bookmark_data.get(RedisDomain::Machine.as_str()),
                        anyhow!("RedisError: No Bookmark/{} present!", RedisDomain::Machine.as_str()))?.clone(),
                    bookmark: option_to_result(
                        bookmark_data.get(RedisDomain::BookMark.as_str()),
                        anyhow!("RedisError: No Bookmark/{} present!", RedisDomain::BookMark.as_str()))?.clone(),
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
        let mut fields = HashMap::<RedisDomain, String>::from([
            (RedisDomain::Machine, machine.to_string()),
        ]);
        if let Some(subs) = subscription {
            fields.insert(RedisDomain::Subscription, subs.to_string());
        }
        self.get_heartbeats_by_field(fields).await
    }

    async fn get_heartbeats_by_ip(
        &self,
        ip: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        let mut fields = HashMap::<RedisDomain, String>::from([
            (RedisDomain::Ip, ip.to_string()),
        ]);
        if let Some(subs) = subscription {
            fields.insert(RedisDomain::Subscription, subs.to_string());
        }
        self.get_heartbeats_by_field(fields).await
    }

    async fn get_heartbeats(&self) -> Result<Vec<HeartbeatData>> {
        let fields = HashMap::<RedisDomain, String>::new();
        self.get_heartbeats_by_field(fields).await
    }

    async fn get_heartbeats_by_subscription(
        &self,
        subscription: &str,
    ) -> Result<Vec<HeartbeatData>> {
        let fields = HashMap::<RedisDomain, String>::from([
            (RedisDomain::Subscription, subscription.to_string()),
        ]);
        self.get_heartbeats_by_field(fields).await
    }

    async fn store_heartbeat(
        &self,
        machine: &str,
        ip: String,
        subscription: &str,
        is_event: bool,
    ) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();

        let hbv = HeartbeatValue{
            ip,
            last_seen: now,
            last_event_seen: if is_event { Some(now) } else { None },
        };

        set_heartbeat_inner(&mut conn, subscription, machine, &hbv).await
    }

    async fn store_heartbeats(&self, heartbeats: &HeartbeatsCache) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        for (key, value) in heartbeats.iter() {
            let ip:String = value.ip.clone();
            set_heartbeat(&mut conn, key, value).await?;
        }
        Ok(())
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

    /// Fails if `setup_schema` hasn't previously been called or if the query otherwise fails.
    async fn current_version(&self) -> Result<Option<Version>> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = MIGRATION_TABLE_NAME;
        let versions:Vec<String> = conn.zrange(key, -1, -1).await.context("There is no version info stored in DB.")?;
        let last_version = versions.last().and_then(|v| v.parse::<i64>().ok());
        Ok(last_version)
    }

    /// Fails if `setup_schema` hasn't previously been called or if the query otherwise fails.
    async fn migrated_versions(&self) -> Result<BTreeSet<Version>> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = MIGRATION_TABLE_NAME;
        let versions:Vec<String> = conn.zrange(key, 0, -1).await.context("There is no version info stored in DB.")?;
        let result : BTreeSet<i64> = versions.into_iter().map(|v| v.parse::<i64>().context(format!("Failed to parse version: {}", v))).collect::<Result<_>>()?;
        Ok(result)
    }

    /// Fails if `setup_schema` hasn't previously been called or if the migration otherwise fails.
    async fn apply_migration(&self, version: Version) -> Result<()> {
        let migration = self
            .migrations
            .get(&version)
            .ok_or_else(|| anyhow!("Could not retrieve migration with version {}", version))?
            .clone();
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        migration.up(&mut conn).await?;
        let key = MIGRATION_TABLE_NAME;
        let version = migration.version();
        let added_count: i64 = conn.zadd(key, version, version).await.context(format!("Unable to add version: {}", version))?;
        if added_count > 0 {
            println!("Successfully added version {} to sorted set", version);
        } else {
            println!("Version {} was not added (it may already exist)", version);
        }
        Ok(())
    }

    /// Fails if `setup_schema` hasn't previously been called or if the migration otherwise fails.
    async fn revert_migration(&self, version: Version) -> Result<()> {
        let migration = self
            .migrations
            .get(&version)
            .ok_or_else(|| anyhow!("Could not retrieve migration with version {}", version))?
            .clone();
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        migration.down(&mut conn).await?;
        let key = MIGRATION_TABLE_NAME;
        let version = migration.version();
        let removed_count: i64 = conn.zrem(key, version).await.context("Failed to remove version")?;
        if removed_count > 0 {
            println!("Successfully removed version: {}", version);
        } else {
            println!("Version {} not found in the sorted set.", version);
        }
        Ok(())
    }

    /// Create the tables required to keep track of schema state. If the tables already
    /// exist, this function has no operation.
    async fn setup_schema(&self) -> Result<()> {
        Ok(())
    }

    async fn migrations(&self) -> BTreeMap<Version, Arc<dyn Migration + Send + Sync>> {
        let mut base_migrations = BTreeMap::new();
        for (version, migration) in self.migrations.iter() {
            base_migrations.insert(*version, migration.to_base());
        }
        base_migrations
    }

    async fn get_stats(
        &self,
        subscription: &str,
        start_time: i64,
    ) -> Result<SubscriptionStatsCounters> {
        let fields = HashMap::<RedisDomain, String>::from([
            (RedisDomain::Subscription, subscription.to_string()),
        ]);
        let heartbeats = self.get_heartbeats_by_field(fields).await?;

        let total_machines_count = i64::try_from(heartbeats.len())?;
        let mut alive_machines_count = 0;
        let mut active_machines_count = 0;
        let mut dead_machines_count = 0;

        for hb in heartbeats.iter() {
            match hb {
                HeartbeatData{last_seen, last_event_seen, ..} if MachineStatusFilter::Alive.is_match(last_seen, last_event_seen, start_time) => {
                    alive_machines_count += 1;
                },
                HeartbeatData{last_seen, last_event_seen, ..} if MachineStatusFilter::Active.is_match(last_seen, last_event_seen, start_time) => {
                    active_machines_count += 1;
                },
                HeartbeatData{last_seen, last_event_seen, ..} if MachineStatusFilter::Dead.is_match(last_seen, last_event_seen, start_time) => {
                    dead_machines_count += 1;
                },
                _ => {},
            };
        }

        Ok(SubscriptionStatsCounters::new(
            total_machines_count,
            alive_machines_count,
            active_machines_count,
            dead_machines_count,
        ))
    }

    async fn get_machines(
        &self,
        subscription: &str,
        start_time: i64,
        stat_type: Option<SubscriptionMachineState>,
    ) -> Result<Vec<SubscriptionMachine>> {
        let fields = HashMap::<RedisDomain, String>::from([
            (RedisDomain::Subscription, subscription.to_string()),
        ]);
        let heartbeats = self.get_heartbeats_by_field(fields).await?;
        let mut result = Vec::<SubscriptionMachine>::new();

        for hb in heartbeats.iter() {

            match stat_type {
                None => {},
                Some(SubscriptionMachineState::Active) => {
                    if !MachineStatusFilter::Active.is_match(&hb.last_seen, &hb.last_event_seen, start_time) {
                        continue;
                    }
                },
                Some(SubscriptionMachineState::Alive) => {
                    if !MachineStatusFilter::Alive.is_match(&hb.last_seen, &hb.last_event_seen, start_time) {
                        continue;
                    }
                },
                Some(SubscriptionMachineState::Dead) => {
                    if !MachineStatusFilter::Dead.is_match(&hb.last_seen, &hb.last_event_seen, start_time) {
                        continue;
                    }
                },
            }
            result.push(SubscriptionMachine::new(hb.machine().to_string(), hb.ip().to_string()));
        }

        Ok(result)
    }
}


#[cfg(test)]
mod tests {

    use std::env;

    use crate::{
        database::schema::{self, Migrator},
        migration,
    };

    use super::*;
    use serial_test::serial;

    #[allow(unused)]
    async fn cleanup_db(db: &RedisDatabase) -> Result<()> {
        let mut con = db.pool.get().await?;
        let _ : () = deadpool_redis::redis::cmd("FLUSHALL").query_async(&mut con).await?;
        Ok(())
    }

    async fn drop_migrations_table(db: &RedisDatabase) -> Result<()> {
        let mut conn = db.pool.get().await.context("Failed to get Redis connection")?;
        let key = MIGRATION_TABLE_NAME;
        let _:() = conn.del(key).await?;
        Ok(())
    }

    async fn redis_db() -> Result<RedisDatabase> {
        let connection_string = env::var("REDIS_URL").unwrap_or("redis://127.0.0.1:6379".to_string());
        RedisDatabase::new(connection_string.as_str()).await
    }

    async fn db_with_migrations() -> Result<Arc<dyn Database>> {
        let mut db = redis_db().await?;
        schema::redis::register_migrations(&mut db);
        cleanup_db(&db).await?;
        drop_migrations_table(&db).await?;
        Ok(Arc::new(db))
    }

    #[tokio::test]
    #[serial]
    async fn test_open_and_close() -> Result<()> {
            redis_db()
            .await
            .expect("Could not connect to database");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_bookmarks() -> Result<()> {
        crate::database::tests::test_bookmarks(db_with_migrations().await?).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_heartbeats() -> Result<()> {
        crate::database::tests::test_heartbeats(db_with_migrations().await?).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_heartbeats_cache() -> Result<()> {
        crate::database::tests::test_heartbeats_cache(db_with_migrations().await?).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_subscriptions() -> Result<()> {
        crate::database::tests::test_subscriptions(db_with_migrations().await?).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_stats() -> Result<()> {
        crate::database::tests::test_stats_and_machines(db_with_migrations().await?).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_current_version_empty() -> Result<()> {
        let db = db_with_migrations().await?;
        let res = db.current_version().await?;
        assert_eq!(res, None);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_current_version() -> Result<()> {
        let db = redis_db().await?;
        let mut con = db.pool.get().await?;
        let members = vec![(1.0, 1),(2.0, 2),(3.0, 3)];
        let _:() = con.zadd_multiple(MIGRATION_TABLE_NAME, &members).await?;
        let res = db.current_version().await?;
        assert_eq!(res, Some(3));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_migrated_versions() -> Result<()> {
        let db = redis_db().await?;
        let mut con = db.pool.get().await?;
        let members = vec![(1.0, 1),(2.0, 2),(3.0, 3)];
        let _:() = con.zadd_multiple(MIGRATION_TABLE_NAME, &members).await?;
        let res = db.migrated_versions().await?;
        assert_eq!(res, BTreeSet::<i64>::from_iter(vec![1,2,3]));
        Ok(())
    }

    struct CreateUsers;
    migration!(CreateUsers, 1, "create users table");

    #[async_trait]
    impl RedisMigration for CreateUsers {
        async fn up(&self, conn: &mut Connection) -> Result<()> {
            let key = format!("{}", RedisDomain::Users);
            let _:() = conn.set(key, "").await?;
            Ok(())
        }

        async fn down(&self, conn: &mut Connection) -> Result<()> {
            let key = format!("{}", RedisDomain::Users);
            let  _:() = conn.del(key).await?;
            Ok(())
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_register() -> Result<()> {
        let mut db = redis_db()
            .await
            .expect("Could not connect to database");

        drop_migrations_table(&db).await?;
        db.register_migration(Arc::new(CreateUsers));

        db.setup_schema().await.expect("Could not setup schema");

        let db_arc = Arc::new(db);

        let migrator = Migrator::new(db_arc.clone());

        migrator.up(None, false).await.unwrap();

        assert_eq!(db_arc.current_version().await.unwrap(), Some(1));

        migrator.down(None, false).await.unwrap();

        assert_eq!(db_arc.current_version().await.unwrap(), None);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_keys() -> Result<()> {
        let db = redis_db().await?;
        cleanup_db(&db).await?;
        let mut con = db.pool.get().await?;
        db.store_bookmark("machine1", "subscription", "bookmark1").await?;
        db.store_bookmark("machine2", "subscription", "bookmark2").await?;
        let key = "BookMark:SUBSCRIPTION:*";
        let keys = list_keys(&mut con, key).await?;
        assert!(keys.len() == 2);
        Ok(())
    }

}
