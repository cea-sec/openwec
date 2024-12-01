// Some of the following code comes from
// https://github.com/SkylerLipthay/schemamama_postgres. It was not used
// directly has some parts needed to be modify to be integrated to OpenWEC. As
// stated by its license (MIT), we include below its copyright notice and
// permission notice:
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
use crate::bookmark::BookmarkData;
use crate::heartbeat::{HeartbeatKey, HeartbeatsCache};
use crate::settings::PostgresSslMode;
use crate::subscription::{
    ContentFormat, InternalVersion, ClientFilter, SubscriptionMachine, SubscriptionMachineState,
    SubscriptionStatsCounters, SubscriptionUuid,
};
use crate::{
    database::Database, heartbeat::HeartbeatData, settings::Postgres,
    subscription::SubscriptionData,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use async_trait::async_trait;
use deadpool_postgres::{Config, Pool, Runtime, SslMode, Transaction};
use log::{error, warn};
use openssl::ssl::{SslConnector, SslMethod};
use postgres_openssl::MakeTlsConnector;
use std::collections::btree_map::Entry::Vacant;
use std::str::FromStr;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::SystemTime,
};
use tokio_postgres::types::ToSql;
use tokio_postgres::{NoTls, Row};
use uuid::Uuid;

use super::schema::{Migration, MigrationBase, Version};

const MIGRATION_TABLE_NAME: &str = "__schema_migrations";

/// A migration to be used within a PostgreSQL connection.
#[async_trait]
pub trait PostgresMigration: Migration {
    /// Called when this migration is to be executed.
    async fn up(&self, transaction: &mut Transaction) -> Result<()>;

    /// Called when this migration is to be reversed.
    async fn down(&self, transaction: &mut Transaction) -> Result<()>;
    fn to_base(&self) -> Arc<dyn Migration + Send + Sync> {
        Arc::new(MigrationBase::new(self.version(), self.description()))
    }
}

struct PostgresHeartbeatEventValue {
    pub ip: String,
    pub last_seen: i64,
    pub last_event_seen: i64,
}

struct PostgresHeartbeatValue {
    pub ip: String,
    pub last_seen: i64,
}

pub struct PostgresDatabase {
    pool: Pool,
    migrations: BTreeMap<Version, Arc<dyn PostgresMigration + Send + Sync>>,
    max_chunk_size: usize,
}

impl PostgresDatabase {
    pub async fn new(settings: &Postgres) -> Result<PostgresDatabase> {
        let mut config = Config {
            host: Some(settings.host().to_string()),
            port: Some(settings.port()),
            user: Some(settings.user().to_string()),
            password: Some(settings.password().to_string()),
            dbname: Some(settings.dbname().to_string()),
            ..Default::default()
        };

        let pool = if *settings.ssl_mode() == PostgresSslMode::Disable {
            config
                .create_pool(Some(Runtime::Tokio1), NoTls)
                .context("Failed to create database pool (with NoTls)")?
        } else {
            config.ssl_mode = match settings.ssl_mode() {
                PostgresSslMode::Prefer => Some(SslMode::Prefer),
                PostgresSslMode::Require => Some(SslMode::Require),
                _ => None,
            };
            let mut builder = SslConnector::builder(SslMethod::tls())
                .context("Failed to initialize TLS context")?;
            if let Some(ca_file) = settings.ca_file() {
                builder
                    .set_ca_file(ca_file)
                    .context("Failed to configure CA cert file")?;
            }
            let connector = MakeTlsConnector::new(builder.build());
            config
                .create_pool(Some(Runtime::Tokio1), connector)
                .context("Failed to create database pool (with Tls)")?
        };

        let db = PostgresDatabase {
            pool,
            migrations: BTreeMap::new(),
            max_chunk_size: settings.max_chunk_size(),
        };

        Ok(db)
    }

    /// Register a migration. If a migration with the same version is already registered, a warning
    /// is logged and the registration fails.
    pub fn register_migration(&mut self, migration: Arc<dyn PostgresMigration + Send + Sync>) {
        let version = migration.version();
        if let Vacant(e) = self.migrations.entry(version) {
            e.insert(migration);
        } else {
            warn!("Migration with version {:?} is already registered", version);
        }
    }

    async fn get_heartbeats_by_field(
        &self,
        field: &str,
        field_value: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        let client = self.pool.get().await?;

        let rows = if let Some(value) = subscription {
            client
                .query(
                    format!(
                        r#"SELECT *
                            FROM heartbeats
                            JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription
                            WHERE {} = $1
                            AND subscription = $2"#,
                        field
                    )
                    .as_str(),
                    &[&field_value, &value],
                )
                .await?
        } else {
            client
                .query(
                    format!(
                        r#"SELECT *
                        FROM heartbeats
                        JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription
                        WHERE {} = $1"#,
                        field
                    )
                    .as_str(),
                    &[&field_value],
                )
                .await?
        };

        let mut heartbeats = Vec::new();
        for row in rows {
            heartbeats.push(row_to_heartbeat(&row)?);
        }
        Ok(heartbeats)
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }
}

fn row_to_subscription(row: &Row) -> Result<SubscriptionData> {
    let outputs_str: String = row.try_get("outputs")?;
    let outputs = match serde_json::from_str(&outputs_str) {
        Ok(outputs) => outputs,
        Err(e) => {
            error!(
                "Failed to parse subscription output : {}. Subscription output is {}",
                e, outputs_str
            );
            bail!("Failed to parse subscription output");
        }
    };
    let heartbeat_interval: i32 = row.try_get("heartbeat_interval")?;
    let connection_retry_count: i32 = row.try_get("connection_retry_count")?;
    let connection_retry_interval: i32 = row.try_get("connection_retry_interval")?;
    let max_envelope_size: i32 = row.try_get("max_envelope_size")?;
    let max_time: i32 = row.try_get("max_time")?;
    let max_elements: Option<i32> = row.try_get("max_elements")?;

    let client_filter = ClientFilter::from(
        row.try_get("princs_filter_op")?,
        row.try_get("princs_filter_value")?,
    )?;

    let mut subscription = SubscriptionData::new(row.try_get("name")?, row.try_get("query")?);
    subscription
        .set_uuid(SubscriptionUuid(Uuid::parse_str(row.try_get("uuid")?)?))
        .set_uri(row.try_get("uri")?)
        .set_revision(row.try_get("revision")?)
        .set_heartbeat_interval(heartbeat_interval.try_into()?)
        .set_connection_retry_count(connection_retry_count.try_into()?)
        .set_connection_retry_interval(connection_retry_interval.try_into()?)
        .set_max_time(max_time.try_into()?)
        .set_max_elements(match max_elements {
            Some(x) => Some(x.try_into()?),
            None => None,
        })
        .set_max_envelope_size(max_envelope_size.try_into()?)
        .set_enabled(row.try_get("enabled")?)
        .set_read_existing_events(row.try_get("read_existing_events")?)
        .set_content_format(ContentFormat::from_str(row.try_get("content_format")?)?)
        .set_ignore_channel_error(row.try_get("ignore_channel_error")?)
        .set_locale(row.try_get("locale")?)
        .set_data_locale(row.try_get("data_locale")?)
        .set_client_filter(client_filter)
        .set_outputs(outputs);

    // This needs to be done at the end because version is updated each time
    // a "set_" function is called
    subscription.set_internal_version(InternalVersion(Uuid::parse_str(row.try_get("version")?)?));

    Ok(subscription)
}

fn row_to_heartbeat(row: &Row) -> Result<HeartbeatData> {
    let subscription = row_to_subscription(row)?;
    let heartbeat = HeartbeatData::new(
        row.try_get("machine")?,
        row.try_get("ip")?,
        subscription,
        row.try_get("first_seen")?,
        row.try_get("last_seen")?,
        row.try_get("last_event_seen")?,
    );
    Ok(heartbeat)
}

fn gen_heartbeats_query(size: usize, with_event: bool) -> String {
    let mut query = "INSERT INTO heartbeats(machine, ip, subscription, first_seen, last_seen, last_event_seen) VALUES ".to_string();

    for i in 0..size {
        let values = if with_event {
            format!(
                "(${}, ${}, ${}, ${}, ${}, ${}) ",
                6 * i + 1,
                6 * i + 2,
                6 * i + 3,
                6 * i + 4,
                6 * i + 5,
                6 * i + 6
            )
        } else {
            format!(
                "(${}, ${}, ${}, ${}, ${}, null) ",
                5 * i + 1,
                5 * i + 2,
                5 * i + 3,
                5 * i + 4,
                5 * i + 5,
            )
        };
        if i == size - 1 {
            query.push_str(&values);
        } else {
            query.push_str(&values);
            query.push_str(", ");
        }
    }

    if with_event {
        query.push_str(
            r#"ON CONFLICT (machine, subscription) DO UPDATE SET
                last_seen = excluded.last_seen,
                last_event_seen = excluded.last_event_seen,
                ip = excluded.ip"#,
        );
    } else {
        query.push_str(
            r#"ON CONFLICT (machine, subscription) DO UPDATE SET
                last_seen = excluded.last_seen,
                ip = excluded.ip"#,
        );
    }
    query
}

#[async_trait]
impl Database for PostgresDatabase {
    async fn get_bookmark(&self, machine: &str, subscription: &str) -> Result<Option<String>> {
        let res = self
            .pool
            .get()
            .await?
            .query_opt(
                r#"SELECT bookmark
                FROM bookmarks
                WHERE machine = $1
                    AND subscription = $2"#,
                &[&machine, &subscription],
            )
            .await?;
        Ok(match res {
            Some(row) => Some(row.try_get("bookmark")?),
            None => None,
        })
    }

    async fn get_bookmarks(&self, subscription: &str) -> Result<Vec<BookmarkData>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"SELECT machine, bookmark
                FROM bookmarks
                WHERE subscription = $1"#,
                &[&subscription],
            )
            .await?;
        let mut bookmarks = Vec::new();
        for row in rows {
            bookmarks.push(BookmarkData {
                machine: row.try_get("machine")?,
                subscription: subscription.to_owned(),
                bookmark: row.try_get("bookmark")?,
            });
        }

        Ok(bookmarks)
    }

    async fn store_bookmark(
        &self,
        machine: &str,
        subscription: &str,
        bookmark: &str,
    ) -> Result<()> {
        let count = self
            .pool
            .get()
            .await?
            .execute(
                r#"INSERT INTO bookmarks(machine, subscription, bookmark)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (machine, subscription) DO
                        UPDATE SET bookmark = excluded.bookmark"#,
                &[&machine, &subscription, &bookmark],
            )
            .await?;

        ensure!(count == 1, "Only one row must have been updated");

        Ok(())
    }

    async fn delete_bookmarks(
        &self,
        machine: Option<&str>,
        subscription: Option<&str>,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        match (machine, subscription) {
            (Some(machine), Some(subscription)) => {
                client
                    .execute(
                        "DELETE FROM bookmarks WHERE machine = $1 AND subscription = $2",
                        &[&machine, &subscription],
                    )
                    .await?;
            }
            (Some(machine), None) => {
                client
                    .execute("DELETE FROM bookmarks WHERE machine = $1", &[&machine])
                    .await?;
            }
            (None, Some(subscription)) => {
                client
                    .execute(
                        "DELETE FROM bookmarks WHERE subscription = $1",
                        &[&subscription],
                    )
                    .await?;
            }
            (None, None) => {
                client.execute("DELETE FROM bookmarks", &[]).await?;
            }
        };
        Ok(())
    }

    async fn get_heartbeats_by_machine(
        &self,
        machine: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        self.get_heartbeats_by_field("machine", machine, subscription)
            .await
    }

    async fn get_heartbeats_by_ip(
        &self,
        ip: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        self.get_heartbeats_by_field("ip", ip, subscription).await
    }

    async fn get_heartbeats(&self) -> Result<Vec<HeartbeatData>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                r#"SELECT *
                FROM heartbeats
                JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription"#,
                &[],
            )
            .await?;
        let mut heartbeats = Vec::new();
        for row in rows {
            heartbeats.push(row_to_heartbeat(&row)?);
        }

        Ok(heartbeats)
    }

    async fn get_heartbeats_by_subscription(
        &self,
        subscription: &str,
    ) -> Result<Vec<HeartbeatData>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                r#"SELECT *
                    FROM heartbeats
                    JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription
                    WHERE subscription = $1"#,
                &[&subscription],
            )
            .await?;

        let mut heartbeats = Vec::new();
        for row in rows {
            heartbeats.push(row_to_heartbeat(&row)?);
        }

        Ok(heartbeats)
    }

    async fn store_heartbeat(
        &self,
        machine: &str,
        ip: String,
        subscription: &str,
        is_event: bool,
    ) -> Result<()> {
        let now: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .try_into()?;

        let query = if is_event {
            r#"INSERT INTO heartbeats(machine, ip, subscription, first_seen, last_seen, last_event_seen)
                    VALUES ($1, $2, $3, $4, $4, $4)
                    ON CONFLICT (machine, subscription) DO
                        UPDATE SET last_seen = excluded.last_seen,
                            last_event_seen = excluded.last_event_seen"#
        } else {
            r#"INSERT INTO heartbeats(machine, ip, subscription, first_seen, last_seen, last_event_seen)
                    VALUES ($1, $2, $3, $4, $4, null)
                    ON CONFLICT (machine, subscription) DO
                        UPDATE SET last_seen = excluded.last_seen"#
        };
        let count = self
            .pool
            .get()
            .await?
            .execute(query, &[&machine, &ip, &subscription, &now])
            .await?;

        ensure!(count == 1, "Only one row must have been updated");
        Ok(())
    }

    async fn store_heartbeats(&self, heartbeats: &HeartbeatsCache) -> Result<()> {
        let client = self.pool.get().await?;

        let mut with_event: Vec<(HeartbeatKey, PostgresHeartbeatEventValue)> = Vec::new();
        let mut without_event: Vec<(HeartbeatKey, PostgresHeartbeatValue)> = Vec::new();
        for (key, value) in heartbeats {
            let last_seen: i64 = value.last_seen.try_into()?;
            match value.last_event_seen {
                Some(last_event_seen) => {
                    let last_event_seen: i64 = last_event_seen.try_into()?;
                    with_event.push((
                        key.clone(),
                        PostgresHeartbeatEventValue {
                            last_seen,
                            ip: value.ip.clone(),
                            last_event_seen,
                        },
                    ))
                }
                None => {
                    without_event.push((
                        key.clone(),
                        PostgresHeartbeatValue {
                            last_seen,
                            ip: value.ip.clone(),
                        },
                    ));
                }
            }
        }

        for chunk in with_event.chunks(self.max_chunk_size) {
            let query = gen_heartbeats_query(chunk.len(), true);
            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
            for (key, value) in chunk {
                params.push(&key.machine);
                params.push(&value.ip);
                params.push(&key.subscription);
                params.push(&value.last_seen);
                params.push(&value.last_seen);
                params.push(&value.last_event_seen);
            }
            client.execute(&query, &params[..]).await?;
        }

        for chunk in without_event.chunks(self.max_chunk_size) {
            let query = gen_heartbeats_query(chunk.len(), false);
            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
            for (key, value) in chunk {
                params.push(&key.machine);
                params.push(&value.ip);
                params.push(&key.subscription);
                params.push(&value.last_seen);
                params.push(&value.last_seen);
            }
            client.execute(&query, &params[..]).await?;
        }

        Ok(())
    }

    async fn get_subscriptions(&self) -> Result<Vec<SubscriptionData>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                r#"
            SELECT *
            FROM subscriptions
            "#,
                &[],
            )
            .await?;

        let mut subscriptions = Vec::new();
        for row in rows {
            subscriptions.push(row_to_subscription(&row)?)
        }

        Ok(subscriptions)
    }

    async fn get_subscription_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<SubscriptionData>> {
        let res = self
            .pool
            .get()
            .await?
            .query_opt(
                r#"SELECT *
                        FROM subscriptions
                        WHERE uuid = $1 OR name = $1"#,
                &[&identifier],
            )
            .await?;

        Ok(match res {
            Some(row) => Some(row_to_subscription(&row)?),
            None => None,
        })
    }

    async fn store_subscription(&self, subscription: &SubscriptionData) -> Result<()> {
        let heartbeat_interval: i32 = subscription.heartbeat_interval().try_into()?;
        let connection_retry_count: i32 = subscription.connection_retry_count().into();
        let connection_retry_interval: i32 = subscription.connection_retry_interval().try_into()?;
        let max_time: i32 = subscription.max_time().try_into()?;
        let max_elements: Option<i32> = match subscription.max_elements() {
            Some(x) => Some(x.try_into()?),
            None => None,
        };

        let max_envelope_size: i32 = subscription.max_envelope_size().try_into()?;
        let count = self
            .pool
            .get()
            .await?
            .execute(
                r#"INSERT INTO subscriptions (uuid, version, revision, name, uri, query,
                    heartbeat_interval, connection_retry_count, connection_retry_interval,
                    max_time, max_elements, max_envelope_size, enabled, read_existing_events, content_format,
                    ignore_channel_error, princs_filter_op, princs_filter_value, outputs, locale,
                    data_locale)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
                    ON CONFLICT (uuid) DO UPDATE SET
                        version = excluded.version,
                        revision = excluded.revision,
                        name = excluded.name,
                        uri = excluded.uri,
                        query = excluded.query,
                        heartbeat_interval = excluded.heartbeat_interval,
                        connection_retry_count = excluded.connection_retry_count,
                        connection_retry_interval = excluded.connection_retry_interval,
                        max_time = excluded.max_time,
                        max_elements = excluded.max_elements,
                        max_envelope_size = excluded.max_envelope_size,
                        enabled = excluded.enabled,
                        read_existing_events = excluded.read_existing_events,
                        content_format = excluded.content_format,
                        ignore_channel_error = excluded.ignore_channel_error,
                        princs_filter_op = excluded.princs_filter_op,
                        princs_filter_value = excluded.princs_filter_value,
                        outputs = excluded.outputs,
                        locale = excluded.locale,
                        data_locale = excluded.data_locale"#,
                &[
                    &subscription.uuid_string(),
                    &subscription.internal_version().to_string(),
                    &subscription.revision(),
                    &subscription.name(),
                    &subscription.uri(),
                    &subscription.query(),
                    &heartbeat_interval,
                    &connection_retry_count,
                    &connection_retry_interval,
                    &max_time,
                    &max_elements,
                    &max_envelope_size,
                    &subscription.enabled(),
                    &subscription.read_existing_events(),
                    &subscription.content_format().to_string(),
                    &subscription.ignore_channel_error(),
                    &subscription
                        .client_filter()
                        .operation()
                        .map(|x| x.to_string()),
                    &subscription.client_filter().princs_to_opt_string(),
                    &serde_json::to_string(subscription.outputs())?.as_str(),
                    &subscription.locale(),
                    &subscription.data_locale()
                ],
            )
            .await?;

        ensure!(count == 1, "Only one row must have been updated");

        Ok(())
    }
    async fn delete_subscription(&self, uuid: &str) -> Result<()> {
        let count = self
            .pool
            .get()
            .await?
            .execute(r#"DELETE FROM subscriptions WHERE uuid = $1"#, &[&uuid])
            .await?;

        ensure!(count == 1, "Only one row must have been deleted");

        Ok(())
    }
    /// Create the tables required to keep track of schema state. If the tables already
    /// exist, this function has no operation.
    async fn setup_schema(&self) -> Result<()> {
        let query = format!(
            "CREATE TABLE IF NOT EXISTS {} (version BIGINT PRIMARY KEY);",
            MIGRATION_TABLE_NAME,
        );
        self.pool.get().await?.execute(query.as_str(), &[]).await?;
        Ok(())
    }

    async fn current_version(&self) -> Result<Option<Version>> {
        let query = format!(
            "SELECT version FROM {} ORDER BY version DESC LIMIT 1;",
            MIGRATION_TABLE_NAME
        );
        let conn = self.pool.get().await?;
        let row = conn.query_opt(query.as_str(), &[]).await?;
        let res = row.map(|r| r.get(0));

        Ok(res)
    }

    async fn migrated_versions(&self) -> Result<BTreeSet<Version>> {
        let query = format!("SELECT version FROM {};", MIGRATION_TABLE_NAME);
        let conn = self.pool.get().await?;
        let row = conn
            .query(query.as_str(), &[])
            .await
            .with_context(|| format!("Failed to execute query: \"{}\"", query))?;
        Ok(row.iter().map(|r| r.get(0)).collect())
    }

    async fn apply_migration(&self, version: Version) -> Result<()> {
        let migration = self
            .migrations
            .get(&version)
            .ok_or_else(|| anyhow!("Could not retrieve migration with version {}", version))?;
        let mut conn = self.pool.get().await?;
        let mut inner_tx = conn.transaction().await?;
        migration.up(&mut inner_tx).await?;
        let query = format!(
            "INSERT INTO {} (version) VALUES ($1);",
            MIGRATION_TABLE_NAME
        );
        let _count = inner_tx
            .execute(query.as_str(), &[&migration.version()])
            .await?;
        inner_tx.commit().await?;
        Ok(())
    }

    async fn revert_migration(&self, version: Version) -> Result<()> {
        let migration = self
            .migrations
            .get(&version)
            .ok_or_else(|| anyhow!("Could not retrieve migration with version {}", version))?;
        let mut conn = self.pool.get().await?;
        let mut inner_tx = conn.transaction().await?;
        migration.down(&mut inner_tx).await?;
        let query = format!("DELETE FROM {} WHERE version = $1;", MIGRATION_TABLE_NAME);
        let _count = inner_tx
            .execute(query.as_str(), &[&migration.version()])
            .await?;
        inner_tx.commit().await?;
        Ok(())
    }

    async fn migrations(&self) -> BTreeMap<Version, Arc<dyn Migration + Send + Sync>> {
        // TODO: Remove copy/paste between db backends
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
        let client = self.pool.get().await?;
        let total_machines_count = {
            let query = "SELECT COUNT(machine) FROM heartbeats WHERE subscription = $1";
            client
                .query_one(query, &[&subscription])
                .await
                .with_context(|| format!("Failed to execute query: \"{}\"", query))?
                .get(0)
        };
        let alive_machines_count = {
            let query =
                "SELECT COUNT(machine) FROM heartbeats WHERE subscription = $1 AND last_seen > $2 AND (last_event_seen IS NULL OR last_event_seen <= $2)";
            client
                .query_one(query, &[&subscription, &start_time])
                .await
                .with_context(|| format!("Failed to execute query: \"{}\"", query))?
                .get(0)
        };
        let active_machines_count = {
            let query =
                "SELECT COUNT(machine) FROM heartbeats WHERE subscription = $1 AND last_event_seen > $2";
            client
                .query_one(query, &[&subscription, &start_time])
                .await
                .with_context(|| format!("Failed to execute query: \"{}\"", query))?
                .get(0)
        };
        let dead_machines_count = {
            let query =
                "SELECT COUNT(machine) FROM heartbeats WHERE subscription = $1 AND last_seen <= $2 AND (last_event_seen IS NULL OR last_event_seen <= $2)";
            client
                .query_one(query, &[&subscription, &start_time])
                .await
                .with_context(|| format!("Failed to execute query: \"{}\"", query))?
                .get(0)
        };
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
        state: Option<SubscriptionMachineState>,
    ) -> Result<Vec<SubscriptionMachine>> {
        let client = self.pool.get().await?;

        let rows = match state {
            None => {
                let query = "SELECT machine, ip FROM heartbeats WHERE subscription = $1";
                client
                    .query(query, &[&subscription])
                    .await
                    .with_context(|| format!("Failed to execute query: \"{}\"", query))?
            }
            Some(SubscriptionMachineState::Alive) => {
                let query =
                    "SELECT machine, ip FROM heartbeats WHERE subscription = $1 AND (last_event_seen IS NULL OR last_event_seen <= $2) AND last_seen > $2";
                client
                    .query(query, &[&subscription, &start_time])
                    .await
                    .with_context(|| format!("Failed to execute query: \"{}\"", query))?
            }
            Some(SubscriptionMachineState::Active) => {
                let query =
                    "SELECT machine, ip FROM heartbeats WHERE subscription = $1 AND last_event_seen > $2";
                client
                    .query(query, &[&subscription, &start_time])
                    .await
                    .with_context(|| format!("Failed to execute query: \"{}\"", query))?
            }
            Some(SubscriptionMachineState::Dead) => {
                let query =
                    "SELECT machine, ip FROM heartbeats WHERE subscription = $1 AND (last_event_seen IS NULL OR last_event_seen <= $2) AND last_seen <= $2";
                client
                    .query(query, &[&subscription, &start_time])
                    .await
                    .with_context(|| format!("Failed to execute query: \"{}\"", query))?
            }
        };

        let mut result = Vec::new();
        for row in rows {
            result.push(SubscriptionMachine::new(
                row.try_get("machine")?,
                row.try_get("ip")?,
            ))
        }
        Ok(result)
    }
}

#[cfg(test)]
pub mod tests {

    use serial_test::serial;

    use crate::database::schema::{self, Migrator};
    use crate::migration;

    use super::*;
    use std::env;
    use std::str::FromStr;

    async fn drop_migrations_table(db: &PostgresDatabase) -> Result<()> {
        db.pool
            .get()
            .await?
            .execute(
                format!("DROP TABLE IF EXISTS {};", MIGRATION_TABLE_NAME).as_str(),
                &[],
            )
            .await?;
        Ok(())
    }

    async fn db_with_migrations() -> Result<Arc<dyn Database>> {
        let mut db = PostgresDatabase::new(&get_config())
            .await
            .expect("Could not connect to database");
        schema::postgres::register_migrations(&mut db);
        drop_migrations_table(&db).await?;
        Ok(Arc::new(db))
    }

    pub fn get_config() -> Postgres {
        let host = env::var("POSTGRES_HOST")
            .expect("$POSTGRES_HOST is not set")
            .to_owned();
        let port = u16::from_str(
            env::var("POSTGRES_PORT")
                .expect("$POSTGRES_PORT is not set")
                .to_owned()
                .as_str(),
        )
        .expect("Could not convert port string to u16");
        let user = env::var("POSTGRES_USER")
            .expect("$POSTGRES_USER is not set")
            .to_owned();
        let password = env::var("POSTGRES_PASSWORD")
            .expect("$POSTGRES_PASSWORD is not set")
            .to_owned();
        let dbname = env::var("POSTGRES_DBNAME")
            .expect("$POSTGRES_DBNAME is not set")
            .to_owned();
        let ssl_mode = PostgresSslMode::Disable;
        let ca_file = None;

        Postgres::new(
            &host,
            port,
            &dbname,
            &user,
            &password,
            ssl_mode,
            ca_file,
            Some(50),
        )
    }

    #[tokio::test]
    #[serial]
    async fn test_open_and_close() -> Result<()> {
        PostgresDatabase::new(&get_config())
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

    struct CreateUsers;
    migration!(CreateUsers, 1, "create users table");

    #[async_trait]
    impl PostgresMigration for CreateUsers {
        async fn up(&self, tx: &mut Transaction) -> Result<()> {
            tx.execute("CREATE TABLE users (id BIGINT PRIMARY KEY);", &[])
                .await?;
            Ok(())
        }

        async fn down(&self, tx: &mut Transaction) -> Result<()> {
            tx.execute("DROP TABLE users;", &[]).await?;
            Ok(())
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_register() -> Result<()> {
        let mut db = PostgresDatabase::new(&get_config())
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
    async fn test_stats() -> Result<()> {
        crate::database::tests::test_stats_and_machines(db_with_migrations().await?).await?;
        Ok(())
    }
}
