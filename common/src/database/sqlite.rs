// Some of the following code is inspired from
// https://github.com/SkylerLipthay/schemamama_postgres. As stated by its
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
use anyhow::{anyhow, ensure, Context, Error, Result};
use async_trait::async_trait;
use deadpool_sqlite::{Config, Pool, Runtime};
use log::warn;
use rusqlite::{named_params, params, Connection, OptionalExtension, Row};
use uuid::Uuid;
use std::collections::btree_map::Entry::Vacant;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::bookmark::BookmarkData;
use crate::database::Database;
use crate::heartbeat::{HeartbeatData, HeartbeatsCache};
use crate::subscription::{
    ContentFormat, InternalVersion, ClientFilter, SubscriptionData, SubscriptionMachine, SubscriptionMachineState, SubscriptionStatsCounters, SubscriptionUuid
};

use super::schema::{Migration, MigrationBase, Version};

const MIGRATION_TABLE_NAME: &str = "__schema_migrations";
/// A migration to be used within a Sqlite connection.
pub trait SQLiteMigration: Migration {
    /// Called when this migration is to be executed.
    fn up(&self, conn: &Connection) -> Result<()>;

    /// Called when this migration is to be reversed.
    fn down(&self, conn: &Connection) -> Result<()>;

    fn to_base(&self) -> Arc<dyn Migration + Send + Sync> {
        Arc::new(MigrationBase::new(self.version(), self.description()))
    }
}

pub struct SQLiteDatabase {
    pool: Pool,
    migrations: BTreeMap<Version, Arc<dyn SQLiteMigration + Send + Sync>>,
}

fn optional<T>(res: Result<T>) -> Result<Option<T>> {
    match res {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            match e.downcast_ref::<rusqlite::Error>() {
                Some(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                _ => Err(e),
            }
        }
    }
}

impl SQLiteDatabase {
    pub async fn new(path: &str) -> Result<SQLiteDatabase> {
        let config = Config::new(path);
        let pool = config.create_pool(Runtime::Tokio1)?;

        let db = SQLiteDatabase {
            pool,
            migrations: BTreeMap::new(),
        };

        Ok(db)
    }

    /// Register a migration. If a migration with the same version is already registered, a warning
    /// is logged and the registration fails.
    pub fn register_migration(&mut self, migration: Arc<dyn SQLiteMigration + Send + Sync>) {
        let version = migration.version();
        if let Vacant(e) = self.migrations.entry(version) {
            e.insert(migration);
        } else {
            warn!("Migration with version {:?} is already registered", version);
        }
    }

    async fn get_heartbeats_by_field(
        &self,
        field: &'static str,
        field_value: String,
        subscription: Option<String>,
    ) -> Result<Vec<HeartbeatData>> {
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                if let Some(value) = subscription {
                    let mut statement = conn.prepare(
                        format!(
                            r#"SELECT *
                            FROM heartbeats
                            JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription
                            WHERE {} = :field_value
                            AND subscription = :subscription"#,
                            field
                        )
                        .as_str()
                    )?;
                    let rows = statement.query_and_then(&[(":field_value", &field_value), (":subscription", &value)], row_to_heartbeat)?;

                    let mut heartbeats = Vec::new();
                    for heartbeat in rows {
                        heartbeats.push(heartbeat?);
                    }
                    Ok(heartbeats)
                } else {
                    let mut statement = conn.prepare(
                        format!(
                            r#"SELECT *
                            FROM heartbeats
                            JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription
                            WHERE {} = :field_value"#,
                            field
                        )
                        .as_str()
                    )?;
                    let rows = statement.query_and_then(&[(":field_value", &field_value)], row_to_heartbeat)?;
                    let mut heartbeats = Vec::new();
                    for heartbeat in rows {
                        heartbeats.push(heartbeat?);
                    }
                    Ok(heartbeats)
                }
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }
}

fn row_to_subscription(row: &Row) -> Result<SubscriptionData> {
    let outputs_str: String = row.get("outputs")?;
    let outputs = serde_json::from_str(&outputs_str).context("Failed to parse subscription output")?;

    // row.get can not convert into &str, so we retrieve String(s) first
    let name: String = row.get("name")?;
    let uuid: String = row.get("uuid")?;
    let version: String = row.get("version")?;
    let query: String = row.get("query")?;

    let content_format = ContentFormat::from_str(row.get::<&str, String>("content_format")?.as_ref())?;

    let client_filter_op: Option<String> = row.get("client_filter_op")?;

    let client_filter = match client_filter_op {
        Some(op) => Some(ClientFilter::from(op, row.get("client_filter_value")?)?),
        None => None
    };

    let mut subscription= SubscriptionData::new(&name, &query);
    subscription.set_uuid(SubscriptionUuid(Uuid::parse_str(&uuid)?))
        .set_uri(row.get("uri")?)
        .set_revision(row.get("revision")?)
        .set_heartbeat_interval(row.get("heartbeat_interval")?)
        .set_connection_retry_count(row.get("connection_retry_count")?)
        .set_connection_retry_interval(row.get("connection_retry_interval")?)
        .set_max_time(row.get("max_time")?)
        .set_max_elements(row.get("max_elements")?)
        .set_max_envelope_size(row.get("max_envelope_size")?)
        .set_enabled(row.get("enabled")?)
        .set_read_existing_events(row.get("read_existing_events")?)
        .set_content_format(content_format)
        .set_ignore_channel_error(row.get("ignore_channel_error")?)
        .set_locale(row.get("locale")?)
        .set_data_locale(row.get("data_locale")?)
        .set_client_filter(client_filter)
        .set_outputs(outputs);

    // This needs to be done at the end because version is updated each time
    // a "set_" function is called
    subscription.set_internal_version(InternalVersion(Uuid::parse_str(&version)?));

    Ok(subscription)
}

fn row_to_heartbeat(row: &Row) -> Result<HeartbeatData> {
    let subscription = row_to_subscription(row)?;
    let heartbeat = HeartbeatData::new(
        row.get("machine")?,
        row.get("ip")?,
        subscription,
        row.get("first_seen")?,
        row.get("last_seen")?,
        row.get("last_event_seen")?,
    );
    Ok(heartbeat)
}

#[async_trait]
impl Database for SQLiteDatabase {
    async fn get_bookmark(&self, machine: &str, subscription: &str) -> Result<Option<String>> {
        let machine_owned = machine.to_string();
        let subscription_owned = subscription.to_string();
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                conn.query_row(
                    r#"SELECT bookmark FROM bookmarks
                                WHERE machine = :machine
                                    AND subscription = :subscription"#,
                    &[
                        (":machine", &machine_owned),
                        (":subscription", &subscription_owned),
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|err| anyhow!(err))
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }

    async fn get_bookmarks(&self, subscription: &str) -> Result<Vec<BookmarkData>> {
        let subscription_owned = subscription.to_string();
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                let mut statement = conn.prepare(
                    r#"SELECT machine, bookmark FROM bookmarks
                                WHERE subscription = :subscription"#,
                )?;
                let rows = statement.query_map(&[
                        (":subscription", &subscription_owned),
                    ], |row| Ok(BookmarkData {
                        machine: row.get(0)?,
                        bookmark: row.get(1)?,
                        subscription: subscription_owned.clone(),
                    }))?;

                let mut bookmarks = Vec::new();
                for bookmark in rows {
                    bookmarks.push(bookmark?);
                }
                Ok(bookmarks)
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }

    async fn store_bookmark(
        &self,
        machine: &str,
        subscription: &str,
        bookmark: &str,
    ) -> Result<()> {
        let machine_s = machine.to_string();
        let subscription_s = subscription.to_string();
        let bookmark_s = bookmark.to_string();
        let count = self
            .pool
            .get()
            .await?
            .interact(move |conn| {
                conn.execute(
                    r#"INSERT INTO bookmarks(machine, subscription, bookmark)
                    VALUES (:machine, :subscription, :bookmark)
                    ON CONFLICT (machine, subscription) DO
                        UPDATE SET bookmark = excluded.bookmark"#,
                    &[
                        (":machine", &machine_s),
                        (":subscription", &subscription_s),
                        (":bookmark", &bookmark_s),
                    ],
                )
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;

        ensure!(count == 1, "Only one row must have been updated");

        Ok(())
    }
    async fn delete_bookmarks(
        &self,
        machine: Option<&str>,
        subscription: Option<&str>,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        let future = match (machine, subscription) {
            (Some(machine), Some(subscription)) => {
                let machine = machine.to_owned();
                let subscription = subscription.to_owned();
                client.interact(move |conn| {
                    conn.execute("DELETE FROM bookmarks WHERE machine = ?1 AND subscription = ?2", params![machine, subscription])
                }).await
            }
            (Some(machine), None) => {
                let machine = machine.to_owned();
                client.interact(move |conn| {
                    conn.execute("DELETE FROM bookmarks WHERE machine = ?1", params![machine])
                }).await
            }
            (None, Some(subscription)) => {
                let subscription = subscription.to_owned();
                client.interact(move |conn| {
                    conn.execute("DELETE FROM bookmarks WHERE subscription = ?1", params![subscription])
                }).await
            },
            (None, None) => {
                client.interact(move |conn| {
                    conn.execute("DELETE FROM bookmarks", [])
                }).await
            }
        };
        future.map_err(|err| anyhow!(format!("{}", err)))??;
        Ok(())

    }

    async fn get_heartbeats_by_machine(
        &self,
        machine: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        self.get_heartbeats_by_field(
            "machine",
            machine.to_string(),
            subscription.map(|s| s.to_owned()),
        )
        .await
    }

    async fn get_heartbeats_by_ip(
        &self,
        ip: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>> {
        self.get_heartbeats_by_field("ip", ip.to_string(), subscription.map(|s| s.to_owned()))
            .await
    }

    async fn get_heartbeats(&self) -> Result<Vec<HeartbeatData>> {
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                let mut statement = conn.prepare(
                    r#"SELECT *
                    FROM heartbeats
                    JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription
                    "#,
                )?;
                let rows = statement.query_and_then((), row_to_heartbeat)?;

                let mut heartbeats = Vec::new();
                for heartbeat in rows {
                    heartbeats.push(heartbeat?);
                }
                Ok(heartbeats)
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }

    async fn get_heartbeats_by_subscription(
        &self,
        subscription: &str,
    ) -> Result<Vec<HeartbeatData>> {
        let subscription_owned = subscription.to_string();
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                let mut statement = conn.prepare(
                    r#"SELECT *
                    FROM heartbeats
                    JOIN subscriptions ON subscriptions.uuid = heartbeats.subscription
                    WHERE subscription = :subscription"#,
                )?;
                let rows = statement
                    .query_and_then(&[(":subscription", &subscription_owned)], row_to_heartbeat)?;

                let mut heartbeats = Vec::new();
                for heartbeat in rows {
                    heartbeats.push(heartbeat?);
                }
                Ok(heartbeats)
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }

    async fn store_heartbeat(
        &self,
        machine: &str,
        ip: String,
        subscription: &str,
        is_event: bool,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        let machine_owned = machine.to_string();
        let subscription_owned = subscription.to_string();

        let query = if is_event {
            r#"INSERT INTO heartbeats(machine, ip, subscription, first_seen, last_seen, last_event_seen)
                        VALUES (?1, ?2, ?3, ?4, ?4, ?4)
                        ON CONFLICT (machine, subscription) DO
                            UPDATE SET last_seen = excluded.last_seen,
                                last_event_seen = excluded.last_event_seen"#
        } else {
            r#"INSERT INTO heartbeats(machine, ip, subscription, first_seen, last_seen, last_event_seen)
                        VALUES (?1, ?2, ?3, ?4, ?4, NULL)
                        ON CONFLICT (machine, subscription) DO
                            UPDATE SET last_seen = excluded.last_seen"#
        };

        let count = self
            .pool
            .get()
            .await?
            .interact(move |conn| {
                conn.execute(
                    query,
                    params![&machine_owned, &ip, &subscription_owned, now],
                )
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;

        ensure!(count == 1, "Only one row must have been updated");

        Ok(())
    }

    async fn store_heartbeats(&self, heartbeats: &HeartbeatsCache) -> Result<()> {
        let client = self.pool.get().await?;
        // TODO: remove this clone, maybe use an Arc
        let heartbeats_cloned = heartbeats.clone();

        client.interact(move |conn| {
            let transaction = conn.transaction()?;

            let mut query_with_event = transaction.prepare(
                r#"INSERT INTO heartbeats(machine, ip, subscription, first_seen, last_seen, last_event_seen)
                            VALUES (?1, ?2, ?3, ?4, ?4, ?5)
                            ON CONFLICT (machine, subscription) DO
                                UPDATE SET last_seen = excluded.last_seen,
                                    last_event_seen = excluded.last_event_seen"#)?;
            let mut query_without_event = transaction.prepare(
                r#"INSERT INTO heartbeats(machine, ip, subscription, first_seen, last_seen, last_event_seen)
                            VALUES (?1, ?2, ?3, ?4, ?4, NULL)
                            ON CONFLICT (machine, subscription) DO
                                UPDATE SET last_seen = excluded.last_seen"#)?;

            for (key, value) in heartbeats_cloned {
                match value.last_event_seen {
                    Some(last_event_seen) => {
                        query_with_event
                            .execute(
                                params![
                                    &key.machine,
                                    &value.ip,
                                    &key.subscription,
                                    &value.last_seen,
                                    &last_event_seen,
                                ],
                            )?;
                    }
                    None => {
                        query_without_event
                            .execute(
                                params![&key.machine, &value.ip, &key.subscription, &value.last_seen],
                            )?;
                    }
                }
            }

            query_with_event.finalize()?;
            query_without_event.finalize()?;
            transaction.commit()?;
            Ok::<(), rusqlite::Error>(())
        }).await
            .map_err(|err| anyhow!(format!("{}", err)))??;
        Ok(())
    }

    async fn get_subscriptions(&self) -> Result<Vec<SubscriptionData>> {
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                let mut statement = conn.prepare(
                    r#"SELECT *
                    FROM subscriptions
                "#,
                )?;
                let rows = statement.query_and_then((), row_to_subscription)?;

                let mut subscriptions = Vec::new();
                for subscription in rows {
                    subscriptions.push(subscription?);
                }
                Ok(subscriptions)
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }

    async fn get_subscription_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<SubscriptionData>> {
        let identifier = identifier.to_string();
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                optional(
                    conn.query_row_and_then(
                        r#"SELECT *
                        FROM subscriptions
                        WHERE name = :identifier OR uuid = :identifier"#,
                        &[(":identifier", &identifier)],
                        row_to_subscription,
                    )
                )
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }

    async fn store_subscription(&self, subscription: &SubscriptionData) -> Result<()> {
        let subscription = subscription.clone();
        let client_filter_op: Option<String> = subscription.client_filter().map(|f| f.operation().to_string());
        let client_filter_value = subscription.client_filter().and_then(|f| f.targets_to_opt_string());

        let count = self
            .pool
            .get()
            .await?
            .interact(move |conn| {
                conn.execute(
                    r#"INSERT INTO subscriptions (uuid, version, revision, name, uri, query,
                    heartbeat_interval, connection_retry_count, connection_retry_interval,
                    max_time, max_elements, max_envelope_size, enabled, read_existing_events, content_format,
                    ignore_channel_error, client_filter_op, client_filter_value, outputs, locale,
                    data_locale)
                    VALUES (:uuid, :version, :revision, :name, :uri, :query,
                        :heartbeat_interval, :connection_retry_count, :connection_retry_interval,
                        :max_time, :max_elements, :max_envelope_size, :enabled, :read_existing_events, :content_format,
                        :ignore_channel_error, :client_filter_op, :client_filter_value, :outputs,
                        :locale, :data_locale)
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
                        client_filter_op = excluded.client_filter_op,
                        client_filter_value = excluded.client_filter_value,
                        outputs = excluded.outputs,
                        locale = excluded.locale,
                        data_locale = excluded.data_locale"#,
                    named_params! {
                        ":uuid": subscription.uuid_string(),
                        ":version": subscription.internal_version().to_string(),
                        ":revision": subscription.revision(),
                        ":name": subscription.name(),
                        ":uri": subscription.uri(),
                        ":query": subscription.query(),
                        ":heartbeat_interval": subscription.heartbeat_interval(),
                        ":connection_retry_count": subscription.connection_retry_count(),
                        ":connection_retry_interval": subscription.connection_retry_interval(),
                        ":max_time": subscription.max_time(),
                        ":max_elements": subscription.max_elements(),
                        ":max_envelope_size": subscription.max_envelope_size(),
                        ":enabled": subscription.enabled(),
                        ":read_existing_events": subscription.read_existing_events(),
                        ":content_format": subscription.content_format().to_string(),
                        ":ignore_channel_error": subscription.ignore_channel_error(),
                        ":client_filter_op": client_filter_op,
                        ":client_filter_value": client_filter_value,
                        ":outputs": serde_json::to_string(subscription.outputs())?,
                        ":locale": subscription.locale(),
                        ":data_locale": subscription.data_locale(),
                    },
                )
                .map_err(|err| anyhow!(err))
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;

        ensure!(count == 1, "Only one row must have been updated");

        Ok(())
    }

    async fn delete_subscription(&self, uuid: &str) -> Result<()> {
        let uuid_owned = uuid.to_string();
        let count = self
            .pool
            .get()
            .await?
            .interact(move |conn| {
                conn.execute(
                    r#"DELETE FROM subscriptions WHERE uuid = :uuid"#,
                    &[(":uuid", &uuid_owned)],
                )
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;

        ensure!(count == 1, "Only one row must have been deleted");

        Ok(())
    }

    /// Fails if `setup_schema` hasn't previously been called or if the query otherwise fails.
    async fn current_version(&self) -> Result<Option<Version>> {
        let query = format!(
            "SELECT version FROM {} ORDER BY version DESC LIMIT 1;",
            MIGRATION_TABLE_NAME
        );
        self.pool
            .get()
            .await?
            .interact(
                move |conn| match conn.query_row(&query, [], |row| row.get("version")) {
                    Ok(version) => Ok(Some(version)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                },
            )
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }

    /// Fails if `setup_schema` hasn't previously been called or if the query otherwise fails.
    async fn migrated_versions(&self) -> Result<BTreeSet<Version>> {
        let query = format!("SELECT version FROM {};", MIGRATION_TABLE_NAME);
        // This clone is required if we want to be able to print the query in
        // case of error. This function is called only in the start of programs so
        // the overhead is acceptable.
        let query_for_context_error = query.clone();

        let versions = self
            .pool
            .get()
            .await?
            .interact(move |conn| {
                let mut statement = conn.prepare(&query)?;
                let result =
                    statement.query_map([], |row_result| row_result.get::<&str, i64>("version"))?;
                let mut versions = BTreeSet::new();
                for vresult in result {
                    versions.insert(vresult?);
                }
                Ok::<BTreeSet<i64>, rusqlite::Error>(versions)
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))
            .with_context(|| {
                format!("Failed to execute query: \"{}\"", query_for_context_error)
            })??;

        Ok(versions)
    }

    /// Fails if `setup_schema` hasn't previously been called or if the migration otherwise fails.
    async fn apply_migration(&self, version: Version) -> Result<()> {
        let migration = self
            .migrations
            .get(&version)
            .ok_or_else(|| anyhow!("Could not retrieve migration with version {}", version))?
            .clone();
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                let tx = conn.transaction()?;

                migration.up(&tx)?;
                let query = format!(
                    "INSERT INTO {} (version) VALUES ($1);",
                    MIGRATION_TABLE_NAME
                );
                let _count = tx.execute(&query, [&migration.version()])?;

                tx.commit()?;
                Ok::<_, Error>(())
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;

        Ok(())
    }

    /// Fails if `setup_schema` hasn't previously been called or if the migration otherwise fails.
    async fn revert_migration(&self, version: Version) -> Result<()> {
        let migration = self
            .migrations
            .get(&version)
            .ok_or_else(|| anyhow!("Could not retrieve migration with version {}", version))?
            .clone();
        self.pool
            .get()
            .await?
            .interact(move |conn| {
                let tx = conn.transaction()?;
                migration.down(&tx)?;

                let query = format!("DELETE FROM {} WHERE version = $1;", MIGRATION_TABLE_NAME);
                let _count = tx.execute(&query, [&migration.version()])?;
                tx.commit()?;
                Ok::<_, Error>(())
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;

        Ok(())
    }

    /// Create the tables required to keep track of schema state. If the tables already
    /// exist, this function has no operation.
    async fn setup_schema(&self) -> Result<()> {
        let query = format!(
            "CREATE TABLE IF NOT EXISTS {} (version BIGINT PRIMARY KEY);",
            MIGRATION_TABLE_NAME
        );
        self.pool
            .get()
            .await?
            .interact(move |conn| conn.execute(&query, []))
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;
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
        let subscription_arc = Arc::new(subscription.to_string());
        let client = self.pool.get().await?;
        let subscription_owned = subscription_arc.clone();
        let total_machines_count = client
            .interact(move |conn| {
                conn.query_row(
                    r#"SELECT COUNT(machine)
                    FROM heartbeats
                    WHERE subscription = :subscription"#,
                    &[(":subscription", &subscription_owned)],
                    |row| row.get(0),
                )
                .map_err(|err| anyhow!(err))
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;
        // subscription_owned bas been moved into previous interact closure
        let subscription_owned = subscription_arc.clone();
        let alive_machines_count = client
            .interact(move |conn| {
                conn.query_row(
                    r#"SELECT COUNT(machine)
                    FROM heartbeats
                    WHERE subscription = :subscription AND last_seen > :start_time AND (last_event_seen IS NULL OR last_event_seen <= :start_time)"#,
                    named_params! {
                        ":subscription": &subscription_owned,
                        ":start_time": &start_time,
                    },
                    |row| row.get(0),
                )
                .map_err(|err| anyhow!(err))
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;
        // subscription_owned bas been moved into previous interact closure
        let subscription_owned = subscription_arc.clone();
        let active_machines_count = client
            .interact(move |conn| {
                conn.query_row(
                    r#"SELECT COUNT(machine)
                    FROM heartbeats
                    WHERE subscription = :subscription AND last_event_seen > :start_time"#,
                    named_params! {
                        ":subscription": &subscription_owned,
                        ":start_time": &start_time,
                    },
                    |row| row.get(0),
                )
                .map_err(|err| anyhow!(err))
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;
        // subscription_owned bas been moved into previous interact closure
        let subscription_owned = subscription_arc.clone();
        let dead_machines_count = client
            .interact(move |conn| {
                conn.query_row(
                    r#"SELECT COUNT(machine)
                    FROM heartbeats
                    WHERE subscription = :subscription AND (last_event_seen IS NULL OR last_event_seen <= :start_time) AND last_seen <= :start_time"#,
                    named_params! {
                        ":subscription": &subscription_owned,
                        ":start_time": &start_time,
                    },
                    |row| row.get(0),
                )
                .map_err(|err| anyhow!(err))
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))??;
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
        let subscription_owned = subscription.to_owned();
        let client = self.pool.get().await?;
        client
            .interact(move |conn| {
                let mut result = Vec::new();
                match stat_type {
                    None => {
                        let mut statement = conn.prepare("SELECT * FROM heartbeats WHERE subscription = :subscription")?;
                        let rows = statement.query_map(named_params! { ":subscription": subscription_owned}, |row| {
                            Ok(SubscriptionMachine::new(row.get("machine")?, row.get("ip")?))
                        })?;
                        for stat in rows {
                            result.push(stat?);
                        }
                    },
                    Some(SubscriptionMachineState::Active) => {
                        let mut statement = conn.prepare("SELECT * FROM heartbeats WHERE subscription = :subscription AND last_event_seen > :start_time")?;
                        let rows = statement.query_map(named_params! { ":subscription": subscription_owned, ":start_time": start_time}, |row| {
                            Ok(SubscriptionMachine::new(row.get("machine")?, row.get("ip")?))
                        })?;
                        for stat in rows {
                            result.push(stat?);
                        }
                    },
                    Some(SubscriptionMachineState::Alive) => {
                        let mut statement = conn.prepare("SELECT * FROM heartbeats WHERE subscription = :subscription AND last_seen > :start_time AND (last_event_seen IS NULL OR last_event_seen <= :start_time)")?;
                        let rows = statement.query_map(named_params! { ":subscription": subscription_owned, ":start_time": start_time}, |row| {
                            Ok(SubscriptionMachine::new(row.get("machine")?, row.get("ip")?))
                        })?;
                        for stat in rows {
                            result.push(stat?);
                        }
                    },
                    Some(SubscriptionMachineState::Dead) => {
                        let mut statement = conn.prepare("SELECT * FROM heartbeats WHERE subscription = :subscription AND last_seen <= :start_time AND (last_event_seen IS NULL OR last_event_seen <= :start_time)")?;
                        let rows = statement.query_map(named_params! { ":subscription": subscription_owned, ":start_time": start_time}, |row| {
                            Ok(SubscriptionMachine::new(row.get("machine")?, row.get("ip")?))
                        })?;
                        for stat in rows {
                            result.push(stat?);
                        }
                    }
                };
                Ok::<Vec<SubscriptionMachine>, anyhow::Error>(result)
            })
            .await
            .map_err(|err| anyhow!(format!("{}", err)))?
    }
}

#[cfg(test)]
mod tests {

    use tempfile::TempPath;

    use crate::{
        database::schema::{self, Migrator},
        migration,
    };

    use super::*;

    async fn db_with_migrations(path: &TempPath) -> Result<Arc<dyn Database>> {
        let mut db = SQLiteDatabase::new(path.to_str().expect("Invalid temp file name")).await?;
        schema::sqlite::register_migrations(&mut db);
        Ok(Arc::new(db))
    }

    #[tokio::test]
    async fn test_open_and_close() -> Result<()> {
        let temp_file = tempfile::NamedTempFile::new()?;
        let path = temp_file.into_temp_path();
        {
            SQLiteDatabase::new(path.to_str().expect("Invalid temp file name"))
                .await
                .expect("Could not create database");
        }
        path.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_bookmarks() -> Result<()> {
        let temp_file = tempfile::NamedTempFile::new()?;
        let path = temp_file.into_temp_path();
        {
            crate::database::tests::test_bookmarks(db_with_migrations(&path).await?).await?;
        }
        path.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_heartbeats() -> Result<()> {
        let temp_file = tempfile::NamedTempFile::new()?;
        let path = temp_file.into_temp_path();
        {
            crate::database::tests::test_heartbeats(db_with_migrations(&path).await?).await?;
        }
        path.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_subscriptions() -> Result<()> {
        let temp_file = tempfile::NamedTempFile::new()?;
        let path = temp_file.into_temp_path();
        {
            crate::database::tests::test_subscriptions(db_with_migrations(&path).await?).await?;
        }
        Ok(())
    }

    struct CreateUsers;
    migration!(CreateUsers, 1, "create users table");

    impl SQLiteMigration for CreateUsers {
        fn up(&self, conn: &Connection) -> Result<()> {
            conn.execute("CREATE TABLE users (id BIGINT PRIMARY KEY);", [])
                .map_err(|err| anyhow!("SQLiteError: {}", err))?;
            Ok(())
        }

        fn down(&self, conn: &Connection) -> Result<()> {
            conn.execute("DROP TABLE users;", [])
                .map_err(|err| anyhow!("SQLiteError: {}", err))?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_register() -> Result<()> {
        let temp_file = tempfile::NamedTempFile::new()?;
        let path = temp_file.into_temp_path();
        {
            let mut db =
                SQLiteDatabase::new(path.to_str().expect("Invalid temp file name")).await?;

            db.register_migration(Arc::new(CreateUsers));
            db.setup_schema().await?;

            let arc_db = Arc::new(db);
            let migrator = Migrator::new(arc_db.clone());

            migrator.up(None, false).await.unwrap();

            assert_eq!(arc_db.current_version().await.unwrap(), Some(1));

            migrator.down(None, false).await.unwrap();

            assert_eq!(arc_db.current_version().await.unwrap(), None);
        }
        path.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_stats() -> Result<()> {
        let temp_file = tempfile::NamedTempFile::new()?;
        let path = temp_file.into_temp_path();
        {
            crate::database::tests::test_stats_and_machines(db_with_migrations(&path).await?)
                .await?;
        }
        Ok(())
    }
}
