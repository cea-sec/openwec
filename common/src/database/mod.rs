use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::{
    bookmark::BookmarkData,
    database::postgres::PostgresDatabase,
    database::sqlite::SQLiteDatabase,
    heartbeat::{HeartbeatData, HeartbeatsCache},
    settings::Settings,
    subscription::{
        SubscriptionData, SubscriptionMachine, SubscriptionMachineState, SubscriptionStatsCounters,
    },
};
use anyhow::{Context, Result};
use async_trait::async_trait;

use self::schema::{Migration, Version};

pub mod postgres;
pub mod schema;
pub mod sqlite;

pub type Db = Arc<dyn Database + Send + Sync>;

pub async fn db_from_settings(settings: &Settings) -> Result<Db> {
    match settings.database() {
        crate::settings::Database::SQLite(sqlite) => {
            let mut db = SQLiteDatabase::new(sqlite.path())
                .await
                .context("Failed to initialize SQLite client")?;
            schema::sqlite::register_migrations(&mut db);
            Ok(Arc::new(db))
        }
        crate::settings::Database::Postgres(postgres) => {
            let mut db = PostgresDatabase::new(postgres)
                .await
                .context("Failed to initialize Postgres client")?;
            schema::postgres::register_migrations(&mut db);
            Ok(Arc::new(db))
        }
    }
}

#[async_trait]
pub trait Database {
    async fn get_bookmark(&self, machine: &str, subscription: &str) -> Result<Option<String>>;
    async fn get_bookmarks(&self, subscription: &str) -> Result<Vec<BookmarkData>>;
    async fn store_bookmark(&self, machine: &str, subscription: &str, bookmark: &str)
        -> Result<()>;
    async fn delete_bookmarks(
        &self,
        machine: Option<&str>,
        subscription: Option<&str>,
    ) -> Result<()>;

    async fn get_heartbeats(&self) -> Result<Vec<HeartbeatData>>;
    async fn get_heartbeats_by_machine(
        &self,
        machine: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>>;
    async fn get_heartbeats_by_ip(
        &self,
        ip: &str,
        subscription: Option<&str>,
    ) -> Result<Vec<HeartbeatData>>;
    async fn get_heartbeats_by_subscription(
        &self,
        subscription: &str,
    ) -> Result<Vec<HeartbeatData>>;
    async fn store_heartbeat(
        &self,
        machine: &str,
        ip: String,
        subscription: &str,
        is_event: bool,
    ) -> Result<()>;
    async fn store_heartbeats(&self, heartbeats: &HeartbeatsCache) -> Result<()>;

    async fn get_subscriptions(&self) -> Result<Vec<SubscriptionData>>;
    async fn get_subscription_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<SubscriptionData>>;
    async fn store_subscription(&self, subscription: &SubscriptionData) -> Result<()>;
    async fn delete_subscription(&self, uuid: &str) -> Result<()>;

    async fn setup_schema(&self) -> Result<()>;
    async fn current_version(&self) -> Result<Option<Version>>;
    async fn migrated_versions(&self) -> Result<BTreeSet<Version>>;
    async fn apply_migration(&self, version: Version) -> Result<()>;
    async fn revert_migration(&self, version: Version) -> Result<()>;
    async fn migrations(&self) -> BTreeMap<Version, Arc<dyn Migration + Send + Sync>>;

    async fn get_stats(
        &self,
        subscription: &str,
        start_time: i64,
    ) -> Result<SubscriptionStatsCounters>;
    async fn get_machines(
        &self,
        subscription: &str,
        start_time: i64,
        state: Option<SubscriptionMachineState>,
    ) -> Result<Vec<SubscriptionMachine>>;
}

pub async fn schema_is_up_to_date(db: Db) -> Result<bool> {
    let migrated_versions = db
        .migrated_versions()
        .await
        .context("Failed to retrieve currently applied migrations")?;
    let migrations = db.migrations().await.keys().copied().collect();

    Ok(migrated_versions == migrations)
}

#[cfg(test)]
pub mod tests {
    use anyhow::ensure;

    use crate::{
        heartbeat::{HeartbeatKey, HeartbeatValue},
        subscription::{
            ContentFormat, FilesConfiguration, ClientFilter, ClientFilterOperation,
            SubscriptionOutput, SubscriptionOutputDriver, SubscriptionOutputFormat,
            DEFAULT_CONTENT_FORMAT, DEFAULT_IGNORE_CHANNEL_ERROR, DEFAULT_READ_EXISTING_EVENTS,
        },
    };

    use super::{schema::Migrator, *};
    use std::{collections::HashSet, thread::sleep, time::{Duration, SystemTime}};

    async fn setup_db(db: Arc<dyn Database>) -> Result<()> {
        db.setup_schema().await?;
        let migrator = Migrator::new(db.clone());
        migrator.down(None, false).await?;
        migrator.up(None, false).await?;
        Ok(())
    }

    async fn clean_db(db: Arc<dyn Database>) -> Result<()> {
        let migrator = Migrator::new(db.clone());
        migrator.down(None, false).await?;
        Ok(())
    }

    pub async fn test_subscriptions(db: Arc<dyn Database>) -> Result<()> {
        setup_db(db.clone()).await?;
        assert!(db.get_subscriptions().await?.is_empty(),);
        assert!(db.get_subscription_by_identifier("toto").await?.is_none());

        let mut subscription = SubscriptionData::new("toto", "query");
        subscription
            .set_uri(Some("/test/1".to_owned()))
            .set_enabled(false);
        db.store_subscription(&subscription).await?;

        assert!(db.get_subscriptions().await?.len() == 1);

        let toto = &db.get_subscriptions().await?[0];
        assert_eq!(toto.name(), "toto");
        assert_eq!(toto.uri(), Some(&"/test/1".to_string()));
        assert_eq!(toto.query(), "query",);
        assert_eq!(toto.enabled(), false);
        assert_eq!(toto.read_existing_events(), DEFAULT_READ_EXISTING_EVENTS);
        assert_eq!(toto.content_format(), &DEFAULT_CONTENT_FORMAT);
        assert_eq!(toto.ignore_channel_error(), DEFAULT_IGNORE_CHANNEL_ERROR);
        assert_eq!(toto.client_filter(), None);
        assert_eq!(toto.is_active(), false);
        assert_eq!(toto.is_active_for("couscous"), false);
        assert_eq!(toto.revision(), None);
        assert_eq!(toto.data_locale(), None);
        assert_eq!(toto.locale(), None);
        assert_eq!(toto.max_elements(), None);

        let toto2 = db.get_subscription_by_identifier("toto").await?.unwrap();
        assert_eq!(toto, &toto2);

        let toto3 = db
            .get_subscription_by_identifier(&subscription.uuid_string())
            .await?
            .unwrap();
        assert_eq!(toto, &toto3);

        let file_config_1 =
            FilesConfiguration::new("/path1/{ip}/{principal}/messages".to_string());
        let file_config_2 =
            FilesConfiguration::new("/path2/{ip}/{principal}/messages".to_string());
        let mut subscription2 = SubscriptionData::new("tata", "query2");
        subscription2
            .set_read_existing_events(true)
            .set_content_format(ContentFormat::RenderedText)
            .set_ignore_channel_error(false)
            .set_client_filter(Some(ClientFilter::from(
                "Only".to_string(),
                Some("couscous,boulette".to_string()),
            )?))
            .set_outputs(vec![
                SubscriptionOutput::new(
                    SubscriptionOutputFormat::Json,
                    SubscriptionOutputDriver::Files(file_config_1.clone()),
                    true,
                ),
                SubscriptionOutput::new(
                    SubscriptionOutputFormat::Raw,
                    SubscriptionOutputDriver::Files(file_config_2.clone()),
                    false,
                ),
            ])
            .set_revision(Some("1472".to_string()))
            .set_locale(Some("fr-FR".to_string()))
            .set_data_locale(Some("en-US".to_string()))
            .set_max_elements(Some(10));
        db.store_subscription(&subscription2).await?;

        assert!(db.get_subscriptions().await?.len() == 2);

        let mut tata = db.get_subscription_by_identifier("tata").await?.unwrap();
        assert_eq!(tata.name(), "tata");
        assert_eq!(tata.uri(), None);
        assert_eq!(tata.query(), "query2",);
        assert_eq!(tata.enabled(), true);
        assert_eq!(tata.read_existing_events(), true);
        assert_eq!(tata.content_format(), &ContentFormat::RenderedText);
        assert_eq!(tata.ignore_channel_error(), false);
        assert_eq!(
            *tata.client_filter().unwrap().operation(),
            ClientFilterOperation::Only
        );
        assert_eq!(
            tata.client_filter().unwrap().targets(),
            &HashSet::from(["couscous".to_string(), "boulette".to_string()])
        );

        assert_eq!(
            tata.outputs(),
            vec![
                SubscriptionOutput::new(
                    SubscriptionOutputFormat::Json,
                    SubscriptionOutputDriver::Files(file_config_1.clone()),
                    true,
                ),
                SubscriptionOutput::new(
                    SubscriptionOutputFormat::Raw,
                    SubscriptionOutputDriver::Files(file_config_2.clone()),
                    false,
                )
            ],
        );
        assert_eq!(tata.is_active(), true);
        assert_eq!(tata.is_active_for("couscous"), true);
        // Filter is case-sensitive
        assert_eq!(tata.is_active_for("Couscous"), false);
        assert_eq!(tata.is_active_for("semoule"), false);
        assert_eq!(tata.revision(), Some("1472".to_string()).as_ref());
        assert_eq!(tata.locale(), Some("fr-FR".to_string()).as_ref());
        assert_eq!(tata.data_locale(), Some("en-US".to_string()).as_ref());
        assert_eq!(tata.max_elements(), Some(10));

        let tata_save = tata.clone();
        tata.set_name("titi".to_string())
            .set_max_time(25000)
            .set_heartbeat_interval(1234)
            .set_connection_retry_count(3)
            .set_connection_retry_interval(54321)
            .set_max_envelope_size(7777)
            .set_read_existing_events(false)
            .set_content_format(ContentFormat::Raw)
            .set_ignore_channel_error(true)
            .set_revision(Some("1890".to_string()))
            .set_data_locale(Some("fr-FR".to_string()));


        let orig_filter = &tata.client_filter().unwrap();
        let mut new_targets: HashSet<String> = orig_filter.targets().iter().map(|&f| f.to_owned()).collect();
        new_targets.insert("semoule".to_owned());

        let new_client_filter = ClientFilter::try_new(orig_filter.operation().clone(),
            orig_filter.kind().clone(),
            orig_filter.flags().clone(),
            new_targets
        )?;

        tata.set_client_filter(Some(new_client_filter));

        db.store_subscription(&tata).await?;

        ensure!(db.get_subscriptions().await?.len() == 2);
        let mut tata2 = db
            .get_subscription_by_identifier(&tata.uuid_string())
            .await?
            .unwrap();
        assert_eq!(tata2.name(), "titi");
        assert_eq!(tata2.max_time(), 25000);
        assert_eq!(tata2.heartbeat_interval(), 1234);
        assert_eq!(tata2.connection_retry_count(), 3);
        assert_eq!(tata2.connection_retry_interval(), 54321);
        assert_eq!(tata2.max_envelope_size(), 7777);
        assert_eq!(tata2.read_existing_events(), false);
        assert_eq!(tata2.content_format(), &ContentFormat::Raw);
        assert_eq!(tata2.ignore_channel_error(), true);
        assert_eq!(
            *tata2.client_filter().unwrap().operation(),
            ClientFilterOperation::Only
        );
        assert_eq!(
            tata2.client_filter().unwrap().targets(),
            &HashSet::from([
                "couscous".to_string(),
                "boulette".to_string(),
                "semoule".to_string()
            ])
        );
        assert_eq!(tata2.is_active_for("couscous"), true);
        assert_eq!(tata2.is_active_for("semoule"), true);
        assert_eq!(tata2.revision(), Some("1890".to_string()).as_ref());
        assert_eq!(tata2.locale(), Some("fr-FR".to_string()).as_ref()); // Unchanged
        assert_eq!(tata2.data_locale(), Some("fr-FR".to_string()).as_ref());

        assert!(tata2.public_version()? != tata_save.public_version()?);

        let mut new_client_filter = tata2.client_filter().cloned();

        #[allow(deprecated)]
        new_client_filter.as_mut().unwrap().delete_target("couscous")?;
        #[allow(deprecated)]
        new_client_filter.as_mut().unwrap().set_operation(ClientFilterOperation::Except);
        tata2.set_client_filter(new_client_filter);

        db.store_subscription(&tata2).await?;

        let mut tata2_clone = db
            .get_subscription_by_identifier(&tata.uuid_string())
            .await?
            .unwrap();
        assert_eq!(
            *tata2_clone.client_filter().unwrap().operation(),
            ClientFilterOperation::Except
        );
        assert_eq!(
            tata2_clone.client_filter().unwrap().targets(),
            &HashSet::from(["boulette".to_string(), "semoule".to_string()])
        );

        assert_eq!(tata2_clone.is_active_for("couscous"), true);
        assert_eq!(tata2_clone.is_active_for("semoule"), false);
        assert_eq!(tata2_clone.is_active_for("boulette"), false);

        tata2_clone.set_client_filter(None);

        db.store_subscription(&tata2_clone).await?;

        let tata2_clone_clone = db
            .get_subscription_by_identifier(&tata.uuid_string())
            .await?
            .unwrap();
        assert_eq!(tata2_clone_clone.client_filter(), None);
        assert_eq!(tata2_clone_clone.is_active_for("couscous"), true);
        assert_eq!(tata2_clone_clone.is_active_for("semoule"), true);
        assert_eq!(tata2_clone_clone.is_active_for("boulette"), true);

        db.delete_subscription(&toto3.uuid_string()).await?;
        ensure!(
            db.get_subscription_by_identifier(&toto3.uuid_string())
                .await?
                .is_none(),
            "The subscription with version 'toto' should not exist yet"
        );
        assert!(db.get_subscriptions().await?.len() == 1);

        let tata3 = &db.get_subscriptions().await?[0];
        assert_eq!(tata.uuid(), tata3.uuid());

        db.delete_subscription(&tata.uuid_string()).await?;
        assert!(db.get_subscriptions().await?.is_empty());

        clean_db(db.clone()).await?;
        Ok(())
    }

    pub async fn test_bookmarks(db: Arc<dyn Database>) -> Result<()> {
        setup_db(db.clone()).await?;
        let subscription_tutu = SubscriptionData::new("tutu", "query");
        db.store_subscription(&subscription_tutu).await?;
        let subscription_titi = SubscriptionData::new("titi", "query");
        db.store_subscription(&subscription_titi).await?;

        // Test non existent bookmark
        assert!(db
            .get_bookmark("toto", &subscription_tutu.uuid_string())
            .await?
            .is_none(),);

        assert!(db
            .get_bookmarks(&subscription_tutu.uuid_string())
            .await?
            .is_empty());

        // Store a bookmark
        db.store_bookmark("toto", &subscription_tutu.uuid_string(), "titi")
            .await?;
        // Test if the bookmark is correctly remembered
        assert_eq!(
            db.get_bookmark("toto", &subscription_tutu.uuid_string())
                .await?
                .unwrap(),
            "titi",
        );
        assert_eq!(
            db.get_bookmarks(&subscription_tutu.uuid_string()).await?[0],
            BookmarkData {
                machine: "toto".to_owned(),
                subscription: subscription_tutu.uuid_string().to_owned(),
                bookmark: "titi".to_owned()
            }
        );

        // Update the bookmark
        db.store_bookmark("toto", &subscription_tutu.uuid_string(), "toto")
            .await?;
        // Test if the bookmark is correctly remembered
        assert_eq!(
            db.get_bookmark("toto", &subscription_tutu.uuid_string())
                .await?
                .unwrap(),
            "toto",
        );
        assert_eq!(
            db.get_bookmarks(&subscription_tutu.uuid_string()).await?[0],
            BookmarkData {
                machine: "toto".to_owned(),
                subscription: subscription_tutu.uuid_string().to_owned(),
                bookmark: "toto".to_owned()
            }
        );
        // Update another bookmark
        db.store_bookmark("toto", &subscription_titi.uuid_string(), "babar")
            .await?;
        // Test if the original bookmark is correctly remembered
        assert_eq!(
            db.get_bookmark("toto", &subscription_tutu.uuid_string())
                .await?
                .unwrap(),
            "toto",
        );
        assert_eq!(
            db.get_bookmarks(&subscription_tutu.uuid_string()).await?[0],
            BookmarkData {
                machine: "toto".to_owned(),
                subscription: subscription_tutu.uuid_string().to_owned(),
                bookmark: "toto".to_owned()
            }
        );
        assert_eq!(
            db.get_bookmark("toto", &subscription_titi.uuid_string())
                .await?
                .unwrap(),
            "babar",
        );
        assert_eq!(
            db.get_bookmarks(&subscription_titi.uuid_string()).await?[0],
            BookmarkData {
                machine: "toto".to_owned(),
                subscription: subscription_titi.uuid_string().to_owned(),
                bookmark: "babar".to_owned()
            }
        );

        // Test that bookmarks are deleted if subscription is deleted
        db.delete_subscription(&subscription_tutu.uuid_string())
            .await?;
        assert!(db
            .get_bookmark("toto", &subscription_tutu.uuid_string())
            .await?
            .is_none(),);
        assert!(db
            .get_bookmarks(&subscription_tutu.uuid_string())
            .await?
            .is_empty());
        assert_eq!(
            db.get_bookmark("toto", &subscription_titi.uuid_string())
                .await?
                .unwrap(),
            "babar",
        );
        assert!(!db
            .get_bookmarks(&subscription_titi.uuid_string())
            .await?
            .is_empty());
        db.delete_subscription(&subscription_titi.uuid_string())
            .await?;
        assert!(db
            .get_bookmark("toto", &subscription_titi.uuid_string())
            .await?
            .is_none(),);
        assert!(db
            .get_bookmarks(&subscription_titi.uuid_string())
            .await?
            .is_empty());

        db.store_subscription(&subscription_tutu).await?;
        db.store_subscription(&subscription_titi).await?;

        db.store_bookmark("m1", &subscription_tutu.uuid_string(), "m1b1")
            .await?;
        db.store_bookmark("m2", &subscription_tutu.uuid_string(), "m2b1")
            .await?;
        db.store_bookmark("m1", &subscription_titi.uuid_string(), "m1b2")
            .await?;

        // Test Retrieve bookmarks for subscription tutu
        let bookmarks = db.get_bookmarks(&subscription_tutu.uuid_string()).await?;
        assert_eq!(
            bookmarks
                .iter()
                .find(|b| b.machine == "m1")
                .unwrap()
                .bookmark,
            "m1b1"
        );
        assert_eq!(
            bookmarks
                .iter()
                .find(|b| b.machine == "m2")
                .unwrap()
                .bookmark,
            "m2b1"
        );

        db.delete_bookmarks(Some("m1"), Some(&subscription_titi.uuid_string()))
            .await?;
        assert!(db
            .get_bookmark("m1", &subscription_titi.uuid_string())
            .await?
            .is_none());

        db.store_bookmark("m1", &subscription_titi.uuid_string(), "m1b3")
            .await?;
        db.delete_bookmarks(None, Some(&subscription_tutu.uuid_string()))
            .await?;
        assert!(db
            .get_bookmark("m1", &subscription_tutu.uuid_string())
            .await?
            .is_none());
        assert!(db
            .get_bookmark("m2", &subscription_tutu.uuid_string())
            .await?
            .is_none());
        assert_eq!(
            db.get_bookmark("m1", &subscription_titi.uuid_string())
                .await?
                .unwrap(),
            "m1b3"
        );

        db.store_bookmark("m1", &subscription_tutu.uuid_string(), "m1b4")
            .await?;
        db.store_bookmark("m2", &subscription_tutu.uuid_string(), "m2b2")
            .await?;
        db.delete_bookmarks(Some("m1"), None).await?;
        assert_eq!(
            db.get_bookmark("m2", &subscription_tutu.uuid_string())
                .await?
                .unwrap(),
            "m2b2"
        );
        assert!(db
            .get_bookmark("m1", &subscription_tutu.uuid_string())
            .await?
            .is_none());
        assert!(db
            .get_bookmark("m1", &subscription_titi.uuid_string())
            .await?
            .is_none());

        db.store_bookmark("m1", &subscription_tutu.uuid_string(), "m1b5")
            .await?;
        db.store_bookmark("m2", &subscription_titi.uuid_string(), "m2b3")
            .await?;
        db.delete_bookmarks(None, None).await?;
        assert!(db
            .get_bookmark("m1", &subscription_tutu.uuid_string())
            .await?
            .is_none());
        assert!(db
            .get_bookmark("m2", &subscription_titi.uuid_string())
            .await?
            .is_none());

        clean_db(db.clone()).await?;
        Ok(())
    }

    pub async fn test_heartbeats(db: Arc<dyn Database>) -> Result<()> {
        setup_db(db.clone()).await?;
        ensure!(
            db.get_heartbeats_by_machine("toto", None).await?.is_empty(),
            "Non existent heartbeat should be None"
        );

        assert!(db.get_heartbeats().await?.is_empty());

        let subscription_tutu = SubscriptionData::new("tutu", "query");
        db.store_subscription(&subscription_tutu).await?;

        let before = SystemTime::now();
        sleep(Duration::from_secs(1));

        // Store a heartbeat
        db.store_heartbeat(
            "toto",
            "127.0.0.1".to_string(),
            &subscription_tutu.uuid_string(),
            false,
        )
        .await?;
        let heartbeat = db
            .get_heartbeats_by_machine("toto", Some(&subscription_tutu.uuid_string()))
            .await?[0]
            .clone();
        assert_eq!(
            heartbeat.first_seen(),
            heartbeat.last_seen(),
            "First seen and last seen should be equal"
        );
        assert_eq!(heartbeat.last_event_seen(), None);

        // Store a heartbeat
        let after = SystemTime::now();
        let time_first_seen = SystemTime::UNIX_EPOCH
            + Duration::from_secs(heartbeat.first_seen().try_into().unwrap());
        assert!(
            time_first_seen >= before && time_first_seen <= after,
            "First seen should be correct"
        );
        assert_eq!(heartbeat.ip(), "127.0.0.1");
        assert_eq!(heartbeat.machine(), "toto");
        assert_eq!(heartbeat.subscription(), &subscription_tutu);

        assert!(db.get_heartbeats().await?.len() == 1);
        assert_eq!(db.get_heartbeats().await?[0], heartbeat);
        assert_eq!(
            db.get_heartbeats_by_ip("127.0.0.1", None).await?[0],
            heartbeat
        );
        assert!(db.get_heartbeats_by_ip("127.0.0.2", None).await?.is_empty(),);
        assert_eq!(
            db.get_heartbeats_by_ip("127.0.0.1", Some(&subscription_tutu.uuid_string()))
                .await?[0],
            heartbeat
        );

        sleep(Duration::from_secs(1));

        db.store_heartbeat(
            "toto",
            "127.0.0.1".to_string(),
            &subscription_tutu.uuid_string(),
            true,
        )
        .await?;

        let heartbeat = db
            .get_heartbeats_by_machine("toto", Some(&subscription_tutu.uuid_string()))
            .await?[0]
            .clone();
        assert!(
            heartbeat.first_seen() < heartbeat.last_seen(),
            "First seen and last seen should NOT be equal"
        );
        assert_eq!(heartbeat.last_seen(), heartbeat.last_event_seen().unwrap());

        db.store_heartbeat(
            "tata",
            "127.0.0.2".to_string(),
            &subscription_tutu.uuid_string(),
            false,
        )
        .await?;

        let heartbeats = db.get_heartbeats().await?;
        assert_eq!(heartbeats.len(), 2);

        assert_eq!(
            db.get_heartbeats_by_subscription(&subscription_tutu.uuid_string())
                .await?,
            heartbeats
        );

        db.store_heartbeat(
            "tata",
            "127.0.0.2".to_string(),
            &subscription_tutu.uuid_string(),
            true,
        )
        .await?;
        assert!(!db.get_heartbeats_by_ip("127.0.0.2", None).await?.is_empty());

        // Remove subscription and assert that heartbeats have been deleted
        db.delete_subscription(&subscription_tutu.uuid_string())
            .await?;
        assert!(db.get_heartbeats().await?.is_empty());

        clean_db(db.clone()).await?;
        Ok(())
    }

    pub async fn test_heartbeats_cache(db: Arc<dyn Database>) -> Result<()> {
        setup_db(db.clone()).await?;

        let subscription_tutu = SubscriptionData::new("tutu", "query");
        db.store_subscription(&subscription_tutu).await?;

        let mut heartbeats = HeartbeatsCache::new();
        heartbeats.insert(
            HeartbeatKey {
                machine: "m1".to_string(),
                subscription: subscription_tutu.uuid_string().to_owned(),
            },
            HeartbeatValue {
                ip: "127.0.0.1".to_string(),
                last_seen: 1,
                last_event_seen: None,
            },
        );
        heartbeats.insert(
            HeartbeatKey {
                machine: "m2".to_string(),
                subscription: subscription_tutu.uuid_string().to_owned(),
            },
            HeartbeatValue {
                ip: "127.0.0.2".to_string(),
                last_seen: 2,
                last_event_seen: Some(2),
            },
        );
        db.store_heartbeats(&heartbeats).await?;

        let db_heartbeats = db.get_heartbeats().await?;
        assert_eq!(db_heartbeats.len(), 2);
        let m1_heartbeat = db_heartbeats
            .iter()
            .find(|e| e.machine() == "m1")
            .cloned()
            .expect("m1 heartbeat");
        assert_eq!(m1_heartbeat.first_seen(), 1);
        assert_eq!(m1_heartbeat.last_seen(), 1);
        assert_eq!(m1_heartbeat.last_event_seen(), None);
        assert_eq!(m1_heartbeat.ip(), "127.0.0.1");

        let m2_heartbeat = db_heartbeats
            .iter()
            .find(|e| e.machine() == "m2")
            .cloned()
            .expect("m2 heartbeat");
        assert_eq!(m2_heartbeat.first_seen(), 2);
        assert_eq!(m2_heartbeat.last_seen(), 2);
        assert_eq!(m2_heartbeat.last_event_seen(), Some(2));
        assert_eq!(m2_heartbeat.ip(), "127.0.0.2");

        heartbeats.clear();

        // Update heartbeat for m1, and change its IP address
        heartbeats.insert(
            HeartbeatKey {
                machine: "m1".to_string(),
                subscription: subscription_tutu.uuid_string().to_owned(),
            },
            HeartbeatValue {
                ip: "127.0.0.100".to_string(),
                last_seen: 3,
                last_event_seen: Some(3),
            },
        );
        db.store_heartbeats(&heartbeats).await?;

        let db_heartbeats = db.get_heartbeats().await?;
        assert_eq!(db_heartbeats.len(), 2);
        let m1_heartbeat = db_heartbeats
            .iter()
            .find(|e| e.machine() == "m1")
            .cloned()
            .expect("m1 heartbeat");
        assert_eq!(m1_heartbeat.first_seen(), 1);
        assert_eq!(m1_heartbeat.last_seen(), 3);
        assert_eq!(m1_heartbeat.last_event_seen(), Some(3));
        assert_eq!(m1_heartbeat.ip(), "127.0.0.100");

        // Nothing has changed for m2
        let m2_heartbeat = db_heartbeats
            .iter()
            .find(|e| e.machine() == "m2")
            .cloned()
            .expect("m2 heartbeat");
        assert_eq!(m2_heartbeat.first_seen(), 2);
        assert_eq!(m2_heartbeat.last_seen(), 2);
        assert_eq!(m2_heartbeat.last_event_seen(), Some(2));
        assert_eq!(m2_heartbeat.ip(), "127.0.0.2");

        // Try to store a lot of heartbeats
        let mut heartbeats = HeartbeatsCache::new();
        for i in 0..1020 {
            heartbeats.insert(
                HeartbeatKey {
                    machine: format!("machine${}", i * 2),
                    subscription: subscription_tutu.uuid_string().to_owned(),
                },
                HeartbeatValue {
                    ip: "127.0.0.1".to_string(),
                    last_seen: 1,
                    last_event_seen: None,
                },
            );
            heartbeats.insert(
                HeartbeatKey {
                    machine: format!("machine${}", i * 2 + 1),
                    subscription: subscription_tutu.uuid_string().to_owned(),
                },
                HeartbeatValue {
                    ip: "127.0.0.2".to_string(),
                    last_seen: 2,
                    last_event_seen: Some(2),
                },
            );
        }
        db.store_heartbeats(&heartbeats).await?;
        let db_heartbeats = db.get_heartbeats().await?;
        assert_eq!(db_heartbeats.len(), 1020 * 2 + 2);
        clean_db(db.clone()).await?;
        Ok(())
    }

    pub async fn test_stats_and_machines(db: Arc<dyn Database>) -> Result<()> {
        setup_db(db.clone()).await?;

        assert_eq!(
            db.get_stats("", 0).await?,
            SubscriptionStatsCounters::new(0, 0, 0, 0)
        );

        let subscription_tutu = SubscriptionData::new("tutu", "query");
        db.store_subscription(&subscription_tutu).await?;
        assert_eq!(
            db.get_stats(&subscription_tutu.uuid_string(), 0).await?,
            SubscriptionStatsCounters::new(0, 0, 0, 0)
        );

        assert!(db
            .get_machines(&subscription_tutu.uuid_string(), 0, None)
            .await?
            .is_empty());

        assert!(db
            .get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Alive)
            )
            .await?
            .is_empty());

        assert!(db
            .get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Active)
            )
            .await?
            .is_empty());

        assert!(db
            .get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Dead)
            )
            .await?
            .is_empty());

        let now: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .try_into()?;

        // Store a heartbeat
        db.store_heartbeat(
            "toto",
            "127.0.0.1".to_string(),
            &subscription_tutu.uuid_string(),
            false,
        )
        .await?;

        println!("{:?}", db.get_heartbeats().await?);

        assert_eq!(
            db.get_stats(&subscription_tutu.uuid_string(), 0).await?,
            // total:1, alive:1, active:0, dead:0
            SubscriptionStatsCounters::new(1, 1, 0, 0)
        );

        let alive_machines = db
            .get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Alive),
            )
            .await?;
        println!("{:?}", alive_machines);
        assert_eq!(alive_machines.len(), 1);
        assert_eq!(alive_machines[0].name(), "toto");
        assert_eq!(alive_machines[0].ip(), "127.0.0.1");

        let total_machines = db
            .get_machines(&subscription_tutu.uuid_string(), 0, None)
            .await?;
        assert_eq!(total_machines.len(), 1);
        assert_eq!(total_machines[0].name(), "toto");
        assert_eq!(total_machines[0].ip(), "127.0.0.1");

        assert!(db
            .get_machines(
                &&subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Active)
            )
            .await?
            .is_empty());
        assert!(db
            .get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Dead)
            )
            .await?
            .is_empty());

        // Store an event heartbeat
        db.store_heartbeat(
            "toto",
            "127.0.0.1".to_string(),
            &subscription_tutu.uuid_string(),
            true,
        )
        .await?;

        assert_eq!(
            db.get_stats(&subscription_tutu.uuid_string(), 0).await?,
            // total:1, alive:0, active:1, dead:0
            SubscriptionStatsCounters::new(1, 0, 1, 0)
        );

        assert_eq!(
            db.get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Active)
            )
            .await?
            .len(),
            1
        );
        assert!(db
            .get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Alive)
            )
            .await?
            .is_empty());
        assert!(db
            .get_machines(
                &subscription_tutu.uuid_string(),
                0,
                Some(SubscriptionMachineState::Dead)
            )
            .await?
            .is_empty());
        assert_eq!(
            db.get_machines(&subscription_tutu.uuid_string(), 0, None)
                .await?
                .len(),
            1
        );

        sleep(Duration::from_secs(2));

        // Store a heartbeat for another machine
        db.store_heartbeat(
            "tata",
            "127.0.0.2".to_string(),
            &subscription_tutu.uuid_string(),
            false,
        )
        .await?;

        // We have waited 2 seconds and set heartbeat_interval_start at "now + 1", so
        // only the last stored heartbeat is considered alive.
        assert_eq!(
            db.get_stats(&subscription_tutu.uuid_string(), now + 1)
                .await?,
            // total:2, alive:1, active:0, dead:1
            SubscriptionStatsCounters::new(2, 1, 0, 1)
        );

        let total_machines = db
            .get_machines(&subscription_tutu.uuid_string(), now + 1, None)
            .await?;
        assert_eq!(total_machines.len(), 2);

        let alive_machines = db
            .get_machines(
                &subscription_tutu.uuid_string(),
                now + 1,
                Some(SubscriptionMachineState::Alive),
            )
            .await?;
        assert_eq!(alive_machines.len(), 1);
        assert_eq!(alive_machines[0].name(), "tata");
        assert_eq!(alive_machines[0].ip(), "127.0.0.2");

        let dead_machines = db
            .get_machines(
                &subscription_tutu.uuid_string(),
                now + 1,
                Some(SubscriptionMachineState::Dead),
            )
            .await?;
        assert_eq!(dead_machines.len(), 1);
        assert_eq!(dead_machines[0].name(), "toto");
        assert_eq!(dead_machines[0].ip(), "127.0.0.1");

        assert!(db
            .get_machines(
                &subscription_tutu.uuid_string(),
                now + 1,
                Some(SubscriptionMachineState::Active)
            )
            .await?
            .is_empty());

        // Store an event heartbeat for first machine
        db.store_heartbeat(
            "toto",
            "127.0.0.1".to_string(),
            &subscription_tutu.uuid_string(),
            true,
        )
        .await?;

        // First machine is active again
        assert_eq!(
            db.get_stats(&subscription_tutu.uuid_string(), now + 1)
                .await?,
            // total:2, alive:1, active:1, dead:0
            SubscriptionStatsCounters::new(2, 1, 1, 0)
        );

        // Create another subscription
        let subscription_tata = SubscriptionData::new("tata", "query");
        db.store_subscription(&subscription_tata).await?;

        // Store an heartbeat for this other subscription
        db.store_heartbeat(
            "toto",
            "127.0.0.1".to_string(),
            &subscription_tata.uuid_string(),
            true,
        )
        .await?;

        // Nothing has changed for first subscription
        assert_eq!(
            db.get_stats(&subscription_tutu.uuid_string(), now + 1)
                .await?,
            // total:2, alive:1, active:1, dead:0
            SubscriptionStatsCounters::new(2, 1, 1, 0)
        );

        clean_db(db.clone()).await?;
        Ok(())
    }
}
