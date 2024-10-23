use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct CreateSubscriptionsTable;
migration!(CreateSubscriptionsTable, 1, "create subscriptions table");

#[async_trait]
impl PostgresMigration for CreateSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS subscriptions (
                        uuid TEXT NOT NULL UNIQUE,
                        version TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL UNIQUE,
                        query TEXT NOT NULL,
                        heartbeat_interval INT4,
                        connection_retry_count INT4,
                        connection_retry_interval INT4,
                        max_time INT4,
                        max_elements INT4,
                        max_envelope_size INT4,
                        enabled BOOLEAN,
                        read_existing_events BOOLEAN,
                        outputs TEXT NOT NULL,
                        PRIMARY KEY (uuid)
                );",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute("DROP TABLE IF EXISTS subscriptions;", &[])
            .await?;
        Ok(())
    }
}
