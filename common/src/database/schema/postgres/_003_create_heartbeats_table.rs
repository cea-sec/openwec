use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct CreateHeartbeatsTable;
migration!(CreateHeartbeatsTable, 3, "create heartbeats table");

#[async_trait]
impl PostgresMigration for CreateHeartbeatsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS heartbeats (
                        machine TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        subscription TEXT NOT NULL,
                        first_seen BIGINT,
                        last_seen BIGINT,
                        PRIMARY KEY (machine, subscription),
                        CONSTRAINT fk_subscription
                            FOREIGN KEY (subscription)
                                REFERENCES subscriptions(uuid)
                                ON UPDATE CASCADE
                                ON DELETE CASCADE
                );",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute("DROP TABLE IF EXISTS heartbeats;", &[]).await?;
        Ok(())
    }
}
