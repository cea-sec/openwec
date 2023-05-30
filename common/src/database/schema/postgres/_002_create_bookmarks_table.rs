use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct CreateBookmarksTable;
migration!(CreateBookmarksTable, 2, "create bookmarks table");

#[async_trait]
impl PostgresMigration for CreateBookmarksTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS bookmarks (
                        machine TEXT NOT NULL,
                        subscription TEXT NOT NULL,
                        bookmark TEXT NOT NULL,
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
        tx.execute("DROP TABLE IF EXISTS bookmarks;", &[]).await?;
        Ok(())
    }
}
