use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddUriFieldInSubscriptionsTable;
migration!(
    AddUriFieldInSubscriptionsTable,
    5,
    "add uri field in subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddUriFieldInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS uri TEXT;",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute("ALTER TABLE subscriptions DROP COLUMN IF EXISTS uri", &[])
            .await?;
        Ok(())
    }
}
