use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddRevisionFieldInSubscriptionsTable;
migration!(
    AddRevisionFieldInSubscriptionsTable,
    10,
    "add revision field in subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddRevisionFieldInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS revision TEXT;",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS revision",
            &[],
        )
        .await?;
        Ok(())
    }
}
