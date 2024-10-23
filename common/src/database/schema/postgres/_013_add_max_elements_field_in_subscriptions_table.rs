use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddMaxElementsFieldInSubscriptionsTable;
migration!(
    AddMaxElementsFieldInSubscriptionsTable,
    13,
    "add max_elements field in subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddMaxElementsFieldInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS max_elements INT4;",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS max_elements",
            &[],
        )
        .await?;
        Ok(())
    }
}
