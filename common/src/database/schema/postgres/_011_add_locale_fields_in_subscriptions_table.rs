use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddLocaleFieldsInSubscriptionsTable;
migration!(
    AddLocaleFieldsInSubscriptionsTable,
    11,
    "add locale fields in subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddLocaleFieldsInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS locale TEXT;",
            &[],
        )
        .await?;
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS data_locale TEXT;",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS locale",
            &[],
        )
        .await?;
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS data_locale",
            &[],
        )
        .await?;
        Ok(())
    }
}
