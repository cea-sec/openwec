use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddIgnoreChannelErrorFieldInSubscriptionsTable;
migration!(
    AddIgnoreChannelErrorFieldInSubscriptionsTable,
    7,
    "add ignore_channel_error field in subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddIgnoreChannelErrorFieldInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS ignore_channel_error BOOLEAN DEFAULT true;",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS ignore_channel_error",
            &[],
        )
        .await?;
        Ok(())
    }
}
