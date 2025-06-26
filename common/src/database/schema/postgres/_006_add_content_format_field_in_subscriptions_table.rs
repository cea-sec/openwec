use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddContentFormatFieldInSubscriptionsTable;
migration!(
    AddContentFormatFieldInSubscriptionsTable,
    6,
    "add content_format field in subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddContentFormatFieldInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS content_format TEXT DEFAULT 'RenderedText';",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS content_format",
            &[],
        )
        .await?;
        Ok(())
    }
}
