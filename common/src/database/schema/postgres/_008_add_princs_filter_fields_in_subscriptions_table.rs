use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddPrincsFilterFieldsInSubscriptionsTable;
migration!(
    AddPrincsFilterFieldsInSubscriptionsTable,
    8,
    "add princs_filter fields in subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddPrincsFilterFieldsInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS princs_filter_op TEXT;",
            &[],
        )
        .await?;
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS princs_filter_value TEXT;",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS princs_filter_op",
            &[],
        )
        .await?;
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN IF EXISTS princs_filter_value",
            &[],
        )
        .await?;
        Ok(())
    }
}
