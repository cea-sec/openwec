use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AlterClientFilterInSubscriptionsTable;
migration!(
    AlterClientFilterInSubscriptionsTable,
    14,
    "renames fields and adds filter type and flags to subscriptions table"
);

#[async_trait]
impl PostgresMigration for AlterClientFilterInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute("ALTER TABLE subscriptions RENAME COLUMN princs_filter_op TO client_filter_op", &[]).await?;
        tx.execute("ALTER TABLE subscriptions RENAME COLUMN princs_filter_value TO client_filter_targets", &[]).await?;

        tx.execute("ALTER TABLE subscriptions ADD COLUMN client_filter_kind TEXT", &[]).await?;
        tx.execute("UPDATE subscriptions SET client_filter_kind = 'KerberosPrinc' WHERE client_filter_op IS NOT NULL", &[]).await?;

        tx.execute("ALTER TABLE subscriptions ADD COLUMN client_filter_flags INT4", &[]).await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute("ALTER TABLE subscriptions RENAME COLUMN client_filter_op TO princs_filter_op", &[]).await?;
        tx.execute("ALTER TABLE subscriptions RENAME COLUMN client_filter_targets TO princs_filter_value", &[]).await?;
        tx.execute("ALTER TABLE subscriptions DROP COLUMN client_filter_kind", &[]).await?;
        tx.execute("ALTER TABLE subscriptions DROP COLUMN client_filter_flags", &[]).await?;
        Ok(())
    }
}
