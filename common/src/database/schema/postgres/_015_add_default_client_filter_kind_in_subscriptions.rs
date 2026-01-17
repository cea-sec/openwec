use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddDefaultClientFilterKindInSubscriptionsTable;
migration!(
    AddDefaultClientFilterKindInSubscriptionsTable,
    15,
    "add default value of client_filter_kind for previously configured filters"
);

#[async_trait]
impl PostgresMigration for AddDefaultClientFilterKindInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute("UPDATE subscriptions SET client_filter_kind = 'Client' WHERE client_filter_op IS NOT NULL", &[]).await?;
        Ok(())
    }

    async fn down(&self, _tx: &mut Transaction) -> Result<()> {
        Ok(())
    }
}
