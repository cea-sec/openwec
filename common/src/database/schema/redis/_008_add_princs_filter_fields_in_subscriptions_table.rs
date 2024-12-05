use anyhow::Result;
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::migration;
use deadpool_redis::*;

pub(super) struct AddPrincsFilterFieldsInSubscriptionsTable;
migration!(
    AddPrincsFilterFieldsInSubscriptionsTable,
    8,
    "add princs_filter fields in subscriptions table"
);

#[async_trait]
impl RedisMigration for AddPrincsFilterFieldsInSubscriptionsTable {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
   }
}
