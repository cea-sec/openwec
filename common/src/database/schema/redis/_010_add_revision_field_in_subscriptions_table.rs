use anyhow::Result;
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::migration;
use deadpool_redis::*;

pub(super) struct AddRevisionFieldInSubscriptionsTable;
migration!(
    AddRevisionFieldInSubscriptionsTable,
    10,
    "add revision field in subscriptions table"
);

#[async_trait]
impl RedisMigration for AddRevisionFieldInSubscriptionsTable {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
   }
}
