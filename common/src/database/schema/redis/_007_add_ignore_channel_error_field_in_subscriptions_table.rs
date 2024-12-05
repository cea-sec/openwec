use anyhow::Result;
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::migration;
use deadpool_redis::*;

pub(super) struct AddIgnoreChannelErrorFieldInSubscriptionsTable;
migration!(
    AddIgnoreChannelErrorFieldInSubscriptionsTable,
    7,
    "add ignore_channel_error field in subscriptions table"
);

#[async_trait]
impl RedisMigration for AddIgnoreChannelErrorFieldInSubscriptionsTable {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
   }
}
