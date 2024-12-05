use anyhow::Result;
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::migration;
use deadpool_redis::*;

pub(super) struct AddLastEventSeenFieldInHeartbeatsTable;
migration!(
    AddLastEventSeenFieldInHeartbeatsTable,
    4,
    "add last_event_seen field in heartbeats table"
);

#[async_trait]
impl RedisMigration for AddLastEventSeenFieldInHeartbeatsTable {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
   }
}
