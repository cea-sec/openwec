use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddLastEventSeenFieldInHeartbeatsTable;
migration!(
    AddLastEventSeenFieldInHeartbeatsTable,
    4,
    "add last_event_seen field in heartbeats table"
);

#[async_trait]
impl PostgresMigration for AddLastEventSeenFieldInHeartbeatsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE heartbeats ADD COLUMN IF NOT EXISTS last_event_seen BIGINT;",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE heartbeats DROP COLUMN IF EXISTS last_event_seen",
            &[],
        )
        .await?;
        Ok(())
    }
}
