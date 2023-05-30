use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddLastEventSeenFieldInHeartbeatsTable;
migration!(
    AddLastEventSeenFieldInHeartbeatsTable,
    4,
    "add last_event_seen field in heartbeats table"
);

impl SQLiteMigration for AddLastEventSeenFieldInHeartbeatsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE heartbeats ADD COLUMN last_event_seen INTEGER",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE heartbeats DROP COLUMN last_event_seen", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
