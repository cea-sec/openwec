use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddIgnoreChannelErrorFieldInSubscriptionsTable;
migration!(
    AddIgnoreChannelErrorFieldInSubscriptionsTable,
    7,
    "add ignore_channel_error field in subscriptions table"
);

impl SQLiteMigration for AddIgnoreChannelErrorFieldInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE subscriptions ADD COLUMN ignore_channel_error INTEGER DEFAULT 1",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE subscriptions DROP COLUMN ignore_channel_error",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
