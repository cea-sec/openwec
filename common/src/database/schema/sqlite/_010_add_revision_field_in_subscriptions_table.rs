use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddRevisionFieldInSubscriptionsTable;
migration!(
    AddRevisionFieldInSubscriptionsTable,
    10,
    "add revision field in subscriptions table"
);

impl SQLiteMigration for AddRevisionFieldInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE subscriptions ADD COLUMN revision TEXT",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions DROP COLUMN revision", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
