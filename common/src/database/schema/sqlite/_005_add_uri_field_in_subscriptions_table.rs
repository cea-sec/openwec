use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddUriFieldInSubscriptionsTable;
migration!(
    AddUriFieldInSubscriptionsTable,
    5,
    "add uri field in subscriptions table"
);

impl SQLiteMigration for AddUriFieldInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions ADD COLUMN uri TEXT", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions DROP COLUMN uri", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
