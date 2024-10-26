use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddMaxElementsFieldInSubscriptionsTable;
migration!(
    AddMaxElementsFieldInSubscriptionsTable,
    13,
    "add max_elements field in subscriptions table"
);

impl SQLiteMigration for AddMaxElementsFieldInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions ADD COLUMN max_elements INTEGER", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions DROP COLUMN max_elements", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
