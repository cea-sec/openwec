use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddLocaleFieldsInSubscriptionsTable;
migration!(
    AddLocaleFieldsInSubscriptionsTable,
    11,
    "add locale fields in subscriptions table"
);

impl SQLiteMigration for AddLocaleFieldsInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions ADD COLUMN locale TEXT", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("ALTER TABLE subscriptions ADD COLUMN data_locale TEXT", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions DROP COLUMN locale", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("ALTER TABLE subscriptions DROP COLUMN data_locale", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
