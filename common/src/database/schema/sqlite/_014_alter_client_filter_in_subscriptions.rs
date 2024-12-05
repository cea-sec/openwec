use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AlterClientFilterInSubscriptionsTable;
migration!(
    AlterClientFilterInSubscriptionsTable,
    14,
    "renames fields and adds filter type and flags to subscriptions table"
);

impl SQLiteMigration for AlterClientFilterInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions RENAME COLUMN princs_filter_op TO client_filter_op", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("ALTER TABLE subscriptions RENAME COLUMN princs_filter_value TO client_filter_value", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions RENAME COLUMN client_filter_op TO princs_filter_op", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("ALTER TABLE subscriptions RENAME COLUMN client_filter_value TO princs_filter_value", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
