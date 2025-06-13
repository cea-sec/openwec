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
        conn.execute("ALTER TABLE subscriptions RENAME COLUMN princs_filter_value TO client_filter_targets", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;

        conn.execute("ALTER TABLE subscriptions ADD COLUMN client_filter_kind TEXT", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("UPDATE subscriptions SET client_filter_kind = 'KerberosPrinc' WHERE client_filter_op IS NOT NULL", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;

        conn.execute("ALTER TABLE subscriptions ADD COLUMN client_filter_flags INTEGER", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions RENAME COLUMN client_filter_op TO princs_filter_op", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("ALTER TABLE subscriptions RENAME COLUMN client_filter_targets TO princs_filter_value", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("ALTER TABLE subscriptions DROP COLUMN client_filter_kind", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute("ALTER TABLE subscriptions DROP COLUMN client_filter_flags", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
