use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddPrincsFilterFieldsInSubscriptionsTable;
migration!(
    AddPrincsFilterFieldsInSubscriptionsTable,
    8,
    "add princs_filter fields in subscriptions table"
);

impl SQLiteMigration for AddPrincsFilterFieldsInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE subscriptions ADD COLUMN princs_filter_op TEXT",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute(
            "ALTER TABLE subscriptions ADD COLUMN princs_filter_value TEXT",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions DROP COLUMN princs_filter_op", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute(
            "ALTER TABLE subscriptions DROP COLUMN princs_filter_value",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
