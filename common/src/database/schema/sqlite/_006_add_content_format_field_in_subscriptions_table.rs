use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddContentFormatFieldInSubscriptionsTable;
migration!(
    AddContentFormatFieldInSubscriptionsTable,
    6,
    "add content_format field in subscriptions table"
);

impl SQLiteMigration for AddContentFormatFieldInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE subscriptions ADD COLUMN content_format TEXT DEFAULT 'RenderedText'",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("ALTER TABLE subscriptions DROP COLUMN content_format", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
