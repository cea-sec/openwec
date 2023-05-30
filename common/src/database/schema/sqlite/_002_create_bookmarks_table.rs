use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct CreateBookmarksTable;
migration!(CreateBookmarksTable, 2, "create bookmarks table");

impl SQLiteMigration for CreateBookmarksTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS bookmarks (
                        machine TEXT NOT NULL,
                        subscription TEXT NOT NULL
                            REFERENCES subscriptions(uuid) ON UPDATE CASCADE ON DELETE CASCADE,
                        bookmark TEXT NOT NULL,
                        PRIMARY KEY (machine, subscription)
                )",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE bookmarks;", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
