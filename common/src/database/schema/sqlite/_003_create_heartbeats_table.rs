use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct CreateHeartbeatsTable;
migration!(CreateHeartbeatsTable, 3, "create heartbeats table");

impl SQLiteMigration for CreateHeartbeatsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS heartbeats (
                        machine TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        subscription TEXT NOT NULL
                            REFERENCES subscriptions(uuid) ON UPDATE CASCADE ON DELETE CASCADE,
                        first_seen INTEGER,
                        last_seen INTEGER,
                        PRIMARY KEY (machine, subscription)
                )",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE heartbeats;", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
