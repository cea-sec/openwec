use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct CreateSubscriptionsTable;
migration!(CreateSubscriptionsTable, 1, "create subscriptions table");

impl SQLiteMigration for CreateSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS subscriptions (
                        uuid TEXT NOT NULL UNIQUE,
                        version TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL UNIQUE,
                        query TEXT NOT NULL,
                        heartbeat_interval INTEGER,
                        connection_retry_count INTEGER,
                        connection_retry_interval INTEGER,
                        max_time INTEGER,
                        max_envelope_size INTEGER,
                        enabled INTEGER,
                        read_existing_events INTEGER,
                        outputs TEXT NOT NULL,
                        PRIMARY KEY (uuid)
                )",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute("DROP TABLE subscriptions;", [])
            .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
