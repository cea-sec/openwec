use anyhow::{Context, Result};
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::database::redisdomain::RedisDomain;
use crate::migration;
use deadpool_redis::*;
use redis::AsyncCommands;

pub(super) struct CreateBookmarksTable;
migration!(CreateBookmarksTable, 2, "create bookmarks table");

#[async_trait]
impl RedisMigration for CreateBookmarksTable {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, conn: &mut Connection) -> Result<()> {
        let key = format!("{}:{}:{}", RedisDomain::BookMark, RedisDomain::Any, RedisDomain::Any);
        let bms : Vec<String> = conn.keys(key).await.context("Unable to list keys")?;
        if !bms.is_empty() {
            let _: () = conn.del(bms).await.context("Failed to delete bookmark data")?;
        }
        Ok(())
   }
}
