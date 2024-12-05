use anyhow::{Context, Result};
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::database::redisdomain::RedisDomain;
use crate::migration;
use deadpool_redis::*;
use redis::AsyncCommands;

pub(super) struct CreateHeartbeatsTable;
migration!(CreateHeartbeatsTable, 3, "create heartbeats table");

#[async_trait]
impl RedisMigration for CreateHeartbeatsTable {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, conn: &mut Connection) -> Result<()> {
        let key = format!("{}:{}:{}", RedisDomain::Heartbeat, RedisDomain::Any, RedisDomain::Any);
        let hbs : Vec<String> = conn.keys(key).await.context("Unable to list keys")?;
        if !hbs.is_empty() {
            let _: () = conn.del(hbs).await.context("Failed to delete hearthbeat data")?;
        }
        Ok(())
   }
}
