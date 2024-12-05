use anyhow::{Context, Result};
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::database::redisdomain::RedisDomain;
use crate::migration;
use deadpool_redis::*;
use redis::AsyncCommands;

pub(super) struct AddMaxElementsFieldInSubscriptionsTable;
migration!(
    AddMaxElementsFieldInSubscriptionsTable,
    13,
    "add max_elements field in subscriptions table"
);

#[async_trait]
impl RedisMigration for AddMaxElementsFieldInSubscriptionsTable {
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
    // async fn up(&self, tx: &mut Transaction) -> Result<()> {
    //     tx.execute(
    //         "ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS max_elements INT4;",
    //         &[],
    //     )
    //     .await?;
    //     Ok(())
    // }

    // async fn down(&self, tx: &mut Transaction) -> Result<()> {
    //     tx.execute(
    //         "ALTER TABLE subscriptions DROP COLUMN IF EXISTS max_elements",
    //         &[],
    //     )
    //     .await?;
    //     Ok(())
    // }
}
