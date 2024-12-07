use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::AsyncCommands;
use crate::database::redis::RedisMigration;
use crate::database::redisdomain::RedisDomain;
use crate::migration;
use deadpool_redis::*;

pub(super) struct CreateSubscriptionsTable;
migration!(CreateSubscriptionsTable, 1, "create subscriptions table");

#[async_trait]
impl RedisMigration for CreateSubscriptionsTable {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, conn: &mut Connection) -> Result<()> {
        let key = format!("{}:{}:{}", RedisDomain::Subscription, RedisDomain::Any, RedisDomain::Any);
        let subs : Vec<String> = conn.keys(key).await.context("Unable to list keys")?;
        if !subs.is_empty() {
            let _: () = conn.del(subs).await.context("Failed to delete subscription data")?;
        }
        Ok(())
    }
}
