use anyhow::Result;
use async_trait::async_trait;
use crate::database::redis::RedisMigration;
use crate::migration;
use deadpool_redis::*;

pub(super) struct AlterOutputsFormat;
migration!(AlterOutputsFormat, 9, "alter outputs format");

#[async_trait]
impl RedisMigration for AlterOutputsFormat {
    async fn up(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
    }

    async fn down(&self, _conn: &mut Connection) -> Result<()> {
        Ok(())
   }
}
