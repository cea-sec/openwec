use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::transformers::output_files_use_path;
use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AlterOutputsFilesConfig;
migration!(AlterOutputsFilesConfig, 12, "alter outputs files config");

#[async_trait]
impl PostgresMigration for AlterOutputsFilesConfig {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        let rows = tx
            .query(
                r#"SELECT uuid, outputs
                FROM subscriptions
            "#,
                &[],
            )
            .await?;
        for row in rows {
            let uuid: String = row.try_get("uuid")?;
            let outputs_str: String = row.try_get("outputs")?;
            let outputs: Vec<output_files_use_path::old::SubscriptionOutput> =
                serde_json::from_str(&outputs_str)?;
            let new_outputs: Vec<output_files_use_path::new::SubscriptionOutput> =
                outputs.iter().map(|elt| elt.clone().into()).collect();
            let new_outputs_str = serde_json::to_string(&new_outputs)?;
            tx.execute(
                r#"UPDATE subscriptions
                SET outputs = $1
                WHERE uuid = $2"#,
                &[&new_outputs_str, &uuid],
            )
            .await?;
        }
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        let rows = tx
            .query(
                r#"SELECT uuid, outputs
                FROM subscriptions
            "#,
                &[],
            )
            .await?;
        for row in rows {
            let uuid: String = row.try_get("uuid")?;
            let outputs_str: String = row.try_get("outputs")?;
            let outputs: Vec<output_files_use_path::new::SubscriptionOutput> =
                serde_json::from_str(&outputs_str)?;
            let new_outputs: Vec<output_files_use_path::old::SubscriptionOutput> =
                outputs.iter().map(|elt| elt.clone().into()).collect();
            let new_outputs_str = serde_json::to_string(&new_outputs)?;
            tx.execute(
                r#"UPDATE subscriptions
                SET outputs = $1
                WHERE uuid = $2"#,
                &[&new_outputs_str, &uuid],
            )
            .await?;
        }
        Ok(())
    }
}
