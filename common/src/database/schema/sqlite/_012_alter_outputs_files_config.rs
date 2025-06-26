use anyhow::Result;
use rusqlite::{named_params, Connection};

use crate::database::sqlite::SQLiteMigration;
use crate::migration;
use crate::transformers::output_files_use_path;

pub(super) struct AlterOutputsFilesConfig;
migration!(AlterOutputsFilesConfig, 12, "alter outputs files config");

impl SQLiteMigration for AlterOutputsFilesConfig {
    fn up(&self, conn: &Connection) -> Result<()> {
        let mut statement = conn.prepare(
            r#"SELECT uuid, outputs
                FROM subscriptions
            "#,
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let uuid: String = row.get(0)?;
            let outputs_str: String = row.get(1)?;
            let outputs: Vec<output_files_use_path::old::SubscriptionOutput> =
                serde_json::from_str(&outputs_str)?;
            let new_outputs: Vec<output_files_use_path::new::SubscriptionOutput> =
                outputs.iter().map(|elt| elt.clone().into()).collect();
            let new_outputs_str = serde_json::to_string(&new_outputs)?;
            conn.execute(
                r#"UPDATE subscriptions
                SET outputs = :outputs
                WHERE uuid = :uuid"#,
                named_params! {
                    ":outputs": new_outputs_str,
                    ":uuid": uuid
                },
            )?;
        }
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        let mut statement = conn.prepare(
            r#"SELECT uuid, outputs
                FROM subscriptions
            "#,
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let uuid: String = row.get(0)?;
            let outputs_str: String = row.get(1)?;
            let outputs: Vec<output_files_use_path::new::SubscriptionOutput> =
                serde_json::from_str(&outputs_str)?;
            let new_outputs: Vec<output_files_use_path::old::SubscriptionOutput> =
                outputs.iter().map(|elt| elt.clone().into()).collect();
            let new_outputs_str = serde_json::to_string(&new_outputs)?;
            conn.execute(
                r#"UPDATE subscriptions
                SET outputs = :outputs
                WHERE uuid = :uuid"#,
                named_params! {
                    ":outputs": new_outputs_str,
                    ":uuid": uuid
                },
            )?;
        }
        Ok(())
    }
}
