use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AlterOutputsFormat;
migration!(AlterOutputsFormat, 9, "alter outputs format");

#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub enum SubscriptionOutputFormat {
    Json,
    Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct KafkaConfiguration {
    topic: String,
    options: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RedisConfiguration {
    addr: String,
    list: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TcpConfiguration {
    addr: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FileConfiguration {
    base: String,
    split_on_addr_index: Option<u8>,
    append_node_name: bool,
    filename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UnixDatagramConfiguration {
    path: String,
}

#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
enum OldSubscriptionOutput {
    // The last bool indicates whether the output is enabled or not.
    Files(SubscriptionOutputFormat, FileConfiguration, bool),
    Kafka(SubscriptionOutputFormat, KafkaConfiguration, bool),
    Tcp(SubscriptionOutputFormat, TcpConfiguration, bool),
    Redis(SubscriptionOutputFormat, RedisConfiguration, bool),
    UnixDatagram(SubscriptionOutputFormat, UnixDatagramConfiguration, bool),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SubscriptionOutputDriver {
    Files(FileConfiguration),
    Kafka(KafkaConfiguration),
    Tcp(TcpConfiguration),
    Redis(RedisConfiguration),
    UnixDatagram(UnixDatagramConfiguration),
}

#[derive(Serialize, Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct NewSubscriptionOutput {
    format: SubscriptionOutputFormat,
    driver: SubscriptionOutputDriver,
    enabled: bool,
}

fn old_to_new_output(old: &OldSubscriptionOutput) -> NewSubscriptionOutput {
    match old.clone() {
        OldSubscriptionOutput::Files(format, config, enabled) => NewSubscriptionOutput {
            format,
            driver: SubscriptionOutputDriver::Files(config),
            enabled,
        },
        OldSubscriptionOutput::Kafka(format, config, enabled) => NewSubscriptionOutput {
            format,
            driver: SubscriptionOutputDriver::Kafka(config),
            enabled,
        },
        OldSubscriptionOutput::Tcp(format, config, enabled) => NewSubscriptionOutput {
            format,
            driver: SubscriptionOutputDriver::Tcp(config),
            enabled,
        },
        OldSubscriptionOutput::Redis(format, config, enabled) => NewSubscriptionOutput {
            format,
            driver: SubscriptionOutputDriver::Redis(config),
            enabled,
        },
        OldSubscriptionOutput::UnixDatagram(format, config, enabled) => NewSubscriptionOutput {
            format,
            driver: SubscriptionOutputDriver::UnixDatagram(config),
            enabled,
        },
    }
}

fn new_to_old_output(new: &NewSubscriptionOutput) -> OldSubscriptionOutput {
    let enabled = new.enabled.clone();
    let format = new.format.clone();
    match &new.driver {
        SubscriptionOutputDriver::Files(config) => {
            OldSubscriptionOutput::Files(format, config.clone(), enabled)
        }
        SubscriptionOutputDriver::Kafka(config) => {
            OldSubscriptionOutput::Kafka(format, config.clone(), enabled)
        }
        SubscriptionOutputDriver::Tcp(config) => {
            OldSubscriptionOutput::Tcp(format, config.clone(), enabled)
        }
        SubscriptionOutputDriver::Redis(config) => {
            OldSubscriptionOutput::Redis(format, config.clone(), enabled)
        }
        SubscriptionOutputDriver::UnixDatagram(config) => {
            OldSubscriptionOutput::UnixDatagram(format, config.clone(), enabled)
        }
    }
}

#[async_trait]
impl PostgresMigration for AlterOutputsFormat {
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
            let outputs: Vec<OldSubscriptionOutput> = serde_json::from_str(&outputs_str)?;
            let new_outputs: Vec<NewSubscriptionOutput> =
                outputs.iter().map(old_to_new_output).collect();
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
            let outputs: Vec<NewSubscriptionOutput> = serde_json::from_str(&outputs_str)?;
            let new_outputs: Vec<OldSubscriptionOutput> =
                outputs.iter().map(new_to_old_output).collect();
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
