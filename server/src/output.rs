use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use common::subscription::{FileConfiguration, KafkaConfiguration, SubscriptionOutput, RedisConfiguration};

use crate::{event::EventMetadata, formatter::Format};

#[derive(Debug, Clone)]
pub enum OutputType {
    Files(Format, FileConfiguration, bool),
    Kafka(Format, KafkaConfiguration, bool),
    Redis(Format, RedisConfiguration, bool),
    Tcp(Format, String, u16, bool),
}

impl From<&SubscriptionOutput> for OutputType {
    fn from(so: &SubscriptionOutput) -> Self {
        match so {
            SubscriptionOutput::Files(sof, config, enabled) => {
                OutputType::Files(sof.into(), config.clone(), *enabled)
            }
            SubscriptionOutput::Kafka(sof, config, enabled) => {
                OutputType::Kafka(sof.into(), config.clone(), *enabled)
            }
            SubscriptionOutput::Redis(sof, config, enabled) => {
                OutputType::Redis(sof.into(), config.clone(), *enabled)
            }
            SubscriptionOutput::Tcp(sof, config, enabled) => OutputType::Tcp(
                sof.into(),
                config.addr().to_string(),
                config.port(),
                *enabled,
            ),
        }
    }
}

// async_trait is required to be able to use async functions
// in traits
#[async_trait]
pub trait Output {
    async fn write(
        &self,
        metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()>;

    fn describe(&self) -> String;
    fn format(&self) -> &Format;
}
