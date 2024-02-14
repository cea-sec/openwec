use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use common::subscription::{
    FileConfiguration, KafkaConfiguration, RedisConfiguration, SubscriptionOutput,
    SubscriptionOutputDriver, UnixDatagramConfiguration,
};

use crate::{event::EventMetadata, formatter::Format};

#[derive(Debug, Clone)]
pub enum OutputType {
    Files(Format, FileConfiguration, bool),
    Kafka(Format, KafkaConfiguration, bool),
    Redis(Format, RedisConfiguration, bool),
    Tcp(Format, String, u16, bool),
    UnixDatagram(Format, UnixDatagramConfiguration, bool),
}

impl From<&SubscriptionOutput> for OutputType {
    fn from(so: &SubscriptionOutput) -> Self {
        let format = so.format();
        let enabled = so.is_enabled();
        match so.driver() {
            SubscriptionOutputDriver::Files(config) => {
                OutputType::Files(format.into(), config.clone(), enabled)
            }
            SubscriptionOutputDriver::Kafka(config) => {
                OutputType::Kafka(format.into(), config.clone(), enabled)
            }
            SubscriptionOutputDriver::Redis(config) => {
                OutputType::Redis(format.into(), config.clone(), enabled)
            }
            SubscriptionOutputDriver::Tcp(config) => OutputType::Tcp(
                format.into(),
                config.addr().to_string(),
                config.port(),
                enabled,
            ),
            SubscriptionOutputDriver::UnixDatagram(config) => {
                OutputType::UnixDatagram(format.into(), config.clone(), enabled)
            }
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
