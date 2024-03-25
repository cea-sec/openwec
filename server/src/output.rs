use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use common::subscription::{
    SubscriptionOutputDriver, SubscriptionOutputFormat,
};

use crate::{
    drivers::{
        files::OutputFiles, kafka::OutputKafka, redis::OutputRedis, tcp::OutputTcp,
        unix::OutputUnixDatagram,
    },
    event::{EventData, EventMetadata}, formats::{json::JsonFormat, raw::RawFormat, raw_json::RawJsonFormat},

};

#[derive(Clone)]
pub struct Output {
    format: SubscriptionOutputFormat,
    driver: Arc<dyn OutputDriver + Send + Sync>,
    // Only used for "describe()"
    subscription_output_driver: SubscriptionOutputDriver,
}

impl Output {
    pub fn new(
        format: &SubscriptionOutputFormat,
        driver: &SubscriptionOutputDriver,
    ) -> Result<Self> {
        Ok(Self {
            driver: match driver {
                SubscriptionOutputDriver::Files(config) => {
                    Arc::new(OutputFiles::new(config))
                }
                SubscriptionOutputDriver::Kafka(config) => {
                    Arc::new(OutputKafka::new(config)?)
                }
                SubscriptionOutputDriver::Tcp(config) => {
                    Arc::new(OutputTcp::new(config)?)
                }
                SubscriptionOutputDriver::Redis(config) => {
                    Arc::new(OutputRedis::new(config)?)
                }
                SubscriptionOutputDriver::UnixDatagram(config) => {
                    Arc::new(OutputUnixDatagram::new(config)?)
                }
            },
            format: format.clone(),
            subscription_output_driver: driver.clone(),
        })
    }

    pub fn describe(&self) -> String {
        format!(
            "format: {:?}, driver: {:?}",
            self.format, self.subscription_output_driver
        )
    }

    pub async fn write(
        &self,
        metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {
        self.driver.write(metadata, events).await
    }
    
    pub fn format(&self) -> &SubscriptionOutputFormat {
        &self.format
    }
}

#[async_trait]
pub trait OutputDriver {
    /// Write a batch of events and associated metadata
    async fn write(
        &self,
        metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()>;
}

pub trait OutputFormat {
    /// Formats an event.
    /// If something wrong happens, formatter is allowed to return None.
    fn format(&self, metadata: &EventMetadata, data: &EventData) -> Option<Arc<String>>;
}

pub fn get_formatter(format :&SubscriptionOutputFormat) -> Box<dyn OutputFormat> {
    match format {
        SubscriptionOutputFormat::Json => Box::new(JsonFormat),
        SubscriptionOutputFormat::Raw => Box::new(RawFormat),
        SubscriptionOutputFormat::RawJson => Box::new(RawJsonFormat)
    }
}