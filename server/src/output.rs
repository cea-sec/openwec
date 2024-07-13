use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use common::{
    settings::Outputs,
    subscription::{SubscriptionData, SubscriptionOutputDriver, SubscriptionOutputFormat},
};

use crate::{
    drivers::{
        files::{OutputFiles, OutputFilesContext},
        kafka::{OutputKafka, OutputKafkaContext},
        redis::OutputRedis,
        tcp::OutputTcp,
        unix::OutputUnixDatagram,
    },
    event::{EventData, EventMetadata},
    formats::{json::JsonFormat, nxlog::NxlogFormat, raw::RawFormat, raw_json::RawJsonFormat},
};

pub struct OutputDriversContext {
    settings: Outputs,
    files: Option<OutputFilesContext>,
    kafka: Option<OutputKafkaContext>,
}

impl OutputDriversContext {
    pub fn new(settings: &Outputs) -> Self {
        Self {
            settings: settings.clone(),
            files: None,
            kafka: None,
        }
    }

    pub fn initialize_missing(&mut self, subscriptions: &[SubscriptionData]) -> Result<()> {
        // Depending on the output drivers used and the settings, this function
        // initializes the required output contexts if not already done.
        // - It makes sure that the files context is initialized if at least one output uses the Files driver
        // - It makes sure that the kafka context is initialized if at least one output uses the Kafka driver
        //      AND one output did not configure kafka options (such as bootstrap.servers)

        if Self::need_files_context(subscriptions) && self.files.is_none() {
            self.files = Some(OutputFilesContext::new());
        }

        if Self::need_kafka_context(subscriptions) && self.kafka.is_none() {
            self.kafka = Some(OutputKafkaContext::new(self.settings.kafka())?);
        }

        Ok(())
    }

    fn need_files_context(subscriptions: &[SubscriptionData]) -> bool {
        for subscription in subscriptions {
            if subscription.is_active() {
                for output in subscription.outputs() {
                    if output.enabled() {
                        if let SubscriptionOutputDriver::Files(_) = output.driver() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn need_kafka_context(subscriptions: &[SubscriptionData]) -> bool {
        for subscription in subscriptions {
            if subscription.is_active() {
                for output in subscription.outputs() {
                    if let SubscriptionOutputDriver::Kafka(config) = output.driver() {
                        if output.enabled() && config.options().is_empty() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn clear(&mut self) {
        if let Some(files) = &mut self.files {
            files.clear();
        }
    }

    pub fn garbage_collect(&mut self, settings: &Outputs) -> Result<()> {
        if let Some(files) = &mut self.files {
            files.garbage_collect(settings.files().files_descriptor_close_timeout());
        }
        Ok(())
    }
}

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
        context: &mut OutputDriversContext,
    ) -> Result<Self> {
        let output_driver: Arc<dyn OutputDriver + Send + Sync> = match driver {
            SubscriptionOutputDriver::Files(config) => {
                Arc::new(OutputFiles::new(config, &context.files)?)
            }
            SubscriptionOutputDriver::Kafka(config) => {
                Arc::new(OutputKafka::new(config, &context.kafka)?)
            }
            SubscriptionOutputDriver::Tcp(config) => Arc::new(OutputTcp::new(config)?),
            SubscriptionOutputDriver::Redis(config) => Arc::new(OutputRedis::new(config)?),
            SubscriptionOutputDriver::UnixDatagram(config) => {
                Arc::new(OutputUnixDatagram::new(config)?)
            }
        };

        Ok(Self {
            driver: output_driver,
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

pub fn get_formatter(format: &SubscriptionOutputFormat) -> Box<dyn OutputFormat> {
    match format {
        SubscriptionOutputFormat::Json => Box::new(JsonFormat),
        SubscriptionOutputFormat::Raw => Box::new(RawFormat),
        SubscriptionOutputFormat::RawJson => Box::new(RawJsonFormat),
        SubscriptionOutputFormat::Nxlog => Box::new(NxlogFormat),
    }
}
