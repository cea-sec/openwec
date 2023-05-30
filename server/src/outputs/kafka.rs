use anyhow::{bail, Result};
use async_trait::async_trait;
use common::subscription::KafkaConfiguration;
use futures::future::join_all;
use log::debug;
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    util::Timeout,
    ClientConfig,
};
use std::{sync::Arc, time::Duration};

use crate::{event::EventMetadata, formatter::Format, output::Output};

pub struct OutputKafka {
    format: Format,
    config: KafkaConfiguration,
    producer: FutureProducer,
}

impl OutputKafka {
    pub fn new(format: Format, config: &KafkaConfiguration) -> Result<Self> {
        let mut client_config = ClientConfig::new();
        // Set a default value for Kafka delivery timeout
        // This can be overwritten in Kafka configuration
        client_config.set("delivery.timeout.ms", "30000");
        for (key, value) in config.options() {
            client_config.set(key, value);
        }
        debug!(
            "Initialize kafka output with format {:?} and config {:?}",
            format, config
        );
        Ok(OutputKafka {
            format,
            config: config.clone(),
            producer: client_config.create()?,
        })
    }
}

#[async_trait]
impl Output for OutputKafka {
    async fn write(
        &self,
        _metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {
        let mut futures = Vec::new();
        for event in events.iter() {
            // We need to explicitly assign the Key type as ()
            futures.push(self.producer.send::<(), _, _>(
                FutureRecord::to(self.config.topic()).payload(event.as_ref()),
                Timeout::After(Duration::from_secs(30)),
            ));
        }

        // Wait for all events to be sent and ack
        let results = join_all(futures).await;

        for result in results {
            match result {
                Ok(delivery) => debug!("Kafka message sent: {:?}", delivery),
                Err((e, _)) => bail!(e),
            }
        }

        Ok(())
    }

    fn describe(&self) -> String {
        format!("Kafka (topic {})", self.config.topic())
    }

    fn format(&self) -> &Format {
        &self.format
    }
}
