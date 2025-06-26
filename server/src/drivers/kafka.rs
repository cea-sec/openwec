use anyhow::{bail, Result};
use async_trait::async_trait;
use common::{settings, subscription::KafkaConfiguration};
use futures::future::join_all;
use log::debug;
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    util::Timeout,
    ClientConfig,
};
use std::{sync::Arc, time::Duration};

use crate::{event::EventMetadata, output::OutputDriver};

pub struct OutputKafkaContext {
    producer: FutureProducer,
}

impl OutputKafkaContext {
    pub fn new(settings: &settings::KafkaOutput) -> Result<Self> {
        let mut client_config = ClientConfig::new();
        // Set a default value for Kafka delivery timeout
        // This can be overwritten in Kafka configuration
        client_config.set("delivery.timeout.ms", "30000");
        for (key, value) in settings.options() {
            client_config.set(key, value);
        }

        if client_config.get("bootstrap.servers").is_none() {
            bail!("'bootstrap.servers' option must be configured for Kafka outputs to work")
        }

        debug!(
            "Initialize kafka context with options {:?}",
            settings.options()
        );
        Ok(Self {
            producer: client_config.create()?,
        })
    }
}

pub struct OutputKafka {
    config: KafkaConfiguration,
    producer: FutureProducer,
}

impl OutputKafka {
    pub fn new(config: &KafkaConfiguration, context: &Option<OutputKafkaContext>) -> Result<Self> {
        let producer = if config.options().is_empty() {
            if let Some(kafka_context) = context {
                debug!("Initialize kafka output with config {:?}", config);
                kafka_context.producer.clone()
            } else {
                bail!("Kafka output options are empty but Kafka context is not initialized")
            }
        } else {
            let mut client_config = ClientConfig::new();
            // Set a default value for Kafka delivery timeout
            // This can be overwritten in Kafka configuration
            client_config.set("delivery.timeout.ms", "30000");
            for (key, value) in config.options() {
                client_config.set(key, value);
            }

            if client_config.get("bootstrap.servers").is_none() {
                bail!("'bootstrap.servers' option must be configured for Kafka outputs to work")
            }
            debug!(
                "Initialize kafka output with a standalone producer and config {:?}",
                config
            );
            client_config.create()?
        };
        Ok(OutputKafka {
            config: config.clone(),
            producer,
        })
    }
}

#[async_trait]
impl OutputDriver for OutputKafka {
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
}
