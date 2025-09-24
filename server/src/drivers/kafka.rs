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
use std::{
    sync::{Arc, atomic::{
        AtomicUsize,
        Ordering,
    }},
    time::Duration,
};

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
    topic_index: AtomicUsize,
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
            topic_index: AtomicUsize::new(0),
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
        let topics_array = self.config.topic_as_array();
        let mut l_topic_index = self.topic_index.load(Ordering::Relaxed);
        let mut futures = Vec::new();
        for event in events.iter() {
            // Get current topic
            let topic = topics_array[l_topic_index].as_ref();
            // We need to explicitly assign the Key type as ()
            futures.push(self.producer.send::<(), _, _>(
                FutureRecord::to(topic).payload(event.as_ref()),
                Timeout::After(Duration::from_secs(30)),
            ));
            l_topic_index = (l_topic_index + 1) % topics_array.len();
        }
        self.topic_index.store(l_topic_index, Ordering::Relaxed);

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
