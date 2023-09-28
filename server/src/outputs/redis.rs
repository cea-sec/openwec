use anyhow::{Result};
use async_trait::async_trait;
use common::subscription::{ RedisConfiguration};
use log::debug;

use std::{sync::Arc};
use redis::RedisResult;
use crate::{event::EventMetadata, formatter::Format, output::Output};

pub struct OutputRedis {
    format: Format,
    config: RedisConfiguration,
    producer: redis::Client,
}

impl OutputRedis {
    pub fn new(format: Format, config: &RedisConfiguration) -> Result<Self> {

        let client = redis::Client::open(format!("redis://{}/", config.addr())).unwrap();

        debug!(
            "Initialize redis output with format {:?} and config {:?}",
            format, config
        );
        Ok(OutputRedis {
            format,
            config: config.clone(),
            producer: client,
        })
    }
}

#[async_trait]
impl Output for OutputRedis {
    async fn write(
        &self,
        _metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {


        let cmd = redis::cmd("LPUSH");

        for event in events.iter() {

            let mut redis_cmd = cmd.clone();
            let mut redis_connection = self.producer.get_tokio_connection().await?;


            let result : RedisResult<Option<String>> = redis_cmd
                .arg(&[self.config.list(), event.as_ref()])
                .query_async(&mut redis_connection).await;

            debug!("Redis message sent: {:?}", result)

        }

        Ok(())
    }

    fn describe(&self) -> String {
        format!("Redis (list {})", self.config.list())
    }

    fn format(&self) -> &Format {
        &self.format
    }
}
