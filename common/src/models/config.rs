use std::collections::{HashMap, HashSet};

use anyhow::{bail, Context, Result};
use log::error;
use serde::Deserialize;
use uuid::Uuid;

use crate::{subscription::{
    SubscriptionData, DEFAULT_OUTPUT_ENABLED,
}, transformers::output_files_use_path::transform_files_config_to_path};

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct KafkaConfiguration {
    pub topic: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
}

impl From<KafkaConfiguration> for crate::subscription::KafkaConfiguration {
    fn from(value: KafkaConfiguration) -> Self {
        crate::subscription::KafkaConfiguration::new(value.topic, value.options)
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RedisConfiguration {
    pub addr: String,
    pub list: String,
}

impl From<RedisConfiguration> for crate::subscription::RedisConfiguration {
    fn from(value: RedisConfiguration) -> Self {
        crate::subscription::RedisConfiguration::new(value.addr, value.list)
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct TcpConfiguration {
    pub addr: String,
    pub port: u16,
}

impl From<TcpConfiguration> for crate::subscription::TcpConfiguration {
    fn from(value: TcpConfiguration) -> Self {
        crate::subscription::TcpConfiguration::new(value.addr, value.port)
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FilesConfiguration {
    pub path: Option<String>,
    pub base: Option<String>,
    pub split_on_addr_index: Option<u8>,
    pub append_node_name: Option<bool>,
    pub filename: Option<String>,
}

impl From<FilesConfiguration> for crate::subscription::FilesConfiguration {
    fn from(value: FilesConfiguration) -> Self {
        let path = match value.path {
            Some(path) => path,
            None => {
                match transform_files_config_to_path(&value.base, &value.split_on_addr_index, &value.append_node_name, &value.filename) {
                    Ok(path) => path,
                    Err(err) => {
                        error!("Failed to import Files configuration {:?}: {:?}", value, err);
                        String::new()
                    }
                }
            }
        };
        crate::subscription::FilesConfiguration::new(path)
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct UnixDatagramConfiguration {
    pub path: String,
}

impl From<UnixDatagramConfiguration> for crate::subscription::UnixDatagramConfiguration {
    fn from(value: UnixDatagramConfiguration) -> Self {
        crate::subscription::UnixDatagramConfiguration::new(value.path)
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(tag = "driver", content = "config")]
enum SubscriptionOutputDriver {
    Files(FilesConfiguration),
    Kafka(KafkaConfiguration),
    Tcp(TcpConfiguration),
    Redis(RedisConfiguration),
    UnixDatagram(UnixDatagramConfiguration),
}

impl From<SubscriptionOutputDriver> for crate::subscription::SubscriptionOutputDriver {
    fn from(value: SubscriptionOutputDriver) -> Self {
        match value {
            SubscriptionOutputDriver::Files(config) => {
                crate::subscription::SubscriptionOutputDriver::Files(config.into())
            }
            SubscriptionOutputDriver::Kafka(config) => {
                crate::subscription::SubscriptionOutputDriver::Kafka(config.into())
            }
            SubscriptionOutputDriver::Tcp(config) => {
                crate::subscription::SubscriptionOutputDriver::Tcp(config.into())
            }
            SubscriptionOutputDriver::Redis(config) => {
                crate::subscription::SubscriptionOutputDriver::Redis(config.into())
            }
            SubscriptionOutputDriver::UnixDatagram(config) => {
                crate::subscription::SubscriptionOutputDriver::UnixDatagram(config.into())
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SubscriptionOutput {
    pub format: SubscriptionOutputFormat,
    #[serde(flatten)]
    pub driver: SubscriptionOutputDriver,
    pub enabled: Option<bool>,
}

impl From<SubscriptionOutput> for crate::subscription::SubscriptionOutput {
    fn from(value: SubscriptionOutput) -> Self {
        crate::subscription::SubscriptionOutput::new(
            value.format.into(),
            value.driver.into(),
            value.enabled.unwrap_or(DEFAULT_OUTPUT_ENABLED),
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
enum SubscriptionOutputFormat {
    Json,
    Raw,
    RawJson,
    Nxlog
}

impl From<SubscriptionOutputFormat> for crate::subscription::SubscriptionOutputFormat {
    fn from(value: SubscriptionOutputFormat) -> Self {
        match value {
            SubscriptionOutputFormat::Json => crate::subscription::SubscriptionOutputFormat::Json,
            SubscriptionOutputFormat::Raw => crate::subscription::SubscriptionOutputFormat::Raw,
            SubscriptionOutputFormat::RawJson => crate::subscription::SubscriptionOutputFormat::RawJson,
            SubscriptionOutputFormat::Nxlog => crate::subscription::SubscriptionOutputFormat::Nxlog
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
enum ClientFilterOperation {
    Only,
    Except,
}

impl From<ClientFilterOperation> for crate::subscription::ClientFilterOperation {
    fn from(value: ClientFilterOperation) -> Self {
        match value {
            ClientFilterOperation::Except => crate::subscription::ClientFilterOperation::Except,
            ClientFilterOperation::Only => crate::subscription::ClientFilterOperation::Only,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientFilter {
    pub operation: ClientFilterOperation,
    #[serde(alias = "cert_subjects", alias = "princs")]
    pub targets: HashSet<String>,
}

impl TryFrom<ClientFilter> for crate::subscription::ClientFilter {
    type Error = anyhow::Error;

    fn try_from(value: ClientFilter) -> std::prelude::v1::Result<Self, Self::Error> {
        Ok(crate::subscription::ClientFilter::new(value.operation.into(), value.targets))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
enum ContentFormat {
    Raw,
    RenderedText,
}

impl From<ContentFormat> for crate::subscription::ContentFormat {
    fn from(value: ContentFormat) -> Self {
        match value {
            ContentFormat::Raw => crate::subscription::ContentFormat::Raw,
            ContentFormat::RenderedText => crate::subscription::ContentFormat::RenderedText,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionOptions {
    pub uri: Option<String>,
    pub heartbeat_interval: Option<u32>,
    pub connection_retry_count: Option<u16>,
    pub connection_retry_interval: Option<u32>,
    pub max_time: Option<u32>,
    pub max_elements: Option<u32>,
    pub max_envelope_size: Option<u32>,
    pub enabled: Option<bool>,
    pub read_existing_events: Option<bool>,
    pub content_format: Option<ContentFormat>,
    pub ignore_channel_error: Option<bool>,
    pub locale: Option<String>,
    pub data_locale: Option<String>,
}

impl SubscriptionOptions {
    pub fn feed_subscription_data(&self, data: &mut SubscriptionData) {
        data.set_uri(self.uri.clone());

        if let Some(heartbeat_interval) = self.heartbeat_interval {
            data.set_heartbeat_interval(heartbeat_interval);
        }

        if let Some(connection_retry_count) = self.connection_retry_count {
            data.set_connection_retry_count(connection_retry_count);
        }

        if let Some(connection_retry_interval) = self.connection_retry_interval {
            data.set_connection_retry_interval(connection_retry_interval);
        }

        if let Some(max_time) = self.max_time {
            data.set_max_time(max_time);
        }

        data.set_max_elements(self.max_elements);

        if let Some(max_envelope_size) = self.max_envelope_size {
            data.set_max_envelope_size(max_envelope_size);
        }

        if let Some(enabled) = self.enabled {
            data.set_enabled(enabled);
        }

        if let Some(read_existing_events) = self.read_existing_events {
            data.set_read_existing_events(read_existing_events);
        }

        if let Some(content_format) = self.content_format.clone() {
            data.set_content_format(content_format.into());
        }

        if let Some(ignore_channel_error) = self.ignore_channel_error {
            data.set_ignore_channel_error(ignore_channel_error);
        }

        data.set_locale(self.locale.clone());
        data.set_data_locale(self.data_locale.clone());
    }
}
#[derive(Debug, PartialEq, Clone, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Subscription {
    pub uuid: Uuid,
    #[serde(default)]
    pub version: Uuid,
    pub name: String,
    pub query: String,
    pub filter: Option<ClientFilter>,
    pub outputs: Vec<SubscriptionOutput>,
    pub options: Option<SubscriptionOptions>,
}

impl TryFrom<Subscription> for crate::subscription::SubscriptionData {
    type Error = anyhow::Error;

    fn try_from(subscription: Subscription) -> std::prelude::v1::Result<Self, Self::Error> {
        let mut data =
            crate::subscription::SubscriptionData::new(&subscription.name, &subscription.query);
        data.set_uuid(crate::subscription::SubscriptionUuid(subscription.uuid));
        data.set_name(subscription.name.clone());
        data.set_query(subscription.query.clone());
        if let Some(filter) = subscription.filter {
            data.set_client_filter(Some(filter.try_into()?));
        }

        if subscription.outputs.is_empty() {
            bail!("Missing subscription outputs");
        }

        for output in subscription.outputs.iter() {
            data.add_output(output.clone().into());
        }

        if let Some(options) = subscription.options {
            options.feed_subscription_data(&mut data);
        }

        Ok(data)
    }
}

pub fn parse(
    content: &str,
    revision: Option<&String>,
) -> Result<crate::subscription::SubscriptionData> {
    let subscription: Subscription = toml::from_str(content).context("Error while parsing TOML")?;
    let mut data: SubscriptionData = subscription.try_into()?;
    data.set_revision(revision.cloned());
    Ok(data)
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    use crate::subscription::InternalVersion;

    use super::*;

    const FULL_CONTENT: &str = r#"
uuid = "b00bf259-3ba9-4faf-b58e-d0e9a3275778"
name = "my-subscription"

query = """
a wonderful query
"""

[options]
enabled = true
uri = "toto"
heartbeat_interval = 32
connection_retry_count = 11
connection_retry_interval = 12
max_time = 13
max_elements = 15
max_envelope_size = 14
read_existing_events = false
content_format = "Raw" # or RenderedText
ignore_channel_error = true

[filter]
operation = "Only" # or Except
princs = ["toto@windomain.local", "tutu@windomain.local"]

## Files output with old config format
[[outputs]]
driver = "Files"
format = "Json" # or "Raw"
enabled = true

[outputs.config]
base = "/tmp/"
split_on_addr_index = 2
append_node_name = true
filename = "courgette"

## Kafka output
[[outputs]]
driver = "Kafka"
format = "Raw"
enabled = false

[outputs.config]
topic = "my-topic"

[outputs.config.options]
"bootstrap.server" = "localhost:9092"

## Tcp output
[[outputs]]
driver = "Tcp"
format = "RawJson"
enabled = true

[outputs.config]
addr = "127.0.0.1"
port = 8080

## Redis output
[[outputs]]
driver = "Redis"
format = "Nxlog"
enabled = false

[outputs.config]
addr = "localhost"
list = "my-list"

## UnixDatagram output
[[outputs]]
format = "Raw"
enabled =  true
driver = "UnixDatagram"

[outputs.config]
path = "/tmp/openwec.socket"

## Files output with new config format
[[outputs]]
driver = "Files"
format = "Json" # or "Raw"
enabled = true

[outputs.config]
path = "/whatever/you/{ip}/want/{principal}/{ip:2}/{node}/end"
    "#;

    #[test]
    fn test_deserialize_full() -> Result<()> {
        let revision = "My-revision".to_string();
        let mut data = parse(FULL_CONTENT, Some(&revision))?;

        let mut expected =
            crate::subscription::SubscriptionData::new("my-subscription", "a wonderful query\n");
        expected
            .set_uuid(crate::subscription::SubscriptionUuid(Uuid::from_str(
                "b00bf259-3ba9-4faf-b58e-d0e9a3275778",
            )?))
            .set_uri(Some("toto".to_string()))
            .set_enabled(true)
            .set_heartbeat_interval(32)
            .set_connection_retry_count(11)
            .set_connection_retry_interval(12)
            .set_max_time(13)
            .set_max_elements(Some(15))
            .set_max_envelope_size(14)
            .set_read_existing_events(false)
            .set_content_format(crate::subscription::ContentFormat::Raw)
            .set_ignore_channel_error(true)
            .set_revision(Some(revision));

        let mut kafka_options = HashMap::new();
        kafka_options.insert("bootstrap.server".to_string(), "localhost:9092".to_string());

        let outputs = vec![
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Json,
                crate::subscription::SubscriptionOutputDriver::Files(
                    crate::subscription::FilesConfiguration::new(
                        "/tmp/{ip:2}/{ip:3}/{ip}/{principal}/{node}/courgette".to_string()
                    ),
                ),
                true,
            ),
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Raw,
                crate::subscription::SubscriptionOutputDriver::Kafka(
                    crate::subscription::KafkaConfiguration::new(
                        "my-topic".to_string(),
                        kafka_options,
                    ),
                ),
                false,
            ),
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::RawJson,
                crate::subscription::SubscriptionOutputDriver::Tcp(
                    crate::subscription::TcpConfiguration::new("127.0.0.1".to_string(), 8080),
                ),
                true,
            ),
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Nxlog,
                crate::subscription::SubscriptionOutputDriver::Redis(
                    crate::subscription::RedisConfiguration::new(
                        "localhost".to_string(),
                        "my-list".to_string(),
                    ),
                ),
                false,
            ),
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Raw,
                crate::subscription::SubscriptionOutputDriver::UnixDatagram(
                    crate::subscription::UnixDatagramConfiguration::new(
                        "/tmp/openwec.socket".to_string(),
                    ),
                ),
                true,
            ),
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Json,
                crate::subscription::SubscriptionOutputDriver::Files(
                    crate::subscription::FilesConfiguration::new(
                        "/whatever/you/{ip}/want/{principal}/{ip:2}/{node}/end".to_string()
                    ),
                ),
                true,
            ),
        ];

        expected.set_outputs(outputs);

        let mut targets = HashSet::new();
        targets.insert("toto@windomain.local".to_string());
        targets.insert("tutu@windomain.local".to_string());
        let filter = crate::subscription::ClientFilter::new(crate::subscription::ClientFilterOperation::Only, targets);

        expected.set_client_filter(Some(filter));

        // The only difference between both subscriptions should be the
        // internal version, so we set both the same value
        let version = Uuid::new_v4();
        // Must be done last
        expected.set_internal_version(crate::subscription::InternalVersion(version.clone()));
        data.set_internal_version(crate::subscription::InternalVersion(version.clone()));

        assert_eq!(data, expected);
        Ok(())
    }

    const MINIMAL_CONTENT: &str = r#"
uuid = "b00bf259-3ba9-4faf-b58e-d0e9a3757798"
name = "minimal"

query = """
a very small query
"""

[[outputs]]
driver = "UnixDatagram"
format = "Json"

[outputs.config]
path = "/tmp/my.socket"
    "#;

    #[test]
    fn test_serialize_minimal() -> Result<()> {
        let mut data = parse(MINIMAL_CONTENT, None)?;

        let mut expected =
            crate::subscription::SubscriptionData::new("minimal", "a very small query\n");
        expected
            .set_uuid(crate::subscription::SubscriptionUuid(Uuid::from_str(
                "b00bf259-3ba9-4faf-b58e-d0e9a3757798",
            )?))
            .set_outputs(vec![crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Json,
                crate::subscription::SubscriptionOutputDriver::UnixDatagram(
                    crate::subscription::UnixDatagramConfiguration::new(
                        "/tmp/my.socket".to_string(),
                    ),
                ),
                true,
            )]);

        // Must be done last
        let version = Uuid::new_v4();
        data.set_internal_version(InternalVersion(version));
        expected.set_internal_version(InternalVersion(version));

        assert_eq!(data, expected);
        Ok(())
    }

    const MISSING_UUID: &str = r#"
name = "minimal"

query = """
a very small query
"""

[[outputs]]
driver = "UnixDatagram"
format = "Json"

[outputs.config]
path = "/tmp/my.socket"
    "#;

    #[test]
    #[should_panic(expected = "missing field `uuid`")]
    fn test_serialize_missing_uuid() {
        parse(MISSING_UUID, None).unwrap();
    }

    const MISSING_NAME: &str = r#"
uuid = "b00bf259-3ba9-4faf-b58e-d0e9a3757798"

query = """
a very small query
"""

[[outputs]]
driver = "UnixDatagram"
format = "Json"

[outputs.config]
path = "/tmp/my.socket"
    "#;

    #[test]
    #[should_panic(expected = "missing field `name`")]
    fn test_serialize_missing_name() {
        parse(MISSING_NAME, None).unwrap();
    }

    const MISSING_QUERY: &str = r#"
uuid = "b00bf259-3ba9-4faf-b58e-d0e9a3757798"
name = "minimal"

[[outputs]]
driver = "UnixDatagram"
format = "Json"

[outputs.config]
path = "/tmp/my.socket"
    "#;

    #[test]
    #[should_panic(expected = "missing field `query`")]
    fn test_serialize_missing_query() {
        parse(MISSING_QUERY, None).unwrap();
    }

    const MISSING_OUTPUTS: &str = r#"
uuid = "b00bf259-3ba9-4faf-b58e-d0e9a3757798"
name = "minimal"

query = """
a very small query
"""

outputs = []
    "#;

    #[test]
    #[should_panic(expected = "Missing subscription outputs")]
    fn test_serialize_missing_outputs() {
        parse(MISSING_OUTPUTS, None).unwrap();
    }

    const RANDOM_FIELD: &str = r#"
babar = "courgette"
uuid = "b00bf259-3ba9-4faf-b58e-d0e9a3757798"
name = "minimal"

query = """
a very small query
"""

[[outputs]]
driver = "UnixDatagram"
format = "Json"

[outputs.config]
path = "/tmp/my.socket"
    "#;

    #[test]
    #[should_panic(expected = "unknown field `babar`")]
    fn test_random_field() {
        parse(RANDOM_FIELD, None).unwrap();
    }

    const GETTING_STARTED_CONF: &str = r#"
# conf/my-test-subscription.toml

# Unique identifier of the subscription
uuid = "28fcc206-1336-4e4a-b76b-18b0ab46e585"
# Unique name of the subscription
name = "my-test-subscription"

# Subscription query
query = """
<QueryList>
    <Query Id="0">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
"""

# Subscription outputs
[[outputs]]
driver = "Files"
format = "Raw"
config = { path = "/data/logs/{ip}/{principal}/messages" }

# Subscription outputs
[[outputs]]
driver = "Kafka"
format = "RawJson"
# FIXME: `config.options` should be configured in OpenWEC settings (`outputs.kafka.options`)
# to use only one kafka producer client for all kafka outputs
config = { topic = "my-kafka-topic", options = { "bootstrap.servers" = "localhost:9092" } }
    "#;
    const GETTING_STARTED_QUERY: &str = r#"<QueryList>
    <Query Id="0">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
"#;

    #[test]
    fn test_getting_started_conf() -> Result<()> {
        let mut data = parse(GETTING_STARTED_CONF, None)?;

        let mut expected =
            crate::subscription::SubscriptionData::new("my-test-subscription", GETTING_STARTED_QUERY);
        expected
            .set_uuid(crate::subscription::SubscriptionUuid(Uuid::from_str(
                "28fcc206-1336-4e4a-b76b-18b0ab46e585",
            )?));

        let mut kafka_options = HashMap::new();
        kafka_options.insert("bootstrap.servers".to_string(), "localhost:9092".to_string());

        let outputs = vec![
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Raw,
                crate::subscription::SubscriptionOutputDriver::Files(
                    crate::subscription::FilesConfiguration::new(
                        "/data/logs/{ip}/{principal}/messages".to_string()
                    ),
                ),
                true,
            ),
            crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::RawJson,
                crate::subscription::SubscriptionOutputDriver::Kafka(
                    crate::subscription::KafkaConfiguration::new(
                        "my-kafka-topic".to_string(),
                        kafka_options,
                    ),
                ),
                true,
            ),
        ];

        expected.set_outputs(outputs);

        // The only difference between both subscriptions should be the
        // internal version, so we set both the same value
        let version = Uuid::new_v4();
        // Must be done last
        expected.set_internal_version(crate::subscription::InternalVersion(version.clone()));
        data.set_internal_version(crate::subscription::InternalVersion(version.clone()));

        assert_eq!(data, expected);
        Ok(())
    }
}
