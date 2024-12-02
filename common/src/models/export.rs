use serde::{Deserialize, Serialize};

use anyhow::{Context, Result};

// Export/Import structures of an already existing version must NOT change
// because we want to be able to import subscriptions that have been exported
// using an "old" version of OpenWEC.
//
// If you want to change something in the SubscriptionData struct, you must
// create a new version of the schema and adapt the import code of the already
// existing versions so that importing from old versions still works.
// Then, you need to update the version used while exporting (see serialize()).

#[derive(Debug, PartialEq, Clone, Eq, Deserialize, Serialize)]
#[serde(tag = "schema", content = "data")]
enum ImportExport {
    V1(v1::Subscriptions),
    V2(v2::Subscriptions),
}

pub fn serialize(subscriptions: &[crate::subscription::SubscriptionData]) -> Result<String> {
    let export = ImportExport::V2(subscriptions.into());
    Ok(serde_json::to_string(&export)?)
}

pub fn parse(content: &str) -> Result<Vec<crate::subscription::SubscriptionData>> {
    let import: ImportExport = serde_json::from_str(content).context("Failed to parse file")?;
    let subscriptions = match import {
        ImportExport::V1(subscriptions) => subscriptions.into(),
        ImportExport::V2(subscriptions) => subscriptions.into(),
    };
    Ok(subscriptions)
}

mod v1 {
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    use crate::transformers::output_files_use_path::transform_files_config_to_path;

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct KafkaConfiguration {
        pub topic: String,
        pub options: HashMap<String, String>,
    }

    // Used for import
    impl From<KafkaConfiguration> for crate::subscription::KafkaConfiguration {
        fn from(value: KafkaConfiguration) -> Self {
            crate::subscription::KafkaConfiguration::new(value.topic, value.options)
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct RedisConfiguration {
        pub addr: String,
        pub list: String,
    }

    impl From<RedisConfiguration> for crate::subscription::RedisConfiguration {
        fn from(value: RedisConfiguration) -> Self {
            crate::subscription::RedisConfiguration::new(value.addr, value.list)
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct TcpConfiguration {
        pub addr: String,
        pub port: u16,
    }

    impl From<TcpConfiguration> for crate::subscription::TcpConfiguration {
        fn from(value: TcpConfiguration) -> Self {
            crate::subscription::TcpConfiguration::new(value.addr, value.port)
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct FilesConfiguration {
        pub base: String,
        pub split_on_addr_index: Option<u8>,
        pub append_node_name: bool,
        pub filename: String,
    }

    impl From<FilesConfiguration> for crate::subscription::FilesConfiguration {
        fn from(value: FilesConfiguration) -> Self {
            let path = transform_files_config_to_path(&Some(value.base), &value.split_on_addr_index, &Some(value.append_node_name), &Some(value.filename)).expect("Failed to convert old Files driver configuration");
            crate::subscription::FilesConfiguration::new(path)
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct UnixDatagramConfiguration {
        pub path: String,
    }

    impl From<UnixDatagramConfiguration> for crate::subscription::UnixDatagramConfiguration {
        fn from(value: UnixDatagramConfiguration) -> Self {
            crate::subscription::UnixDatagramConfiguration::new(value.path)
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) enum SubscriptionOutputDriver {
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

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) enum SubscriptionOutputFormat {
        Json,
        Raw,
        RawJson,
        Nxlog,
    }

    impl From<SubscriptionOutputFormat> for crate::subscription::SubscriptionOutputFormat {
        fn from(value: SubscriptionOutputFormat) -> Self {
            match value {
                SubscriptionOutputFormat::Json => {
                    crate::subscription::SubscriptionOutputFormat::Json
                }
                SubscriptionOutputFormat::Raw => crate::subscription::SubscriptionOutputFormat::Raw,
                SubscriptionOutputFormat::RawJson => {
                    crate::subscription::SubscriptionOutputFormat::RawJson
                }
                SubscriptionOutputFormat::Nxlog => {
                    crate::subscription::SubscriptionOutputFormat::Nxlog
                }
            }
        }
    }

    #[derive(Deserialize, Debug, Clone, Eq, PartialEq, Serialize)]
    pub(super) struct SubscriptionOutput {
        pub format: SubscriptionOutputFormat,
        pub driver: SubscriptionOutputDriver,
        pub enabled: bool,
    }

    impl From<SubscriptionOutput> for crate::subscription::SubscriptionOutput {
        fn from(value: SubscriptionOutput) -> Self {
            crate::subscription::SubscriptionOutput::new(
                value.format.into(),
                value.driver.into(),
                value.enabled,
            )
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) enum PrincsFilterOperation {
        Only,
        Except,
    }

    impl From<PrincsFilterOperation> for crate::subscription::ClientFilterOperation {
        fn from(value: PrincsFilterOperation) -> Self {
            match value {
                PrincsFilterOperation::Except => crate::subscription::ClientFilterOperation::Except,
                PrincsFilterOperation::Only => crate::subscription::ClientFilterOperation::Only,
            }
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) struct PrincsFilter {
        pub operation: Option<PrincsFilterOperation>,
        pub princs: HashSet<String>,
    }

    impl PrincsFilter {
        fn to_client_filter(self) -> Option<crate::subscription::ClientFilter> {
            let Some(op) = self.operation else {
                return None;
            };

            Some(crate::subscription::ClientFilter::new(op.into(), self.princs))
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) enum ContentFormat {
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

    #[derive(Debug, PartialEq, Clone, Eq, Deserialize, Serialize)]
    pub(super) struct SubscriptionData {
        pub uuid: Uuid,
        pub revision: Option<String>,
        pub name: String,
        pub uri: Option<String>,
        pub query: String,
        pub heartbeat_interval: u32,
        pub connection_retry_count: u16,
        pub connection_retry_interval: u32,
        pub max_time: u32,
        pub max_envelope_size: u32,
        pub enabled: bool,
        pub read_existing_events: bool,
        pub content_format: ContentFormat,
        pub ignore_channel_error: bool,
        pub locale: Option<String>,
        pub data_locale: Option<String>,
        pub filter: PrincsFilter,
        pub outputs: Vec<SubscriptionOutput>,
    }

    impl From<SubscriptionData> for crate::subscription::SubscriptionData {
        fn from(value: SubscriptionData) -> Self {
            let mut data = crate::subscription::SubscriptionData::new(&value.name, &value.query);
            data.set_uuid(crate::subscription::SubscriptionUuid(value.uuid))
                .set_uri(value.uri)
                .set_heartbeat_interval(value.heartbeat_interval)
                .set_connection_retry_count(value.connection_retry_count)
                .set_connection_retry_interval(value.connection_retry_interval)
                .set_max_time(value.max_time)
                .set_max_envelope_size(value.max_envelope_size)
                .set_enabled(value.enabled)
                .set_read_existing_events(value.read_existing_events)
                .set_content_format(value.content_format.into())
                .set_ignore_channel_error(value.ignore_channel_error)
                .set_client_filter(value.filter.to_client_filter())
                .set_locale(value.locale)
                .set_data_locale(value.data_locale)
                .set_outputs(value.outputs.iter().map(|s| s.clone().into()).collect())
                .set_revision(value.revision);
            // Note: internal version is not exported nor set
            data
        }
    }

    #[derive(Debug, PartialEq, Clone, Eq, Deserialize, Serialize)]
    pub(super) struct Subscriptions {
        pub subscriptions: Vec<SubscriptionData>,
    }

    impl From<Subscriptions> for Vec<crate::subscription::SubscriptionData> {
        fn from(value: Subscriptions) -> Self {
            value
                .subscriptions
                .iter()
                .map(|s| s.clone().into())
                .collect()
        }
    }
}

pub mod v2 {
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct KafkaConfiguration {
        pub topic: String,
        pub options: HashMap<String, String>,
    }

    // Used for import
    impl From<KafkaConfiguration> for crate::subscription::KafkaConfiguration {
        fn from(value: KafkaConfiguration) -> Self {
            crate::subscription::KafkaConfiguration::new(value.topic, value.options)
        }
    }

    // Used for export
    impl From<crate::subscription::KafkaConfiguration> for KafkaConfiguration {
        fn from(value: crate::subscription::KafkaConfiguration) -> Self {
            Self {
                topic: value.topic().to_string(),
                options: value.options().clone(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct RedisConfiguration {
        pub addr: String,
        pub list: String,
    }

    impl From<RedisConfiguration> for crate::subscription::RedisConfiguration {
        fn from(value: RedisConfiguration) -> Self {
            crate::subscription::RedisConfiguration::new(value.addr, value.list)
        }
    }

    impl From<crate::subscription::RedisConfiguration> for RedisConfiguration {
        fn from(value: crate::subscription::RedisConfiguration) -> Self {
            Self {
                addr: value.addr().to_string(),
                list: value.list().to_string(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct TcpConfiguration {
        pub addr: String,
        pub port: u16,
    }

    impl From<TcpConfiguration> for crate::subscription::TcpConfiguration {
        fn from(value: TcpConfiguration) -> Self {
            crate::subscription::TcpConfiguration::new(value.addr, value.port)
        }
    }

    impl From<crate::subscription::TcpConfiguration> for TcpConfiguration {
        fn from(value: crate::subscription::TcpConfiguration) -> Self {
            Self {
                addr: value.addr().to_string(),
                port: value.port(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct FilesConfiguration {
        pub path: String
    }

    impl From<FilesConfiguration> for crate::subscription::FilesConfiguration {
        fn from(value: FilesConfiguration) -> Self {
            crate::subscription::FilesConfiguration::new(value.path)
        }
    }

    impl From<crate::subscription::FilesConfiguration> for FilesConfiguration {
        fn from(value: crate::subscription::FilesConfiguration) -> Self {
            Self {
                path: value.path().to_owned()
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) struct UnixDatagramConfiguration {
        pub path: String,
    }

    impl From<UnixDatagramConfiguration> for crate::subscription::UnixDatagramConfiguration {
        fn from(value: UnixDatagramConfiguration) -> Self {
            crate::subscription::UnixDatagramConfiguration::new(value.path)
        }
    }

    impl From<crate::subscription::UnixDatagramConfiguration> for UnixDatagramConfiguration {
        fn from(value: crate::subscription::UnixDatagramConfiguration) -> Self {
            Self {
                path: value.path().to_string(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
    pub(super) enum SubscriptionOutputDriver {
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

    impl From<crate::subscription::SubscriptionOutputDriver> for SubscriptionOutputDriver {
        fn from(value: crate::subscription::SubscriptionOutputDriver) -> Self {
            match value {
                crate::subscription::SubscriptionOutputDriver::Files(config) => {
                    SubscriptionOutputDriver::Files(config.into())
                }
                crate::subscription::SubscriptionOutputDriver::Kafka(config) => {
                    SubscriptionOutputDriver::Kafka(config.into())
                }
                crate::subscription::SubscriptionOutputDriver::Tcp(config) => {
                    SubscriptionOutputDriver::Tcp(config.into())
                }
                crate::subscription::SubscriptionOutputDriver::Redis(config) => {
                    SubscriptionOutputDriver::Redis(config.into())
                }
                crate::subscription::SubscriptionOutputDriver::UnixDatagram(config) => {
                    SubscriptionOutputDriver::UnixDatagram(config.into())
                }
            }
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) enum SubscriptionOutputFormat {
        Json,
        Raw,
        RawJson,
        Nxlog,
    }

    impl From<SubscriptionOutputFormat> for crate::subscription::SubscriptionOutputFormat {
        fn from(value: SubscriptionOutputFormat) -> Self {
            match value {
                SubscriptionOutputFormat::Json => {
                    crate::subscription::SubscriptionOutputFormat::Json
                }
                SubscriptionOutputFormat::Raw => crate::subscription::SubscriptionOutputFormat::Raw,
                SubscriptionOutputFormat::RawJson => {
                    crate::subscription::SubscriptionOutputFormat::RawJson
                }
                SubscriptionOutputFormat::Nxlog => {
                    crate::subscription::SubscriptionOutputFormat::Nxlog
                }
            }
        }
    }

    impl From<crate::subscription::SubscriptionOutputFormat> for SubscriptionOutputFormat {
        fn from(value: crate::subscription::SubscriptionOutputFormat) -> Self {
            match value {
                crate::subscription::SubscriptionOutputFormat::Json => {
                    SubscriptionOutputFormat::Json
                }
                crate::subscription::SubscriptionOutputFormat::Raw => SubscriptionOutputFormat::Raw,
                crate::subscription::SubscriptionOutputFormat::RawJson => {
                    SubscriptionOutputFormat::RawJson
                }
                crate::subscription::SubscriptionOutputFormat::Nxlog => {
                    SubscriptionOutputFormat::Nxlog
                }
            }
        }
    }

    #[derive(Deserialize, Debug, Clone, Eq, PartialEq, Serialize)]
    pub(super) struct SubscriptionOutput {
        pub format: SubscriptionOutputFormat,
        pub driver: SubscriptionOutputDriver,
        pub enabled: bool,
    }

    impl From<SubscriptionOutput> for crate::subscription::SubscriptionOutput {
        fn from(value: SubscriptionOutput) -> Self {
            crate::subscription::SubscriptionOutput::new(
                value.format.into(),
                value.driver.into(),
                value.enabled,
            )
        }
    }

    impl From<crate::subscription::SubscriptionOutput> for SubscriptionOutput {
        fn from(value: crate::subscription::SubscriptionOutput) -> Self {
            Self {
                format: value.format().clone().into(),
                driver: value.driver().clone().into(),
                enabled: value.enabled(),
            }
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) enum PrincsFilterOperation {
        Only,
        Except,
    }

    impl From<PrincsFilterOperation> for crate::subscription::ClientFilterOperation {
        fn from(value: PrincsFilterOperation) -> Self {
            match value {
                PrincsFilterOperation::Except => crate::subscription::ClientFilterOperation::Except,
                PrincsFilterOperation::Only => crate::subscription::ClientFilterOperation::Only,
            }
        }
    }

    impl From<crate::subscription::ClientFilterOperation> for PrincsFilterOperation {
        fn from(value: crate::subscription::ClientFilterOperation) -> Self {
            match value {
                crate::subscription::ClientFilterOperation::Except => PrincsFilterOperation::Except,
                crate::subscription::ClientFilterOperation::Only => PrincsFilterOperation::Only,
            }
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) struct PrincsFilter {
        pub operation: Option<PrincsFilterOperation>,
        pub princs: HashSet<String>,
    }

    impl PrincsFilter {
        fn to_client_filter(self) -> Option<crate::subscription::ClientFilter> {
            let Some(op) = self.operation else {
                return None;
            };

            Some(crate::subscription::ClientFilter::new(op.into(), self.princs))
        }
    }

    impl From<Option<crate::subscription::ClientFilter>> for PrincsFilter {
        fn from(value: Option<crate::subscription::ClientFilter>) -> Self {
            Self {
                operation: value.as_ref().and_then(|f| Some(f.operation().clone().into())),
                princs: value.map_or(HashSet::new(), |f| f.targets().clone()),
            }
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
    pub(super) enum ContentFormat {
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

    impl From<crate::subscription::ContentFormat> for ContentFormat {
        fn from(value: crate::subscription::ContentFormat) -> Self {
            match value {
                crate::subscription::ContentFormat::Raw => ContentFormat::Raw,
                crate::subscription::ContentFormat::RenderedText => ContentFormat::RenderedText,
            }
        }
    }

    #[derive(Debug, PartialEq, Clone, Eq, Deserialize, Serialize)]
    pub(super) struct SubscriptionData {
        pub uuid: Uuid,
        pub revision: Option<String>,
        pub name: String,
        pub uri: Option<String>,
        pub query: String,
        pub heartbeat_interval: u32,
        pub connection_retry_count: u16,
        pub connection_retry_interval: u32,
        pub max_time: u32,
        pub max_elements: Option<u32>,
        pub max_envelope_size: u32,
        pub enabled: bool,
        pub read_existing_events: bool,
        pub content_format: ContentFormat,
        pub ignore_channel_error: bool,
        pub locale: Option<String>,
        pub data_locale: Option<String>,
        pub filter: PrincsFilter,
        pub outputs: Vec<SubscriptionOutput>,
    }

    impl From<SubscriptionData> for crate::subscription::SubscriptionData {
        fn from(value: SubscriptionData) -> Self {
            let mut data = crate::subscription::SubscriptionData::new(&value.name, &value.query);
            data.set_uuid(crate::subscription::SubscriptionUuid(value.uuid))
                .set_uri(value.uri)
                .set_heartbeat_interval(value.heartbeat_interval)
                .set_connection_retry_count(value.connection_retry_count)
                .set_connection_retry_interval(value.connection_retry_interval)
                .set_max_time(value.max_time)
                .set_max_elements(value.max_elements)
                .set_max_envelope_size(value.max_envelope_size)
                .set_enabled(value.enabled)
                .set_read_existing_events(value.read_existing_events)
                .set_content_format(value.content_format.into())
                .set_ignore_channel_error(value.ignore_channel_error)
                .set_client_filter(value.filter.to_client_filter())
                .set_locale(value.locale)
                .set_data_locale(value.data_locale)
                .set_outputs(value.outputs.iter().map(|s| s.clone().into()).collect())
                .set_revision(value.revision);
            // Note: internal version is not exported nor set
            data
        }
    }

    impl From<crate::subscription::SubscriptionData> for SubscriptionData {
        fn from(value: crate::subscription::SubscriptionData) -> Self {
            // Note: internal version is not exported nor set
            Self {
                uuid: value.uuid().0,
                name: value.name().to_string(),
                uri: value.uri().cloned(),
                revision: value.revision().cloned(),
                query: value.query().to_string(),
                heartbeat_interval: value.heartbeat_interval(),
                connection_retry_count: value.connection_retry_count(),
                connection_retry_interval: value.connection_retry_interval(),
                max_time: value.max_time(),
                max_elements: value.max_elements(),
                max_envelope_size: value.max_envelope_size(),
                enabled: value.enabled(),
                read_existing_events: value.read_existing_events(),
                content_format: value.content_format().to_owned().into(),
                ignore_channel_error: value.ignore_channel_error(),
                locale: value.locale().cloned(),
                data_locale: value.data_locale().cloned(),
                filter: value.client_filter().cloned().into(),
                outputs: value.outputs().iter().map(|o| o.clone().into()).collect(),
            }
        }
    }

    #[derive(Debug, PartialEq, Clone, Eq, Deserialize, Serialize)]
    pub(super) struct Subscriptions {
        pub subscriptions: Vec<SubscriptionData>,
    }

    impl From<Subscriptions> for Vec<crate::subscription::SubscriptionData> {
        fn from(value: Subscriptions) -> Self {
            value
                .subscriptions
                .iter()
                .map(|s| s.clone().into())
                .collect()
        }
    }

    impl From<&[crate::subscription::SubscriptionData]> for Subscriptions {
        fn from(value: &[crate::subscription::SubscriptionData]) -> Self {
            Self {
                subscriptions: value.iter().map(|s| s.clone().into()).collect(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::collections::HashSet;

    use super::{parse, serialize};

    #[test]
    fn test_export_import() -> Result<()> {
        let mut subscription =
            crate::subscription::SubscriptionData::new("my-subscription", "my-query");
        let mut targets = HashSet::new();
        targets.insert("courgette@WINDOMAIN.LOCAL".to_string());
        targets.insert("boulette@WINDOMAIN.LOCAL".to_string());

        subscription
            .set_content_format(crate::subscription::ContentFormat::RenderedText)
            .set_connection_retry_count(10)
            .set_max_time(5)
            .set_connection_retry_interval(1)
            .set_heartbeat_interval(1000)
            .set_ignore_channel_error(false)
            .set_max_envelope_size(10000)
            .set_max_time(1)
            .set_max_elements(Some(100))
            .set_read_existing_events(false)
            .set_uri(Some("toto".to_string()))
            .set_client_filter(Some(crate::subscription::ClientFilter::new(
                crate::subscription::ClientFilterOperation::Except,
                targets,
            )))
            .set_outputs(vec![crate::subscription::SubscriptionOutput::new(
                crate::subscription::SubscriptionOutputFormat::Json,
                crate::subscription::SubscriptionOutputDriver::Tcp(
                    crate::subscription::TcpConfiguration::new("127.0.0.1".to_string(), 5000),
                ),
                true,
            )])
            .set_revision(Some("1234".to_string()));

        let subscriptions = vec![subscription.clone()];
        let content = serialize(&subscriptions)?;

        let mut imported_subscriptions = parse(&content)?;
        assert_eq!(imported_subscriptions.len(), 1);

        let mut imported_subscription = imported_subscriptions.pop().unwrap();

        // Internal version is generated randomly during import, so we need to set it
        // to be able to compare
        imported_subscription.set_internal_version(subscription.internal_version());

        assert_eq!(subscription, imported_subscription);

        Ok(())
    }
}
