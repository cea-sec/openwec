use std::{path::PathBuf, str::FromStr};

use anyhow::Result;

pub fn transform_files_config_to_path(
    base: &Option<String>,
    split_on_addr_index: &Option<u8>,
    append_node_name: &Option<bool>,
    filename: &Option<String>,
) -> Result<String> {
    let mut path: PathBuf = match base {
        Some(base) => PathBuf::from_str(base)?,
        None => PathBuf::new(),
    };

    if let Some(index) = split_on_addr_index {
        for i in *index..4 {
            path.push(format!("{{ip:{}}}", i))
        }
        path.push("{ip}")
    } else {
        path.push("{ip}")
    }

    path.push("{client}");

    let append_node_name = append_node_name.unwrap_or(false);
    if append_node_name {
        path.push("{node}");
    }

    let name = match filename {
        Some(filename) => filename.to_owned(),
        None => "messages".to_string(),
    };
    path.push(name);

    Ok(path.to_string_lossy().to_string())
}

pub mod old {
    use std::collections::HashMap;

    use log::warn;
    use serde::{Deserialize, Serialize};
    use strum::{AsRefStr, EnumString, VariantNames};

    use super::new;

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct KafkaConfiguration {
        pub topic: String,
        // If not empty, a standalone Kafka producer will be used for the output
        pub options: HashMap<String, String>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct RedisConfiguration {
        pub addr: String,
        pub list: String,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct TcpConfiguration {
        pub addr: String,
        pub port: u16,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct FilesConfiguration {
        pub path: Option<String>,
        pub base: Option<String>,
        // None => don't split
        // Some(n) => Split starting on the n-th segment (IPv4 and IPv6)
        pub split_on_addr_index: Option<u8>,
        // requires server.node_name to be configured
        pub append_node_name: Option<bool>,
        pub filename: Option<String>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct UnixDatagramConfiguration {
        pub path: String,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, AsRefStr)]
    #[strum(serialize_all = "lowercase")]
    pub enum SubscriptionOutputDriver {
        Files(FilesConfiguration),
        Kafka(KafkaConfiguration),
        Tcp(TcpConfiguration),
        Redis(RedisConfiguration),
        UnixDatagram(UnixDatagramConfiguration),
    }

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        Serialize,
        Deserialize,
        Hash,
        VariantNames,
        AsRefStr,
        EnumString,
    )]
    #[strum(serialize_all = "snake_case", ascii_case_insensitive)]
    pub enum SubscriptionOutputFormat {
        Json,
        Raw,
        RawJson,
        Nxlog,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct SubscriptionOutput {
        pub format: SubscriptionOutputFormat,
        pub driver: SubscriptionOutputDriver,
        pub enabled: bool,
    }

    impl From<new::SubscriptionOutput> for SubscriptionOutput {
        fn from(new: new::SubscriptionOutput) -> Self {
            let (driver, enabled) = match &new.driver {
                new::SubscriptionOutputDriver::Files(config) => {
                    warn!("Output Files {:?} has been disabled and its properties have been lost during downgrade.", config);
                    (
                        SubscriptionOutputDriver::Files(FilesConfiguration {
                            base: Some("/".to_string()),
                            split_on_addr_index: None,
                            append_node_name: Some(false),
                            filename: Some("messages".to_string()),
                            path: None,
                        }),
                        false,
                    )
                }
                new::SubscriptionOutputDriver::Kafka(config) => {
                    (SubscriptionOutputDriver::Kafka(config.clone()), true)
                }
                new::SubscriptionOutputDriver::Redis(config) => {
                    (SubscriptionOutputDriver::Redis(config.clone()), true)
                }
                new::SubscriptionOutputDriver::Tcp(config) => {
                    (SubscriptionOutputDriver::Tcp(config.clone()), true)
                }
                new::SubscriptionOutputDriver::UnixDatagram(config) => {
                    (SubscriptionOutputDriver::UnixDatagram(config.clone()), true)
                }
            };
            SubscriptionOutput {
                format: new.format.clone(),
                enabled,
                driver,
            }
        }
    }
}

pub mod new {

    use log::info;
    use serde::{Deserialize, Serialize};
    use strum::AsRefStr;

    use super::{old, transform_files_config_to_path};

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct FilesConfiguration {
        pub path: String,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, AsRefStr)]
    #[strum(serialize_all = "lowercase")]
    pub enum SubscriptionOutputDriver {
        Files(FilesConfiguration),
        Kafka(super::old::KafkaConfiguration),
        Tcp(super::old::TcpConfiguration),
        Redis(super::old::RedisConfiguration),
        UnixDatagram(super::old::UnixDatagramConfiguration),
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct SubscriptionOutput {
        pub format: super::old::SubscriptionOutputFormat,
        pub driver: SubscriptionOutputDriver,
        pub enabled: bool,
    }

    impl From<old::SubscriptionOutput> for SubscriptionOutput {
        fn from(old: old::SubscriptionOutput) -> Self {
            SubscriptionOutput {
                format: old.format.clone(),
                enabled: old.enabled,
                driver: match &old.driver {
                    old::SubscriptionOutputDriver::Files(config) => {
                        if let Some(path) = &config.path {
                            info!(
                                "Output Files {:?} already has a path configured: {}",
                                config, path
                            );
                            SubscriptionOutputDriver::Files(FilesConfiguration {
                                path: path.clone(),
                            })
                        } else {
                            let path = transform_files_config_to_path(
                                &config.base.clone(),
                                &config.split_on_addr_index,
                                &config.append_node_name,
                                &config.filename.clone(),
                            )
                            .expect("Failed to convert old Files path to new format");
                            info!(
                                "Output Files {:?} has been converted to new path format: {}",
                                config, path
                            );
                            SubscriptionOutputDriver::Files(FilesConfiguration { path })
                        }
                    }
                    old::SubscriptionOutputDriver::Kafka(config) => {
                        SubscriptionOutputDriver::Kafka(config.clone())
                    }
                    old::SubscriptionOutputDriver::Redis(config) => {
                        SubscriptionOutputDriver::Redis(config.clone())
                    }
                    old::SubscriptionOutputDriver::Tcp(config) => {
                        SubscriptionOutputDriver::Tcp(config.clone())
                    }
                    old::SubscriptionOutputDriver::UnixDatagram(config) => {
                        SubscriptionOutputDriver::UnixDatagram(config.clone())
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_files_config_to_path() -> Result<()> {
        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &None,
                &None,
                &None
            )?,
            "/base/openwec/{ip}/{client}/messages".to_string()
        );

        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &Some(1),
                &None,
                &None
            )?,
            "/base/openwec/{ip:1}/{ip:2}/{ip:3}/{ip}/{client}/messages".to_string()
        );

        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &Some(2),
                &None,
                &None
            )?,
            "/base/openwec/{ip:2}/{ip:3}/{ip}/{client}/messages".to_string()
        );

        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &Some(3),
                &None,
                &None
            )?,
            "/base/openwec/{ip:3}/{ip}/{client}/messages".to_string()
        );

        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &Some(4),
                &None,
                &None
            )?,
            "/base/openwec/{ip}/{client}/messages".to_string()
        );

        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &None,
                &Some(false),
                &None
            )?,
            "/base/openwec/{ip}/{client}/messages".to_string()
        );

        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &None,
                &Some(true),
                &None
            )?,
            "/base/openwec/{ip}/{client}/{node}/messages".to_string()
        );

        assert_eq!(
            transform_files_config_to_path(
                &Some("/base/openwec".to_string()),
                &None,
                &Some(true),
                &Some("test".to_string())
            )?,
            "/base/openwec/{ip}/{client}/{node}/test".to_string()
        );

        Ok(())
    }
}
