use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
};

use crate::utils::new_uuid;
use anyhow::{anyhow, bail, Error, Result};
use log::info;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct KafkaConfiguration {
    topic: String,
    options: HashMap<String, String>,
}

impl KafkaConfiguration {
    pub fn new(topic: String, options: HashMap<String, String>) -> Self {
        KafkaConfiguration { topic, options }
    }

    /// Get a reference to the kafka configuration's topic.
    pub fn topic(&self) -> &str {
        self.topic.as_ref()
    }

    /// Get a reference to the kafka configuration's options.
    pub fn options(&self) -> &HashMap<String, String> {
        &self.options
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TcpConfiguration {
    addr: String,
    port: u16,
}

impl TcpConfiguration {
    pub fn new(addr: String, port: u16) -> Self {
        TcpConfiguration { addr, port }
    }

    pub fn addr(&self) -> &str {
        self.addr.as_ref()
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

// File storage path format is:
// <base>/<ip>/<princ>/[<node_name>/]/<filename>
// <ip> can be splitted (depends of split_on_addr_index)
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FileConfiguration {
    base: String,
    // None => don't split
    // Some(n) => Split starting on the n-th segment (IPv4 and IPv6)
    split_on_addr_index: Option<u8>,
    // requires server.node_name to be configured
    append_node_name: bool,
    filename: String,
}

impl FileConfiguration {
    pub fn new(
        base: String,
        split_on_addr_index: Option<u8>,
        append_node_name: bool,
        filename: String,
    ) -> Self {
        Self {
            base,
            split_on_addr_index,
            append_node_name,
            filename,
        }
    }

    pub fn base(&self) -> &str {
        self.base.as_ref()
    }

    pub fn split_on_addr_index(&self) -> Option<u8> {
        self.split_on_addr_index
    }

    pub fn append_node_name(&self) -> bool {
        self.append_node_name
    }

    pub fn filename(&self) -> &str {
        self.filename.as_ref()
    }
}

#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub enum SubscriptionOutput {
    // The last bool indicates whether the output is enabled or not.
    Files(SubscriptionOutputFormat, FileConfiguration, bool),
    Kafka(SubscriptionOutputFormat, KafkaConfiguration, bool),
    Tcp(SubscriptionOutputFormat, TcpConfiguration, bool),
}

impl SubscriptionOutput {
    pub fn format(&self) -> &SubscriptionOutputFormat {
        match self {
            SubscriptionOutput::Files(format, _, _) => format,
            SubscriptionOutput::Kafka(format, _, _) => format,
            SubscriptionOutput::Tcp(format, _, _) => format,
        }
    }

    pub fn is_enabled(&self) -> bool {
        match self {
            SubscriptionOutput::Files(_, _, enabled) => *enabled,
            SubscriptionOutput::Kafka(_, _, enabled) => *enabled,
            SubscriptionOutput::Tcp(_, _, enabled) => *enabled,
        }
    }

    pub fn set_enabled(&self, value: bool) -> SubscriptionOutput {
        match self {
            SubscriptionOutput::Files(format, config, _) => {
                SubscriptionOutput::Files(format.clone(), config.clone(), value)
            }
            SubscriptionOutput::Kafka(format, config, _) => {
                SubscriptionOutput::Kafka(format.clone(), config.clone(), value)
            }
            SubscriptionOutput::Tcp(format, config, _) => {
                SubscriptionOutput::Tcp(format.clone(), config.clone(), value)
            }
        }
    }
}

impl Display for SubscriptionOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionOutput::Files(format, config, enabled) => {
                write!(
                    f,
                    "Enabled: {:?}, Format: {}, Output: Files({:?})",
                    enabled, format, config
                )
            }
            SubscriptionOutput::Kafka(format, config, enabled) => {
                write!(
                    f,
                    "Enabled: {:?}, Format: {}, Output: Kafka({:?})",
                    enabled, format, config
                )
            }
            SubscriptionOutput::Tcp(format, config, enabled) => {
                write!(
                    f,
                    "Enabled: {:?}, Format: {}, Output: Tcp({}:{})",
                    enabled, format, config.addr, config.port
                )
            }
        }
    }
}

#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub enum SubscriptionOutputFormat {
    Json,
    Raw,
}

impl Display for SubscriptionOutputFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            SubscriptionOutputFormat::Json => write!(f, "Json"),
            SubscriptionOutputFormat::Raw => write!(f, "Raw"),
        }
    }
}

impl TryFrom<u8> for SubscriptionOutputFormat {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => SubscriptionOutputFormat::Json,
            1 => SubscriptionOutputFormat::Raw,
            _ => bail!("Unknown subscription output format {}", value),
        })
    }
}

#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub enum ContentFormat {
    Raw,
    RenderedText,
}

impl ContentFormat {
    pub fn to_string(&self) -> String {
        match self {
            ContentFormat::Raw => "Raw".to_owned(),
            ContentFormat::RenderedText => "RenderedText".to_owned(),
        }
    }

    pub fn from_str(text: &str) -> Result<Self> {
        if text == "Raw" {
            Ok(ContentFormat::Raw)
        } else if text == "RenderedText" {
            Ok(ContentFormat::RenderedText)
        } else {
            bail!("Invalid ContentFormat string")
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct SubscriptionData {
    #[serde(default = "new_uuid")]
    uuid: String,
    #[serde(default = "new_uuid")]
    version: String,
    name: String,
    uri: Option<String>,
    query: String,
    heartbeat_interval: u32,
    connection_retry_count: u16,
    connection_retry_interval: u32,
    max_time: u32,
    max_envelope_size: u32,
    enabled: bool,
    read_existing_events: bool,
    content_format: ContentFormat,
    ignore_channel_error: bool,
    #[serde(default)]
    outputs: Vec<SubscriptionOutput>,
}

impl Display for SubscriptionData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Subscription {}", self.name)?;
        writeln!(f, "\tUUID: {}", self.uuid())?;
        writeln!(f, "\tVersion: {}", self.version())?;
        writeln!(
            f,
            "\tURI: {}",
            match self.uri() {
                Some(uri) => uri,
                None => "None",
            }
        )?;
        writeln!(f, "\tHeartbeat interval: {}s", self.heartbeat_interval())?;
        writeln!(
            f,
            "\tConnection retry count: {}",
            self.connection_retry_count()
        )?;
        writeln!(
            f,
            "\tConnection retry interval: {}s",
            self.connection_retry_interval()
        )?;
        writeln!(
            f,
            "\tMax time without heartbeat/events: {}s",
            self.max_time()
        )?;
        writeln!(f, "\tMax envelope size: {} bytes", self.max_envelope_size())?;
        writeln!(f, "\tReadExistingEvents: {}", self.read_existing_events)?;
        writeln!(f, "\tContent format: {}", self.content_format().to_string())?;
        writeln!(f, "\tIgnore channel error: {}", self.ignore_channel_error())?;
        if self.outputs().is_empty() {
            writeln!(f, "\tOutputs: None")?;
        } else {
            writeln!(f, "\tOutputs:")?;
            for (index, output) in self.outputs().iter().enumerate() {
                writeln!(f, "\t- {}: {}", index, output)?;
            }
        }
        writeln!(f, "\tEnabled: {}", self.enabled)
    }
}

impl SubscriptionData {
    pub fn empty() -> Self {
        SubscriptionData {
            uuid: Uuid::new_v4().to_string().to_ascii_uppercase(),
            version: Uuid::new_v4().to_string().to_ascii_uppercase(),
            name: String::new(),
            uri: None,
            query: String::new(),
            heartbeat_interval: 3_600,
            connection_retry_count: 5,
            connection_retry_interval: 60,
            max_time: 30,
            max_envelope_size: 512_000,
            enabled: true,
            read_existing_events: false,
            content_format: ContentFormat::Raw,
            ignore_channel_error: true,
            outputs: Vec::new(),
        }
    }

    pub fn new(
        name: &str,
        uri: Option<&str>,
        query: &str,
        heartbeat_interval: Option<&u32>,
        connection_retry_count: Option<&u16>,
        connection_retry_interval: Option<&u32>,
        max_time: Option<&u32>,
        max_envelope_size: Option<&u32>,
        enabled: bool,
        read_existing_events: bool,
        content_format: ContentFormat,
        ignore_channel_error: bool,
        outputs: Option<Vec<SubscriptionOutput>>,
    ) -> Self {
        SubscriptionData {
            uuid: Uuid::new_v4().to_string().to_ascii_uppercase(),
            version: Uuid::new_v4().to_string().to_ascii_uppercase(),
            name: name.to_owned(),
            uri: uri.map(|e| e.to_string()),
            query: query.to_owned(),
            heartbeat_interval: *heartbeat_interval.unwrap_or(&3_600),
            connection_retry_count: *connection_retry_count.unwrap_or(&5),
            connection_retry_interval: *connection_retry_interval.unwrap_or(&60),
            max_time: *max_time.unwrap_or(&30),
            max_envelope_size: *max_envelope_size.unwrap_or(&512_000),
            enabled,
            read_existing_events,
            content_format,
            ignore_channel_error,
            outputs: outputs.unwrap_or_default(),
        }
    }

    pub fn from(
        uuid: String,
        version: String,
        name: String,
        uri: Option<String>,
        query: String,
        heartbeat_interval: u32,
        connection_retry_count: u16,
        connection_retry_interval: u32,
        max_time: u32,
        max_envelope_size: u32,
        enabled: bool,
        read_existing_events: bool,
        content_format: ContentFormat,
        ignore_channel_error: bool,
        outputs: Vec<SubscriptionOutput>,
    ) -> Self {
        SubscriptionData {
            uuid,
            version,
            name,
            uri,
            query,
            heartbeat_interval,
            connection_retry_count,
            connection_retry_interval,
            max_time,
            max_envelope_size,
            enabled,
            read_existing_events,
            content_format,
            ignore_channel_error,
            outputs,
        }
    }

    pub fn short(&self) -> String {
        let mut res = String::new();
        if self.enabled {
            res.push_str("[+] ");
        } else {
            res.push_str("[-] ");
        }

        res.push_str(format!("{} ", self.name).as_str());
        if let Some(uri) = &self.uri {
            res.push_str(format!("({})", uri).as_str());
        } else {
            res.push_str("(*)");
        }

        res
    }

    pub fn update_version(&mut self) {
        self.version = Uuid::new_v4().to_string().to_ascii_uppercase();
    }

    pub fn update_uuid(&mut self) {
        // This should only be used when duplicating an existing subscription
        self.uuid = Uuid::new_v4().to_string().to_ascii_uppercase();
    }

    /// Get a reference to the subscription's uuid.
    pub fn uuid(&self) -> &str {
        self.uuid.as_ref()
    }

    /// Get a reference to the subscription's version.
    pub fn version(&self) -> &str {
        self.version.as_ref()
    }

    /// Get a reference to the subscription's name.
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Get a reference to the subscription's heartbeat interval.
    pub fn heartbeat_interval(&self) -> u32 {
        self.heartbeat_interval
    }

    /// Get a reference to the subscription's connection retry count.
    pub fn connection_retry_count(&self) -> u16 {
        self.connection_retry_count
    }

    /// Get a reference to the subscription's connection retry interval.
    pub fn connection_retry_interval(&self) -> u32 {
        self.connection_retry_interval
    }

    /// Get a reference to the subscription's max time.
    pub fn max_time(&self) -> u32 {
        self.max_time
    }

    /// Get a reference to the subscription's max envelope size.
    pub fn max_envelope_size(&self) -> u32 {
        self.max_envelope_size
    }

    /// Get a reference to the subscription's query.
    pub fn query(&self) -> &str {
        self.query.as_ref()
    }

    /// Set the subscription's name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
        self.update_version();
    }

    /// Set the subscription's query.
    pub fn set_query(&mut self, query: String) {
        self.query = query;
        self.update_version();
    }

    /// Set the subscription's heartbeat interval.
    pub fn set_heartbeat_interval(&mut self, heartbeat_interval: u32) {
        self.heartbeat_interval = heartbeat_interval;
        self.update_version();
    }

    /// Set the subscription's connection retry count.
    pub fn set_connection_retry_count(&mut self, connection_retry_count: u16) {
        self.connection_retry_count = connection_retry_count;
        self.update_version();
    }

    /// Set the subscription's connection retry interval.
    pub fn set_connection_retry_interval(&mut self, connection_retry_interval: u32) {
        self.connection_retry_interval = connection_retry_interval;
        self.update_version();
    }

    /// Set the subscription's max time.
    pub fn set_max_time(&mut self, max_time: u32) {
        self.max_time = max_time;
        self.update_version();
    }

    /// Set the subscription's max envelope size.
    pub fn set_max_envelope_size(&mut self, max_envelope_size: u32) {
        self.max_envelope_size = max_envelope_size;
        self.update_version();
    }

    /// Get a reference to the subscription's outputs.
    pub fn outputs(&self) -> &[SubscriptionOutput] {
        self.outputs.as_ref()
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.update_version();
    }

    pub fn read_existing_events(&self) -> bool {
        self.read_existing_events
    }

    pub fn set_read_existing_events(&mut self, read_existing_events: bool) {
        self.read_existing_events = read_existing_events;
        self.update_version();
    }

    pub fn content_format(&self) -> &ContentFormat {
        &self.content_format
    }

    pub fn set_content_format(&mut self, content_format: ContentFormat) {
        self.content_format = content_format;
        self.update_version();
    }

    pub fn ignore_channel_error(&self) -> bool {
        self.ignore_channel_error
    }

    pub fn set_ignore_channel_error(&mut self, ignore_channel_error: bool) {
        self.ignore_channel_error = ignore_channel_error;
        self.update_version();
    }

    pub fn add_output(&mut self, output: SubscriptionOutput) {
        self.outputs.push(output);
        self.update_version();
    }

    pub fn delete_output(&mut self, index: usize) -> Result<()> {
        if index >= self.outputs.len() {
            bail!("Index out of range");
        }
        let output = self.outputs.remove(index);
        info!("Deleting output {:?}", output);
        self.update_version();
        Ok(())
    }

    pub fn set_output_enabled(&mut self, index: usize, value: bool) -> Result<()> {
        if index >= self.outputs.len() {
            bail!("Index out of range");
        }
        let output = self
            .outputs
            .get(index)
            .ok_or_else(|| anyhow!("Index out of range"))?;
        if value {
            info!("Enabling output {:?}", output);
        } else {
            info!("Disabling output {:?}", output);
        }
        self.outputs[index] = output.set_enabled(value);
        self.update_version();
        Ok(())
    }

    pub fn uri(&self) -> Option<&String> {
        self.uri.as_ref()
    }

    pub fn set_uri(&mut self, uri: Option<String>) {
        self.uri = uri;
        self.update_version();
    }

    pub fn is_active(&self) -> bool {
        self.enabled()
            && self
                .outputs()
                .iter()
                .find(|output| output.is_enabled())
                .is_some()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SubscriptionStatsCounters {
    /// Total number of machines seen in the subscription
    total_machines_count: i64,
    /// Number of machines that have sent an heartbeat "recently" but no events
    alive_machines_count: i64,
    /// Number of machines that have sent events "recently"
    active_machines_count: i64,
    /// Number of machines that did not interact "recently"
    dead_machines_count: i64,
}

impl SubscriptionStatsCounters {
    pub fn new(
        total_machines_count: i64,
        alive_machines_count: i64,
        active_machines_count: i64,
        dead_machines_count: i64,
    ) -> Self {
        Self {
            total_machines_count,
            alive_machines_count,
            active_machines_count,
            dead_machines_count,
        }
    }

    pub fn total_machines_count(&self) -> i64 {
        self.total_machines_count
    }

    pub fn active_machines_count(&self) -> i64 {
        self.active_machines_count
    }

    pub fn alive_machines_count(&self) -> i64 {
        self.alive_machines_count
    }

    pub fn dead_machines_count(&self) -> i64 {
        self.dead_machines_count
    }
}

pub enum SubscriptionMachineState {
    Alive,
    Active,
    Dead,
}

#[derive(Debug)]
pub struct SubscriptionMachine {
    name: String,
    ip: String,
}

impl SubscriptionMachine {
    /// Creates a new [`SubscriptionStat`].
    pub fn new(name: String, ip: String) -> Self {
        Self { name, ip }
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn ip(&self) -> &str {
        self.ip.as_ref()
    }
}
