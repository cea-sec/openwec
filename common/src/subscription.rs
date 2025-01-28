use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    str::FromStr,
};

use anyhow::{anyhow, bail, Result, Error};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use strum::{Display, AsRefStr, EnumString, VariantNames};
use uuid::Uuid;
use bitflags::bitflags;
use glob::Pattern;

use crate::utils::VersionHasher;

pub const DEFAULT_HEARTBEAT_INTERVAL: u32 = 3_600;
pub const DEFAULT_CONNECTION_RETRY_COUNT: u16 = 5;
pub const DEFAULT_CONNECTION_RETRY_INTERVAL: u32 = 60;
pub const DEFAULT_MAX_TIME: u32 = 30;
pub const DEFAULT_MAX_ENVELOPE_SIZE: u32 = 512_000;
pub const DEFAULT_READ_EXISTING_EVENTS: bool = false;
pub const DEFAULT_CONTENT_FORMAT: ContentFormat = ContentFormat::Raw;
pub const DEFAULT_IGNORE_CHANNEL_ERROR: bool = true;
pub const DEFAULT_ENABLED: bool = true;

pub const DEFAULT_OUTPUT_ENABLED: bool = true;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KafkaConfiguration {
    topic: String,
    // If not empty, a standalone Kafka producer will be used for the output
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedisConfiguration {
    addr: String,
    list: String,
}

impl RedisConfiguration {
    pub fn new(addr: String, list: String) -> Self {
        RedisConfiguration { addr, list }
    }

    /// Get a reference to the redis configuration's list.
    pub fn list(&self) -> &str {
        self.list.as_ref()
    }

    /// Get a reference to the redis configuration's server address.
    pub fn addr(&self) -> &str {
        self.addr.as_ref()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesConfiguration {
    path: String,
}

impl FilesConfiguration {
    pub fn new(
        path: String,
    ) -> Self {
        Self {
            path
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnixDatagramConfiguration {
    path: String,
}

impl UnixDatagramConfiguration {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &str {
        self.path.as_ref()
    }
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionOutput {
    format: SubscriptionOutputFormat,
    driver: SubscriptionOutputDriver,
    enabled: bool,
}

impl SubscriptionOutput {
    pub fn new(
        format: SubscriptionOutputFormat,
        driver: SubscriptionOutputDriver,
        enabled: bool,
    ) -> Self {
        Self {
            format,
            driver,
            enabled,
        }
    }
    pub fn format(&self) -> &SubscriptionOutputFormat {
        &self.format
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, value: bool) {
        self.enabled = value;
    }

    pub fn driver(&self) -> &SubscriptionOutputDriver {
        &self.driver
    }
}

impl Display for SubscriptionOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Enabled: {:?}, Format: {}, Driver: {:?}",
            self.enabled,
            self.format.as_ref(),
            self.driver
        )
    }
}
#[derive(
    Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash, VariantNames, AsRefStr, EnumString,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
pub enum SubscriptionOutputFormat {
    Json,
    Raw,
    RawJson,
    Nxlog,
}

impl SubscriptionOutputFormat {
    /// Whether the output format needs to be given a parsed version
    /// of the event.
    pub fn needs_parsed_event(&self) -> bool {
        match self {
            SubscriptionOutputFormat::Raw => false,
            SubscriptionOutputFormat::RawJson => false,
            SubscriptionOutputFormat::Json => true,
            SubscriptionOutputFormat::Nxlog => true,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ClientFilterOperation {
    Only,
    Except,
}

impl Display for ClientFilterOperation {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ClientFilterOperation::Only => write!(f, "Only"),
            ClientFilterOperation::Except => write!(f, "Except"),
        }
    }
}

impl FromStr for ClientFilterOperation {
    type Err = Error;

    fn from_str(op: &str) -> std::result::Result<Self, Self::Err> {
        if op.eq_ignore_ascii_case("only") {
            return Ok(ClientFilterOperation::Only);
        }

        if op.eq_ignore_ascii_case("except") {
            return Ok(ClientFilterOperation::Except);
        }

        bail!("Could not parse client filter operation")
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Display, AsRefStr, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum ClientFilterType {
    #[default]
    KerberosPrinc,
    TLSCertSubject,
    MachineID,
}

bitflags! {
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ClientFilterFlags: u32 {
        const CaseSensitive = 1 << 0;
        const GlobPattern = 1 << 1;
    }
}

impl Display for ClientFilterFlags {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer_strict(self, f)
    }
}

impl Default for ClientFilterFlags {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ClientFilterTargets {
    Exact(HashSet<String>),
    Glob(Vec<Pattern>)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientFilter {
    operation: ClientFilterOperation,
    kind: ClientFilterType,
    flags: ClientFilterFlags,
    targets: ClientFilterTargets,
}

impl ClientFilter {
    pub fn new_legacy(operation: ClientFilterOperation, targets: HashSet<String>) -> Self {
        Self {
            operation,
            kind: ClientFilterType::KerberosPrinc,
            flags: ClientFilterFlags::CaseSensitive,
            targets: ClientFilterTargets::Exact(targets),
        }
    }

    pub fn try_new(operation: ClientFilterOperation, kind: ClientFilterType, flags: ClientFilterFlags, mut targets: HashSet<String>) -> Result<Self> {
        let targets = if flags.contains(ClientFilterFlags::GlobPattern) {
            ClientFilterTargets::Glob(targets.iter().map(|t| Pattern::new(t.as_str())).collect::<Result<Vec<Pattern>, _>>()?)
        } else {
            if !flags.contains(ClientFilterFlags::CaseSensitive) {
                targets = targets.iter().map(|t| t.to_lowercase()).collect();
            }
            ClientFilterTargets::Exact(targets)
        };

        Ok(Self { operation, kind, flags, targets })
    }

    pub fn from(operation: String, kind: String, flags: Option<String>, targets: Option<String>) -> Result<Self> {
        let flags: ClientFilterFlags = bitflags::parser::from_str_strict(flags.unwrap_or_default().as_str()).map_err(|e| anyhow!("{:?}", e))?;

        let mut t = if flags.contains(ClientFilterFlags::GlobPattern) {
            ClientFilterTargets::Glob(Vec::new())
        } else {
            ClientFilterTargets::Exact(HashSet::new())
        };

        if let Some(targets) = targets {
            let targets = targets.split(',');

            t = if flags.contains(ClientFilterFlags::GlobPattern) {
                ClientFilterTargets::Glob(targets.map(Pattern::new).collect::<Result<Vec<Pattern>, _>>()?)
            } else {
                let targets = if !flags.contains(ClientFilterFlags::CaseSensitive) {
                    HashSet::from_iter(targets.map(|t| t.to_lowercase()))
                } else {
                    HashSet::from_iter(targets.map(|s| s.to_string()))
                };

                ClientFilterTargets::Exact(targets)
            };
        }

        Ok(ClientFilter {
            operation: operation.parse()?, kind: kind.parse()?, flags, targets: t
        })
    }

    fn matches(&self, target: &str) -> bool {
        match &self.targets {
            ClientFilterTargets::Exact(targets) => {
                if !self.flags.contains(ClientFilterFlags::CaseSensitive) {
                    return targets.contains(&target.to_lowercase());
                }

                targets.contains(target)
            },
            ClientFilterTargets::Glob(targets) => {
                let mut match_opts = glob::MatchOptions::new();
                match_opts.case_sensitive = self.flags.contains(ClientFilterFlags::CaseSensitive);

                for p in targets {
                    if p.matches_with(target, match_opts) {
                        return true;
                    }
                }

                false
            }
        }
    }

    pub fn eval(&self, client: &str, machine_id: Option<&str>) -> bool {
        let target = match self.kind {
            ClientFilterType::MachineID => {
                let Some(machine_id) = machine_id else {
                    return false;
                };

                machine_id
            }
            _ => client,
        };

        match self.operation {
            ClientFilterOperation::Only => self.matches(target),
            ClientFilterOperation::Except => !self.matches(target),
        }
    }

    pub fn targets(&self) -> HashSet<&str> {
        match &self.targets {
            ClientFilterTargets::Exact(targets) => targets.iter().map(|t| t.as_str()).collect(),
            ClientFilterTargets::Glob(targets) => targets.iter().map(|t| t.as_str()).collect(),
        }
    }

    pub fn targets_to_string(&self) -> String {
        self.targets()
            .iter()
            .cloned()
            .map(String::from)
            .collect::<Vec<String>>()
            .join(",")
    }

    pub fn targets_to_opt_string(&self) -> Option<String> {
        match &self.targets {
            ClientFilterTargets::Exact(targets) => {
                if targets.is_empty() {
                    return None;
                }
            },
            ClientFilterTargets::Glob(targets) => {
                if targets.is_empty() {
                    return None;
                }
            }
        }

        Some(self.targets_to_string())
    }

    #[deprecated(since = "0.4.0", note = "This should be used only by the legacy CLI interface. Use ClientFilter constructors instead")]
    pub fn add_target(&mut self, target: &str) -> Result<()> {
        match &mut self.targets {
            ClientFilterTargets::Exact(targets) => { targets.insert(target.to_owned()); },
            ClientFilterTargets::Glob(targets) => { targets.push(Pattern::new(target)?); },
        }
        Ok(())
    }

    #[deprecated(since = "0.4.0", note = "This should be used only by the legacy CLI interface. Use ClientFilter constructors instead")]
    pub fn delete_target(&mut self, target: &str) -> Result<()> {
        match &mut self.targets {
            ClientFilterTargets::Exact(targets) => {
                if !targets.remove(target) {
                    warn!("{} was not present in the targets set", target)
                }
            },
            ClientFilterTargets::Glob(targets) => {
                let Some(i) = targets.iter().position(|p| p.as_str() == target) else {
                    warn!("{} was not present in the targets set", target);
                    return Ok(());
                };

                targets.remove(i);
            },
        }

        Ok(())
    }

    #[deprecated(since = "0.4.0", note = "This should be used only by the legacy CLI interface. Use ClientFilter constructors instead")]
    pub fn set_targets(&mut self, targets: HashSet<String>) -> Result<()> {
        match &mut self.targets {
            ClientFilterTargets::Exact(t) => *t = targets,
            ClientFilterTargets::Glob(t) => *t = targets.iter().map(|t| Pattern::new(t)).collect::<Result<Vec<Pattern>, _>>()?,
        }

        Ok(())
    }

    pub fn operation(&self) -> &ClientFilterOperation {
        &self.operation
    }

    #[deprecated(since = "0.4.0", note = "This should be used only by the legacy CLI interface. Use ClientFilter constructors instead")]
    pub fn set_operation(&mut self, operation: ClientFilterOperation) {
        self.operation = operation;
    }

    pub fn kind(&self) -> &ClientFilterType {
        &self.kind
    }

    pub fn flags(&self) -> &ClientFilterFlags {
        &self.flags
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ContentFormat {
    Raw,
    RenderedText,
}

impl Display for ContentFormat {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ContentFormat::Raw => write!(f, "Raw"),
            ContentFormat::RenderedText => write!(f, "RenderedText"),
        }
    }
}

impl FromStr for ContentFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "Raw" {
            Ok(ContentFormat::Raw)
        } else if s == "RenderedText" {
            Ok(ContentFormat::RenderedText)
        } else {
            bail!("Invalid ContentFormat string")
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash, Copy, Serialize)]
pub struct SubscriptionUuid(pub Uuid);

impl Display for SubscriptionUuid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
// Internal version and public version are both uuids
// We use the newtype pattern so that the compiler can check that
// we don't use one instead of the other

#[derive(Debug, PartialEq, Clone, Eq, Hash, Copy)]
pub struct InternalVersion(pub Uuid);

impl Display for InternalVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Default, Hash, Copy)]
pub struct PublicVersion(pub Uuid);

impl Display for PublicVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Contains subscription parameters visible for clients
/// When one element of this structure changes, the "public" version
/// of the subscription is updated and clients are expected to update
/// their configuration.
/// Every elements must implement the Hash trait
#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct SubscriptionParameters {
    pub name: String,
    pub query: String,
    pub heartbeat_interval: u32,
    pub connection_retry_count: u16,
    pub connection_retry_interval: u32,
    pub max_time: u32,
    pub max_elements: Option<u32>,
    pub max_envelope_size: u32,
    pub read_existing_events: bool,
    pub content_format: ContentFormat,
    pub ignore_channel_error: bool,
    pub locale: Option<String>,
    pub data_locale: Option<String>,
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct SubscriptionData {
    // Unique identifier of the subscription
    uuid: SubscriptionUuid,
    // Internal version, NOT the version of the subscription sent to clients
    // It is generated when the subscription is created and updated every time
    // there is a change in the subscription.
    // Its goal is to synchronize the configuration of the subscription between
    // all openwec nodes.
    internal_version: InternalVersion,
    // Optional revision name of the subscription. Can be set using
    // openwec subscriptions load <...>
    revision: Option<String>,
    // Optional URI on which subscription will be shown
    uri: Option<String>,
    // Enable or disable the subscription
    enabled: bool,
    // Configure which client can see the subscription
    client_filter: Option<ClientFilter>,
    // Public parameters of the subscriptions. This structure is used
    // to compute the public subscription version sent to clients.
    parameters: SubscriptionParameters,
    // Outputs of the subscription
    outputs: Vec<SubscriptionOutput>,
}

impl Display for SubscriptionData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Subscription {}", self.name())?;
        writeln!(f, "\tUUID: {}", self.uuid())?;
        writeln!(f, "\tInternal version: {}", self.internal_version())?;
        writeln!(
            f,
            "\tPublic version: {}",
            self.public_version().unwrap_or_default()
        )?;
        writeln!(
            f,
            "\tRevision: {}",
            match self.revision() {
                Some(revision) => revision,
                None => "Not configured",
            }
        )?;
        writeln!(
            f,
            "\tURI: {}",
            match self.uri() {
                Some(uri) => uri,
                None => "Not configured",
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
        writeln!(
            f,
            "\tMax events in a batch: {}",
            match self.max_elements() {
                Some(max_elements) => max_elements.to_string(),
                None => "Not configured".to_string(),
            }
        )?;
        writeln!(f, "\tMax envelope size: {} bytes", self.max_envelope_size())?;
        writeln!(f, "\tRead existing events: {}", self.read_existing_events())?;
        writeln!(f, "\tContent format: {}", self.content_format())?;
        writeln!(f, "\tIgnore channel error: {}", self.ignore_channel_error())?;
        writeln!(
            f,
            "\tLocale: {}",
            match self.locale() {
                Some(locale) => locale,
                None => "Not configured",
            }
        )?;
        writeln!(
            f,
            "\tData Locale: {}",
            match self.data_locale() {
                Some(data_locale) => data_locale,
                None => "Not configured",
            }
        )?;
        match self.client_filter() {
            None => {
                writeln!(f, "\tClient filter: Not configured")?;
            }
            Some(filter) => {
                writeln!(
                    f,
                    "\tClient filter: {} the following targets: {}",
                    filter.operation(),
                    filter.targets_to_string(),
                )?;
            }
        }
        if self.outputs().is_empty() {
            writeln!(f, "\tOutputs: Not configured")?;
        } else {
            writeln!(f, "\tOutputs:")?;
            for (index, output) in self.outputs().iter().enumerate() {
                writeln!(f, "\t- {}: {}", index, output)?;
            }
        }
        writeln!(f, "\tEnabled: {}", self.enabled)?;
        writeln!(f, "\tEvent filter query:\n\n{}", self.query())
    }
}

impl SubscriptionData {
    pub fn new(name: &str, query: &str) -> Self {
        Self {
            uuid: SubscriptionUuid(Uuid::new_v4()),
            internal_version: InternalVersion(Uuid::new_v4()),
            revision: None,
            uri: None,
            enabled: DEFAULT_ENABLED,
            client_filter: None,
            outputs: Vec::new(),
            parameters: SubscriptionParameters {
                name: name.to_string(),
                query: query.to_string(),
                // Defaults
                heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
                connection_retry_count: DEFAULT_CONNECTION_RETRY_COUNT,
                connection_retry_interval: DEFAULT_CONNECTION_RETRY_INTERVAL,
                max_time: DEFAULT_MAX_TIME,
                max_elements: None,
                max_envelope_size: DEFAULT_MAX_ENVELOPE_SIZE,
                read_existing_events: DEFAULT_READ_EXISTING_EVENTS,
                content_format: DEFAULT_CONTENT_FORMAT,
                ignore_channel_error: DEFAULT_IGNORE_CHANNEL_ERROR,
                locale: None,
                data_locale: None,
            },
        }
    }

    pub fn short(&self) -> String {
        let mut res = String::new();
        if self.enabled {
            res.push_str("[+] ");
        } else {
            res.push_str("[-] ");
        }

        res.push_str(format!("{} ", self.name()).as_str());
        if let Some(uri) = &self.uri {
            res.push_str(format!("({})", uri).as_str());
        } else {
            res.push_str("(*)");
        }

        res
    }

    pub fn update_uuid(&mut self) {
        // This should only be used when duplicating an existing subscription
        self.uuid = SubscriptionUuid(Uuid::new_v4());
    }

    pub fn set_uuid(&mut self, uuid: SubscriptionUuid) -> &mut Self {
        self.uuid = uuid;
        self
    }

    /// Get a reference to the subscription's uuid.
    pub fn uuid(&self) -> &SubscriptionUuid {
        &self.uuid
    }

    pub fn uuid_string(&self) -> String {
        self.uuid.to_string().to_uppercase()
    }

    /// Compute the subscription's public version
    pub fn public_version(&self) -> Result<PublicVersion> {
        let mut hasher = VersionHasher::new()?;
        self.parameters.hash(&mut hasher);
        // hasher only gives a u64, but it is enough for this usage
        let result = hasher.finish();
        Ok(PublicVersion(Uuid::from_u64_pair(result, result)))
    }

    /// Get a reference to the subscription's name.
    pub fn name(&self) -> &str {
        self.parameters.name.as_ref()
    }

    /// Get a reference to the subscription's heartbeat interval.
    pub fn heartbeat_interval(&self) -> u32 {
        self.parameters.heartbeat_interval
    }

    /// Get a reference to the subscription's connection retry count.
    pub fn connection_retry_count(&self) -> u16 {
        self.parameters.connection_retry_count
    }

    /// Get a reference to the subscription's connection retry interval.
    pub fn connection_retry_interval(&self) -> u32 {
        self.parameters.connection_retry_interval
    }

    /// Get a reference to the subscription's max time.
    pub fn max_time(&self) -> u32 {
        self.parameters.max_time
    }

    /// Get a reference to the subscription's max elements.
    pub fn max_elements(&self) -> Option<u32> {
        self.parameters.max_elements
    }

    /// Get a reference to the subscription's max envelope size.
    pub fn max_envelope_size(&self) -> u32 {
        self.parameters.max_envelope_size
    }

    /// Get a reference to the subscription's query.
    pub fn query(&self) -> &str {
        self.parameters.query.as_ref()
    }

    /// Set the subscription's name.
    pub fn set_name(&mut self, name: String) -> &mut Self {
        self.parameters.name = name;
        self.update_internal_version();
        self
    }

    /// Set the subscription's query.
    pub fn set_query(&mut self, query: String) -> &mut Self {
        self.parameters.query = query;
        self.update_internal_version();
        self
    }

    /// Set the subscription's heartbeat interval.
    pub fn set_heartbeat_interval(&mut self, heartbeat_interval: u32) -> &mut Self {
        self.parameters.heartbeat_interval = heartbeat_interval;
        self.update_internal_version();
        self
    }

    /// Set the subscription's connection retry count.
    pub fn set_connection_retry_count(&mut self, connection_retry_count: u16) -> &mut Self {
        self.parameters.connection_retry_count = connection_retry_count;
        self.update_internal_version();
        self
    }

    /// Set the subscription's connection retry interval.
    pub fn set_connection_retry_interval(&mut self, connection_retry_interval: u32) -> &mut Self {
        self.parameters.connection_retry_interval = connection_retry_interval;
        self.update_internal_version();
        self
    }

    /// Set the subscription's max time.
    pub fn set_max_time(&mut self, max_time: u32) -> &mut Self {
        self.parameters.max_time = max_time;
        self.update_internal_version();
        self
    }

     /// Set the subscription's max elements.
     pub fn set_max_elements(&mut self, max_elements: Option<u32>) -> &mut Self {
        self.parameters.max_elements = max_elements;
        self.update_internal_version();
        self
    }

    /// Set the subscription's max envelope size.
    pub fn set_max_envelope_size(&mut self, max_envelope_size: u32) -> &mut Self {
        self.parameters.max_envelope_size = max_envelope_size;
        self.update_internal_version();
        self
    }

    /// Get a reference to the subscription's outputs.
    pub fn outputs(&self) -> &[SubscriptionOutput] {
        self.outputs.as_ref()
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) -> &mut Self {
        self.enabled = enabled;
        self.update_internal_version();
        self
    }

    pub fn read_existing_events(&self) -> bool {
        self.parameters.read_existing_events
    }

    pub fn set_read_existing_events(&mut self, read_existing_events: bool) -> &mut Self {
        self.parameters.read_existing_events = read_existing_events;
        self.update_internal_version();
        self
    }

    pub fn content_format(&self) -> &ContentFormat {
        &self.parameters.content_format
    }

    pub fn set_content_format(&mut self, content_format: ContentFormat) -> &mut Self {
        self.parameters.content_format = content_format;
        self.update_internal_version();
        self
    }

    pub fn ignore_channel_error(&self) -> bool {
        self.parameters.ignore_channel_error
    }

    pub fn set_ignore_channel_error(&mut self, ignore_channel_error: bool) -> &mut Self {
        self.parameters.ignore_channel_error = ignore_channel_error;
        self.update_internal_version();
        self
    }

    pub fn set_outputs(&mut self, outputs: Vec<SubscriptionOutput>) -> &mut Self {
        self.outputs = outputs;
        self.update_internal_version();
        self
    }

    pub fn add_output(&mut self, output: SubscriptionOutput) -> &mut Self {
        self.outputs.push(output);
        self.update_internal_version();
        self
    }

    pub fn delete_output(&mut self, index: usize) -> Result<&mut Self> {
        if index >= self.outputs.len() {
            bail!("Index out of range");
        }
        let output = self.outputs.remove(index);
        info!("Deleting output {:?}", output);
        self.update_internal_version();
        Ok(self)
    }

    pub fn set_output_enabled(&mut self, index: usize, value: bool) -> Result<&mut Self> {
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
        self.outputs[index].set_enabled(value);
        self.update_internal_version();
        Ok(self)
    }

    pub fn uri(&self) -> Option<&String> {
        self.uri.as_ref()
    }

    pub fn set_uri(&mut self, uri: Option<String>) -> &mut Self {
        self.uri = uri;
        self.update_internal_version();
        self
    }

    pub fn is_active(&self) -> bool {
        self.enabled() && self.outputs().iter().any(|output| output.enabled())
    }

    pub fn client_filter(&self) -> Option<&ClientFilter> {
        self.client_filter.as_ref()
    }

    pub fn set_client_filter(&mut self, client_filter: Option<ClientFilter>) -> &mut Self {
        self.client_filter = client_filter;
        self.update_internal_version();
        self
    }

    pub fn is_active_for(&self, client: &str, machine_id: Option<&str>) -> bool {
        if !self.is_active() {
            return false;
        }

        if let Some(client_filter) = self.client_filter() {
            return client_filter.eval(client, machine_id);
        }

        true
    }

    pub fn revision(&self) -> Option<&String> {
        self.revision.as_ref()
    }

    pub fn set_revision(&mut self, revision: Option<String>) -> &mut Self {
        self.revision = revision;
        self.update_internal_version();
        self
    }

    pub fn internal_version(&self) -> InternalVersion {
        self.internal_version
    }

    pub fn set_internal_version(&mut self, internal_version: InternalVersion) {
        self.internal_version = internal_version;
    }

    pub fn update_internal_version(&mut self) {
        self.internal_version = InternalVersion(Uuid::new_v4());
    }

    pub fn locale(&self) -> Option<&String> {
        self.parameters.locale.as_ref()
    }

    pub fn set_locale(&mut self, locale: Option<String>) -> &mut Self {
        self.parameters.locale = locale;
        self.update_internal_version();
        self
    }

    pub fn data_locale(&self) -> Option<&String> {
        self.parameters.data_locale.as_ref()
    }

    pub fn set_data_locale(&mut self, locale: Option<String>) -> &mut Self {
        self.parameters.data_locale = locale;
        self.update_internal_version();
        self
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
