use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    str::FromStr,
};

use anyhow::{anyhow, bail, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString, VariantNames};
use uuid::Uuid;

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
pub enum PrincsFilterOperation {
    Only,
    Except,
}

impl Display for PrincsFilterOperation {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PrincsFilterOperation::Only => write!(f, "Only"),
            PrincsFilterOperation::Except => write!(f, "Except"),
        }
    }
}

impl PrincsFilterOperation {
    pub fn opt_from_str(op: &str) -> Result<Option<PrincsFilterOperation>> {
        if op.eq_ignore_ascii_case("only") {
            Ok(Some(PrincsFilterOperation::Only))
        } else if op.eq_ignore_ascii_case("except") {
            Ok(Some(PrincsFilterOperation::Except))
        } else if op.eq_ignore_ascii_case("none") {
            Ok(None)
        } else {
            bail!("Could not parse principal filter operation")
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrincsFilter {
    operation: Option<PrincsFilterOperation>,
    princs: HashSet<String>,
}

impl PrincsFilter {
    pub fn empty() -> Self {
        PrincsFilter {
            operation: None,
            princs: HashSet::new(),
        }
    }

    pub fn new(operation: Option<PrincsFilterOperation>, princs: HashSet<String>) -> Self {
        Self { operation, princs }
    }

    pub fn from(operation: Option<String>, princs: Option<String>) -> Result<Self> {
        Ok(PrincsFilter {
            operation: match operation {
                Some(op) => PrincsFilterOperation::opt_from_str(&op)?,
                None => None,
            },
            princs: match princs {
                Some(p) => HashSet::from_iter(p.split(',').map(|s| s.to_string())),
                None => HashSet::new(),
            },
        })
    }

    pub fn princs(&self) -> &HashSet<String> {
        &self.princs
    }

    pub fn princs_to_string(&self) -> String {
        self.princs()
            .iter()
            .cloned()
            .collect::<Vec<String>>()
            .join(",")
    }

    pub fn princs_to_opt_string(&self) -> Option<String> {
        if self.princs().is_empty() {
            None
        } else {
            Some(self.princs_to_string())
        }
    }

    pub fn add_princ(&mut self, princ: &str) -> Result<()> {
        if self.operation.is_none() {
            bail!("Could not add a principal to an unset filter")
        }
        self.princs.insert(princ.to_owned());
        Ok(())
    }

    pub fn delete_princ(&mut self, princ: &str) -> Result<()> {
        if self.operation.is_none() {
            bail!("Could not delete a principal of an unset filter")
        }
        if !self.princs.remove(princ) {
            warn!("{} was not present in the principals set", princ)
        }
        Ok(())
    }

    pub fn set_princs(&mut self, princs: HashSet<String>) -> Result<()> {
        if self.operation.is_none() {
            bail!("Could not set principals of an unset filter")
        }
        self.princs = princs;
        Ok(())
    }

    pub fn operation(&self) -> Option<&PrincsFilterOperation> {
        self.operation.as_ref()
    }

    pub fn set_operation(&mut self, operation: Option<PrincsFilterOperation>) {
        if operation.is_none() {
            self.princs.clear();
        }
        self.operation = operation;
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
    // Configure which principal can see the subscription
    princs_filter: PrincsFilter,
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
        match self.princs_filter().operation() {
            None => {
                writeln!(f, "\tPrincipal filter: Not configured")?;
            }
            Some(operation) => {
                writeln!(
                    f,
                    "\tPrincipal filter: {} the following principals: {}",
                    operation,
                    self.princs_filter().princs_to_string(),
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
            princs_filter: PrincsFilter::empty(),
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

    pub fn princs_filter(&self) -> &PrincsFilter {
        &self.princs_filter
    }

    pub fn set_princs_filter(&mut self, princs_filter: PrincsFilter) -> &mut Self {
        self.princs_filter = princs_filter;
        self.update_internal_version();
        self
    }

    pub fn is_active_for(&self, principal: &str) -> bool {
        if !self.is_active() {
            return false;
        }

        match self.princs_filter().operation {
            None => true,
            Some(PrincsFilterOperation::Only) => self.princs_filter().princs().contains(principal),
            Some(PrincsFilterOperation::Except) => {
                !self.princs_filter().princs().contains(principal)
            }
        }
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
