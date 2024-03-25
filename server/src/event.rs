use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, info, trace, warn};
use roxmltree::{Document, Error, Node};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::subscription::Subscription;

#[derive(Debug, Default, Serialize, Clone)]
pub struct EventDataType {
    pub named_data: HashMap<String, String>,
    pub unamed_data: Vec<String>,
    pub binary: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct DebugDataType {
    pub sequence_number: Option<u32>,
    pub flags_name: Option<String>,
    pub level_name: Option<String>,
    pub component: String,
    pub sub_component: Option<String>,
    pub file_line: Option<String>,
    pub function: Option<String>,
    pub message: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct ProcessingErrorDataType {
    pub error_code: u32,
    pub data_item_name: String,
    pub event_payload: String,
}

pub type UserDataType = String;
pub type BinaryEventDataType = String;

#[derive(Debug, Default, Clone)]
pub enum DataType {
    EventData(EventDataType),
    UserData(UserDataType),
    DebugData(DebugDataType),
    ProcessingErrorData(ProcessingErrorDataType),
    BinaryEventData(BinaryEventDataType),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum ErrorType {
    /// Initial XML parsing failed but Raw content could be recovered
    RawContentRecovered(String),
    /// Initial XML parsing failed and recovering failed again
    FailedToRecoverRawContent(String),
    /// Initial XML parsing failed and no recovering strategy was usable
    Unrecoverable(String),
    /// Failed to feed event from parsed XML document
    FailedToFeedEvent(String),
    #[default]
    Unknown,
}

impl ToString for ErrorType {
    fn to_string(&self) -> String {
        match self {
            ErrorType::RawContentRecovered(message) => message.clone(),
            ErrorType::FailedToRecoverRawContent(message ) => message.clone(),
            ErrorType::Unrecoverable(message ) => message.clone(),
            ErrorType::FailedToFeedEvent (message ) => message.clone(),
            ErrorType::Unknown => "Unknown error".to_string(),
        }
    }
}


#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ErrorInfo {
    pub original_content: String,
    pub error_type: ErrorType,
}

#[derive(Debug, Default, Clone)]
pub struct Event {
    pub system: Option<System>,
    pub data: DataType,
    pub rendering_info: Option<RenderingInfo>,
    pub additional: Additional,
}

impl Event {
    /// Reads a parsed XML document and feeds an Event struct
    fn feed_event_from_document(
        event: &mut Event,
        doc: &Document<'_>,
        content: &str, // Only used for logging
    ) -> Result<()> {
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "System" {
                event.system = Some(System::from(&node).context("Parsing failure in System")?)
            } else if node.tag_name().name() == "EventData" {
                event.data = parse_event_data(&node).context("Parsing failure in EventData")?
            } else if node.tag_name().name() == "UserData" {
                event.data = parse_user_data(&node).context("Parsing failure in UserData")?
            } else if node.tag_name().name() == "BinaryEventData" {
                event.data = DataType::BinaryEventData(node.text().unwrap_or_default().to_owned());
            } else if node.tag_name().name() == "DebugData" {
                event.data = parse_debug_data(&node).context("Parsing failure in DebugData")?
            } else if node.tag_name().name() == "ProcessingErrorData" {
                event.data = parse_processing_error_data(&node)
                    .context("Parsing failure in ProcessingErrorData")?
            } else if node.tag_name().name() == "RenderingInfo" {
                event.rendering_info =
                    Some(RenderingInfo::from(&node).context("Parsing failure in RenderingInfo")?)
            } else if node.tag_name().name() == "SubscriptionBookmarkEvent" {
                // Nothing to do, this node is present in the first received event (EventID 111)
            } else {
                info!("Unknown node {} when parsing Event", node.tag_name().name());
                trace!("Event was: {}", content);
            }
        }
        Ok(())
    }

    fn add_event_parsing_error(
        event: &mut Event,
        content: &str,
        error_type: ErrorType,
        warn: bool,
    ) {
        event.additional.error = Some(ErrorInfo {
            original_content: content.to_string(),
            error_type: error_type.clone(),
        });
        let error_message = error_type.to_string();
        if warn {
            warn!("{}. Context: {:?}", error_message, event.additional);
        } else {
            debug!("{}. Context: {:?}", error_message, event.additional);
        }
    }

    fn try_to_recover(event: &mut Event, initial_error: Error, content: &str) {
        // Sometimes, `RenderingInfo` content is malformed, meaning that
        // the event content is cut off in the middle without appropriate closing
        // tags resulting in invalid XML (see issue #46 for more details).
        //
        // When this problem occurs, we try to remove the RenderingInfo
        // element and recover the Raw event content. Such an operation should
        // be valid because RenderingInfo is the last "specified" child node
        // of the Event element according to the Event schema.
        //
        // See tests:
        // - test_serialize_malformed_raw_content_recovered
        // - test_serialize_malformed_unrecoverable_1
        // - test_serialize_malformed_unrecoverable_2
        // - test_serialize_failed_to_recover
        // - test_serialize_malformed_failed_to_feed_event
        let (error_type, do_warn) = match content.rsplit_once("<RenderingInfo") {
            Some((beginning, _end)) => {
                let clean_content = beginning.to_string() + "</Event>";
                match Document::parse(&clean_content) {
                    Ok(doc) => {
                        match Event::feed_event_from_document(event, &doc, &clean_content) {
                            Ok(_) =>
                                (ErrorType::RawContentRecovered(format!(
                                    "Failed to parse event XML ({}) but Raw content could be recovered.",
                                    initial_error
                                )), false),
                            Err(feed_error) =>
                                (ErrorType::FailedToFeedEvent(format!(
                                    "Could not feed event from document: {}",
                                    feed_error
                                )), true),
                        }
                    }
                    Err(recovering_error) => {
                            (ErrorType::FailedToRecoverRawContent(format!(
                            "Failed to parse event XML ({}) and Raw content recovering failed ({})",
                            initial_error, recovering_error
                        )), true)
                    }
                }
            }
            None => (
                ErrorType::Unrecoverable(format!("Failed to parse event XML: {}", initial_error)),
                true,
            ),
        };
        Event::add_event_parsing_error(event, content, error_type, do_warn);
    }

    pub fn from_str(content: &str) -> Self {
        let mut event = Event::default();
    
        let doc_parse_attempt = Document::parse(content);
        match doc_parse_attempt {
            Ok(doc) => {
                if let Err(feed_error) = Event::feed_event_from_document(&mut event, &doc, content)
                {
                    let message = format!("Could not feed event from document: {}", feed_error);
                    Event::add_event_parsing_error(
                        &mut event,
                        content,
                        ErrorType::FailedToFeedEvent(message),
                        true,
                    );
                }
            }
            Err(initial_error) => {
                debug!(
                    "Failed to parse XML event: {}. Lets try to recover it.",
                    initial_error
                );
                Event::try_to_recover(&mut event, initial_error, content);
            }
        }
        event
    }
}

fn parse_event_data(event_data_node: &Node) -> Result<DataType> {
    let mut named_data = HashMap::new();
    let mut unamed_data = Vec::new();
    let mut binary: Option<String> = None;
    for node in event_data_node.children() {
        if node.tag_name().name() == "Data" {
            let name = node.attribute("Name").map(str::to_string);
            let value = node.text().unwrap_or_default().to_owned();

            match name {
                Some(n) => {
                    named_data.insert(n, value);
                }
                None if !value.is_empty() => unamed_data.push(value),
                _ => (),
            };
        }
        if node.tag_name().name() == "Binary" {
            binary = node.text().map(str::to_string);
        }
    }
    Ok(DataType::EventData(EventDataType {
        named_data,
        unamed_data,
        binary,
    }))
}

fn parse_debug_data(debug_data_node: &Node) -> Result<DataType> {
    let mut debug_data = DebugDataType::default();
    for node in debug_data_node.children() {
        if node.tag_name().name() == "SequenceNumber" {
            debug_data.sequence_number = node.text().and_then(|s| s.parse().ok());
        } else if node.tag_name().name() == "FlagsName" {
            debug_data.flags_name = node.text().map(str::to_string);
        } else if node.tag_name().name() == "LevelName" {
            debug_data.level_name = node.text().map(str::to_string);
        } else if node.tag_name().name() == "Component" {
            debug_data.component = node.text().unwrap_or_default().to_owned();
        } else if node.tag_name().name() == "SubComponent" {
            debug_data.sub_component = node.text().map(str::to_string);
        } else if node.tag_name().name() == "FileLine" {
            debug_data.file_line = node.text().map(str::to_string);
        } else if node.tag_name().name() == "Function" {
            debug_data.function = node.text().map(str::to_string);
        } else if node.tag_name().name() == "Message" {
            debug_data.message = node.text().unwrap_or_default().to_owned();
        }
    }
    Ok(DataType::DebugData(debug_data))
}

fn parse_processing_error_data(processing_error_data_node: &Node) -> Result<DataType> {
    let mut processing_error_data = ProcessingErrorDataType::default();
    for node in processing_error_data_node.children() {
        if node.tag_name().name() == "ErrorCode" {
            processing_error_data.error_code = node.text().unwrap_or_default().parse()?;
        } else if node.tag_name().name() == "DataItemName" {
            processing_error_data.data_item_name = node.text().unwrap_or_default().to_owned();
        } else if node.tag_name().name() == "EventPayload" {
            processing_error_data.event_payload = node.text().unwrap_or_default().to_owned();
        }
    }
    Ok(DataType::ProcessingErrorData(processing_error_data))
}

fn parse_user_data(user_data_node: &Node) -> Result<DataType> {
    // We don't try to parse UserData node content as XML since its content
    // is not specified. Instead, we retrieve its content as text.
    let mut data = String::new();
    for node in user_data_node.children() {
        data.push_str(node.document().input_text()[node.range()].as_ref())
    }
    Ok(DataType::UserData(data))
}

#[derive(Debug, Default, Clone)]
pub struct Additional {
    pub error: Option<ErrorInfo>,
}

#[derive(Debug, Default, Clone)]
pub struct Provider {
    pub name: Option<String>,
    pub guid: Option<String>,
    pub event_source_name: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct Correlation {
    pub activity_id: Option<String>,
    pub related_activity_id: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct Execution {
    pub process_id: u32,
    pub thread_id: u32,
    pub processor_id: Option<u8>,
    pub session_id: Option<u32>,
    pub kernel_time: Option<u32>,
    pub user_time: Option<u32>,
    pub processor_time: Option<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct System {
    pub provider: Provider,
    pub event_id: u32,
    pub event_id_qualifiers: Option<u16>,
    pub version: Option<u8>,
    pub level: Option<u8>,
    pub task: Option<u16>,
    pub opcode: Option<u8>,
    pub keywords: Option<String>,
    pub time_created: Option<String>,
    pub event_record_id: Option<u64>,
    pub correlation: Option<Correlation>,
    pub execution: Option<Execution>,
    pub channel: Option<String>,
    pub computer: String,
    pub container: Option<String>,
    pub user_id: Option<String>,
}

impl System {
    fn from(system_node: &Node) -> Result<System> {
        let mut system = System::default();
        let mut computer_opt = None;
        let mut event_id_opt = None;
        for node in system_node.children() {
            let tag = node.tag_name();
            if tag.name() == "Provider" {
                system.provider = Provider {
                    name: node.attribute("Name").map(str::to_string),
                    guid: node.attribute("Guid").map(str::to_string),
                    event_source_name: node.attribute("EventSourceName").map(str::to_string),
                };
            } else if tag.name() == "EventID" {
                event_id_opt = node.text().and_then(|s| s.parse().ok());
                system.event_id_qualifiers = node
                    .attribute("Qualifiers")
                    .unwrap_or_default()
                    .parse()
                    .ok();
            } else if tag.name() == "Version" {
                system.version = node.text().and_then(|s| s.parse().ok());
            } else if tag.name() == "Level" {
                system.level = node.text().and_then(|s| s.parse().ok());
            } else if tag.name() == "Task" {
                system.task = node.text().and_then(|s| s.parse().ok());
            } else if tag.name() == "Opcode" {
                system.opcode = node.text().and_then(|s| s.parse().ok());
            } else if tag.name() == "Keywords" {
                system.keywords = node.text().map(str::to_string);
            } else if tag.name() == "TimeCreated" {
                system.time_created = Some(
                    node.attribute("SystemTime")
                        .ok_or_else(|| {
                            anyhow!("SystemTime attribute of TimeCreated field is missing")
                        })?
                        .to_owned(),
                );
            } else if tag.name() == "EventRecordID" {
                system.event_record_id = node.text().and_then(|s| s.parse().ok());
            } else if tag.name() == "Correlation" {
                system.correlation = Some(Correlation {
                    activity_id: node.attribute("ActivityID").map(str::to_string),
                    related_activity_id: node.attribute("RelatedActivityID").map(str::to_string),
                });
            } else if tag.name() == "Execution" {
                system.execution = Some(Execution {
                    process_id: node
                        .attribute("ProcessID")
                        .ok_or_else(|| anyhow!("ProcessID field is missing"))?
                        .parse()?,
                    thread_id: node
                        .attribute("ThreadID")
                        .ok_or_else(|| anyhow!("ThreadID is missing"))?
                        .parse()?,
                    processor_id: node.attribute("ProcessorID").and_then(|s| s.parse().ok()),
                    session_id: node.attribute("SessionID").and_then(|s| s.parse().ok()),
                    kernel_time: node.attribute("KernelTime").and_then(|s| s.parse().ok()),
                    user_time: node.attribute("UserTime").and_then(|s| s.parse().ok()),
                    processor_time: node.attribute("ProcessorTime").and_then(|s| s.parse().ok()),
                });
            } else if tag.name() == "Channel" {
                system.channel = node.text().map(str::to_string);
            } else if tag.name() == "Computer" {
                computer_opt = node.text().map(str::to_string);
            } else if tag.name() == "Container" {
                system.container = node.text().map(str::to_string);
            } else if tag.name() == "Security" {
                system.user_id = node.attribute("UserID").and_then(|s| s.parse().ok());
            }
        }

        if let Some(computer) = computer_opt {
            system.computer = computer;
        } else {
            bail!("Computer field is missing or invalid");
        }

        if let Some(event_id) = event_id_opt {
            system.event_id = event_id;
        } else {
            bail!("EventID field is missing or invalid");
        }

        Ok(system)
    }
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct RenderingInfo {
    pub message: Option<String>,
    pub level: Option<String>,
    pub task: Option<String>,
    pub opcode: Option<String>,
    pub channel: Option<String>,
    // Microsoft schema states that this field should be called "Publisher"
    // but this is not what has been observed in practice
    pub provider: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub culture: String,
}

impl RenderingInfo {
    fn from(rendering_info_node: &Node) -> Result<RenderingInfo> {
        let mut rendering_info = RenderingInfo {
            culture: rendering_info_node
                .attribute("Culture")
                .unwrap_or_default()
                .to_owned(),
            ..Default::default()
        };

        for node in rendering_info_node.children() {
            let tag = node.tag_name();
            if tag.name() == "Message" {
                rendering_info.message = node.text().map(str::to_string);
            } else if tag.name() == "Level" {
                rendering_info.level = node.text().map(str::to_string);
            } else if tag.name() == "Task" {
                rendering_info.task = node.text().map(str::to_string);
            } else if tag.name() == "Opcode" {
                rendering_info.opcode = node.text().map(str::to_string);
            } else if tag.name() == "Channel" {
                rendering_info.channel = node.text().map(str::to_string);
            } else if tag.name() == "Provider" {
                rendering_info.provider = node.text().map(str::to_string);
            } else if tag.name() == "Keywords" {
                let mut keywords = Vec::new();
                for keyword_node in node.children() {
                    if keyword_node.tag_name().name() == "Keyword" && keyword_node.text().is_some()
                    {
                        keywords.push(keyword_node.text().unwrap_or_default().to_owned());
                    }
                }
                rendering_info.keywords = Some(keywords);
            }
        }

        Ok(rendering_info)
    }
}

#[derive(Debug, Clone)]
pub struct EventMetadata {
    // TODO : add authentication method (TLS or Kerberos)
    addr: SocketAddr,
    principal: String,
    node_name: Option<String>,
    time_received: DateTime<Utc>,
    subscription_uuid: String,
    subscription_version: String,
    subscription_name: String,
    subscription_uri: Option<String>,
    subscription_revision: Option<String>,
}

impl EventMetadata {
    pub fn new(
        addr: &SocketAddr,
        principal: &str,
        node_name: Option<String>,
        subscription: &Subscription,
    ) -> Self {
        EventMetadata {
            addr: *addr,
            principal: principal.to_owned(),
            node_name,
            time_received: Utc::now(),
            subscription_uuid: subscription.data().uuid_string(),
            subscription_version: subscription.public_version_string(),
            subscription_name: subscription.data().name().to_owned(),
            subscription_uri: subscription.data().uri().cloned(),
            subscription_revision: subscription.data().revision().cloned(),
        }
    }

    #[cfg(test)]
    pub fn set_time_received(&mut self, time_received: DateTime<Utc>) {
        self.time_received = time_received; 
    }

    /// Get a reference to the event metadata's addr.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn principal(&self) -> &str {
        self.principal.as_ref()
    }

    pub fn node_name(&self) -> Option<&String> {
        self.node_name.as_ref()
    }

    pub fn time_received(&self) -> DateTime<Utc> {
        self.time_received
    }

    pub fn subscription_uuid(&self) -> &str {
        self.subscription_uuid.as_ref()
    }

    pub fn subscription_version(&self) -> &str {
        self.subscription_version.as_ref()
    }

    pub fn subscription_name(&self) -> &str {
        self.subscription_name.as_ref()
    }

    pub fn subscription_uri(&self) -> Option<&String> {
        self.subscription_uri.as_ref()
    }

    pub fn subscription_revision(&self) -> Option<&String> {
        self.subscription_revision.as_ref()
    }
}

pub struct EventData {
    raw: Arc<String>,
    event: Option<Event>,
}

impl EventData {
    pub fn new(raw: Arc<String>, parse_event: bool) -> Self {
        let event = if parse_event {
            Some(Event::from_str(raw.as_ref()))
        } else {
            None
        };
        Self {
            raw,
            event
        } 
    }

    pub fn raw(&self) -> Arc<String> {
        self.raw.clone()
    }
    
    pub fn event(&self) -> Option<&Event> {
        self.event.as_ref()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const EVENT_142: &str = r#"
        <Event
            xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-WinRM" Guid="{a7975c8f-ac13-49f1-87da-5a984a4ab417}"/>
                <EventID>142</EventID>
                <Version>0</Version>
                <Level>2</Level>
                <Task>10</Task>
                <Opcode>2</Opcode>
                <Keywords>0x4000000000000002</Keywords>
                <TimeCreated SystemTime="2022-09-22T07:49:32.0356778Z"/>
                <EventRecordID>149161</EventRecordID>
                <Correlation ActivityID="{8cb1229f-ce57-0000-8437-b18c57ced801}"/>
                <Execution ProcessID="352" ThreadID="2468"/>
                <Channel>Microsoft-Windows-WinRM/Operational</Channel>
                <Computer>win10.windomain.local</Computer>
                <Security UserID="S-1-5-18"/>
            </System>
            <EventData>
                <Data Name="operationName">Enumeration</Data>
                <Data Name="errorCode">2150858770</Data>
            </EventData>
            <RenderingInfo Culture="en-US">
                <Message>WSMan operation Enumeration failed, error code 2150858770</Message>
                <Level>Error</Level>
                <Task>Response handling</Task>
                <Opcode>Stop</Opcode>
                <Channel>Microsoft-Windows-WinRM/Operational</Channel>
                <Provider>Microsoft-Windows-Windows Remote Management</Provider>
                <Keywords>
                    <Keyword>Client</Keyword>
                </Keywords>
            </RenderingInfo>
        </Event>"#;

    #[test]
    fn test_142_system_parsing() {
        let doc = Document::parse(EVENT_142).expect("Failed to parse Event");
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "System" {
                let system = System::from(&node).expect("Failed to parse System node");
                assert_eq!(system.provider.name.unwrap(), "Microsoft-Windows-WinRM");
                assert_eq!(
                    system.provider.guid.unwrap(),
                    "{a7975c8f-ac13-49f1-87da-5a984a4ab417}"
                );
                assert_eq!(system.event_id, 142);
                assert_eq!(system.version.unwrap(), 0);
                assert_eq!(system.level.unwrap(), 2);
                assert_eq!(system.task.unwrap(), 10);
                assert_eq!(system.opcode.unwrap(), 2);
                assert_eq!(system.keywords.unwrap(), "0x4000000000000002");
                assert_eq!(system.time_created.unwrap(), "2022-09-22T07:49:32.0356778Z");
                assert_eq!(system.event_record_id.unwrap(), 149161);
                assert_eq!(
                    system.correlation.unwrap().activity_id.unwrap(),
                    "{8cb1229f-ce57-0000-8437-b18c57ced801}"
                );
                assert_eq!(system.execution.as_ref().unwrap().process_id, 352);
                assert_eq!(system.execution.as_ref().unwrap().thread_id, 2468);
                assert_eq!(
                    system.channel.unwrap(),
                    "Microsoft-Windows-WinRM/Operational"
                );
                assert_eq!(system.computer, "win10.windomain.local");
                assert_eq!(system.user_id.unwrap(), "S-1-5-18");
            }
        }
    }

    #[test]
    fn test_142_event_data_parsing() {
        let doc = Document::parse(EVENT_142).expect("Failed to parse Event");
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "EventData" {
                let data = parse_event_data(&node).expect("Failed to parse EventData node");
                match data {
                    DataType::EventData(event_data) => {
                        assert_eq!(
                            event_data.named_data.get("operationName"),
                            Some(&"Enumeration".to_string())
                        );
                        assert_eq!(
                            event_data.named_data.get("errorCode"),
                            Some(&"2150858770".to_string())
                        );
                    }
                    _ => panic!("Wrong EventData node"),
                }
            }
        }
    }

    #[test]
    fn test_142_rendering_info_parsing() {
        let doc = Document::parse(EVENT_142).expect("Failed to parse Event");
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "RenderingInfo" {
                let rendering_info =
                    RenderingInfo::from(&node).expect("Failed to parse RenderingInfo node");
                assert_eq!(rendering_info.culture, "en-US");
                assert_eq!(
                    rendering_info.message.unwrap(),
                    "WSMan operation Enumeration failed, error code 2150858770"
                );
                assert_eq!(rendering_info.level.unwrap(), "Error");
                assert_eq!(rendering_info.task.unwrap(), "Response handling");
                assert_eq!(rendering_info.opcode.unwrap(), "Stop");
                assert_eq!(
                    rendering_info.channel.unwrap(),
                    "Microsoft-Windows-WinRM/Operational"
                );
                assert_eq!(
                    rendering_info.provider.unwrap(),
                    "Microsoft-Windows-Windows Remote Management"
                );
                assert_eq!(rendering_info.keywords.unwrap(), ["Client"]);
            }
        }
    }

    const EVENT_4624: &str = r#"
        <Event
            xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
                <EventID>4624</EventID>
                <Version>2</Version>
                <Level>0</Level>
                <Task>12544</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime="2022-09-23T11:53:47.9077543Z"/>
                <EventRecordID>72207</EventRecordID>
                <Correlation ActivityID="{d88ee832-cf42-0000-26e9-8ed842cfd801}"/>
                <Execution ProcessID="588" ThreadID="652"/>
                <Channel>Security</Channel>
                <Computer>win10.windomain.local</Computer>
                <Security/>
            </System>
            <EventData>
                <Data Name="SubjectUserSid">S-1-5-18</Data>
                <Data Name="SubjectUserName">WIN10$</Data>
                <Data Name="SubjectDomainName">WINDOMAIN</Data>
                <Data Name="SubjectLogonId">0x3e7</Data>
                <Data Name="TargetUserSid">S-1-5-18</Data>
                <Data Name="TargetUserName">SYSTEM</Data>
                <Data Name="TargetDomainName">NT AUTHORITY</Data>
                <Data Name="TargetLogonId">0x3e7</Data>
                <Data Name="LogonType">5</Data>
                <Data Name="LogonProcessName">Advapi  </Data>
                <Data Name="AuthenticationPackageName">Negotiate</Data>
                <Data Name="WorkstationName">-</Data>
                <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
                <Data Name="TransmittedServices">-</Data>
                <Data Name="LmPackageName">-</Data>
                <Data Name="KeyLength">0</Data>
                <Data Name="ProcessId">0x244</Data>
                <Data Name="ProcessName">C:\\Windows\\System32\\services.exe</Data>
                <Data Name="IpAddress">-</Data>
                <Data Name="IpPort">-</Data>
                <Data Name="ImpersonationLevel">%%1833</Data>
                <Data Name="RestrictedAdminMode">-</Data>
                <Data Name="TargetOutboundUserName">-</Data>
                <Data Name="TargetOutboundDomainName">-</Data>
                <Data Name="VirtualAccount">%%1843</Data>
                <Data Name="TargetLinkedLogonId">0x0</Data>
                <Data Name="ElevatedToken">%%1842</Data>
            </EventData>
            <RenderingInfo Culture="en-US">
                <Message>An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tWIN10$\r\n\tAccount Domain:\t\tWINDOMAIN\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t5\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSYSTEM\r\n\tAccount Domain:\t\tNT AUTHORITY\r\n\tLogon ID:\t\t0x3E7\r\n\tLinked Logon ID:\t\t0x0\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x244\r\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t-\r\n\tSource Port:\t\t-\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tAdvapi  \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.</Message>
                <Level>Information</Level>
                <Task>Logon</Task>
                <Opcode>Info</Opcode>
                <Channel>Security</Channel>
                <Provider>Microsoft Windows security auditing.</Provider>
                <Keywords>
                    <Keyword>Audit Success</Keyword>
                </Keywords>
            </RenderingInfo>
        </Event>"#;
    #[test]
    fn test_4624_system_parsing() {
        let doc = Document::parse(EVENT_4624).expect("Failed to parse Event");
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "System" {
                let system = System::from(&node).expect("Failed to parse System node");
                assert_eq!(
                    system.provider.name.unwrap(),
                    "Microsoft-Windows-Security-Auditing"
                );
                assert_eq!(
                    system.provider.guid.unwrap(),
                    "{54849625-5478-4994-a5ba-3e3b0328c30d}"
                );
                assert_eq!(system.event_id, 4624);
                assert_eq!(system.version.unwrap(), 2);
                assert_eq!(system.level.unwrap(), 0);
                assert_eq!(system.task.unwrap(), 12544);
                assert_eq!(system.opcode.unwrap(), 0);
                assert_eq!(system.keywords.unwrap(), "0x8020000000000000");
                assert_eq!(system.time_created.unwrap(), "2022-09-23T11:53:47.9077543Z");
                assert_eq!(system.event_record_id.unwrap(), 72207);
                assert_eq!(
                    system.correlation.unwrap().activity_id.unwrap(),
                    "{d88ee832-cf42-0000-26e9-8ed842cfd801}"
                );
                assert_eq!(system.execution.as_ref().unwrap().process_id, 588);
                assert_eq!(system.execution.as_ref().unwrap().thread_id, 652);
                assert_eq!(system.channel.unwrap(), "Security");
                assert_eq!(system.computer, "win10.windomain.local");
                assert!(system.user_id.is_none());
            }
        }
    }

    #[test]
    fn test_4624_event_data_parsing() {
        let doc = Document::parse(EVENT_4624).expect("Failed to parse Event");
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "EventData" {
                let data = parse_event_data(&node).expect("Failed to parse EventData node");
                match data {
                    DataType::EventData(event) => {
                        assert_eq!(event.named_data.get("SubjectUserSid").unwrap(), "S-1-5-18");
                        assert_eq!(event.named_data.get("SubjectUserName").unwrap(), "WIN10$");
                        assert_eq!(
                            event.named_data.get("SubjectDomainName").unwrap(),
                            "WINDOMAIN"
                        );
                        assert_eq!(event.named_data.get("SubjectLogonId").unwrap(), "0x3e7");
                        assert_eq!(event.named_data.get("TargetUserSid").unwrap(), "S-1-5-18");
                        assert_eq!(event.named_data.get("TargetUserName").unwrap(), "SYSTEM");
                        assert_eq!(
                            event.named_data.get("TargetDomainName").unwrap(),
                            "NT AUTHORITY"
                        );
                        assert_eq!(event.named_data.get("TargetLogonId").unwrap(), "0x3e7");
                        assert_eq!(event.named_data.get("LogonType").unwrap(), "5");
                        assert_eq!(
                            event.named_data.get("LogonProcessName").unwrap(),
                            "Advapi  "
                        );
                        assert_eq!(
                            event.named_data.get("AuthenticationPackageName").unwrap(),
                            "Negotiate"
                        );
                        assert_eq!(event.named_data.get("WorkstationName").unwrap(), "-");
                        assert_eq!(
                            event.named_data.get("LogonGuid").unwrap(),
                            "{00000000-0000-0000-0000-000000000000}"
                        );
                        assert_eq!(event.named_data.get("TransmittedServices").unwrap(), "-");
                        assert_eq!(event.named_data.get("LmPackageName").unwrap(), "-");
                        assert_eq!(event.named_data.get("KeyLength").unwrap(), "0");
                        assert_eq!(event.named_data.get("ProcessId").unwrap(), "0x244");
                        assert_eq!(
                            event.named_data.get("ProcessName").unwrap(),
                            r#"C:\\Windows\\System32\\services.exe"#
                        );
                        assert_eq!(event.named_data.get("IpAddress").unwrap(), "-");
                        assert_eq!(event.named_data.get("IpPort").unwrap(), "-");
                        assert_eq!(
                            event.named_data.get("ImpersonationLevel").unwrap(),
                            "%%1833"
                        );
                        assert_eq!(event.named_data.get("RestrictedAdminMode").unwrap(), "-");
                        assert_eq!(event.named_data.get("TargetOutboundUserName").unwrap(), "-");
                        assert_eq!(
                            event.named_data.get("TargetOutboundDomainName").unwrap(),
                            "-"
                        );
                        assert_eq!(event.named_data.get("VirtualAccount").unwrap(), "%%1843");
                        assert_eq!(event.named_data.get("TargetLinkedLogonId").unwrap(), "0x0");
                        assert_eq!(event.named_data.get("ElevatedToken").unwrap(), "%%1842");
                    }
                    _ => panic!("Wrong EventData node"),
                }
            }
        }
    }

    #[test]
    fn test_4624_rendering_info_parsing() {
        let doc = Document::parse(EVENT_4624).expect("Failed to parse Event");
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "RenderingInfo" {
                let rendering_info =
                    RenderingInfo::from(&node).expect("Failed to parse RenderingInfo node");
                assert_eq!(rendering_info.culture, "en-US");
                assert_eq!(
                    rendering_info.message.unwrap(),
                    r#"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tWIN10$\r\n\tAccount Domain:\t\tWINDOMAIN\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t5\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSYSTEM\r\n\tAccount Domain:\t\tNT AUTHORITY\r\n\tLogon ID:\t\t0x3E7\r\n\tLinked Logon ID:\t\t0x0\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x244\r\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t-\r\n\tSource Port:\t\t-\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tAdvapi  \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."#
                );
                assert_eq!(rendering_info.level.unwrap(), "Information");
                assert_eq!(rendering_info.task.unwrap(), "Logon");
                assert_eq!(rendering_info.opcode.unwrap(), "Info");
                assert_eq!(rendering_info.channel.unwrap(), "Security");
                assert_eq!(
                    rendering_info.provider.unwrap(),
                    "Microsoft Windows security auditing."
                );
                assert_eq!(rendering_info.keywords.unwrap(), ["Audit Success"]);
            }
        }
    }

    const EVENT_4689: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4689</EventID><Version>0</Version><Level>0</Level><Task>13313</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2022-10-27T10:30:06.5647827Z'/><EventRecordID>94071</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='196'/><Channel>Security</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-2892044109-3067629140-1698523921-1000</Data><Data Name='SubjectUserName'>vagrant</Data><Data Name='SubjectDomainName'>WIN10</Data><Data Name='SubjectLogonId'>0x391d2</Data><Data Name='Status'>0x0</Data><Data Name='ProcessId'>0x10fc</Data><Data Name='ProcessName'>C:\\Windows\\System32\\RuntimeBroker.exe</Data></EventData><RenderingInfo Culture='en-US'><Message>A process has exited.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-2892044109-3067629140-1698523921-1000\r\n\tAccount Name:\t\tvagrant\r\n\tAccount Domain:\t\tWIN10\r\n\tLogon ID:\t\t0x391D2\r\n\r\nProcess Information:\r\n\tProcess ID:\t0x10fc\r\n\tProcess Name:\tC:\\Windows\\System32\\RuntimeBroker.exe\r\n\tExit Status:\t0x0</Message><Level>Information</Level><Task>Process Termination</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event>"#;

    #[test]
    fn test_4689_parsing() {
        let event = Event::from_str(
            EVENT_4689,
        );
        assert!(event.additional.error.is_none())
    }

    const RAW_CONTENT_RECOVERED: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4798</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2023-09-29T13:39:08.7234692Z'/><EventRecordID>980236</EventRecordID><Correlation ActivityID='{f59bb999-ec5b-0008-f6b9-9bf55becd901}'/><Execution ProcessID='1440' ThreadID='16952'/><Channel>Security</Channel><Computer>dvas0004_xps</Computer><Security/></System><EventData><Data Name='TargetUserName'>davev</Data><Data Name='TargetDomainName'>xxxxx_xps</Data><Data Name='TargetSid'>S-1-5-21-1604529354-1295832394-4197355770-1001</Data><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>xxxxx_XPS$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='CallerProcessId'>0x28d4</Data><Data Name='CallerProcessName'>C:\\Windows\\System32\\svchost.exe</Data></EventData><RenderingInfo Culture='en-US'><Message>A user's local group membership was enumerated.&#13;&#10;&#13;&#10;Subject:&#13;&#10;&#9;"#;

    #[test]
    fn test_serialize_malformed_raw_content_recovered() {
        // Try to serialize a malformed event, and use the recovering strategy to
        // recover its Raw content
        let event = Event::from_str(
            RAW_CONTENT_RECOVERED,
        );

        let error = event.additional.error.unwrap();
        assert_eq!(error.error_type, ErrorType::RawContentRecovered("Failed to parse event XML (the root node was opened but never closed) but Raw content could be recovered.".to_string()));
        assert_eq!(error.original_content, RAW_CONTENT_RECOVERED);

        let system = event.system.unwrap();
        assert_eq!(system.provider.name.unwrap(), "Microsoft-Windows-Security-Auditing".to_string());
        assert_eq!(system.event_id, 4798);
        assert_eq!(system.execution.unwrap().thread_id, 16952);

        assert!(event.rendering_info.is_none());

        match event.data {
            DataType::EventData(data) => {
                assert_eq!(data.named_data.get("TargetDomainName").unwrap(), "xxxxx_xps");
                assert_eq!(data.named_data.get("TargetSid").unwrap(), "S-1-5-21-1604529354-1295832394-4197355770-1001");
            },
            _ => panic!("Wrong event data type")
        };
    }

    const UNRECOVERABLE_1: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4798</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2023-09-29T13:39:08.7234692Z'/><EventRecordID>980236</EventRecordID><Correlation ActivityID='{f59bb999-ec5b-0008-f6b9-9bf55becd901}'/><Execution ProcessID='1440' ThreadID='16952'/><Channel>Security</Channel><Computer>dvas0004_xps</Computer><Security/></System><EventData><Data Name='TargetUserName'>davev</Data><Data Name='TargetDomainName'>xxxxx_xps</Data><Data Name='TargetSid'>S-1-5-21-1604529354-1295832394-4197355770-1001</Data><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>xxxxx_XPS$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='CallerProcessId'>0x28d4</Data><Data Name='CallerProcessName'>C:\\Windows\\System32\\svchost.exe</Data></EventData>"#;

    #[test]
    fn test_serialize_malformed_unrecoverable_1() {
        // Try to serialize an event for which there is no recovering strategy
        let event = Event::from_str(
            UNRECOVERABLE_1,
        );
        assert!(event.additional.error.is_some());
        assert!(event.system.is_none());
        assert!(event.rendering_info.is_none());

        match event.data {
            DataType::Unknown => (),
            _ => panic!("Wrong event data type")
        };

        let error = event.additional.error.unwrap();
        assert_eq!(error.error_type, ErrorType::Unrecoverable("Failed to parse event XML: the root node was opened but never closed".to_string()));
        assert_eq!(error.original_content, UNRECOVERABLE_1);
    }

    const UNRECOVERABLE_2: &str = r#"<Event xmlns='http://"#;

    #[test]
    fn test_serialize_malformed_unrecoverable_2() {
        // Try to serialize a malformed event for which no recovery
        // is possible.
        let event = Event::from_str(
            UNRECOVERABLE_2,
        );
        assert!(event.additional.error.is_some());
        assert!(event.system.is_none());
        assert!(event.rendering_info.is_none());

        match event.data {
            DataType::Unknown => (),
            _ => panic!("Wrong event data type")
        };

        let error = event.additional.error.unwrap();
        assert_eq!(error.error_type, ErrorType::Unrecoverable("Failed to parse event XML: unexpected end of stream".to_string()));
        assert_eq!(error.original_content, UNRECOVERABLE_2);
    }

    const FAILED_TO_RECOVER_RAW_CONTENT: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4798</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2023-09-29T13:39:08.7234692Z'/><EventRecordID>980236</EventRecordID><Correlation ActivityID='{f59bb999-ec5b-0008-f6b9-9bf55becd901}'/><Execution ProcessID='1440' ThreadID='16952'/><Channel>Security</Channel><Computer>dvas0004_xps</Computer><Security/></System><EventData><Data Name='TargetUserName'>davev</Data><Data Name='TargetDomainName'>xxxxx_xps</Data><Data Name='TargetSid'>S-1-5-21-1604529354-1295832394-4197355770-1001</Data><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>xxxxx_XPS$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='CallerProcessId'>0x28d4</Data><Data Name='CallerProcessName'>C:\\Windows\\System32\\svchost.exe</Data></EventData><RecoveringInfo <RenderingInfo"#;

    #[test]
    fn test_serialize_failed_to_recover() {
        // Try to serialize a malformed event for which the recovering strategy can
        // not succeed
        let event = Event::from_str(
            FAILED_TO_RECOVER_RAW_CONTENT,
        );
        assert!(event.additional.error.is_some());
        assert!(event.system.is_none());
        assert!(event.rendering_info.is_none());

        match event.data {
            DataType::Unknown => (),
            _ => panic!("Wrong event data type")
        };

        let error = event.additional.error.unwrap();
        assert_eq!(error.error_type, ErrorType::FailedToRecoverRawContent("Failed to parse event XML (invalid name token at 1:1088) and Raw content recovering failed (invalid name token at 1:1088)".to_string()));
        assert_eq!(error.original_content, FAILED_TO_RECOVER_RAW_CONTENT);
    }

    const FAILED_TO_FEED_EVENT: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><WrongEventID>4798</WrongEventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2023-09-29T13:39:08.7234692Z'/><EventRecordID>980236</EventRecordID><Correlation ActivityID='{f59bb999-ec5b-0008-f6b9-9bf55becd901}'/><Execution ProcessID='1440' ThreadID='16952'/><Channel>Security</Channel><Computer>dvas0004_xps</Computer><Security/></System><EventData><Data Name='TargetUserName'>davev</Data><Data Name='TargetDomainName'>xxxxx_xps</Data><Data Name='TargetSid'>S-1-5-21-1604529354-1295832394-4197355770-1001</Data><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>xxxxx_XPS$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='CallerProcessId'>0x28d4</Data><Data Name='CallerProcessName'>C:\\Windows\\System32\\svchost.exe</Data></EventData><RenderingInfo Culture='en-US'><Message>A use"#;

    #[test]
    fn test_serialize_malformed_failed_to_feed_event() {
        // Try to serialize a malformed event for which the recovering strategy can
        // not succeed because <System> is invalid.
        let event = Event::from_str(
            FAILED_TO_FEED_EVENT,
        );
        assert!(event.additional.error.is_some());
        assert!(event.system.is_none());
        assert!(event.rendering_info.is_none());

        match event.data {
            DataType::Unknown => (),
            _ => panic!("Wrong event data type")
        };

        let error = event.additional.error.unwrap();
        assert_eq!(error.error_type, ErrorType::FailedToFeedEvent("Could not feed event from document: Parsing failure in System".to_string()));
        assert_eq!(error.original_content, FAILED_TO_FEED_EVENT);
    }
} 