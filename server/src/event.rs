use anyhow::{anyhow, bail, Context, Result};
use log::{info, trace};
use roxmltree::{Document, Node};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr};

#[derive(Debug, Default, Serialize, Clone)]
pub struct EventDataType {
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    named_data: HashMap<String, String>,
    #[serde(rename = "Data", skip_serializing_if = "Vec::is_empty")]
    unamed_data: Vec<String>,
    #[serde(rename = "Binary", skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct DebugDataType {
    #[serde(rename = "SequenceNumber", skip_serializing_if = "Option::is_none")]
    sequence_number: Option<u32>,
    #[serde(rename = "FlagsName", skip_serializing_if = "Option::is_none")]
    flags_name: Option<String>,
    #[serde(rename = "LevelName", skip_serializing_if = "Option::is_none")]
    level_name: Option<String>,
    #[serde(rename = "Component")]
    component: String,
    #[serde(rename = "SubComponent", skip_serializing_if = "Option::is_none")]
    sub_component: Option<String>,
    #[serde(rename = "FileLine", skip_serializing_if = "Option::is_none")]
    file_line: Option<String>,
    #[serde(rename = "Function", skip_serializing_if = "Option::is_none")]
    function: Option<String>,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct ProcessingErrorDataType {
    #[serde(rename = "ErrorCode")]
    error_code: u32,
    #[serde(rename = "DataItemName")]
    data_item_name: String,
    #[serde(rename = "EventPayload")]
    event_payload: String,
}

pub type UserDataType = String;
pub type BinaryEventDataType = String;

#[derive(Debug, Default, Serialize, Clone)]
pub enum DataType {
    EventData(EventDataType),
    UserData(UserDataType),
    DebugData(DebugDataType),
    ProcessingErrorData(ProcessingErrorDataType),
    BinaryEventData(BinaryEventDataType),
    #[default]
    Unknown,
}

impl DataType {
    fn is_unknown(&self) -> bool {
        matches!(self, DataType::Unknown)
    }
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct Event {
    #[serde(rename = "System")]
    system: System,
    #[serde(flatten, skip_serializing_if = "DataType::is_unknown")]
    data: DataType,
    #[serde(rename = "RenderingInfo")]
    rendering_info: RenderingInfo,
    #[serde(rename = "OpenWEC")]
    additional: Additional,
}

impl Event {
    pub fn from_str(
        addr: &str,
        principal: &str,
        time_received: &str,
        subscription_uuid: &str,
        subscription_version: &str,
        subscription_name: &str,
        subscription_uri: Option<&String>,
        content: &str,
    ) -> Result<Self> {
        let doc = Document::parse(content).context("Failed to parse event XML")?;
        let mut event = Event::default();
        event.additional = Additional {
            addr: addr.to_owned(),
            principal: principal.to_owned(),
            time_received: time_received.to_owned(),
            subscription: SubscriptionType {
                uuid: subscription_uuid.to_owned(),
                version: subscription_version.to_owned(),
                name: subscription_name.to_owned(),
                uri: subscription_uri.cloned(),
            },
        };
        let root = doc.root_element();
        for node in root.children() {
            if node.tag_name().name() == "System" {
                event.system = System::from(&node).context("Parsing failure in System")?
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
                    RenderingInfo::from(&node).context("Parsing failure in RenderingInfo")?
            } else if node.tag_name().name() == "SubscriptionBookmarkEvent" {
                // Nothing to do, this node is present in the first received event (EventID 111)
            } else {
                info!("Unknown node {} when parsing Event", node.tag_name().name());
                trace!("Event was: {}", content);
            }
        }

        Ok(event)
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

#[derive(Debug, Default, Serialize, Clone)]
struct Additional {
    #[serde(rename = "IpAddress")]
    addr: String,
    #[serde(rename = "TimeReceived")]
    time_received: String,
    #[serde(rename = "Principal")]
    principal: String,
    #[serde(rename = "Subscription")]
    subscription: SubscriptionType,
}

#[derive(Debug, Default, Serialize, Clone)]
struct SubscriptionType {
    #[serde(rename = "Uuid")]
    uuid: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Uri", skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct Provider {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Guid")]
    pub guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EventSourceName")]
    pub event_source_name: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct Correlation {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ActivityID")]
    pub activity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "RelatedActivityID")]
    pub related_activity_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct Execution {
    #[serde(rename = "ProcessID")]
    pub process_id: u32,

    #[serde(rename = "ThreadID")]
    pub thread_id: u32,

    #[serde(rename = "ProcessorID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor_id: Option<u8>,

    #[serde(rename = "SessionID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,

    #[serde(rename = "KernelTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_time: Option<u32>,

    #[serde(rename = "UserTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_time: Option<u32>,

    #[serde(rename = "ProcessorTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor_time: Option<u32>,
}

#[derive(Debug, Default, Serialize, Clone)]
struct System {
    #[serde(rename = "Provider")]
    provider: Provider,
    #[serde(rename = "EventID")]
    event_id: u32,
    #[serde(rename = "EventIDQualifiers", skip_serializing_if = "Option::is_none")]
    event_id_qualifiers: Option<u16>,
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    version: Option<u8>,
    #[serde(rename = "Level", skip_serializing_if = "Option::is_none")]
    level: Option<u8>,
    #[serde(rename = "Task", skip_serializing_if = "Option::is_none")]
    task: Option<u16>,
    #[serde(rename = "Opcode", skip_serializing_if = "Option::is_none")]
    opcode: Option<u8>,
    #[serde(rename = "Keywords", skip_serializing_if = "Option::is_none")]
    keywords: Option<String>,
    #[serde(rename = "TimeCreated", skip_serializing_if = "Option::is_none")]
    time_created: Option<String>,
    #[serde(rename = "EventRecordID", skip_serializing_if = "Option::is_none")]
    event_record_id: Option<u64>,
    #[serde(rename = "Correlation", skip_serializing_if = "Option::is_none")]
    correlation: Option<Correlation>,
    #[serde(rename = "Execution", skip_serializing_if = "Option::is_none")]
    execution: Option<Execution>,
    #[serde(rename = "Channel", skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(rename = "Computer")]
    computer: String,
    #[serde(rename = "Container", skip_serializing_if = "Option::is_none")]
    container: Option<String>,
    #[serde(rename = "UserID", skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
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
struct RenderingInfo {
    #[serde(rename = "Message", skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(rename = "Level", skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    #[serde(rename = "Task", skip_serializing_if = "Option::is_none")]
    task: Option<String>,
    #[serde(rename = "Opcode", skip_serializing_if = "Option::is_none")]
    opcode: Option<String>,
    #[serde(rename = "Channel", skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(rename = "Provider", skip_serializing_if = "Option::is_none")]
    // Microsoft schema states that this field should be called "Publisher"
    // but this is not what has been observed in practice
    provider: Option<String>,
    #[serde(rename = "Keywords", skip_serializing_if = "Option::is_none")]
    keywords: Option<Vec<String>>,
    #[serde(rename = "Culture")]
    culture: String,
}

impl RenderingInfo {
    fn from(rendering_info_node: &Node) -> Result<RenderingInfo> {
        let mut rendering_info = RenderingInfo::default();

        rendering_info.culture = rendering_info_node
            .attribute("Culture")
            .unwrap_or_default()
            .to_owned();
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
    addr: SocketAddr,
    principal: String,
    node_name: Option<String>,
}

impl EventMetadata {
    pub fn new(addr: &SocketAddr, principal: &str, node_name: Option<String>) -> Self {
        EventMetadata {
            addr: *addr,
            principal: principal.to_owned(),
            node_name,
        }
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
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

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
        Event::from_str(
            "192.168.0.1",
            "win10.windomain.local",
            "2022-11-07T17:08:27.169805+01:00",
            "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
            "AD0D118F-31EF-4111-A0CA-D87249747278",
            "Test",
            Some(&"/this/is/a/test".to_string()),
            EVENT_4689,
        )
        .expect("Failed to parse Event");
    }

    const EVENT_4688: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:06:51.0643605Z'/><EventRecordID>114689</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='196'/><Channel>Security</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>WIN10$</Data><Data Name='SubjectDomainName'>WINDOMAIN</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='NewProcessId'>0x3a8</Data><Data Name='NewProcessName'>C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe</Data><Data Name='TokenElevationType'>%%1936</Data><Data Name='ProcessId'>0x240</Data><Data Name='CommandLine'></Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>-</Data><Data Name='TargetDomainName'>-</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='ParentProcessName'>C:\Windows\System32\services.exe</Data><Data Name='MandatoryLabel'>S-1-16-16384</Data></EventData><RenderingInfo Culture='en-US'><Message>A new process has been created.

Creator Subject:
	Security ID:		S-1-5-18
	Account Name:		WIN10$
	Account Domain:		WINDOMAIN
	Logon ID:		0x3E7

Target Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x3a8
	New Process Name:	C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe
	Token Elevation Type:	%%1936
	Mandatory Label:		S-1-16-16384
	Creator Process ID:	0x240
	Creator Process Name:	C:\Windows\System32\services.exe
	Process Command Line:	

Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.

Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.

Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.</Message><Level>Information</Level><Task>Process Creation</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_4688_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-Security-Auditing","Guid":"{54849625-5478-4994-a5ba-3e3b0328c30d}"},"EventID":4688,"Version":2,"Level":0,"Task":13312,"Opcode":0,"Keywords":"0x8020000000000000","TimeCreated":"2022-12-14T16:06:51.0643605Z","EventRecordID":114689,"Correlation":{},"Execution":{"ProcessID":4,"ThreadID":196},"Channel":"Security","Computer":"win10.windomain.local"},"EventData":{"SubjectLogonId":"0x3e7","SubjectUserName":"WIN10$","SubjectDomainName":"WINDOMAIN","ParentProcessName":"C:\\Windows\\System32\\services.exe","MandatoryLabel":"S-1-16-16384","SubjectUserSid":"S-1-5-18","NewProcessName":"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe","TokenElevationType":"%%1936","TargetUserSid":"S-1-0-0","TargetDomainName":"-","CommandLine":"","TargetUserName":"-","NewProcessId":"0x3a8","TargetLogonId":"0x0","ProcessId":"0x240"},"RenderingInfo":{"Message":"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWIN10$\n\tAccount Domain:\t\tWINDOMAIN\n\tLogon ID:\t\t0x3E7\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x3a8\n\tNew Process Name:\tC:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\n\tToken Elevation Type:\t%%1936\n\tMandatory Label:\t\tS-1-16-16384\n\tCreator Process ID:\t0x240\n\tCreator Process Name:\tC:\\Windows\\System32\\services.exe\n\tProcess Command Line:\t\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.","Level":"Information","Task":"Process Creation","Opcode":"Info","Channel":"Security","Provider":"Microsoft Windows security auditing.","Keywords":["Audit Success"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T17:07:03.331+01:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"AD0D118F-31EF-4111-A0CA-D87249747278","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_4688_event_data() {
        let event = Event::from_str(
            "192.168.58.100",
            "WIN10$@WINDOMAIN.LOCAL",
            "2022-12-14T17:07:03.331+01:00",
            "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
            "AD0D118F-31EF-4111-A0CA-D87249747278",
            "Test",
            Some(&"/this/is/a/test".to_string()),
            EVENT_4688,
        )
        .expect("Failed to parse Event");

        let event_json = serde_json::to_string(&event).unwrap();

        let event_json_value: Value = serde_json::from_str(&event_json).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_4688_JSON).unwrap();

        println!("{}", event_json_value);
        println!("{}", expected_value);
        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_1003: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-SPP' Guid='{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}' EventSourceName='Software Protection Platform Service'/><EventID Qualifiers='16384'>1003</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:05:59.7074374Z'/><EventRecordID>7603</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>Application</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data>55c92734-d682-4d71-983e-d6ec3f16059f</Data><Data>
1: 3f4c0546-36c6-46a8-a37f-be13cdd0cf25, 1, 1 [(0 [0xC004E003, 0, 0], [( 9 0xC004FC07 90 0)( 1 0x00000000)(?)( 2 0x00000000 0 0 msft:rm/algorithm/hwid/4.0 0x00000000 0)(?)( 9 0xC004FC07 90 0)( 10 0x00000000 msft:rm/algorithm/flags/1.0)(?)])(1 )(2 )(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004FC07)])]

</Data></EventData><RenderingInfo Culture='en-US'><Message>The Software Protection service has completed licensing status check.
Application Id=55c92734-d682-4d71-983e-d6ec3f16059f
Licensing Status=
1: 3f4c0546-36c6-46a8-a37f-be13cdd0cf25, 1, 1 [(0 [0xC004E003, 0, 0], [( 9 0xC004FC07 90 0)( 1 0x00000000)(?)( 2 0x00000000 0 0 msft:rm/algorithm/hwid/4.0 0x00000000 0)(?)( 9 0xC004FC07 90 0)( 10 0x00000000 msft:rm/algorithm/flags/1.0)(?)])(1 )(2 )(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004FC07)])]

</Message><Level>Information</Level><Task></Task><Opcode></Opcode><Channel></Channel><Provider>Microsoft-Windows-Security-SPP</Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>
    "#;
    const EVENT_1003_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-Security-SPP","Guid":"{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}","EventSourceName":"Software Protection Platform Service"},"EventID":1003,"EventIDQualifiers":16384,"Version":0,"Level":4,"Task":0,"Opcode":0,"Keywords":"0x80000000000000","TimeCreated":"2022-12-14T16:05:59.7074374Z","EventRecordID":7603,"Correlation":{},"Execution":{"ProcessID":0,"ThreadID":0},"Channel":"Application","Computer":"win10.windomain.local"},"EventData":{"Data":["55c92734-d682-4d71-983e-d6ec3f16059f","\n1: 3f4c0546-36c6-46a8-a37f-be13cdd0cf25, 1, 1 [(0 [0xC004E003, 0, 0], [( 9 0xC004FC07 90 0)( 1 0x00000000)(?)( 2 0x00000000 0 0 msft:rm/algorithm/hwid/4.0 0x00000000 0)(?)( 9 0xC004FC07 90 0)( 10 0x00000000 msft:rm/algorithm/flags/1.0)(?)])(1 )(2 )(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004FC07)])]\n\n"]},"RenderingInfo":{"Message":"The Software Protection service has completed licensing status check.\nApplication Id=55c92734-d682-4d71-983e-d6ec3f16059f\nLicensing Status=\n1: 3f4c0546-36c6-46a8-a37f-be13cdd0cf25, 1, 1 [(0 [0xC004E003, 0, 0], [( 9 0xC004FC07 90 0)( 1 0x00000000)(?)( 2 0x00000000 0 0 msft:rm/algorithm/hwid/4.0 0x00000000 0)(?)( 9 0xC004FC07 90 0)( 10 0x00000000 msft:rm/algorithm/flags/1.0)(?)])(1 )(2 )(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004FC07)])]\n\n","Level":"Information","Provider":"Microsoft-Windows-Security-SPP","Keywords":["Classic"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T17:07:03.324+01:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"AD0D118F-31EF-4111-A0CA-D87249747278","Name":"Test"}}}"#;

    #[test]
    fn test_serialize_1003_event_data_unamed() {
        let event = Event::from_str(
            "192.168.58.100",
            "WIN10$@WINDOMAIN.LOCAL",
            "2022-12-14T17:07:03.324+01:00",
            "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
            "AD0D118F-31EF-4111-A0CA-D87249747278",
            "Test",
            None,
            EVENT_1003,
        )
        .expect("Failed to parse Event");

        let event_json = serde_json::to_string(&event).unwrap();

        let event_json_value: Value = serde_json::from_str(&event_json).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_1003_JSON).unwrap();

        println!("{}", event_json_value);
        println!("{}", expected_value);
        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_5719: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='NETLOGON'/><EventID Qualifiers='0'>5719</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:04:59.0817047Z'/><EventRecordID>9466</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>System</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data>WINDOMAIN</Data><Data>%%1311</Data><Binary>5E0000C0</Binary></EventData><RenderingInfo Culture='en-US'><Message>This computer was not able to set up a secure session with a domain controller in domain WINDOMAIN due to the following: 
We can't sign you in with this credential because your domain isn't available. Make sure your device is connected to your organization's network and try again. If you previously signed in on this device with another credential, you can sign in with that credential. 
This may lead to authentication problems. Make sure that this computer is connected to the network. If the problem persists, please contact your domain administrator.  

ADDITIONAL INFO 
If this computer is a domain controller for the specified domain, it sets up the secure session to the primary domain controller emulator in the specified domain. Otherwise, this computer sets up the secure session to any domain controller in the specified domain.</Message><Level>Error</Level><Task></Task><Opcode>Info</Opcode><Channel></Channel><Provider></Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_5719_JSON: &str = r#"{"System":{"Provider":{"Name":"NETLOGON"},"EventID":5719,"EventIDQualifiers":0,"Version":0,"Level":2,"Task":0,"Opcode":0,"Keywords":"0x80000000000000","TimeCreated":"2022-12-14T16:04:59.0817047Z","EventRecordID":9466,"Correlation":{},"Execution":{"ProcessID":0,"ThreadID":0},"Channel":"System","Computer":"win10.windomain.local"},"EventData":{"Data":["WINDOMAIN","%%1311"],"Binary":"5E0000C0"},"RenderingInfo":{"Message":"This computer was not able to set up a secure session with a domain controller in domain WINDOMAIN due to the following: \nWe can't sign you in with this credential because your domain isn't available. Make sure your device is connected to your organization's network and try again. If you previously signed in on this device with another credential, you can sign in with that credential. \nThis may lead to authentication problems. Make sure that this computer is connected to the network. If the problem persists, please contact your domain administrator.  \n\nADDITIONAL INFO \nIf this computer is a domain controller for the specified domain, it sets up the secure session to the primary domain controller emulator in the specified domain. Otherwise, this computer sets up the secure session to any domain controller in the specified domain.","Level":"Error","Opcode":"Info","Keywords":["Classic"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T17:07:02.919+01:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"AD0D118F-31EF-4111-A0CA-D87249747278","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_5719_event_data_binary() {
        let event = Event::from_str(
            "192.168.58.100",
            "WIN10$@WINDOMAIN.LOCAL",
            "2022-12-14T17:07:02.919+01:00",
            "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
            "AD0D118F-31EF-4111-A0CA-D87249747278",
            "Test",
            Some(&"/this/is/a/test".to_string()),
            EVENT_5719,
        )
        .expect("Failed to parse Event");

        let event_json = serde_json::to_string(&event).unwrap();

        let event_json_value: Value = serde_json::from_str(&event_json).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_5719_JSON).unwrap();

        println!("{}", event_json_value);
        println!("{}", expected_value);
        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_6013: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='EventLog'/><EventID Qualifiers='32768'>6013</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:04:43.7965565Z'/><EventRecordID>9427</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>System</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data></Data><Data></Data><Data></Data><Data></Data><Data>6</Data><Data>60</Data><Data>0 Coordinated Universal Time</Data><Binary>31002E003100000030000000570069006E0064006F0077007300200031003000200045006E007400650072007000720069007300650020004500760061006C0075006100740069006F006E000000310030002E0030002E003100390030003400330020004200750069006C0064002000310039003000340033002000200000004D0075006C0074006900700072006F0063006500730073006F007200200046007200650065000000310039003000340031002E00760062005F00720065006C0065006100730065002E003100390031003200300036002D00310034003000360000003600320031003400640066003100630000004E006F007400200041007600610069006C00610062006C00650000004E006F007400200041007600610069006C00610062006C00650000003900000031000000320030003400380000003400300039000000770069006E00310030002E00770069006E0064006F006D00610069006E002E006C006F00630061006C0000000000</Binary></EventData><RenderingInfo Culture='en-US'><Message>The system uptime is 6 seconds.</Message><Level>Information</Level><Task></Task><Opcode></Opcode><Channel></Channel><Provider></Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_6013_JSON: &str = r#"{"System":{"Provider":{"Name":"EventLog"},"EventID":6013,"EventIDQualifiers":32768,"Version":0,"Level":4,"Task":0,"Opcode":0,"Keywords":"0x80000000000000","TimeCreated":"2022-12-14T16:04:43.7965565Z","EventRecordID":9427,"Correlation":{},"Execution":{"ProcessID":0,"ThreadID":0},"Channel":"System","Computer":"win10.windomain.local"},"EventData":{"Data":["6","60","0 Coordinated Universal Time"],"Binary":"31002E003100000030000000570069006E0064006F0077007300200031003000200045006E007400650072007000720069007300650020004500760061006C0075006100740069006F006E000000310030002E0030002E003100390030003400330020004200750069006C0064002000310039003000340033002000200000004D0075006C0074006900700072006F0063006500730073006F007200200046007200650065000000310039003000340031002E00760062005F00720065006C0065006100730065002E003100390031003200300036002D00310034003000360000003600320031003400640066003100630000004E006F007400200041007600610069006C00610062006C00650000004E006F007400200041007600610069006C00610062006C00650000003900000031000000320030003400380000003400300039000000770069006E00310030002E00770069006E0064006F006D00610069006E002E006C006F00630061006C0000000000"},"RenderingInfo":{"Message":"The system uptime is 6 seconds.","Level":"Information","Keywords":["Classic"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T17:07:02.524+01:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"AD0D118F-31EF-4111-A0CA-D87249747278","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_6013_event_data_unamed_empty() {
        let event = Event::from_str(
            "192.168.58.100",
            "WIN10$@WINDOMAIN.LOCAL",
            "2022-12-14T17:07:02.524+01:00",
            "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
            "AD0D118F-31EF-4111-A0CA-D87249747278",
            "Test",
            Some(&"/this/is/a/test".to_string()),
            EVENT_6013,
        )
        .expect("Failed to parse Event");

        let event_json = serde_json::to_string(&event).unwrap();

        let event_json_value: Value = serde_json::from_str(&event_json).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_6013_JSON).unwrap();

        println!("{}", event_json_value);
        println!("{}", expected_value);
        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_1100: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1100</EventID><Version>0</Version><Level>4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2022-12-14T14:39:07.1686183Z'/><EventRecordID>114371</EventRecordID><Correlation/><Execution ProcessID='496' ThreadID='204'/><Channel>Security</Channel><Computer>win10.windomain.local</Computer><Security/></System><UserData><ServiceShutdown xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'></ServiceShutdown></UserData><RenderingInfo Culture='en-US'><Message>The event logging service has shut down.</Message><Level>Information</Level><Task>Service shutdown</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft-Windows-Eventlog</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_1100_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-Eventlog","Guid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"},"EventID":1100,"Version":0,"Level":4,"Task":103,"Opcode":0,"Keywords":"0x4020000000000000","TimeCreated":"2022-12-14T14:39:07.1686183Z","EventRecordID":114371,"Correlation":{},"Execution":{"ProcessID":496,"ThreadID":204},"Channel":"Security","Computer":"win10.windomain.local"},"UserData":"<ServiceShutdown xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'></ServiceShutdown>","RenderingInfo":{"Message":"The event logging service has shut down.","Level":"Information","Task":"Service shutdown","Opcode":"Info","Channel":"Security","Provider":"Microsoft-Windows-Eventlog","Keywords":["Audit Success"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T17:07:02.156+01:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"AD0D118F-31EF-4111-A0CA-D87249747278","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_1100_user_data() {
        let event = Event::from_str(
            "192.168.58.100",
            "WIN10$@WINDOMAIN.LOCAL",
            "2022-12-14T17:07:02.156+01:00",
            "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
            "AD0D118F-31EF-4111-A0CA-D87249747278",
            "Test",
            Some(&"/this/is/a/test".to_string()),
            EVENT_1100,
        )
        .expect("Failed to parse Event");

        let event_json = serde_json::to_string(&event).unwrap();

        let event_json_value: Value = serde_json::from_str(&event_json).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_1100_JSON).unwrap();

        println!("{}", event_json_value);
        println!("{}", expected_value);
        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_111: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-EventForwarder'/><EventID>111</EventID><TimeCreated SystemTime='2023-02-14T09:14:23.175Z'/><Computer>win10.windomain.local</Computer></System><SubscriptionBookmarkEvent><SubscriptionId></SubscriptionId></SubscriptionBookmarkEvent></Event>"#;
    const EVENT_111_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-EventForwarder"},"EventID":111,"TimeCreated":"2023-02-14T09:14:23.175Z","Computer":"win10.windomain.local"},"RenderingInfo":{"Culture":""},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T17:07:02.156+01:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"AD0D118F-31EF-4111-A0CA-D87249747278","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_111() {
        let event = Event::from_str(
            "192.168.58.100",
            "WIN10$@WINDOMAIN.LOCAL",
            "2022-12-14T17:07:02.156+01:00",
            "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
            "AD0D118F-31EF-4111-A0CA-D87249747278",
            "Test",
            Some(&"/this/is/a/test".to_string()),
            EVENT_111,
        )
        .expect("Failed to parse Event");

        let event_json = serde_json::to_string(&event).expect("Failed to serialize event");

        let event_json_value: Value = serde_json::from_str(&event_json).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_111_JSON).unwrap();

        assert_eq!(event_json_value, expected_value);
    }
}
