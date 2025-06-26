use std::{collections::HashMap, fmt::Debug, sync::Arc};

use log::warn;
use serde::Serialize;

use crate::{
    event::{EventData, EventMetadata},
    output::OutputFormat,
};

pub struct JsonFormat;

impl OutputFormat for JsonFormat {
    fn format(&self, metadata: &EventMetadata, data: &EventData) -> Option<Arc<String>> {
        if let Some(event) = data.event() {
            let json_event = JsonEvent::new(event.clone(), metadata);
            match serde_json::to_string(&json_event) {
                Ok(str) => Some(Arc::new(str)),
                Err(e) => {
                    warn!(
                        "Failed to serialize event in JSON: {:?}. Event was: {:?}",
                        e, event
                    );
                    None
                }
            }
        } else {
            warn!("Failed to retrieve parsed event");
            None
        }
    }
}

#[derive(Debug, Serialize)]
struct EventDataType {
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    named_data: HashMap<String, String>,
    #[serde(rename = "Data", skip_serializing_if = "Vec::is_empty")]
    unamed_data: Vec<String>,
    #[serde(rename = "Binary", skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
}

impl From<crate::event::EventDataType> for EventDataType {
    fn from(value: crate::event::EventDataType) -> Self {
        Self {
            named_data: value.named_data,
            unamed_data: value.unamed_data,
            binary: value.binary,
        }
    }
}

#[derive(Debug, Serialize)]
struct DebugDataType {
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

impl From<crate::event::DebugDataType> for DebugDataType {
    fn from(value: crate::event::DebugDataType) -> Self {
        Self {
            sequence_number: value.sequence_number,
            flags_name: value.flags_name,
            level_name: value.level_name,
            component: value.component,
            sub_component: value.sub_component,
            file_line: value.file_line,
            function: value.function,
            message: value.message,
        }
    }
}

#[derive(Debug, Serialize)]
struct ProcessingErrorDataType {
    #[serde(rename = "ErrorCode")]
    error_code: u32,
    #[serde(rename = "DataItemName")]
    data_item_name: String,
    #[serde(rename = "EventPayload")]
    event_payload: String,
}

impl From<crate::event::ProcessingErrorDataType> for ProcessingErrorDataType {
    fn from(value: crate::event::ProcessingErrorDataType) -> Self {
        Self {
            error_code: value.error_code,
            data_item_name: value.data_item_name,
            event_payload: value.event_payload,
        }
    }
}

#[derive(Debug, Serialize)]
enum DataType {
    EventData(EventDataType),
    UserData(String),
    DebugData(DebugDataType),
    ProcessingErrorData(ProcessingErrorDataType),
    BinaryEventData(String),
    Unknown,
}

impl DataType {
    fn is_unknown(&self) -> bool {
        matches!(self, DataType::Unknown)
    }
}

impl From<crate::event::DataType> for DataType {
    fn from(value: crate::event::DataType) -> Self {
        match value {
            crate::event::DataType::EventData(t) => DataType::EventData(t.into()),
            crate::event::DataType::UserData(t) => DataType::UserData(t),
            crate::event::DataType::DebugData(t) => DataType::DebugData(t.into()),
            crate::event::DataType::ProcessingErrorData(t) => {
                DataType::ProcessingErrorData(t.into())
            }
            crate::event::DataType::BinaryEventData(t) => DataType::BinaryEventData(t),
            crate::event::DataType::Unknown => DataType::Unknown,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "Type")]
enum ErrorType {
    /// Initial XML parsing failed but Raw content could be recovered
    RawContentRecovered {
        #[serde(rename = "Message")]
        message: String,
    },
    /// Initial XML parsing failed and recovering failed again
    FailedToRecoverRawContent {
        #[serde(rename = "Message")]
        message: String,
    },
    /// Initial XML parsing failed and no recovering strategy was usable
    Unrecoverable {
        #[serde(rename = "Message")]
        message: String,
    },
    /// Failed to feed event from parsed XML document
    FailedToFeedEvent {
        #[serde(rename = "Message")]
        message: String,
    },
    Unknown,
}

impl From<crate::event::ErrorType> for ErrorType {
    fn from(value: crate::event::ErrorType) -> Self {
        match value {
            crate::event::ErrorType::RawContentRecovered(message) => {
                ErrorType::RawContentRecovered { message }
            }
            crate::event::ErrorType::FailedToRecoverRawContent(message) => {
                ErrorType::FailedToRecoverRawContent { message }
            }
            crate::event::ErrorType::Unrecoverable(message) => ErrorType::Unrecoverable { message },
            crate::event::ErrorType::FailedToFeedEvent(message) => {
                ErrorType::FailedToFeedEvent { message }
            }
            crate::event::ErrorType::Unknown => ErrorType::Unknown,
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorInfo {
    #[serde(rename = "OriginalContent")]
    original_content: String,
    #[serde(flatten)]
    error_type: ErrorType,
}

impl From<crate::event::ErrorInfo> for ErrorInfo {
    fn from(value: crate::event::ErrorInfo) -> Self {
        Self {
            original_content: value.original_content,
            error_type: value.error_type.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonEvent {
    #[serde(rename = "System", skip_serializing_if = "Option::is_none")]
    system: Option<System>,
    #[serde(flatten, skip_serializing_if = "DataType::is_unknown")]
    data: DataType,
    #[serde(rename = "RenderingInfo", skip_serializing_if = "Option::is_none")]
    rendering_info: Option<RenderingInfo>,
    #[serde(rename = "OpenWEC")]
    additional: Additional,
}

impl JsonEvent {
    pub fn new(event: crate::event::Event, metadata: &EventMetadata) -> Self {
        Self {
            system: event.system.map(Into::into),
            data: event.data.into(),
            rendering_info: event.rendering_info.map(Into::into),
            additional: Additional::new(event.additional, metadata),
        }
    }
}

#[derive(Debug, Serialize)]
struct Additional {
    #[serde(rename = "IpAddress")]
    addr: String,
    #[serde(rename = "TimeReceived")]
    time_received: String,
    #[serde(rename = "Principal")]
    principal: String,
    #[serde(rename = "Subscription")]
    subscription: SubscriptionType,
    #[serde(rename = "Node", skip_serializing_if = "Option::is_none")]
    node: Option<String>,
    #[serde(rename = "Error", skip_serializing_if = "Option::is_none")]
    error: Option<ErrorInfo>,
}

impl Additional {
    pub fn new(additional: crate::event::Additional, metadata: &EventMetadata) -> Self {
        Self {
            addr: metadata.addr().ip().to_string(),
            principal: metadata.principal().to_owned(), // TODO : change to something that works for TLS as well (modify db and output)
            node: metadata.node_name().cloned(),
            time_received: metadata.time_received().to_rfc3339(),
            subscription: SubscriptionType {
                uuid: metadata.subscription_uuid().to_owned(),
                version: metadata.subscription_version().to_owned(),
                name: metadata.subscription_name().to_owned(),
                uri: metadata.subscription_uri().cloned(),
                client_revision: metadata.subscription_client_revision().cloned(),
                server_revision: metadata.subscription_server_revision().cloned(),
            },
            error: additional.error.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct SubscriptionType {
    #[serde(rename = "Uuid")]
    uuid: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Uri", skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(rename = "ClientRevision", skip_serializing_if = "Option::is_none")]
    client_revision: Option<String>,
    #[serde(rename = "ServerRevision", skip_serializing_if = "Option::is_none")]
    server_revision: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct Provider {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Guid")]
    guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EventSourceName")]
    event_source_name: Option<String>,
}

impl From<crate::event::Provider> for Provider {
    fn from(value: crate::event::Provider) -> Self {
        Self {
            name: value.name,
            guid: value.guid,
            event_source_name: value.event_source_name,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct Correlation {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ActivityID")]
    activity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "RelatedActivityID")]
    related_activity_id: Option<String>,
}

impl From<crate::event::Correlation> for Correlation {
    fn from(value: crate::event::Correlation) -> Self {
        Self {
            activity_id: value.activity_id,
            related_activity_id: value.related_activity_id,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct Execution {
    #[serde(rename = "ProcessID")]
    process_id: u32,
    #[serde(rename = "ThreadID")]
    thread_id: u32,
    #[serde(rename = "ProcessorID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    processor_id: Option<u8>,
    #[serde(rename = "SessionID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<u32>,
    #[serde(rename = "KernelTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_time: Option<u32>,
    #[serde(rename = "UserTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    user_time: Option<u32>,
    #[serde(rename = "ProcessorTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    processor_time: Option<u32>,
}

impl From<crate::event::Execution> for Execution {
    fn from(value: crate::event::Execution) -> Self {
        Self {
            process_id: value.process_id,
            thread_id: value.thread_id,
            processor_id: value.processor_id,
            session_id: value.session_id,
            kernel_time: value.kernel_time,
            user_time: value.user_time,
            processor_time: value.processor_time,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
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

impl From<crate::event::System> for System {
    fn from(value: crate::event::System) -> Self {
        Self {
            provider: value.provider.into(),
            event_id: value.event_id,
            event_id_qualifiers: value.event_id_qualifiers,
            version: value.version,
            level: value.level,
            task: value.task,
            opcode: value.opcode,
            keywords: value.keywords,
            time_created: value.time_created,
            event_record_id: value.event_record_id,
            correlation: value.correlation.map(Into::into),
            execution: value.execution.map(Into::into),
            channel: value.channel,
            computer: value.computer,
            container: value.container,
            user_id: value.user_id,
        }
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
    provider: Option<String>,
    #[serde(rename = "Keywords", skip_serializing_if = "Option::is_none")]
    keywords: Option<Vec<String>>,
    #[serde(rename = "Culture")]
    culture: String,
}

impl From<crate::event::RenderingInfo> for RenderingInfo {
    fn from(value: crate::event::RenderingInfo) -> Self {
        Self {
            message: value.message,
            level: value.level,
            task: value.task,
            opcode: value.opcode,
            channel: value.channel,
            provider: value.provider,
            keywords: value.keywords,
            culture: value.culture,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, sync::Arc};

    use chrono::Utc;
    use common::{
        settings,
        subscription::{SubscriptionData, SubscriptionUuid},
    };
    use serde_json::Value;
    use uuid::Uuid;

    use crate::{
        event::{EventData, EventMetadata},
        formats::json::JsonFormat,
        output::{OutputDriversContext, OutputFormat},
        subscription::Subscription,
    };

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
    const EVENT_4688_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-Security-Auditing","Guid":"{54849625-5478-4994-a5ba-3e3b0328c30d}"},"EventID":4688,"Version":2,"Level":0,"Task":13312,"Opcode":0,"Keywords":"0x8020000000000000","TimeCreated":"2022-12-14T16:06:51.0643605Z","EventRecordID":114689,"Correlation":{},"Execution":{"ProcessID":4,"ThreadID":196},"Channel":"Security","Computer":"win10.windomain.local"},"EventData":{"SubjectLogonId":"0x3e7","SubjectUserName":"WIN10$","SubjectDomainName":"WINDOMAIN","ParentProcessName":"C:\\Windows\\System32\\services.exe","MandatoryLabel":"S-1-16-16384","SubjectUserSid":"S-1-5-18","NewProcessName":"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe","TokenElevationType":"%%1936","TargetUserSid":"S-1-0-0","TargetDomainName":"-","CommandLine":"","TargetUserName":"-","NewProcessId":"0x3a8","TargetLogonId":"0x0","ProcessId":"0x240"},"RenderingInfo":{"Message":"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWIN10$\n\tAccount Domain:\t\tWINDOMAIN\n\tLogon ID:\t\t0x3E7\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x3a8\n\tNew Process Name:\tC:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\n\tToken Elevation Type:\t%%1936\n\tMandatory Label:\t\tS-1-16-16384\n\tCreator Process ID:\t0x240\n\tCreator Process Name:\tC:\\Windows\\System32\\services.exe\n\tProcess Command Line:\t\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.","Level":"Information","Task":"Process Creation","Opcode":"Info","Channel":"Security","Provider":"Microsoft Windows security auditing.","Keywords":["Audit Success"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T16:07:03.331+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Node":"openwec","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","ClientRevision":"1234","ServerRevision":"babar"}}}"#;

    #[test]
    fn test_serialize_4688_event_data() {
        // Generate metadata
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());

        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()))
            .set_revision(Some("babar".to_string()));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("openwec".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            Some("1234".to_string()),
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:03.331+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        // Parse and check event

        let event_data = EventData::new(Arc::new(EVENT_4688.to_string()), true);
        assert!(event_data.event().unwrap().additional.error.is_none());

        let formatter: JsonFormat = JsonFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_4688_JSON).unwrap();

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
    const EVENT_1003_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-Security-SPP","Guid":"{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}","EventSourceName":"Software Protection Platform Service"},"EventID":1003,"EventIDQualifiers":16384,"Version":0,"Level":4,"Task":0,"Opcode":0,"Keywords":"0x80000000000000","TimeCreated":"2022-12-14T16:05:59.7074374Z","EventRecordID":7603,"Correlation":{},"Execution":{"ProcessID":0,"ThreadID":0},"Channel":"Application","Computer":"win10.windomain.local"},"EventData":{"Data":["55c92734-d682-4d71-983e-d6ec3f16059f","\n1: 3f4c0546-36c6-46a8-a37f-be13cdd0cf25, 1, 1 [(0 [0xC004E003, 0, 0], [( 9 0xC004FC07 90 0)( 1 0x00000000)(?)( 2 0x00000000 0 0 msft:rm/algorithm/hwid/4.0 0x00000000 0)(?)( 9 0xC004FC07 90 0)( 10 0x00000000 msft:rm/algorithm/flags/1.0)(?)])(1 )(2 )(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004FC07)])]\n\n"]},"RenderingInfo":{"Message":"The Software Protection service has completed licensing status check.\nApplication Id=55c92734-d682-4d71-983e-d6ec3f16059f\nLicensing Status=\n1: 3f4c0546-36c6-46a8-a37f-be13cdd0cf25, 1, 1 [(0 [0xC004E003, 0, 0], [( 9 0xC004FC07 90 0)( 1 0x00000000)(?)( 2 0x00000000 0 0 msft:rm/algorithm/hwid/4.0 0x00000000 0)(?)( 9 0xC004FC07 90 0)( 10 0x00000000 msft:rm/algorithm/flags/1.0)(?)])(1 )(2 )(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004FC07)])]\n\n","Level":"Information","Provider":"Microsoft-Windows-Security-SPP","Keywords":["Classic"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T16:07:03.324+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Node":"openwec","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test"}}}"#;

    #[test]
    fn test_serialize_1003_event_data_unamed() {
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data.set_uuid(SubscriptionUuid(
            Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
        ));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("openwec".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            None,
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:03.324+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        let event_data = EventData::new(Arc::new(EVENT_1003.to_string()), true);

        assert!(event_data.event().unwrap().additional.error.is_none());
        let formatter: JsonFormat = JsonFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_1003_JSON).unwrap();

        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_5719: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='NETLOGON'/><EventID Qualifiers='0'>5719</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:04:59.0817047Z'/><EventRecordID>9466</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>System</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data>WINDOMAIN</Data><Data>%%1311</Data><Binary>5E0000C0</Binary></EventData><RenderingInfo Culture='en-US'><Message>This computer was not able to set up a secure session with a domain controller in domain WINDOMAIN due to the following:
We can't sign you in with this credential because your domain isn't available. Make sure your device is connected to your organization's network and try again. If you previously signed in on this device with another credential, you can sign in with that credential.
This may lead to authentication problems. Make sure that this computer is connected to the network. If the problem persists, please contact your domain administrator.

ADDITIONAL INFO
If this computer is a domain controller for the specified domain, it sets up the secure session to the primary domain controller emulator in the specified domain. Otherwise, this computer sets up the secure session to any domain controller in the specified domain.</Message><Level>Error</Level><Task></Task><Opcode>Info</Opcode><Channel></Channel><Provider></Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_5719_JSON: &str = r#"{"System":{"Provider":{"Name":"NETLOGON"},"EventID":5719,"EventIDQualifiers":0,"Version":0,"Level":2,"Task":0,"Opcode":0,"Keywords":"0x80000000000000","TimeCreated":"2022-12-14T16:04:59.0817047Z","EventRecordID":9466,"Correlation":{},"Execution":{"ProcessID":0,"ThreadID":0},"Channel":"System","Computer":"win10.windomain.local"},"EventData":{"Data":["WINDOMAIN","%%1311"],"Binary":"5E0000C0"},"RenderingInfo":{"Message":"This computer was not able to set up a secure session with a domain controller in domain WINDOMAIN due to the following:\nWe can't sign you in with this credential because your domain isn't available. Make sure your device is connected to your organization's network and try again. If you previously signed in on this device with another credential, you can sign in with that credential.\nThis may lead to authentication problems. Make sure that this computer is connected to the network. If the problem persists, please contact your domain administrator.\n\nADDITIONAL INFO\nIf this computer is a domain controller for the specified domain, it sets up the secure session to the primary domain controller emulator in the specified domain. Otherwise, this computer sets up the secure session to any domain controller in the specified domain.","Level":"Error","Opcode":"Info","Keywords":["Classic"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T16:07:02.919+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Node":"openwec","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","ServerRevision":"babar","ClientRevision": "babar"}}}"#;

    #[test]
    fn test_serialize_5719_event_data_binary() {
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()))
            .set_revision(Some("babar".to_string()));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("openwec".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            Some("babar".to_string()),
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:02.919+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        let event_data = EventData::new(Arc::new(EVENT_5719.to_string()), true);

        assert!(event_data.event().unwrap().additional.error.is_none());
        let formatter: JsonFormat = JsonFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_5719_JSON).unwrap();

        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_6013: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='EventLog'/><EventID Qualifiers='32768'>6013</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:04:43.7965565Z'/><EventRecordID>9427</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>System</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data></Data><Data></Data><Data></Data><Data></Data><Data>6</Data><Data>60</Data><Data>0 Coordinated Universal Time</Data><Binary>31002E003100000030000000570069006E0064006F0077007300200031003000200045006E007400650072007000720069007300650020004500760061006C0075006100740069006F006E000000310030002E0030002E003100390030003400330020004200750069006C0064002000310039003000340033002000200000004D0075006C0074006900700072006F0063006500730073006F007200200046007200650065000000310039003000340031002E00760062005F00720065006C0065006100730065002E003100390031003200300036002D00310034003000360000003600320031003400640066003100630000004E006F007400200041007600610069006C00610062006C00650000004E006F007400200041007600610069006C00610062006C00650000003900000031000000320030003400380000003400300039000000770069006E00310030002E00770069006E0064006F006D00610069006E002E006C006F00630061006C0000000000</Binary></EventData><RenderingInfo Culture='en-US'><Message>The system uptime is 6 seconds.</Message><Level>Information</Level><Task></Task><Opcode></Opcode><Channel></Channel><Provider></Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_6013_JSON: &str = r#"{"System":{"Provider":{"Name":"EventLog"},"EventID":6013,"EventIDQualifiers":32768,"Version":0,"Level":4,"Task":0,"Opcode":0,"Keywords":"0x80000000000000","TimeCreated":"2022-12-14T16:04:43.7965565Z","EventRecordID":9427,"Correlation":{},"Execution":{"ProcessID":0,"ThreadID":0},"Channel":"System","Computer":"win10.windomain.local"},"EventData":{"Data":["6","60","0 Coordinated Universal Time"],"Binary":"31002E003100000030000000570069006E0064006F0077007300200031003000200045006E007400650072007000720069007300650020004500760061006C0075006100740069006F006E000000310030002E0030002E003100390030003400330020004200750069006C0064002000310039003000340033002000200000004D0075006C0074006900700072006F0063006500730073006F007200200046007200650065000000310039003000340031002E00760062005F00720065006C0065006100730065002E003100390031003200300036002D00310034003000360000003600320031003400640066003100630000004E006F007400200041007600610069006C00610062006C00650000004E006F007400200041007600610069006C00610062006C00650000003900000031000000320030003400380000003400300039000000770069006E00310030002E00770069006E0064006F006D00610069006E002E006C006F00630061006C0000000000"},"RenderingInfo":{"Message":"The system uptime is 6 seconds.","Level":"Information","Keywords":["Classic"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T16:07:02.524+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_6013_event_data_unamed_empty() {
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            None,
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            None,
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:02.524+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        let event_data = EventData::new(Arc::new(EVENT_6013.to_string()), true);

        assert!(event_data.event().unwrap().additional.error.is_none());
        let formatter: JsonFormat = JsonFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_6013_JSON).unwrap();

        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_1100: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1100</EventID><Version>0</Version><Level>4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2022-12-14T14:39:07.1686183Z'/><EventRecordID>114371</EventRecordID><Correlation/><Execution ProcessID='496' ThreadID='204'/><Channel>Security</Channel><Computer>win10.windomain.local</Computer><Security/></System><UserData><ServiceShutdown xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'></ServiceShutdown></UserData><RenderingInfo Culture='en-US'><Message>The event logging service has shut down.</Message><Level>Information</Level><Task>Service shutdown</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft-Windows-Eventlog</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_1100_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-Eventlog","Guid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"},"EventID":1100,"Version":0,"Level":4,"Task":103,"Opcode":0,"Keywords":"0x4020000000000000","TimeCreated":"2022-12-14T14:39:07.1686183Z","EventRecordID":114371,"Correlation":{},"Execution":{"ProcessID":496,"ThreadID":204},"Channel":"Security","Computer":"win10.windomain.local"},"UserData":"<ServiceShutdown xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'></ServiceShutdown>","RenderingInfo":{"Message":"The event logging service has shut down.","Level":"Information","Task":"Service shutdown","Opcode":"Info","Channel":"Security","Provider":"Microsoft-Windows-Eventlog","Keywords":["Audit Success"],"Culture":"en-US"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T16:07:02.156+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Node":"openwec","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_1100_user_data() {
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("openwec".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            None,
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:02.156+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        let event_data = EventData::new(Arc::new(EVENT_1100.to_string()), true);

        assert!(event_data.event().unwrap().additional.error.is_none());
        let formatter: JsonFormat = JsonFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_1100_JSON).unwrap();

        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_111: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-EventForwarder'/><EventID>111</EventID><TimeCreated SystemTime='2023-02-14T09:14:23.175Z'/><Computer>win10.windomain.local</Computer></System><SubscriptionBookmarkEvent><SubscriptionId></SubscriptionId></SubscriptionBookmarkEvent></Event>"#;
    const EVENT_111_JSON: &str = r#"{"System":{"Provider":{"Name":"Microsoft-Windows-EventForwarder"},"EventID":111,"TimeCreated":"2023-02-14T09:14:23.175Z","Computer":"win10.windomain.local"},"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T16:07:02.156+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Node":"other_node","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test"}}}"#;

    #[test]
    fn test_serialize_111() {
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("other_node".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            None,
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:02.156+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        let event_data = EventData::new(Arc::new(EVENT_111.to_string()), true);

        assert!(event_data.event().unwrap().additional.error.is_none());
        let formatter: JsonFormat = JsonFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_111_JSON).unwrap();

        assert_eq!(event_json_value, expected_value);
    }
}
