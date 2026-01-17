use std::{collections::HashMap, fmt::Debug, sync::Arc};

use log::warn;
use serde::Serialize;
use strum::Display;

use crate::{
    event::{EventData, EventMetadata},
    output::OutputFormat,
};

// Contants taken from https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.tracing.eventkeywords?view=net-8.0
const AUDIT_SUCCESS_MASK: i64 = 9007199254740992;
const AUDIT_FAILURE_MASK: i64 = 4503599627370496;

pub struct NxlogFormat;

impl OutputFormat for NxlogFormat {
    fn format(&self, metadata: &EventMetadata, data: &EventData) -> Option<Arc<String>> {
        if let Some(event) = data.event() {
            let json_event = NxlogEvent::new(event.clone(), metadata);
            match serde_json::to_string(&json_event) {
                Ok(str) => Some(Arc::new(str)),
                Err(e) => {
                    warn!(
                        "Failed to serialize event in JSON with NxlogFormat: {:?}. Event was: {:?}. Metadata was: {:?}. Raw event was: {:?}.",
                        e, event, metadata, data.raw()
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

#[derive(Serialize, Debug)]
struct UserDataType {
    #[serde(rename = "UserData")]
    payload: String,
}

impl From<String> for UserDataType {
    fn from(value: String) -> Self {
        Self { payload: value }
    }
}

#[derive(Serialize, Debug)]
struct BinaryEventData {
    #[serde(rename = "BinaryEventData")]
    payload: String,
}

impl From<String> for BinaryEventData {
    fn from(value: String) -> Self {
        Self { payload: value }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum DataType {
    EventData(EventDataType),
    UserData(UserDataType),
    DebugData(DebugDataType),
    ProcessingErrorData(ProcessingErrorDataType),
    BinaryEventData(BinaryEventData),
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
            crate::event::DataType::UserData(t) => DataType::UserData(t.into()),
            crate::event::DataType::DebugData(t) => DataType::DebugData(t.into()),
            crate::event::DataType::ProcessingErrorData(t) => {
                DataType::ProcessingErrorData(t.into())
            }
            crate::event::DataType::BinaryEventData(t) => DataType::BinaryEventData(t.into()),
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
struct NxlogEvent {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    system: Option<System>,
    #[serde(flatten, skip_serializing_if = "DataType::is_unknown")]
    data: DataType,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    rendering_info: Option<RenderingInfo>,
    #[serde(rename = "OpenWEC")]
    additional: Additional,
    #[serde(rename = "EventReceivedTime")]
    event_received_time: String,
}

impl NxlogEvent {
    pub fn new(event: crate::event::Event, metadata: &EventMetadata) -> Self {
        Self {
            system: event.system.map(Into::into),
            data: event.data.into(),
            rendering_info: event.rendering_info.map(Into::into),
            additional: Additional::new(event.additional, metadata),
            event_received_time: metadata.time_received().to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
struct Additional {
    #[serde(rename = "IpAddress")]
    addr: String,
    #[serde(rename = "TimeReceived")]
    time_received: String,
    // deprecated, will disappear at some point
    #[serde(rename = "Principal")]
    principal: String,
    #[serde(rename = "Client")]
    client: String,
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
            principal: metadata.client().to_owned(),
            client: metadata.client().to_owned(),
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
    #[serde(rename = "SourceName")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ProviderGuid")]
    guid: Option<String>,
}

impl From<crate::event::Provider> for Provider {
    fn from(value: crate::event::Provider) -> Self {
        Self {
            name: value.name,
            guid: value.guid.map(|x| x.to_uppercase()),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct Correlation {
    #[serde(rename = "ActivityID", skip_serializing_if = "Option::is_none")]
    activity_id: Option<String>,
    #[serde(rename = "RelatedActivityID", skip_serializing_if = "Option::is_none")]
    related_activity_id: Option<String>,
}

impl From<crate::event::Correlation> for Correlation {
    fn from(value: crate::event::Correlation) -> Self {
        Self {
            activity_id: value.activity_id.map(|x| x.to_uppercase()),
            related_activity_id: value.related_activity_id.map(|x| x.to_uppercase()),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct Execution {
    #[serde(rename = "ProcessID")]
    process_id: u32,
    #[serde(rename = "ThreadID")]
    thread_id: u32,
}

impl From<crate::event::Execution> for Execution {
    fn from(value: crate::event::Execution) -> Self {
        Self {
            process_id: value.process_id,
            thread_id: value.thread_id,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct System {
    #[serde(flatten)]
    provider: Provider,
    #[serde(rename = "EventID")]
    event_id: u32,
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    version: Option<u8>,
    #[serde(rename = "Task", skip_serializing_if = "Option::is_none")]
    task: Option<u16>,
    #[serde(rename = "OpcodeValue", skip_serializing_if = "Option::is_none")]
    opcode: Option<u8>,
    #[serde(rename = "Keywords", skip_serializing_if = "Option::is_none")]
    keywords: Option<i64>,
    #[serde(rename = "EventTime", skip_serializing_if = "Option::is_none")]
    time_created: Option<String>,
    #[serde(rename = "RecordNumber", skip_serializing_if = "Option::is_none")]
    event_record_id: Option<u64>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    correlation: Option<Correlation>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    execution: Option<Execution>,
    #[serde(rename = "Channel", skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(rename = "Hostname")]
    computer: String,
    #[serde(rename = "UserID", skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(rename = "EventType", skip_serializing_if = "Option::is_none")]
    event_type: Option<String>,
    #[serde(rename = "Severity", skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(rename = "SeverityValue", skip_serializing_if = "Option::is_none")]
    severity_value: Option<u8>,
}

impl From<crate::event::System> for System {
    fn from(value: crate::event::System) -> Self {
        let keywords_number = parse_keywords(value.keywords.as_ref());
        let event_type = get_event_type(value.channel.as_ref(), value.level, keywords_number);
        let severity: Option<Severity> = event_type.clone().map(|e| e.into());
        Self {
            event_type: event_type.map(|e| e.to_string()),
            provider: value.provider.into(),
            event_id: value.event_id,
            version: value.version,
            task: value.task,
            opcode: value.opcode,
            keywords: keywords_number,
            time_created: value.time_created,
            event_record_id: value.event_record_id,
            correlation: value.correlation.map(Into::into),
            execution: value.execution.map(Into::into),
            channel: value.channel,
            computer: value.computer,
            user_id: value.user_id,
            severity: severity.as_ref().map(|s| s.to_string()),
            severity_value: severity.map(|s| s as u8),
        }
    }
}

fn parse_keywords(keywords_opt: Option<&String>) -> Option<i64> {
    if let Some(keywords) = keywords_opt {
        if let Some(keywords_without_prefix) = keywords.strip_prefix("0x") {
            // We need to convert u64 to i64 because for some reason
            // i64::from_str_radix can't decode negative values.
            match u64::from_str_radix(keywords_without_prefix, 16) {
                Ok(res) => Some(res as i64),
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Debug, Display, Clone)]
enum EventType {
    #[strum(to_string = "CRITICAL")]
    Critical,
    #[strum(to_string = "ERROR")]
    Error,
    #[strum(to_string = "WARNING")]
    Warning,
    #[strum(to_string = "INFO")]
    Info,
    #[strum(to_string = "VERBOSE")]
    Verbose,
    #[strum(to_string = "AUDIT_SUCCESS")]
    AuditSuccess,
    #[strum(to_string = "AUDIT_FAILURE")]
    AuditFailure,
}

fn get_event_type(
    channel_opt: Option<&String>,
    level_opt: Option<u8>,
    keywords_number: Option<i64>,
) -> Option<EventType> {
    // Read https://eventlogxp.com/blog/windows-event-level-keywords-or-type/
    // https://docs.nxlog.co/refman/current/im/msvistalog.html#eventtype
    match channel_opt {
        Some(channel) if channel == "Security" => {
            if let Some(keywords) = keywords_number {
                if keywords & AUDIT_SUCCESS_MASK != 0 {
                    Some(EventType::AuditSuccess)
                } else if keywords & AUDIT_FAILURE_MASK != 0 {
                    Some(EventType::AuditFailure)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Some(_) => match level_opt {
            Some(1) => Some(EventType::Critical),
            Some(2) => Some(EventType::Error),
            Some(3) => Some(EventType::Warning),
            Some(4) => Some(EventType::Info),
            Some(5) => Some(EventType::Verbose),
            _ => None,
        },
        None => None,
    }
}

#[derive(Display)]
#[repr(u8)]
enum Severity {
    #[strum(to_string = "DEBUG")]
    Debug = 1,
    #[strum(to_string = "INFO")]
    Info = 2,
    #[strum(to_string = "WARNING")]
    Warning = 3,
    #[strum(to_string = "ERROR")]
    Error = 4,
    #[strum(to_string = "CRITICAL")]
    Critical = 5,
}

impl From<EventType> for Severity {
    fn from(event_type: EventType) -> Severity {
        match event_type {
            EventType::AuditSuccess => Severity::Info,
            EventType::AuditFailure => Severity::Error,
            EventType::Critical => Severity::Critical,
            EventType::Error => Severity::Error,
            EventType::Warning => Severity::Warning,
            EventType::Info => Severity::Info,
            EventType::Verbose => Severity::Debug,
        }
    }
}

#[derive(Debug, Default, Serialize, Clone)]
struct RenderingInfo {
    #[serde(rename = "Message", skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(rename = "Category", skip_serializing_if = "Option::is_none")]
    task: Option<String>,
    #[serde(rename = "Opcode", skip_serializing_if = "Option::is_none")]
    opcode: Option<String>,
}

impl From<crate::event::RenderingInfo> for RenderingInfo {
    fn from(value: crate::event::RenderingInfo) -> Self {
        Self {
            message: value.message,
            task: value.task,
            opcode: value.opcode,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, sync::Arc};

    use chrono::Utc;
    use common::settings;
    use common::subscription::SubscriptionData;
    use common::subscription::SubscriptionUuid;
    use serde_json::Value;
    use uuid::Uuid;

    use crate::output::OutputDriversContext;
    use crate::{
        event::{EventData, EventMetadata},
        formats::nxlog::NxlogFormat,
        output::OutputFormat,
        subscription::Subscription,
    };

    fn compare(xml: &str, expected_json: &str) {
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        // Generate metadata
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()))
            .set_revision(Some("BABAR".to_string()));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("openwec".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            Some("TOTO".to_string()),
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2024-03-14T14:54:20.331+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        // Format event and compare with expected result
        let event_data = EventData::new(Arc::new(xml.to_string()), true);
        assert!(event_data.event().unwrap().additional.error.is_none());

        let formatter = NxlogFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(expected_json).unwrap();

        assert_eq!(event_json_value, expected_value);
    }

    const EVENT_4624: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2024-03-14T13:54:19.3628662Z'/><EventRecordID>1446</EventRecordID><Correlation ActivityID='{b073a4bf-7611-0000-bca5-73b01176da01}'/><Execution ProcessID='780' ThreadID='2832'/><Channel>Security</Channel><Computer>WKS10001</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>WKS10001$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-1430380458-3079459327-630937868-1001</Data><Data Name='TargetUserName'>user</Data><Data Name='TargetDomainName'>WKS10001</Data><Data Name='TargetLogonId'>0x615a44</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>WKS10001</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x5c8</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='IpAddress'>127.0.0.1</Data><Data Name='IpPort'>0</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x615a61</Data><Data Name='ElevatedToken'>%%1842</Data></EventData><RenderingInfo Culture='en-GB'><Message>An account was successfully logged on.&#13;&#10;&#13;&#10;Subject:&#13;&#10;&#9;Security ID:&#9;&#9;S-1-5-18&#13;&#10;&#9;Account Name:&#9;&#9;WKS10001$&#13;&#10;&#9;Account Domain:&#9;&#9;WORKGROUP&#13;&#10;&#9;Logon ID:&#9;&#9;0x3E7&#13;&#10;&#13;&#10;Logon Information:&#13;&#10;&#9;Logon Type:&#9;&#9;2&#13;&#10;&#9;Restricted Admin Mode:&#9;-&#13;&#10;&#9;Remote Credential Guard:&#9;-&#13;&#10;&#9;Virtual Account:&#9;&#9;No&#13;&#10;&#9;Elevated Token:&#9;&#9;Yes&#13;&#10;&#13;&#10;Impersonation Level:&#9;&#9;Impersonation&#13;&#10;&#13;&#10;New Logon:&#13;&#10;&#9;Security ID:&#9;&#9;S-1-5-21-1430380458-3079459327-630937868-1001&#13;&#10;&#9;Account Name:&#9;&#9;user&#13;&#10;&#9;Account Domain:&#9;&#9;WKS10001&#13;&#10;&#9;Logon ID:&#9;&#9;0x615A44&#13;&#10;&#9;Linked Logon ID:&#9;&#9;0x615A61&#13;&#10;&#9;Network Account Name:&#9;-&#13;&#10;&#9;Network Account Domain:&#9;-&#13;&#10;&#9;Logon GUID:&#9;&#9;{00000000-0000-0000-0000-000000000000}&#13;&#10;&#13;&#10;Process Information:&#13;&#10;&#9;Process ID:&#9;&#9;0x5c8&#13;&#10;&#9;Process Name:&#9;&#9;C:\Windows\System32\svchost.exe&#13;&#10;&#13;&#10;Network Information:&#13;&#10;&#9;Workstation Name:&#9;WKS10001&#13;&#10;&#9;Source Network Address:&#9;127.0.0.1&#13;&#10;&#9;Source Port:&#9;&#9;0&#13;&#10;&#13;&#10;Detailed Authentication Information:&#13;&#10;&#9;Logon Process:&#9;&#9;User32 &#13;&#10;&#9;Authentication Package:&#9;Negotiate&#13;&#10;&#9;Transited Services:&#9;-&#13;&#10;&#9;Package Name (NTLM only):&#9;-&#13;&#10;&#9;Key Length:&#9;&#9;0&#13;&#10;&#13;&#10;This event is generated when a logon session is created. It is generated on the computer that was accessed.&#13;&#10;&#13;&#10;The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.&#13;&#10;&#13;&#10;The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).&#13;&#10;&#13;&#10;The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.&#13;&#10;&#13;&#10;The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.&#13;&#10;&#13;&#10;The impersonation level field indicates the extent to which a process in the logon session can impersonate.&#13;&#10;&#13;&#10;The authentication information fields provide detailed information about this specific logon request.&#13;&#10;&#9;- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.&#13;&#10;&#9;- Transited services indicate which intermediate services have participated in this logon request.&#13;&#10;&#9;- Package name indicates which sub-protocol was used among the NTLM protocols.&#13;&#10;&#9;- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.</Message><Level>Information</Level><Task>Logon</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event> "#;
    const EVENT_4624_JSON: &str = r#"{"EventTime":"2024-03-14T13:54:19.3628662Z","Hostname":"WKS10001","Keywords":-9214364837600034816,"EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4624,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Version":3,"Task":12544,"OpcodeValue":0,"RecordNumber":1446,"ActivityID":"{B073A4BF-7611-0000-BCA5-73B01176DA01}","ProcessID":780,"ThreadID":2832,"Channel":"Security","Message":"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tWKS10001$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t2\r\n\tRestricted Admin Mode:\t-\r\n\tRemote Credential Guard:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-1430380458-3079459327-630937868-1001\r\n\tAccount Name:\t\tuser\r\n\tAccount Domain:\t\tWKS10001\r\n\tLogon ID:\t\t0x615A44\r\n\tLinked Logon ID:\t\t0x615A61\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x5c8\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tWKS10001\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.","Category":"Logon","Opcode":"Info","SubjectUserSid":"S-1-5-18","SubjectUserName":"WKS10001$","SubjectDomainName":"WORKGROUP","SubjectLogonId":"0x3e7","TargetUserSid":"S-1-5-21-1430380458-3079459327-630937868-1001","TargetUserName":"user","TargetDomainName":"WKS10001","TargetLogonId":"0x615a44","LogonType":"2","LogonProcessName":"User32 ","AuthenticationPackageName":"Negotiate","WorkstationName":"WKS10001","LogonGuid":"{00000000-0000-0000-0000-000000000000}","TransmittedServices":"-","LmPackageName":"-","KeyLength":"0","ProcessName":"C:\\Windows\\System32\\svchost.exe","IpAddress":"127.0.0.1","IpPort":"0","ImpersonationLevel":"%%1833","RestrictedAdminMode":"-","RemoteCredentialGuard":"-","TargetOutboundUserName":"-","TargetOutboundDomainName":"-","VirtualAccount":"%%1843","TargetLinkedLogonId":"0x615a61","ElevatedToken":"%%1842","EventReceivedTime":"2024-03-14T13:54:20.331+00:00","OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2024-03-14T13:54:20.331+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Client":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","ServerRevision":"BABAR","ClientRevision":"TOTO"},"Node":"openwec"}, "ProcessId": "0x5c8"}"#;

    #[test]
    fn test_serialize_4624_event_data() {
        compare(EVENT_4624, EVENT_4624_JSON)
    }

    const EVENT_1003: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-SPP' Guid='{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}' EventSourceName='Software Protection Platform Service'/><EventID Qualifiers='16384'>1003</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2024-03-14T13:54:25.0379869Z'/><EventRecordID>403</EventRecordID><Correlation/><Execution ProcessID='6628' ThreadID='0'/><Channel>Application</Channel><Computer>WKS10001</Computer><Security/></System><EventData><Data>55c92734-d682-4d71-983e-d6ec3f16059f</Data><Data>
1: 040fa323-92b1-4baf-97a2-5b67feaefddb, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
2: 0724cb7d-3437-4cb7-93cb-830375d0079d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
3: 0ad2ac98-7bb9-4201-8d92-312299201369, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
4: 1a9a717a-cf13-4ba5-83c3-0fe25fa868d5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
5: 221a02da-e2a1-4b75-864c-0a4410a33fdf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
6: 291ece0e-9c38-40ca-a9e1-32cc7ec19507, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
7: 2936d1d2-913a-4542-b54e-ce5a602a2a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
8: 2c293c26-a45a-4a2a-a350-c69a67097529, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
9: 2de67392-b7a7-462a-b1ca-108dd189f588, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
10: 2ffd8952-423e-4903-b993-72a1aa44cf82, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
11: 30a42c86-b7a0-4a34-8c90-ff177cb2acb7, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
12: 345a5db0-d94f-4e3b-a0c0-7c42f7bc3ebf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
13: 3502365a-f88a-4ba4-822a-5769d3073b65, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
14: 377333b1-8b5d-48d6-9679-1225c872d37c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
15: 3df374ef-d444-4494-a5a1-4b0d9fd0e203, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
16: 3f1afc82-f8ac-4f6c-8005-1d233e606eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
17: 49cd895b-53b2-4dc4-a5f7-b18aa019ad37, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
18: 4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c, 1, 1 [(0 )(1 )(2 [0xC004E003, 0, 0], [( 1 0xC004F034)( 1 0xC004F034)(?)(?)(?)(?)(?)(?)])(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004F034)])]
19: 4f3da0d2-271d-4508-ae81-626b60809a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
20: 5d78c4e9-aeb3-4b40-8ac2-6a6005e0ad6d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
21: 60b3ec1b-9545-4921-821f-311b129dd6f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
22: 613d217f-7f13-4268-9907-1662339531cd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
23: 62f0c100-9c53-4e02-b886-a3528ddfe7f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
24: 6365275e-368d-46ca-a0ef-fc0404119333, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
25: 721f9237-9341-4453-a661-09e8baa6cca5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
26: 73111121-5638-40f6-bc11-f1d7b0d64300, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
27: 7a802526-4c94-4bd1-ba14-835a1aca2120, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
28: 7cb546c0-c7d5-44d8-9a5c-69ecdd782b69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
29: 82bbc092-bc50-4e16-8e18-b74fc486aec3, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
30: 8ab9bdd1-1f67-4997-82d9-8878520837d9, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
31: 8b351c9c-f398-4515-9900-09df49427262, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
32: 90da7373-1c51-430b-bf26-c97e9c5cdc31, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
33: 92fb8726-92a8-4ffc-94ce-f82e07444653, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
34: 95dca82f-385d-4d39-b85b-5c73fa285d6f, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
35: a48938aa-62fa-4966-9d44-9f04da3f72f2, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
36: b0773a15-df3a-4312-9ad2-83d69648e356, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
37: b4bfe195-541e-4e64-ad23-6177f19e395e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
38: b68e61d2-68ca-4757-be45-0cc2f3e68eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
39: bd3762d7-270d-4760-8fb3-d829ca45278a, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
40: c86d5194-4840-4dae-9c1c-0301003a5ab0, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
41: ca7df2e3-5ea0-47b8-9ac1-b1be4d8edd69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
42: d552befb-48cc-4327-8f39-47d2d94f987c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
43: d6eadb3b-5ca8-4a6b-986e-35b550756111, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
44: df96023b-dcd9-4be2-afa0-c6c871159ebe, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
45: e0c42288-980c-4788-a014-c080d2e1926e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
46: e4db50ea-bda1-4566-b047-0ca50abc6f07, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
47: e558417a-5123-4f6f-91e7-385c1c7ca9d4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
48: e7a950a2-e548-4f10-bf16-02ec848e0643, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
49: eb6d346f-1c60-4643-b960-40ec31596c45, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
50: ec868e65-fadf-4759-b23e-93fe37f2cc29, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
51: ef51e000-2659-4f25-8345-3de70a9cf4c4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
52: f7af7d09-40e4-419c-a49b-eae366689ebd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
53: fa755fe6-6739-40b9-8d84-6d0ea3b6d1ab, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]
54: fe74f55b-0338-41d6-b267-4a201abe7285, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]

</Data></EventData><RenderingInfo Culture='en-GB'><Message>The Software Protection service has completed licensing status check.&#13;&#10;Application Id=55c92734-d682-4d71-983e-d6ec3f16059f&#13;&#10;Licensing Status=&#10;1: 040fa323-92b1-4baf-97a2-5b67feaefddb, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;2: 0724cb7d-3437-4cb7-93cb-830375d0079d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;3: 0ad2ac98-7bb9-4201-8d92-312299201369, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;4: 1a9a717a-cf13-4ba5-83c3-0fe25fa868d5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;5: 221a02da-e2a1-4b75-864c-0a4410a33fdf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;6: 291ece0e-9c38-40ca-a9e1-32cc7ec19507, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;7: 2936d1d2-913a-4542-b54e-ce5a602a2a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;8: 2c293c26-a45a-4a2a-a350-c69a67097529, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;9: 2de67392-b7a7-462a-b1ca-108dd189f588, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;10: 2ffd8952-423e-4903-b993-72a1aa44cf82, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;11: 30a42c86-b7a0-4a34-8c90-ff177cb2acb7, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;12: 345a5db0-d94f-4e3b-a0c0-7c42f7bc3ebf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;13: 3502365a-f88a-4ba4-822a-5769d3073b65, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;14: 377333b1-8b5d-48d6-9679-1225c872d37c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;15: 3df374ef-d444-4494-a5a1-4b0d9fd0e203, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;16: 3f1afc82-f8ac-4f6c-8005-1d233e606eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;17: 49cd895b-53b2-4dc4-a5f7-b18aa019ad37, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;18: 4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c, 1, 1 [(0 )(1 )(2 [0xC004E003, 0, 0], [( 1 0xC004F034)( 1 0xC004F034)(?)(?)(?)(?)(?)(?)])(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004F034)])]&#10;19: 4f3da0d2-271d-4508-ae81-626b60809a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;20: 5d78c4e9-aeb3-4b40-8ac2-6a6005e0ad6d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;21: 60b3ec1b-9545-4921-821f-311b129dd6f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;22: 613d217f-7f13-4268-9907-1662339531cd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;23: 62f0c100-9c53-4e02-b886-a3528ddfe7f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;24: 6365275e-368d-46ca-a0ef-fc0404119333, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;25: 721f9237-9341-4453-a661-09e8baa6cca5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;26: 73111121-5638-40f6-bc11-f1d7b0d64300, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;27: 7a802526-4c94-4bd1-ba14-835a1aca2120, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;28: 7cb546c0-c7d5-44d8-9a5c-69ecdd782b69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;29: 82bbc092-bc50-4e16-8e18-b74fc486aec3, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;30: 8ab9bdd1-1f67-4997-82d9-8878520837d9, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;31: 8b351c9c-f398-4515-9900-09df49427262, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;32: 90da7373-1c51-430b-bf26-c97e9c5cdc31, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;33: 92fb8726-92a8-4ffc-94ce-f82e07444653, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;34: 95dca82f-385d-4d39-b85b-5c73fa285d6f, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;35: a48938aa-62fa-4966-9d44-9f04da3f72f2, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;36: b0773a15-df3a-4312-9ad2-83d69648e356, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;37: b4bfe195-541e-4e64-ad23-6177f19e395e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;38: b68e61d2-68ca-4757-be45-0cc2f3e68eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;39: bd3762d7-270d-4760-8fb3-d829ca45278a, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;40: c86d5194-4840-4dae-9c1c-0301003a5ab0, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;41: ca7df2e3-5ea0-47b8-9ac1-b1be4d8edd69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;42: d552befb-48cc-4327-8f39-47d2d94f987c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;43: d6eadb3b-5ca8-4a6b-986e-35b550756111, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;44: df96023b-dcd9-4be2-afa0-c6c871159ebe, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;45: e0c42288-980c-4788-a014-c080d2e1926e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;46: e4db50ea-bda1-4566-b047-0ca50abc6f07, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;47: e558417a-5123-4f6f-91e7-385c1c7ca9d4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;48: e7a950a2-e548-4f10-bf16-02ec848e0643, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;49: eb6d346f-1c60-4643-b960-40ec31596c45, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;50: ec868e65-fadf-4759-b23e-93fe37f2cc29, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;51: ef51e000-2659-4f25-8345-3de70a9cf4c4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;52: f7af7d09-40e4-419c-a49b-eae366689ebd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;53: fa755fe6-6739-40b9-8d84-6d0ea3b6d1ab, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;54: fe74f55b-0338-41d6-b267-4a201abe7285, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]&#10;&#10;</Message><Level>Information</Level><Provider>Microsoft-Windows-Security-SPP</Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_1003_JSON: &str = r#"{"EventTime":"2024-03-14T13:54:25.0379869Z","Hostname":"WKS10001","Keywords":36028797018963968,"EventType":"INFO","SeverityValue":2,"Severity":"INFO","EventID":1003,"SourceName":"Microsoft-Windows-Security-SPP","ProviderGuid":"{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}","Version":0,"Task":0,"OpcodeValue":0,"RecordNumber":403,"ProcessID":6628,"ThreadID":0,"Channel":"Application","Message":"The Software Protection service has completed licensing status check.\r\nApplication Id=55c92734-d682-4d71-983e-d6ec3f16059f\r\nLicensing Status=\n1: 040fa323-92b1-4baf-97a2-5b67feaefddb, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n2: 0724cb7d-3437-4cb7-93cb-830375d0079d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n3: 0ad2ac98-7bb9-4201-8d92-312299201369, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n4: 1a9a717a-cf13-4ba5-83c3-0fe25fa868d5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n5: 221a02da-e2a1-4b75-864c-0a4410a33fdf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n6: 291ece0e-9c38-40ca-a9e1-32cc7ec19507, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n7: 2936d1d2-913a-4542-b54e-ce5a602a2a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n8: 2c293c26-a45a-4a2a-a350-c69a67097529, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n9: 2de67392-b7a7-462a-b1ca-108dd189f588, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n10: 2ffd8952-423e-4903-b993-72a1aa44cf82, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n11: 30a42c86-b7a0-4a34-8c90-ff177cb2acb7, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n12: 345a5db0-d94f-4e3b-a0c0-7c42f7bc3ebf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n13: 3502365a-f88a-4ba4-822a-5769d3073b65, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n14: 377333b1-8b5d-48d6-9679-1225c872d37c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n15: 3df374ef-d444-4494-a5a1-4b0d9fd0e203, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n16: 3f1afc82-f8ac-4f6c-8005-1d233e606eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n17: 49cd895b-53b2-4dc4-a5f7-b18aa019ad37, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n18: 4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c, 1, 1 [(0 )(1 )(2 [0xC004E003, 0, 0], [( 1 0xC004F034)( 1 0xC004F034)(?)(?)(?)(?)(?)(?)])(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004F034)])]\n19: 4f3da0d2-271d-4508-ae81-626b60809a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n20: 5d78c4e9-aeb3-4b40-8ac2-6a6005e0ad6d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n21: 60b3ec1b-9545-4921-821f-311b129dd6f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n22: 613d217f-7f13-4268-9907-1662339531cd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n23: 62f0c100-9c53-4e02-b886-a3528ddfe7f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n24: 6365275e-368d-46ca-a0ef-fc0404119333, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n25: 721f9237-9341-4453-a661-09e8baa6cca5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n26: 73111121-5638-40f6-bc11-f1d7b0d64300, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n27: 7a802526-4c94-4bd1-ba14-835a1aca2120, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n28: 7cb546c0-c7d5-44d8-9a5c-69ecdd782b69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n29: 82bbc092-bc50-4e16-8e18-b74fc486aec3, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n30: 8ab9bdd1-1f67-4997-82d9-8878520837d9, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n31: 8b351c9c-f398-4515-9900-09df49427262, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n32: 90da7373-1c51-430b-bf26-c97e9c5cdc31, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n33: 92fb8726-92a8-4ffc-94ce-f82e07444653, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n34: 95dca82f-385d-4d39-b85b-5c73fa285d6f, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n35: a48938aa-62fa-4966-9d44-9f04da3f72f2, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n36: b0773a15-df3a-4312-9ad2-83d69648e356, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n37: b4bfe195-541e-4e64-ad23-6177f19e395e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n38: b68e61d2-68ca-4757-be45-0cc2f3e68eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n39: bd3762d7-270d-4760-8fb3-d829ca45278a, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n40: c86d5194-4840-4dae-9c1c-0301003a5ab0, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n41: ca7df2e3-5ea0-47b8-9ac1-b1be4d8edd69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n42: d552befb-48cc-4327-8f39-47d2d94f987c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n43: d6eadb3b-5ca8-4a6b-986e-35b550756111, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n44: df96023b-dcd9-4be2-afa0-c6c871159ebe, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n45: e0c42288-980c-4788-a014-c080d2e1926e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n46: e4db50ea-bda1-4566-b047-0ca50abc6f07, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n47: e558417a-5123-4f6f-91e7-385c1c7ca9d4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n48: e7a950a2-e548-4f10-bf16-02ec848e0643, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n49: eb6d346f-1c60-4643-b960-40ec31596c45, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n50: ec868e65-fadf-4759-b23e-93fe37f2cc29, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n51: ef51e000-2659-4f25-8345-3de70a9cf4c4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n52: f7af7d09-40e4-419c-a49b-eae366689ebd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n53: fa755fe6-6739-40b9-8d84-6d0ea3b6d1ab, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n54: fe74f55b-0338-41d6-b267-4a201abe7285, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n\n","EventReceivedTime":"2024-03-14T13:54:20.331+00:00","Data":["55c92734-d682-4d71-983e-d6ec3f16059f","\n1: 040fa323-92b1-4baf-97a2-5b67feaefddb, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n2: 0724cb7d-3437-4cb7-93cb-830375d0079d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n3: 0ad2ac98-7bb9-4201-8d92-312299201369, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n4: 1a9a717a-cf13-4ba5-83c3-0fe25fa868d5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n5: 221a02da-e2a1-4b75-864c-0a4410a33fdf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n6: 291ece0e-9c38-40ca-a9e1-32cc7ec19507, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n7: 2936d1d2-913a-4542-b54e-ce5a602a2a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n8: 2c293c26-a45a-4a2a-a350-c69a67097529, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n9: 2de67392-b7a7-462a-b1ca-108dd189f588, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n10: 2ffd8952-423e-4903-b993-72a1aa44cf82, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n11: 30a42c86-b7a0-4a34-8c90-ff177cb2acb7, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n12: 345a5db0-d94f-4e3b-a0c0-7c42f7bc3ebf, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n13: 3502365a-f88a-4ba4-822a-5769d3073b65, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n14: 377333b1-8b5d-48d6-9679-1225c872d37c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n15: 3df374ef-d444-4494-a5a1-4b0d9fd0e203, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n16: 3f1afc82-f8ac-4f6c-8005-1d233e606eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n17: 49cd895b-53b2-4dc4-a5f7-b18aa019ad37, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n18: 4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c, 1, 1 [(0 )(1 )(2 [0xC004E003, 0, 0], [( 1 0xC004F034)( 1 0xC004F034)(?)(?)(?)(?)(?)(?)])(3 [0x00000000, 0, 0], [( 6 0xC004F009 0 0)( 1 0x00000000)( 6 0xC004F009 0 0)(?)(?)(?)( 10 0x00000000 msft:rm/algorithm/flags/1.0)( 11 0x00000000 0xC004F034)])]\n19: 4f3da0d2-271d-4508-ae81-626b60809a38, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n20: 5d78c4e9-aeb3-4b40-8ac2-6a6005e0ad6d, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n21: 60b3ec1b-9545-4921-821f-311b129dd6f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n22: 613d217f-7f13-4268-9907-1662339531cd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n23: 62f0c100-9c53-4e02-b886-a3528ddfe7f6, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n24: 6365275e-368d-46ca-a0ef-fc0404119333, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n25: 721f9237-9341-4453-a661-09e8baa6cca5, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n26: 73111121-5638-40f6-bc11-f1d7b0d64300, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n27: 7a802526-4c94-4bd1-ba14-835a1aca2120, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n28: 7cb546c0-c7d5-44d8-9a5c-69ecdd782b69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n29: 82bbc092-bc50-4e16-8e18-b74fc486aec3, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n30: 8ab9bdd1-1f67-4997-82d9-8878520837d9, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n31: 8b351c9c-f398-4515-9900-09df49427262, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n32: 90da7373-1c51-430b-bf26-c97e9c5cdc31, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n33: 92fb8726-92a8-4ffc-94ce-f82e07444653, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n34: 95dca82f-385d-4d39-b85b-5c73fa285d6f, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n35: a48938aa-62fa-4966-9d44-9f04da3f72f2, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n36: b0773a15-df3a-4312-9ad2-83d69648e356, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n37: b4bfe195-541e-4e64-ad23-6177f19e395e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n38: b68e61d2-68ca-4757-be45-0cc2f3e68eee, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n39: bd3762d7-270d-4760-8fb3-d829ca45278a, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n40: c86d5194-4840-4dae-9c1c-0301003a5ab0, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n41: ca7df2e3-5ea0-47b8-9ac1-b1be4d8edd69, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n42: d552befb-48cc-4327-8f39-47d2d94f987c, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n43: d6eadb3b-5ca8-4a6b-986e-35b550756111, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n44: df96023b-dcd9-4be2-afa0-c6c871159ebe, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n45: e0c42288-980c-4788-a014-c080d2e1926e, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n46: e4db50ea-bda1-4566-b047-0ca50abc6f07, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n47: e558417a-5123-4f6f-91e7-385c1c7ca9d4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n48: e7a950a2-e548-4f10-bf16-02ec848e0643, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n49: eb6d346f-1c60-4643-b960-40ec31596c45, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n50: ec868e65-fadf-4759-b23e-93fe37f2cc29, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n51: ef51e000-2659-4f25-8345-3de70a9cf4c4, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n52: f7af7d09-40e4-419c-a49b-eae366689ebd, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n53: fa755fe6-6739-40b9-8d84-6d0ea3b6d1ab, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n54: fe74f55b-0338-41d6-b267-4a201abe7285, 1, 0 [(0 [0xC004F014, 0, 0], [(?)(?)(?)(?)(?)(?)(?)(?)])(1 )(2 )(3 )]\n\n"],"OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2024-03-14T13:54:20.331+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Client":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","ServerRevision":"BABAR","ClientRevision":"TOTO"},"Node":"openwec"}}"#;

    #[test]
    fn test_serialize_1003_event_data_unamed() {
        compare(EVENT_1003, EVENT_1003_JSON);
    }

    const EVENT_8198: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-SPP' Guid='{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}' EventSourceName='Software Protection Platform Service'/><EventID Qualifiers='49152'>8198</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2024-03-14T13:54:25.1166916Z'/><EventRecordID>405</EventRecordID><Correlation/><Execution ProcessID='7240' ThreadID='0'/><Channel>Application</Channel><Computer>WKS10001</Computer><Security/></System><EventData><Data>hr=0x800704CF</Data><Data>RuleId=31e71c49-8da7-4a2f-ad92-45d98a1c79ba;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f16059f;SkuId=4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c;NotificationInterval=1440;Trigger=UserLogon;SessionId=2</Data></EventData><RenderingInfo Culture='en-GB'><Message>License Activation (slui.exe) failed with the following error code:&#13;&#10;hr=0x800704CF&#13;&#10;Command-line arguments:&#13;&#10;RuleId=31e71c49-8da7-4a2f-ad92-45d98a1c79ba;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f16059f;SkuId=4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c;NotificationInterval=1440;Trigger=UserLogon;SessionId=2</Message><Level>Error</Level><Provider>Microsoft-Windows-Security-SPP</Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_8198_JSON: &str = r#"{"Data":["hr=0x800704CF","RuleId=31e71c49-8da7-4a2f-ad92-45d98a1c79ba;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f16059f;SkuId=4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c;NotificationInterval=1440;Trigger=UserLogon;SessionId=2"],"EventTime":"2024-03-14T13:54:25.1166916Z","Hostname":"WKS10001","Keywords":36028797018963968,"EventType":"ERROR","SeverityValue":4,"Severity":"ERROR","EventID":8198,"SourceName":"Microsoft-Windows-Security-SPP","ProviderGuid":"{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}","Version":0,"Task":0,"OpcodeValue":0,"RecordNumber":405,"ProcessID":7240,"ThreadID":0,"Channel":"Application","Message":"License Activation (slui.exe) failed with the following error code:\r\nhr=0x800704CF\r\nCommand-line arguments:\r\nRuleId=31e71c49-8da7-4a2f-ad92-45d98a1c79ba;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f16059f;SkuId=4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c;NotificationInterval=1440;Trigger=UserLogon;SessionId=2","EventReceivedTime":"2024-03-14T13:54:20.331+00:00","OpenWEC":{"IpAddress":"192.168.58.100","Node":"openwec","Principal":"WIN10$@WINDOMAIN.LOCAL","Client":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Name": "Test","Uri":"/this/is/a/test","Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","ServerRevision":"BABAR","ClientRevision":"TOTO"},"TimeReceived":"2024-03-14T13:54:20.331+00:00"}}"#;

    #[test]
    fn test_serialize_8198() {
        compare(EVENT_8198, EVENT_8198_JSON)
    }

    const EVENT_8002: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Store' Guid='{9c2a37f3-e5fd-5cae-bcd1-43dafeee1ff0}'/><EventID>8002</EventID><Version>0</Version><Level>3</Level><Task>8001</Task><Opcode>13</Opcode><Keywords>0x8000100000000000</Keywords><TimeCreated SystemTime='2024-03-14T13:54:11.8558403Z'/><EventRecordID>4974</EventRecordID><Correlation/><Execution ProcessID='5496' ThreadID='3248'/><Channel>Microsoft-Windows-Store/Operational</Channel><Computer>WKS10001</Computer><Security UserID='S-1-5-19'/></System><EventData><Data Name='Message'>Trying to remove timer {5691E7B0-78A4-A20B-3094-CD9BCC47193D} not in table</Data><Data Name='Function'>MemoryTimerService::CancelTimerWithId</Data><Data Name='Source'>onecoreuap\enduser\winstore\licensemanager\lib\memorytimer.cpp</Data><Data Name='Line Number'>80</Data></EventData><RenderingInfo Culture='en-GB'><Message>Trying to remove timer {5691E7B0-78A4-A20B-3094-CD9BCC47193D} not in table&#13;&#10;Function: MemoryTimerService::CancelTimerWithId&#13;&#10;Source: onecoreuap\enduser\winstore\licensemanager\lib\memorytimer.cpp (80)</Message><Level>Warning</Level><Task>LM</Task><Opcode>Warning</Opcode><Provider>Microsoft-Windows-Store</Provider></RenderingInfo></Event>"#;
    const EVENT_8002_JSON: &str = r#"{"EventTime":"2024-03-14T13:54:11.8558403Z","Hostname":"WKS10001","Keywords":-9223354444668731392,"EventType":"WARNING","SeverityValue":3,"Severity":"WARNING","EventID":8002,"SourceName":"Microsoft-Windows-Store","ProviderGuid":"{9C2A37F3-E5FD-5CAE-BCD1-43DAFEEE1FF0}","Version":0,"Task":8001,"OpcodeValue":13,"RecordNumber":4974,"ProcessID":5496,"ThreadID":3248,"Channel":"Microsoft-Windows-Store/Operational","UserID":"S-1-5-19","Message":"Trying to remove timer {5691E7B0-78A4-A20B-3094-CD9BCC47193D} not in table\r\nFunction: MemoryTimerService::CancelTimerWithId\r\nSource: onecoreuap\\enduser\\winstore\\licensemanager\\lib\\memorytimer.cpp (80)","Category":"LM","Opcode":"Warning","Function":"MemoryTimerService::CancelTimerWithId","Source":"onecoreuap\\enduser\\winstore\\licensemanager\\lib\\memorytimer.cpp","Line Number":"80","EventReceivedTime":"2024-03-14T13:54:20.331+00:00","OpenWEC":{"IpAddress":"192.168.58.100","Node":"openwec","Principal":"WIN10$@WINDOMAIN.LOCAL","Client":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Name":"Test","Uri":"/this/is/a/test","Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","ServerRevision":"BABAR","ClientRevision":"TOTO"},"TimeReceived":"2024-03-14T13:54:20.331+00:00"}}"#;

    #[test]
    fn test_serialize_8002() {
        compare(EVENT_8002, EVENT_8002_JSON)
    }

    const EVENT_4625: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2024-03-14T13:54:16.6138329Z'/><EventRecordID>1444</EventRecordID><Correlation ActivityID='{b073a4bf-7611-0000-bca5-73b01176da01}'/><Execution ProcessID='780' ThreadID='8372'/><Channel>Security</Channel><Computer>WKS10001</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>WKS10001$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>user</Data><Data Name='TargetDomainName'>WKS10001</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>User32 </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>WKS10001</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x5c8</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='IpAddress'>127.0.0.1</Data><Data Name='IpPort'>0</Data></EventData><RenderingInfo Culture='en-GB'><Message>An account failed to log on.&#13;&#10;&#13;&#10;Subject:&#13;&#10;&#9;Security ID:&#9;&#9;S-1-5-18&#13;&#10;&#9;Account Name:&#9;&#9;WKS10001$&#13;&#10;&#9;Account Domain:&#9;&#9;WORKGROUP&#13;&#10;&#9;Logon ID:&#9;&#9;0x3E7&#13;&#10;&#13;&#10;Logon Type:&#9;&#9;&#9;2&#13;&#10;&#13;&#10;Account For Which Logon Failed:&#13;&#10;&#9;Security ID:&#9;&#9;S-1-0-0&#13;&#10;&#9;Account Name:&#9;&#9;user&#13;&#10;&#9;Account Domain:&#9;&#9;WKS10001&#13;&#10;&#13;&#10;Failure Information:&#13;&#10;&#9;Failure Reason:&#9;&#9;Unknown user name or bad password.&#13;&#10;&#9;Status:&#9;&#9;&#9;0xC000006D&#13;&#10;&#9;Sub Status:&#9;&#9;0xC000006A&#13;&#10;&#13;&#10;Process Information:&#13;&#10;&#9;Caller Process ID:&#9;0x5c8&#13;&#10;&#9;Caller Process Name:&#9;C:\Windows\System32\svchost.exe&#13;&#10;&#13;&#10;Network Information:&#13;&#10;&#9;Workstation Name:&#9;WKS10001&#13;&#10;&#9;Source Network Address:&#9;127.0.0.1&#13;&#10;&#9;Source Port:&#9;&#9;0&#13;&#10;&#13;&#10;Detailed Authentication Information:&#13;&#10;&#9;Logon Process:&#9;&#9;User32 &#13;&#10;&#9;Authentication Package:&#9;Negotiate&#13;&#10;&#9;Transited Services:&#9;-&#13;&#10;&#9;Package Name (NTLM only):&#9;-&#13;&#10;&#9;Key Length:&#9;&#9;0&#13;&#10;&#13;&#10;This event is generated when a logon request fails. It is generated on the computer where access was attempted.&#13;&#10;&#13;&#10;The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.&#13;&#10;&#13;&#10;The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).&#13;&#10;&#13;&#10;The Process Information fields indicate which account and process on the system requested the logon.&#13;&#10;&#13;&#10;The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.&#13;&#10;&#13;&#10;The authentication information fields provide detailed information about this specific logon request.&#13;&#10;&#9;- Transited services indicate which intermediate services have participated in this logon request.&#13;&#10;&#9;- Package name indicates which sub-protocol was used among the NTLM protocols.&#13;&#10;&#9;- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.</Message><Level>Information</Level><Task>Logon</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Failure</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_4625_JSON: &str = r#"{"EventTime":"2024-03-14T13:54:16.6138329Z","Hostname":"WKS10001","Keywords":-9218868437227405312,"EventType":"AUDIT_FAILURE","SeverityValue":4,"Severity":"ERROR","EventID":4625,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Version":0,"Task":12544,"OpcodeValue":0,"RecordNumber":1444,"ActivityID":"{B073A4BF-7611-0000-BCA5-73B01176DA01}","ProcessID":780,"ThreadID":8372,"Channel":"Security","Message":"An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tWKS10001$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Type:\t\t\t2\r\n\r\nAccount For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\tuser\r\n\tAccount Domain:\t\tWKS10001\r\n\r\nFailure Information:\r\n\tFailure Reason:\t\tUnknown user name or bad password.\r\n\tStatus:\t\t\t0xC000006D\r\n\tSub Status:\t\t0xC000006A\r\n\r\nProcess Information:\r\n\tCaller Process ID:\t0x5c8\r\n\tCaller Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tWKS10001\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\r\n\r\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe Process Information fields indicate which account and process on the system requested the logon.\r\n\r\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.","Category":"Logon","Opcode":"Info","SubjectUserSid":"S-1-5-18","SubjectUserName":"WKS10001$","SubjectDomainName":"WORKGROUP","SubjectLogonId":"0x3e7","TargetUserSid":"S-1-0-0","TargetUserName":"user","TargetDomainName":"WKS10001","Status":"0xc000006d","FailureReason":"%%2313","SubStatus":"0xc000006a","LogonType":"2","LogonProcessName":"User32 ","AuthenticationPackageName":"Negotiate","WorkstationName":"WKS10001","TransmittedServices":"-","LmPackageName":"-","KeyLength":"0","ProcessName":"C:\\Windows\\System32\\svchost.exe","IpAddress":"127.0.0.1","IpPort":"0","EventReceivedTime":"2024-03-14T13:54:20.331+00:00","OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2024-03-14T13:54:20.331+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Client":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","ServerRevision":"BABAR","ClientRevision":"TOTO"},"Node":"openwec"},"ProcessId":"0x5c8"}"#;

    #[test]
    fn test_serialize_4625() {
        compare(EVENT_4625, EVENT_4625_JSON)
    }

    const EVENT_328: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppXDeployment' Guid='{8127f6d4-59f9-4abf-8952-3e3a02073d5f}'/><EventID>328</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000010000</Keywords><TimeCreated SystemTime='2024-03-14T13:54:19.4093952Z'/><EventRecordID>20</EventRecordID><Correlation ActivityID='{61a55000-55e5-1017-0000-000000000000}'/><Execution ProcessID='468' ThreadID='4744'/><Channel>Microsoft-Windows-AppXDeployment/Operational</Channel><Computer>WKS10001</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='ErrorCode'>0x800401f0</Data></EventData><RenderingInfo Culture='en-GB'><Message>Unable to determine packages to be installed during logon with error: 0x800401F0.</Message><Level>Error</Level><Opcode>Info</Opcode><Provider>Microsoft-Windows-AppXDeployment</Provider></RenderingInfo></Event>"#;
    const EVENT_328_JSON: &str = r#"{"EventTime":"2024-03-14T13:54:19.4093952Z","Hostname":"WKS10001","Keywords":4611686018427453440,"EventType":"ERROR","SeverityValue":4,"Severity":"ERROR","EventID":328,"SourceName":"Microsoft-Windows-AppXDeployment","ProviderGuid":"{8127F6D4-59F9-4ABF-8952-3E3A02073D5F}","Version":0,"Task":0,"OpcodeValue":0,"RecordNumber":20,"ActivityID":"{61A55000-55E5-1017-0000-000000000000}","ProcessID":468,"ThreadID":4744,"Channel":"Microsoft-Windows-AppXDeployment/Operational","UserID":"S-1-5-18","Message":"Unable to determine packages to be installed during logon with error: 0x800401F0.","Opcode":"Info","ErrorCode":"0x800401f0","EventReceivedTime":"2024-03-14T13:54:20.331+00:00","OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2024-03-14T13:54:20.331+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Client":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","ServerRevision":"BABAR","ClientRevision":"TOTO"},"Node":"openwec"}}"#;

    #[test]
    fn test_serialize_328() {
        compare(EVENT_328, EVENT_328_JSON)
    }

    const EVENT_1100: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1100</EventID><Version>0</Version><Level>4</Level><Task>103</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2022-12-14T14:39:07.1686183Z'/><EventRecordID>114371</EventRecordID><Correlation/><Execution ProcessID='496' ThreadID='204'/><Channel>Security</Channel><Computer>win10.windomain.local</Computer><Security/></System><UserData><ServiceShutdown xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'></ServiceShutdown></UserData><RenderingInfo Culture='en-US'><Message>The event logging service has shut down.</Message><Level>Information</Level><Task>Service shutdown</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft-Windows-Eventlog</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event>"#;
    const EVENT_1100_JSON: &str = r#"{"SourceName":"Microsoft-Windows-Eventlog","ProviderGuid":"{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}","EventID":1100,"Version":0,"Task":103,"OpcodeValue":0,"Keywords":4620693217682128896,"EventTime":"2022-12-14T14:39:07.1686183Z","RecordNumber":114371,"ProcessID":496,"ThreadID":204,"Channel":"Security","Hostname":"win10.windomain.local","EventType":"AUDIT_SUCCESS","Severity":"INFO","SeverityValue":2,"UserData":"<ServiceShutdown xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'></ServiceShutdown>","Message":"The event logging service has shut down.","Category":"Service shutdown","Opcode":"Info","OpenWEC":{"IpAddress":"192.168.58.100","TimeReceived":"2024-03-14T13:54:20.331+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Client":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","ClientRevision":"TOTO","ServerRevision":"BABAR"},"Node":"openwec"},"EventReceivedTime":"2024-03-14T13:54:20.331+00:00"}"#;

    #[test]
    fn test_serialize_1100() {
        // UserData
        compare(EVENT_1100, EVENT_1100_JSON)
    }
}
