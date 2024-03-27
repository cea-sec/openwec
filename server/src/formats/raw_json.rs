use std::sync::Arc;

use log::warn;
use serde::Serialize;

use crate::{
    event::{EventData, EventMetadata},
    output::OutputFormat,
};

pub struct RawJsonFormat;

#[derive(Serialize)]
struct RawJson {
    meta: Metadata,
    data: Arc<String>,
}

#[derive(Serialize)]
struct Metadata {
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
}

#[derive(Serialize)]
struct SubscriptionType {
    #[serde(rename = "Uuid")]
    uuid: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Uri", skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(rename = "Revision", skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
}

impl Metadata {
    pub fn new(metadata: &EventMetadata) -> Self {
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
                revision: metadata.subscription_revision().cloned(),
            },
        }
    }
}

impl OutputFormat for RawJsonFormat {
    fn format(&self, metadata: &EventMetadata, data: &EventData) -> Option<Arc<String>> {
        let event = RawJson {
            meta: Metadata::new(metadata),
            data: data.raw(),
        };
        match serde_json::to_string(&event) {
            Ok(str) => Some(Arc::new(str)),
            Err(e) => {
                warn!("Failed to format event in Raw Json: {:?}.", e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, sync::Arc};

    use chrono::Utc;
    use common::subscription::{SubscriptionData, SubscriptionUuid};
    use serde_json::Value;
    use uuid::Uuid;

    use crate::{
        event::{EventData, EventMetadata},
        formats::raw_json::RawJsonFormat,
        output::OutputFormat,
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
    const EVENT_4688_JSON: &str = r#"{"meta":{"IpAddress":"192.168.58.100","TimeReceived":"2022-12-14T16:07:03.331+00:00","Principal":"WIN10$@WINDOMAIN.LOCAL","Subscription":{"Uuid":"8B18D83D-2964-4F35-AC3B-6F4E6FFA727B","Version":"188BB736-9441-5C66-188B-B73694415C66","Name":"Test","Uri":"/this/is/a/test","Revision":"1234"},"Node":"openwec"},"data":"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2022-12-14T16:06:51.0643605Z'/><EventRecordID>114689</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='196'/><Channel>Security</Channel><Computer>win10.windomain.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>WIN10$</Data><Data Name='SubjectDomainName'>WINDOMAIN</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='NewProcessId'>0x3a8</Data><Data Name='NewProcessName'>C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe</Data><Data Name='TokenElevationType'>%%1936</Data><Data Name='ProcessId'>0x240</Data><Data Name='CommandLine'></Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>-</Data><Data Name='TargetDomainName'>-</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='ParentProcessName'>C:\\Windows\\System32\\services.exe</Data><Data Name='MandatoryLabel'>S-1-16-16384</Data></EventData><RenderingInfo Culture='en-US'><Message>A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWIN10$\n\tAccount Domain:\t\tWINDOMAIN\n\tLogon ID:\t\t0x3E7\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x3a8\n\tNew Process Name:\tC:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\n\tToken Elevation Type:\t%%1936\n\tMandatory Label:\t\tS-1-16-16384\n\tCreator Process ID:\t0x240\n\tCreator Process Name:\tC:\\Windows\\System32\\services.exe\n\tProcess Command Line:\t\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.</Message><Level>Information</Level><Task>Process Creation</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event>"}"#;

    #[test]
    fn test_json_format_4688() {
        // Generate metadata
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()))
            .set_revision(Some("1234".to_string()));
        let subscription = Subscription::try_from(subscription_data).unwrap();

        let mut metadata = EventMetadata::new(
            &SocketAddr::from_str("192.168.58.100:5985").unwrap(),
            "WIN10$@WINDOMAIN.LOCAL",
            Some("openwec".to_owned()),
            &subscription,
            "188BB736-9441-5C66-188B-B73694415C66".to_string(),
            Some("1234".to_string())
        );
        metadata.set_time_received(
            chrono::DateTime::parse_from_rfc3339("2022-12-14T17:07:03.331+01:00")
                .unwrap()
                .with_timezone(&Utc),
        );

        // Parse and check event

        let event_data = EventData::new(Arc::new(EVENT_4688.to_string()), true);
        assert!(event_data.event().unwrap().additional.error.is_none());

        let formatter = RawJsonFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        let event_json_value: Value = serde_json::from_str(&result).unwrap();
        let expected_value: Value = serde_json::from_str(EVENT_4688_JSON).unwrap();

        assert_eq!(event_json_value, expected_value);
    }
}
