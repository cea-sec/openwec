use std::sync::Arc;

use crate::{
    event::{EventData, EventMetadata},
    output::OutputFormat,
};

pub struct RawFormat;

impl OutputFormat for RawFormat {
    fn format(&self, _metadata: &EventMetadata, data: &EventData) -> Option<Arc<String>> {
        Some(data.raw())
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
    use uuid::Uuid;

    use crate::{
        event::{EventData, EventMetadata},
        formats::raw::RawFormat,
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

    #[test]
    fn test_raw_format_4688() {
        // Generate metadata (which should be ignored)
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()))
            .set_revision(Some("1234".to_string()));
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

        let formatter = RawFormat;
        let result = formatter.format(&metadata, &event_data).unwrap();

        assert_eq!(result.as_str(), EVENT_4688);
    }
}
