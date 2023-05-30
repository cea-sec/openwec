# Formats

Windows events received are in a XML format, the same one you can see in Windows Event Viewer.

OpenWEC server can parse each event and format it differently.

## Raw (XML) format

Using this format, you get the exact event received by OpenWEC (no parsing happens).

The XML schema is defined in the Windows SDK (see [event.xsd](event.xsd)).

### Json format

Using this format, raw XML events are parsed and then serialized using Json.

In addition, OpenWEC adds some data that may be useful: the Windows client IP address, its principal, the time when the event was received and the OpenWEC subscription.

The JSON document generated uses the following structure:
```json
event := {
    "System": system,
    "EventData": event_data,
    "DebugData": debug_data,
    "UserData": string,
    "ProcessingErrorData": processing_error_data,
    "BinaryEventData": string,
    "RenderingInfo": rendering_info,
    "OpenWEC": openwec_data
}

openwec_data := {
    /* IP Address of the Windows client */
    "IpAddress": string,
    /* Time when the event was received by OpenWEC */
    "TimeReceived": date,
    /* Principal of the Windows client */
    "Principal": string,
    "Subscription": {
        "Name": string,
        "Version": string,
        "Uuid": string,
        "Uri": string
    }
}

system := {
    "Provider": {
        "Name": string,
        "Guid": string,
        "EventSourceName": string
    },
    "EventID": number,
    "EventIDQualifiers": number,
    "Vesion": number,
    "Level": number,
    "Task": number,
    "Opcode": number,
    "Keywords": string,
    "TimeCreated": date,
    "EventRecordID": number,
    "Correlation": {
        "ActivityID": string,
        "RelatedActivityID": string
    },
    "Execution": execution,
    "Channel": string,
    "Computer": string,
    "Container": string,
    "UserID": string
}

execution := {
    "ProcessID": number,
    "ThreadID": number,
    "ProcessorID": number,
    "SessionID": number,
    "KernelTime": number,
    "UserTime": number,
    "ProcessorTime": number
}

rendering_info := {
    "Message": string,
    "Level": string,
    "Task": string,
    "Opcode": string,
    "Channel": string,
    "Provider": string,
    "Keywords": array[string],
    "Culture": string
}

event_data := {
    /* Depends of the event */
    string: any,
    ...,
    "Data": array[string],
    "Binary": array[string]
}

debug_data := {
    "SequenceNumber": number,
    "FlagsName": string,
    "LevelName": string,
    "Component": string,
    "SubComponent": string,
    "FileLine": string,
    "Function": string,
    "Message": string
}

processing_error_data := {
    "ErrorCode": number,
    "DataItemName": string,
    "EventPayload": string
}
```

#### Example

```json
{
  "System": {
    "Provider": {
      "Name": "Microsoft-Windows-Security-Auditing",
      "Guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}"
    },
    "EventID": 4688,
    "Version": 2,
    "Level": 0,
    "Task": 13312,
    "Opcode": 0,
    "Keywords": "0x8020000000000000",
    "TimeCreated": "2022-12-14T16:06:51.0643605Z",
    "EventRecordID": 114689,
    "Correlation": {},
    "Execution": {
      "ProcessID": 4,
      "ThreadID": 196
    },
    "Channel": "Security",
    "Computer": "win10.windomain.local"
  },
  "EventData": {
    "SubjectLogonId": "0x3e7",
    "SubjectUserName": "WIN10$",
    "SubjectDomainName": "WINDOMAIN",
    "ParentProcessName": "C:\\Windows\\System32\\services.exe",
    "MandatoryLabel": "S-1-16-16384",
    "SubjectUserSid": "S-1-5-18",
    "NewProcessName": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
    "TokenElevationType": "%%1936",
    "TargetUserSid": "S-1-0-0",
    "TargetDomainName": "-",
    "CommandLine": "",
    "TargetUserName": "-",
    "NewProcessId": "0x3a8",
    "TargetLogonId": "0x0",
    "ProcessId": "0x240"
  },
  "RenderingInfo": {
    "Message": "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWIN10$\n\tAccount Domain:\t\tWINDOMAIN\n\tLogon ID:\t\t0x3E7\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x3a8\n\tNew Process Name:\tC:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\n\tToken Elevation Type:\t%%1936\n\tMandatory Label:\t\tS-1-16-16384\n\tCreator Process ID:\t0x240\n\tCreator Process Name:\tC:\\Windows\\System32\\services.exe\n\tProcess Command Line:\t\n\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\n\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\n\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\n\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.",
    "Level": "Information",
    "Task": "Process Creation",
    "Opcode": "Info",
    "Channel": "Security",
    "Provider": "Microsoft Windows security auditing.",
    "Keywords": [
      "Audit Success"
    ],
    "Culture": "en-US"
  },
  "OpenWEC": {
    "IpAddress": "192.168.58.100",
    "TimeReceived": "2022-12-14T17:07:03.331+01:00",
    "Principal": "WIN10$@WINDOMAIN.LOCAL",
    "Subscription": {
      "Uuid": "8B18D83D-2964-4F35-AC3B-6F4E6FFA727B",
      "Version": "AD0D118F-31EF-4111-A0CA-D87249747278",
      "Name": "Test",
      "Uri": "/this/is/a/test"
    }
  }
}
```

## How to add a new formatter ?

TODO
