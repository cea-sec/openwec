# Analysis of the Event Forwarding protocol in Push mode

<!-- @import "[TOC]" {cmd="toc" depthFrom=2 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [Lab](#lab)
- [Step by step](#step-by-step)
  - [The client connects in TCP to srv.windomain.local:5985 (source port: 65091)](#the-client-connects-in-tcp-to-srv.windomain.local5985-source-port-65091)
  - [The client sends a HTTP POST request](#the-client-sends-a-http-post-request)
  - [The collector authenticates the client and sends its response](#the-collector-authenticates-the-client-and-sends-its-response)
  - [The client sends a `Enumerate` request](#the-client-sends-a-enumerate-request)
  - [The collector answers "EnumerateResponse"](#the-collector-answers-enumerateresponse)
  - [The client sends an `End` request](#the-client-sends-an-end-request)
  - [The collector sends back "No Content"](#the-collector-sends-back-no-content)
  - [The client closes the TCP connection](#the-client-closes-the-tcp-connection)
  - [The client opens a new TCP connection (source port 65092)](#the-client-opens-a-new-tcp-connection-source-port-65092)
  - [The client sends a POST request to the URL found in `DeliveryTo/Address` and authenticate in Kerberos](#the-client-sends-a-post-request-to-the-url-found-in-deliverytoaddress-and-authenticate-in-kerberos)
  - [The collector validates the authentication](#the-collector-validates-the-authentication)
  - [The client sends a Heartbeat (may not always happen)](#the-client-sends-a-heartbeat-may-not-always-happen)
  - [The collector acknowledges](#the-collector-acknowledges)
  - [The client sends a POST request containing a batch of events](#the-client-sends-a-post-request-containing-a-batch-of-events)
  - [The collector acknowledges](#the-collector-acknowledges)
  - [And so on...](#and-so-on)
  - [The client can end the subscription](#the-client-can-end-the-subscription)
- [Side note](#side-note)

<!-- /code_chunk_output -->

We analysed the protocol in Push mode. In this mode the client connects to the collector to send it its event.

Documentation:
- [Web Services For Management (WS-Management) Specification (DSP0226)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0226_1.0.0.pdf). Some interesting sections:
    - 5 Addressing
    - 8 WS-Enumeration
    - 10 Eventing
    - 12 Security
    - 13 Transports and Message Encoding
- [MS-WSMV (Web Services Management Protocol Extensions for Windows Vista)](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-WSMV/%5BMS-WSMV%5D.pdf) which is a Microsoft WS-Management extension. The main interesting part is:
    - 3.1.4.1.30 - Subscription

## Lab

For this analysis we used:

- an Active Directory domain with one domain controller
    - see <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100->
- a Windows Event Collector server
    - see <https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription>
- a Windows machine configured to send its logs to a Windows Event Collector
    - see as well <https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription>

For our analysis we used the following client configuration:

```
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager]
"1"="Server=HTTP://srv.windomain.local:5985/wsman/SubscriptionManager/WEC,Refresh=3"
```

## Step by step

When our test environment was ready, we captured every traffic between the Windows machine and the Windows Event collector server.

Here is what we saw step by step.

### The client connects in TCP to srv.windomain.local:5985 (source port: 65091)

### The client sends a HTTP POST request

```
Frame 3730: 90 bytes on wire (720 bits), 90 bytes captured (720 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_a6:35:47 (08:00:27:a6:35:47), Dst: PcsCompu_62:f7:34 (08:00:27:62:f7:34)
Internet Protocol Version 4, Src: 192.168.58.100, Dst: 192.168.58.103
Transmission Control Protocol, Src Port: 65091, Dst Port: 5985, Seq: 2921, Ack: 1, Len: 36
[3 Reassembled TCP Segments (2956 bytes): #3728(1460), #3729(1460), #3730(36)]
Hypertext Transfer Protocol
    POST /wsman/SubscriptionManager/WEC HTTP/1.1\r\n
    Connection: Keep-Alive\r\n
    Content-Type: application/soap+xml;charset=UTF-16\r\n
     [truncated]Authorization: Kerberos YIIH9AYJKoZIhvcSAQICAQBuggfjMIIH36ADAgEFoQMCAQ6iBwMFACAAAACjggYOYYIGCjCCBgagAwIBBaERGw9XSU5ET01BSU4uTE9DQUyiJjAkoAMCAQKhHTAbGwRIVFRQGxNzcnYud2luZG9tYWluLmxvY2Fso4IFwjCCBb6gAwIBEqEDAgEFooIFsASCBazWEk8V/B
    User-Agent: Microsoft WinRM Client\r\n
    Content-Length: 0\r\n
    Host: srv.windomain.local:5985\r\n
    \r\n
    [Full request URI: http://srv.windomain.local:5985/wsman/SubscriptionManager/WEC]
    [HTTP request 1/3]
    [Response in frame: 3732]
    [Next request in frame: 3736]
```

Within the `Authorization` blob we find a `KRB_AP_REQ`:

```
 [truncated]Authorization: Kerberos YIIH9AYJKoZIhvcSAQICAQBuggfjMIIH36ADAgEFoQMCAQ6iBwMFACAAAACjggYOYYIGCjCCBgagAwIBBaERGw9XSU5ET01BSU4uTE9DQUyiJjAkoAMCAQKhHTAbGwRIVFRQGxNzcnYud2luZG9tYWluLmxvY2Fso4IFwjCCBb6gAwIBEqEDAgEFooIFsASCBazWEk8V/B
    GSS-API Generic Security Service Application Program Interface
        OID: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
        krb5_blob: 01006e8207e3308207dfa003020105a10302010ea20703050020000000a382060e618206…
            krb5_tok_id: KRB5_AP_REQ (0x0001)
            Kerberos
                ap-req
                    pvno: 5
                    msg-type: krb-ap-req (14)
                    Padding: 0
                    ap-options: 20000000
                        0... .... = reserved: False
                        .0.. .... = use-session-key: False
                        ..1. .... = mutual-required: True
                    ticket
                        tkt-vno: 5
                        realm: WINDOMAIN.LOCAL
                        sname
                            name-type: kRB5-NT-SRV-INST (2)
                            sname-string: 2 items
                                SNameString: HTTP
                                SNameString: srv.windomain.local
                        enc-part
                            etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                            kvno: 5
                            cipher: d6124f15fc1864ea02cf6a5d15351620f470aaaa1059d073f17533c1f68c8926a0122380…
                                Decrypted keytype 18 usage 2 using keytab principal SRV$@WINDOMAIN.LOCAL (id=keytab.2 same=0) (b589d323...)
                                encTicketPart
                                    Padding: 0
                                    flags: 40a10000
                                        0... .... = reserved: False
                                        .1.. .... = forwardable: True
                                        ..0. .... = forwarded: False
                                        ...0 .... = proxiable: False
                                        .... 0... = proxy: False
                                        .... .0.. = may-postdate: False
                                        .... ..0. = postdated: False
                                        .... ...0 = invalid: False
                                        1... .... = renewable: True
                                        .0.. .... = initial: False
                                        ..1. .... = pre-authent: True
                                        ...0 .... = hw-authent: False
                                        .... 0... = transited-policy-checked: False
                                        .... .0.. = ok-as-delegate: False
                                        .... ..0. = unused: False
                                        .... ...1 = enc-pa-rep: True
                                        0... .... = anonymous: False
                                    key
                                        Learnt encTicketPart_key keytype 18 (id=3730.1) (3510bcf8...)
                                        keytype: 18
                                        keyvalue: 3510bcf8db17bb605f95b3cd36f44a4e2a8e125b5c36bd3281cf0789401f95f7
                                    crealm: WINDOMAIN.LOCAL
                                    cname
                                        name-type: kRB5-NT-PRINCIPAL (1)
                                        cname-string: 1 item
                                            CNameString: WIN10$
                                    transited
                                        tr-type: 1
                                        contents: <MISSING>
                                    authtime: 2022-09-22 08:03:20 (UTC)
                                    starttime: 2022-09-22 08:05:18 (UTC)
                                    endtime: 2022-09-22 18:03:20 (UTC)
                                    renew-till: 2022-09-29 08:03:20 (UTC)
                                    authorization-data: 2 items
                                        AuthorizationData item
                                            ad-type: aD-IF-RELEVANT (1)
                                            ad-data: 3082044a30820446a00402020080a182043c048204380900000000000000010000000802…
                                                AuthorizationData item
                                                    ad-type: aD-WIN2K-PAC (128)
                                                    ad-data: 0900000000000000010000000802000098000000000000000e000000b8000000a0020000…
                                                        Verified Server checksum 16 keytype 18 using keytab principal SRV$@WINDOMAIN.LOCAL (id=keytab.2 same=0) (b589d323...)
                                                        Num Entries: 9
                                                        Version: 0
                                                        Type: Logon Info (1)
                                                            Size: 520
                                                            Offset: 152
                                                            PAC_LOGON_INFO: 01100800ccccccccf801000000000000000002005c85b7c759ced801ffffffffffffff7f…
                                                                MES header
                                                                    Version: 1
                                                                    DREP
                                                                        Byte order: Little-endian (1)
                                                                    HDR Length: 8
                                                                    Fill bytes: 0xcccccccc
                                                                    Blob Length: 504
                                                                PAC_LOGON_INFO:
                                                                    Referent ID: 0x00020000
                                                                    Logon Time: Sep 22, 2022 10:03:20.553404400 CEST
                                                                    Logoff Time: Infinity (absolute time)
                                                                    Kickoff Time: Infinity (absolute time)
                                                                    PWD Last Set: Sep 21, 2022 14:43:14.781129900 CEST
                                                                    PWD Can Change: Sep 21, 2022 14:43:14.781129900 CEST
                                                                    PWD Must Change: Infinity (absolute time)
                                                                    Acct Name: WIN10$
                                                                        Length: 12
                                                                        Size: 12
                                                                        Character Array: WIN10$
                                                                            Referent ID: 0x00020004
                                                                            Max Count: 6
                                                                            Offset: 0
                                                                            Actual Count: 6
                                                                            Acct Name: WIN10$
                                                                    Full Name
                                                                        Length: 0
                                                                        Size: 0
                                                                        Character Array
                                                                            Referent ID: 0x00020008
                                                                            Max Count: 0
                                                                            Offset: 0
                                                                            Actual Count: 0
                                                                    Logon Script
                                                                        Length: 0
                                                                        Size: 0
                                                                        Character Array
                                                                            Referent ID: 0x0002000c
                                                                            Max Count: 0
                                                                            Offset: 0
                                                                            Actual Count: 0
                                                                    Profile Path
                                                                        Length: 0
                                                                        Size: 0
                                                                        Character Array
                                                                            Referent ID: 0x00020010
                                                                            Max Count: 0
                                                                            Offset: 0
                                                                            Actual Count: 0
                                                                    Home Dir
                                                                        Length: 0
                                                                        Size: 0
                                                                        Character Array
                                                                            Referent ID: 0x00020014
                                                                            Max Count: 0
                                                                            Offset: 0
                                                                            Actual Count: 0
                                                                    Dir Drive
                                                                        Length: 0
                                                                        Size: 0
                                                                        Character Array
                                                                            Referent ID: 0x00020018
                                                                            Max Count: 0
                                                                            Offset: 0
                                                                            Actual Count: 0
                                                                    Logon Count: 175
                                                                    Bad PW Count: 0
                                                                    User RID: 1105
                                                                    Group RID: 515
                                                                    Num RIDs: 1
                                                                    GroupIDs
                                                                        Referent ID: 0x0002001c
                                                                        Max Count: 1
                                                                        GROUP_MEMBERSHIP:
                                                                            Group RID: 515
                                                                            Attributes: 0x00000007
                                                                                .... .... .... .... .... .... .... .1.. = Enabled: The enabled bit is SET
                                                                                .... .... .... .... .... .... .... ..1. = Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                                                                                .... .... .... .... .... .... .... ...1 = Mandatory: The MANDATORY bit is SET
                                                                    User Flags: 0x00000020
                                                                        .... .... .... .... .... ..0. .... .... = Resource Groups: The resource_groups is NOT set
                                                                        .... .... .... .... .... .... ..1. .... = Extra SIDs: The EXTRA_SIDS bit is SET
                                                                    User Session Key: 00000000000000000000000000000000
                                                                    Server: DC
                                                                        Length: 4
                                                                        Size: 6
                                                                        Character Array: DC
                                                                            Referent ID: 0x00020020
                                                                            Max Count: 3
                                                                            Offset: 0
                                                                            Actual Count: 2
                                                                            Server: DC
                                                                    Domain: WINDOMAIN
                                                                        Length: 18
                                                                        Size: 20
                                                                        Character Array: WINDOMAIN
                                                                            Referent ID: 0x00020024
                                                                            Max Count: 10
                                                                            Offset: 0
                                                                            Actual Count: 9
                                                                            Domain: WINDOMAIN
                                                                    SID pointer:
                                                                        SID pointer
                                                                            Referent ID: 0x00020028
                                                                            Count: 4
                                                                            Domain SID: S-1-5-21-3597817948-3716833002-415491962  (Domain SID)
                                                                                Revision: 1
                                                                                Num Auth: 4
                                                                                Authority: 5
                                                                                Subauthorities: 21-3597817948-3716833002-415491962
                                                                    Dummy1 Long: 0x00000000
                                                                    Dummy2 Long: 0x00000000
                                                                    User Account Control: 0x00000080
                                                                        .... .... .... ...0 .... .... .... .... = Don't Require PreAuth: This account REQUIRES preauthentication
                                                                        .... .... .... .... 0... .... .... .... = Use DES Key Only: This account does NOT have to use_des_key_only
                                                                        .... .... .... .... .0.. .... .... .... = Not Delegated: This might have been delegated
                                                                        .... .... .... .... ..0. .... .... .... = Trusted For Delegation: This account is NOT trusted_for_delegation
                                                                        .... .... .... .... ...0 .... .... .... = SmartCard Required: This account does NOT require_smartcard to authenticate
                                                                        .... .... .... .... .... 0... .... .... = Encrypted Text Password Allowed: This account does NOT allow encrypted_text_password
                                                                        .... .... .... .... .... .0.. .... .... = Account Auto Locked: This account is NOT auto_locked
                                                                        .... .... .... .... .... ..0. .... .... = Don't Expire Password: This account might expire_passwords
                                                                        .... .... .... .... .... ...0 .... .... = Server Trust Account: This account is NOT a server_trust_account
                                                                        .... .... .... .... .... .... 1... .... = Workstation Trust Account: This account is a WORKSTATION_TRUST_ACCOUNT
                                                                        .... .... .... .... .... .... .0.. .... = Interdomain trust Account: This account is NOT an interdomain_trust_account
                                                                        .... .... .... .... .... .... ..0. .... = MNS Logon Account: This account is NOT a mns_logon_account
                                                                        .... .... .... .... .... .... ...0 .... = Normal Account: This account is NOT a normal_account
                                                                        .... .... .... .... .... .... .... 0... = Temp Duplicate Account: This account is NOT a temp_duplicate_account
                                                                        .... .... .... .... .... .... .... .0.. = Password Not Required: This account REQUIRES a password
                                                                        .... .... .... .... .... .... .... ..0. = Home Directory Required: This account does NOT require_home_directory
                                                                        .... .... .... .... .... .... .... ...0 = Account Disabled: This account is NOT disabled
                                                                    Dummy4 Long: 0x00000000
                                                                    Dummy5 Long: 0x00000000
                                                                    Dummy6 Long: 0x00000000
                                                                    Dummy7 Long: 0x00000000
                                                                    Dummy8 Long: 0x00000000
                                                                    Dummy9 Long: 0x00000000
                                                                    Dummy10 Long: 0x00000000
                                                                    Num Extra SID: 3
                                                                    SID_AND_ATTRIBUTES_ARRAY:
                                                                        Referent ID: 0x0002002c
                                                                        SID_AND_ATTRIBUTES array:
                                                                            Max Count: 3
                                                                            SID_AND_ATTRIBUTES:
                                                                                SID pointer:
                                                                                    SID pointer
                                                                                        Referent ID: 0x00020030
                                                                                        Count: 5
                                                                                        Domain SID: S-1-5-21-0-0-0-497  (Domain SID-Domain RID)
                                                                                            Revision: 1
                                                                                            Num Auth: 5
                                                                                            Authority: 5
                                                                                            Subauthorities: 21-0-0-0-497
                                                                                            RID: 497  (Domain RID)
                                                                                Attributes: 0x00000007
                                                                            SID_AND_ATTRIBUTES:
                                                                                SID pointer:
                                                                                    SID pointer
                                                                                        Referent ID: 0x00020034
                                                                                        Count: 1
                                                                                        Domain SID: S-1-18-1  (Authentication Authority Asserted Identity)
                                                                                            Revision: 1
                                                                                            Num Auth: 1
                                                                                            Authority: 18
                                                                                            Subauthorities: 1
                                                                                Attributes: 0x00000007
                                                                            SID_AND_ATTRIBUTES:
                                                                                SID pointer:
                                                                                    SID pointer
                                                                                        Referent ID: 0x00020038
                                                                                        Count: 5
                                                                                        Domain SID: S-1-5-21-0-0-0-496  (Domain SID-Domain RID)
                                                                                            Revision: 1
                                                                                            Num Auth: 5
                                                                                            Authority: 5
                                                                                            Subauthorities: 21-0-0-0-496
                                                                                            RID: 496  (Domain RID)
                                                                                Attributes: 0x00000007
                                                                    ResourceGroupIDs
                                                                        SID pointer:
                                                                            NULL Pointer: SID pointer
                                                                        ResourceGroup count: 0
                                                                        NULL Pointer: GroupIDs
                                                        Type: Device Info (14)
                                                            Size: 184
                                                            Offset: 672
                                                            PAC_DEVICE_INFO: 01100800cccccccca8000000000000000000020051040000030200000400020001000000…
                                                                MES header
                                                                    Version: 1
                                                                    DREP
                                                                        Byte order: Little-endian (1)
                                                                    HDR Length: 8
                                                                    Fill bytes: 0xcccccccc
                                                                    Blob Length: 168
                                                                PAC_DEVICE_INFO:
                                                                    Referent ID: 0x00020000
                                                                    User RID: 1105
                                                                    Group RID: 515
                                                                    SID pointer:
                                                                        SID pointer
                                                                            Referent ID: 0x00020004
                                                                            Count: 4
                                                                            Domain SID: S-1-5-21-3597817948-3716833002-415491962  (Domain SID)
                                                                                Revision: 1
                                                                                Num Auth: 4
                                                                                Authority: 5
                                                                                Subauthorities: 21-3597817948-3716833002-415491962
                                                                    AccountDomainGroup count: 1
                                                                    AccountDomainGroupIds
                                                                        Referent ID: 0x00020008
                                                                        Max Count: 1
                                                                        GROUP_MEMBERSHIP:
                                                                            Group RID: 515
                                                                            Attributes: 0x00000007
                                                                                .... .... .... .... .... .... .... .1.. = Enabled: The enabled bit is SET
                                                                                .... .... .... .... .... .... .... ..1. = Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                                                                                .... .... .... .... .... .... .... ...1 = Mandatory: The MANDATORY bit is SET
                                                                    Num Extra SID: 1
                                                                    ExtraSids:SID_AND_ATTRIBUTES_ARRAY:
                                                                        Referent ID: 0x0002000c
                                                                        SID_AND_ATTRIBUTES array:
                                                                            Max Count: 1
                                                                            SID_AND_ATTRIBUTES:
                                                                                SID pointer:
                                                                                    SID pointer
                                                                                        Referent ID: 0x00020010
                                                                                        Count: 1
                                                                                        Domain SID: S-1-18-1  (Authentication Authority Asserted Identity)
                                                                                            Revision: 1
                                                                                            Num Auth: 1
                                                                                            Authority: 18
                                                                                            Subauthorities: 1
                                                                                Attributes: 0x00000007
                                                                    ExtraDomain Membership Array
                                                                        Membership Domains count: 1
                                                                        ExtraDomain Membership Array
                                                                            Referent ID: 0x00020014
                                                                            Max Count: 1
                                                                            DomainGroupIDs
                                                                                SID pointer:
                                                                                    SID pointer
                                                                                        Referent ID: 0x00020018
                                                                                        Count: 4
                                                                                        Domain SID: S-1-5-21-0-0-0  (Domain SID)
                                                                                            Revision: 1
                                                                                            Num Auth: 4
                                                                                            Authority: 5
                                                                                            Subauthorities: 21-0-0-0
                                                                                DomainGroup count: 1
                                                                                GroupIDs
                                                                                    Referent ID: 0x0002001c
                                                                                    Max Count: 1
                                                                                    GROUP_MEMBERSHIP:
                                                                                        Group RID: 497
                                                                                        Attributes: 0x00000007
                                                                                            .... .... .... .... .... .... .... .1.. = Enabled: The enabled bit is SET
                                                                                            .... .... .... .... .... .... .... ..1. = Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                                                                                            .... .... .... .... .... .... .... ...1 = Mandatory: The MANDATORY bit is SET
                                                        Type: Client Claims Info (13)
                                                            Size: 0
                                                            Offset: 856
                                                        Type: Device Claims Info (15)
                                                            Size: 0
                                                            Offset: 856
                                                        Type: Client Info Type (10)
                                                            Size: 22
                                                            Offset: 856
                                                            PAC_CLIENT_INFO_TYPE: 001463c759ced8010c00570049004e00310030002400
                                                                ClientID: Sep 22, 2022 10:03:20.000000000 CEST
                                                                Name Length: 12
                                                                Name: WIN10$
                                                        Type: UPN DNS Info (12)
                                                            Size: 152
                                                            Offset: 880
                                                            UPN_DNS_INFO: 2c0018001e004800030000000c0068001c00780000000000570049004e00310030002400…
                                                                UPN Len: 44
                                                                UPN Offset: 24
                                                                DNS Len: 30
                                                                DNS Offset: 72
                                                                Flags: 0x00000003
                                                                UPN Name: WIN10$@windomain.local
                                                                DNS Name: WINDOMAIN.LOCAL
                                                        Type: Server Checksum (6)
                                                            Size: 16
                                                            Offset: 1032
                                                            PAC_SERVER_CHECKSUM: 100000000a21114e8d414728c22c1d70
                                                                Type: 16
                                                                Signature: 0a21114e8d414728c22c1d70
                                                        Type: Privsvr Checksum (7)
                                                            Size: 16
                                                            Offset: 1048
                                                            PAC_PRIVSVR_CHECKSUM: 10000000489a91bb22cfa8a37c9280c2
                                                                Type: 16
                                                                Signature: 489a91bb22cfa8a37c9280c2
                                                        Type: Ticket Checksum (16)
                                                            Size: 16
                                                            Offset: 1064
                                                            PAC_TICKET_CHECKSUM: 10000000751b39b96bc824a0f97d5876
                                                                Type: 16
                                                                Signature: 751b39b96bc824a0f97d5876
                                        AuthorizationData item
                                            ad-type: aD-IF-RELEVANT (1)
                                            ad-data: 305d303fa0040202008da137043530333031a003020100a12a04280000000000400000fe…
                                                AuthorizationData item
                                                    ad-type: aD-TOKEN-RESTRICTIONS (141)
                                                    ad-data: 30333031a003020100a12a04280000000000400000fe4c6a1f9ca2986dae0a7734e70f88…
                                                        restriction-type: 0
                                                        restriction: 0000000000400000fe4c6a1f9ca2986dae0a7734e70f88d17f92e0c31e2b578290e7dae6…
                                                AuthorizationData item
                                                    ad-type: aD-LOCAL (142)
                                                    ad-data: 707c2305e3010000d5ed010000000000
                    authenticator
                        etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                        cipher: f258234f7f1156040f21bcb87650241ff2356fb9b90b88d4da2c421330d9ca1b265bcac8…
                            Decrypted keytype 18 usage 11 using learnt encTicketPart_key in frame 3714 (id=3714.1 same=41) (3510bcf8...)
                            authenticator
                                authenticator-vno: 5
                                crealm: WINDOMAIN.LOCAL
                                cname
                                    name-type: kRB5-NT-PRINCIPAL (1)
                                    cname-string: 1 item
                                        CNameString: WIN10$
                                cksum
                                    cksumtype: cKSUMTYPE-GSSAPI (32771)
                                    checksum: 10000000000000000000000000000000000000003e000000
                                    Length: 16
                                    Bnd: 00000000000000000000000000000000
                                    .... .... .... .... ...0 .... .... .... = DCE-style: Not using DCE-STYLE
                                    .... .... .... .... .... .... ..1. .... = Integ: Integrity protection (signing) may be invoked
                                    .... .... .... .... .... .... ...1 .... = Conf: Confidentiality (sealing) may be invoked
                                    .... .... .... .... .... .... .... 1... = Sequence: Enable Out-of-sequence detection for sign or sealed messages
                                    .... .... .... .... .... .... .... .1.. = Replay: Enable replay protection for signed or sealed messages
                                    .... .... .... .... .... .... .... ..1. = Mutual: Request that remote peer authenticates itself
                                    .... .... .... .... .... .... .... ...0 = Deleg: Do NOT delegate
                                cusec: 49
                                ctime: 2022-09-22 08:05:18 (UTC)
                                subkey
                                    Learnt authenticator_subkey keytype 18 (id=3730.2) (d992625b...)
                                    keytype: 18
                                    keyvalue: d992625b56544efa41daff864c59dfa71ccdeba53aed7122d8aeee3b71c56d15
                                seq-number: 267182760
                                authorization-data: 1 item
                                    AuthorizationData item
                                        ad-type: aD-IF-RELEVANT (1)
                                        ad-data: 3081c9303fa0040202008da137043530333031a003020100a12a04280000000000400000…
                                            AuthorizationData item
                                                ad-type: aD-TOKEN-RESTRICTIONS (141)
                                                ad-data: 30333031a003020100a12a04280000000000400000fe4c6a1f9ca2986dae0a7734e70f88…
                                                    restriction-type: 0
                                                    restriction: 0000000000400000fe4c6a1f9ca2986dae0a7734e70f88d17f92e0c31e2b578290e7dae6…
                                            AuthorizationData item
                                                ad-type: aD-LOCAL (142)
                                                ad-data: 707c2305e3010000d5ed010000000000
                                            AuthorizationData item
                                                ad-type: aD-AP-OPTIONS (143)
                                                ad-data: 00400000
                                                    AD-AP-Options: 0x00004000, ChannelBindings
                                                        .... .... .... .... .1.. .... .... .... = ChannelBindings: Set
                                            AuthorizationData item
                                                ad-type: aD-TARGET-PRINCIPAL (144)
                                                ad-data: 48005400540050002f007300720076002e00770069006e0064006f006d00610069006e00…
                                                    Target Principal: HTTP/srv.windomain.local@WINDOMAIN.LOCAL
                Provides learnt encTicketPart_key in frame 3730 keytype 18 (id=3730.1 same=0) (3510bcf8...)
                Provides learnt authenticator_subkey in frame 3730 keytype 18 (id=3730.2 same=0) (d992625b...)
                Used keytab principal SRV$@WINDOMAIN.LOCAL keytype 18 (id=keytab.2 same=0) (b589d323...)
                Used learnt encTicketPart_key in frame 3714 keytype 18 (id=3714.1 same=41) (3510bcf8...)
```

### The collector authenticates the client and sends its response

```
Frame 3732: 395 bytes on wire (3160 bits), 395 bytes captured (3160 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_62:f7:34 (08:00:27:62:f7:34), Dst: PcsCompu_a6:35:47 (08:00:27:a6:35:47)
Internet Protocol Version 4, Src: 192.168.58.103, Dst: 192.168.58.100
Transmission Control Protocol, Src Port: 5985, Dst Port: 65091, Seq: 1, Ack: 2957, Len: 341
Hypertext Transfer Protocol
    HTTP/1.1 200 \r\n
    WWW-Authenticate: Kerberos YIGXBgkqhkiG9xIBAgICAG+BhzCBhKADAgEFoQMCAQ+ieDB2oAMCARKibwRtyHBO/0Ej2ORfOEzDCqgm3IaPELAcqCgJ62zkjooYA357Cq6E79YS7CgATl0SCCCCMXNiNzMpBB9aveT7rBbEr6zvG8wo76kiQalRVuBZF0MmmHArk8sIpckkSsxsHFYvfPr5XNY7YSp2U2V3zw==\r\n
    Server: Microsoft-HTTPAPI/2.0\r\n
    Date: Thu, 22 Sep 2022 08:05:18 GMT\r\n
    Content-Length: 0\r\n
    \r\n
    [HTTP response 1/3]
    [Time since request: 0.005113000 seconds]
    [Request in frame: 3730]
    [Next request in frame: 3736]
    [Next response in frame: 3738]
    [Request URI: http://srv.windomain.local:5985/wsman/SubscriptionManager/WEC]
```

The Kerberos blob is a `KRB5_AP_REP`:

```
WWW-Authenticate: Kerberos YIGXBgkqhkiG9xIBAgICAG+BhzCBhKADAgEFoQMCAQ+ieDB2oAMCARKibwRtyHBO/0Ej2ORfOEzDCqgm3IaPELAcqCgJ62zkjooYA357Cq6E79YS7CgATl0SCCCCMXNiNzMpBB9aveT7rBbEr6zvG8wo76kiQalRVuBZF0MmmHArk8sIpckkSsxsHFYvfPr5XNY7YSp2U2V3zw==\r\n
    GSS-API Generic Security Service Application Program Interface
        OID: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
        krb5_blob: 02006f8187308184a003020105a10302010fa2783076a003020112a26f046dc8704eff41…
            krb5_tok_id: KRB5_AP_REP (0x0002)
            Kerberos
                ap-rep
                    pvno: 5
                    msg-type: krb-ap-rep (15)
                    enc-part
                        etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                        cipher: c8704eff4123d8e45f384cc30aa826dc868f10b01ca82809eb6ce48e8a18037e7b0aae84…
                            Decrypted keytype 18 usage 12 using learnt encTicketPart_key in frame 3714 (id=3714.1 same=41) (3510bcf8...)
                            encAPRepPart
                                ctime: 2022-09-22 08:05:18 (UTC)
                                cusec: 49
                                subkey
                                    Learnt encAPRepPart_subkey keytype 18 (id=3732.1) (c77374ba...)
                                    keytype: 18
                                    keyvalue: c77374bac25c16eb95cc99b2945788ca0da111af2aba4dba568752ffe25fd0d5
                                seq-number: 261443413
                Provides learnt encAPRepPart_subkey in frame 3732 keytype 18 (id=3732.1 same=0) (c77374ba...)
                Used learnt encTicketPart_key in frame 3714 keytype 18 (id=3714.1 same=41) (3510bcf8...)
```

### The client sends a `Enumerate` request

The request body is encrypted using Kerberos:

```
Frame 3736: 676 bytes on wire (5408 bits), 676 bytes captured (5408 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_a6:35:47 (08:00:27:a6:35:47), Dst: PcsCompu_62:f7:34 (08:00:27:62:f7:34)
Internet Protocol Version 4, Src: 192.168.58.100, Dst: 192.168.58.103
Transmission Control Protocol, Src Port: 65091, Dst Port: 5985, Seq: 6159, Ack: 342, Len: 622
[4 Reassembled TCP Segments (3824 bytes): #3733(282), #3734(1460), #3735(1460), #3736(622)]
Hypertext Transfer Protocol
    POST /wsman/SubscriptionManager/WEC HTTP/1.1\r\n
        [Expert Info (Chat/Sequence): POST /wsman/SubscriptionManager/WEC HTTP/1.1\r\n]
        Request Method: POST
        Request URI: /wsman/SubscriptionManager/WEC
        Request Version: HTTP/1.1
    Connection: Keep-Alive\r\n
    Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"\r\n
    User-Agent: Microsoft WinRM Client\r\n
    Content-Length: 3542\r\n
    Host: srv.windomain.local:5985\r\n
    \r\n
    [Full request URI: http://srv.windomain.local:5985/wsman/SubscriptionManager/WEC]
    [HTTP request 2/3]
    [Prev request in frame: 3730]
    [Response in frame: 3738]
    [Next request in frame: 3755]
    File Data: 3542 bytes
MIME Multipart Media Encapsulation, Type: multipart/encrypted, Boundary: "Encrypted Boundary"
    [Type: multipart/encrypted]
    First boundary: --Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/http-kerberos-session-encrypted)
        Content-Type: application/HTTP-Kerberos-session-encrypted\r\n
        OriginalContent: type=application/soap+xml;charset=UTF-16;Length=3240
    Boundary: \r\n--Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/octet-stream)
        Content-Type: application/octet-stream\r\n
        Length of security token: 60
        GSS-API Generic Security Service Application Program Interface
            krb5_blob: 050406ff0000001c000000000fece2a8f629bb3f3c1bf9dfb3bc040b5f0cb9e637f383ce…
                krb5_tok_id: KRB_TOKEN_CFX_WRAP (0x0405)
                krb5_cfx_flags: 0x06, AcceptorSubkey, Sealed
                    .... .1.. = AcceptorSubkey: Set
                    .... ..1. = Sealed: Set
                    .... ...0 = SendByAcceptor: Not set
                krb5_filler: ff
                krb5_cfx_ec: 0
                krb5_cfx_rrc: 28
                krb5_cfx_seq: 267182760
                krb5_sgn_cksum: f629bb3f3c1bf9dfb3bc040b5f0cb9e637f383ce4db4c8a9dd4c37dc84317411768d7d3f…
                Decrypted keytype 18 usage 24 using learnt encAPRepPart_subkey in frame 3732 (id=3732.1 same=0) (c77374ba...)
        Media Type
            Media type: application (3240 bytes)
    Last boundary: --Encrypted Boundary--\r\n
```

If we provide a keytab of the WEC server, Wireshark is able to give us the cleartext of the body:

```
fffe3c0073003a0045006e00760065006c006f0070006500200078006d006c006e0073003a0073003d00220068007400740070003a002f002f007700770077002e00770033002e006f00720067002f0032003000300033002f00300035002f0073006f00610070002d0065006e00760065006c006f00700065002200200078006d006c006e0073003a0061003d00220068007400740070003a002f002f0073006300680065006d00610073002e0078006d006c0073006f00610070002e006f00720067002f00770073002f0032003000300034002f00300038002f00610064006400720065007300730069006e0067002200200078006d006c006e0073003a006e003d00220068007400740070003a002f002f0073006300680065006d00610073002e0078006d006c0073006f00610070002e006f00720067002f00770073002f0032003000300034002f00300039002f0065006e0075006d00650072006100740069006f006e002200200078006d006c006e0073003a0077003d00220068007400740070003a002f002f0073006300680065006d00610073002e0064006d00740066002e006f00720067002f007700620065006d002f00770073006d0061006e002f0031002f00770073006d0061006e002e007800730064002200200078006d006c006e0073003a0070003d00220068007400740070003a002f002f0073006300680065006d00610073002e006d006900630072006f0073006f00660074002e0063006f006d002f007700620065006d002f00770073006d0061006e002f0031002f00770073006d0061006e002e007800730064002200200078006d006c006e0073003a0062003d00220068007400740070003a002f002f0073006300680065006d00610073002e0064006d00740066002e006f00720067002f007700620065006d002f00770073006d0061006e002f0031002f00630069006d00620069006e00640069006e0067002e0078007300640022003e003c0073003a004800650061006400650072003e003c0061003a0054006f003e0068007400740070003a002f002f007300720076002e00770069006e0064006f006d00610069006e002e006c006f00630061006c003a0035003900380035002f00770073006d0061006e002f0053007500620073006300720069007000740069006f006e004d0061006e0061006700650072002f005700450043003c002f0061003a0054006f003e003c0077003a005200650073006f007500720063006500550052004900200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200740072007500650022003e0068007400740070003a002f002f0073006300680065006d00610073002e006d006900630072006f0073006f00660074002e0063006f006d002f007700620065006d002f00770073006d0061006e002f0031002f0053007500620073006300720069007000740069006f006e004d0061006e0061006700650072002f0053007500620073006300720069007000740069006f006e003c002f0077003a005200650073006f0075007200630065005500520049003e003c006d003a004d0061006300680069006e00650049004400200078006d006c006e0073003a006d003d00220068007400740070003a002f002f0073006300680065006d00610073002e006d006900630072006f0073006f00660074002e0063006f006d002f007700620065006d002f00770073006d0061006e002f0031002f006d0061006300680069006e006500690064002200200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200660061006c007300650022003e00770069006e00310030002e00770069006e0064006f006d00610069006e002e006c006f00630061006c003c002f006d003a004d0061006300680069006e006500490044003e003c0061003a005200650070006c00790054006f003e003c0061003a004100640064007200650073007300200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200740072007500650022003e0068007400740070003a002f002f0073006300680065006d00610073002e0078006d006c0073006f00610070002e006f00720067002f00770073002f0032003000300034002f00300038002f00610064006400720065007300730069006e0067002f0072006f006c0065002f0061006e006f006e0079006d006f00750073003c002f0061003a0041006400640072006500730073003e003c002f0061003a005200650070006c00790054006f003e003c0061003a0041006300740069006f006e00200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200740072007500650022003e0068007400740070003a002f002f0073006300680065006d00610073002e0078006d006c0073006f00610070002e006f00720067002f00770073002f0032003000300034002f00300039002f0065006e0075006d00650072006100740069006f006e002f0045006e0075006d00650072006100740065003c002f0061003a0041006300740069006f006e003e003c0077003a004d006100780045006e00760065006c006f0070006500530069007a006500200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200740072007500650022003e003500310032003000300030003c002f0077003a004d006100780045006e00760065006c006f0070006500530069007a0065003e003c0061003a004d00650073007300610067006500490044003e0075007500690064003a00450039003800300032003200350037002d0036004100370044002d0034004300300044002d0042004600410034002d004500380031004300370042003100430034003400370045003c002f0061003a004d00650073007300610067006500490044003e003c0077003a004c006f00630061006c006500200078006d006c003a006c0061006e0067003d00220065006e002d00550053002200200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200660061006c0073006500220020002f003e003c0070003a0044006100740061004c006f00630061006c006500200078006d006c003a006c0061006e0067003d00220065006e002d00550053002200200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200660061006c0073006500220020002f003e003c0070003a00530065007300730069006f006e0049006400200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200660061006c007300650022003e0075007500690064003a00440032003500440044003000330033002d0043003400300036002d0034003400410042002d0038003400340033002d003800350045003100420043003700390034004600310030003c002f0070003a00530065007300730069006f006e00490064003e003c0070003a004f007000650072006100740069006f006e0049004400200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200660061006c007300650022003e0075007500690064003a00300033004100330044003100420042002d0039004200310036002d0034003800340037002d0039004600300034002d004300390041003800450044003300380045003100450034003c002f0070003a004f007000650072006100740069006f006e00490044003e003c0070003a00530065007100750065006e006300650049006400200073003a006d0075007300740055006e006400650072007300740061006e0064003d002200660061006c007300650022003e0031003c002f0070003a00530065007100750065006e0063006500490064003e003c0077003a004f007000650072006100740069006f006e00540069006d0065006f00750074003e0050005400360030002e0030003000300053003c002f0077003a004f007000650072006100740069006f006e00540069006d0065006f00750074003e003c002f0073003a004800650061006400650072003e003c0073003a0042006f00640079003e003c006e003a0045006e0075006d00650072006100740065003e003c0077003a004f007000740069006d0069007a00650045006e0075006d00650072006100740069006f006e002f003e003c0077003a004d006100780045006c0065006d0065006e00740073003e00330032003000300030003c002f0077003a004d006100780045006c0065006d0065006e00740073003e003c002f006e003a0045006e0075006d00650072006100740065003e003c002f0073003a0042006f00640079003e003c002f0073003a0045006e00760065006c006f00700065003e00
```

This cleartext is a UTF-16 encoded string, starting with a BOM (Byte Order Mark: <https://www.unicode.org/faq/utf_bom.html#bom1>).

```
FE FF 	UTF-16, big-endian  
FF FE 	UTF-16, little-endian
```

In our case, it is in little-endian :)

The decoded text is:

```xml
<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
	xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd">
	<s:Header>
		<a:To>http://srv.windomain.local:5985/wsman/SubscriptionManager/WEC</a:To>
		<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</w:ResourceURI>
		<m:MachineID
			xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid" s:mustUnderstand="false">win10.windomain.local
		</m:MachineID>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
		<a:MessageID>uuid:E9802257-6A7D-4C0D-BFA4-E81C7B1C447E</a:MessageID>
		<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
		<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
		<p:SessionId s:mustUnderstand="false">uuid:D25DD033-C406-44AB-8443-85E1BC794F10</p:SessionId>
		<p:OperationID s:mustUnderstand="false">uuid:03A3D1BB-9B16-4847-9F04-C9A8ED38E1E4</p:OperationID>
		<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
		<w:OperationTimeout>PT60.000S</w:OperationTimeout>
	</s:Header>
	<s:Body>
		<n:Enumerate>
			<w:OptimizeEnumeration/>
			<w:MaxElements>32000</w:MaxElements>
		</n:Enumerate>
	</s:Body>
</s:Envelope>
```

If we look at each field we have:
- `a:To`: the service address (which is the collector) to which the request was sent (DSP0266 - 5.3). Must be in **all messages**.
- `w:ResourceURI`: `http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription`. According to DSP0266, tells "what we are talking about". The `mustUnderstand=true` attribute is mandatory. `w:ResourceURI` is required for some `wsa:Action` (DSP0266 - R5.1.2.1-3).
- `m:MachineID`: the client DNS name.
- `ReplyTo`: `http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous` indicates that the response should be sent on the same connection as the request (DSP0226 - 5.4.2).
    > "The service shall fully duplicate the entire wsa:Address of the wsa:ReplyTo element in the wsa:To header of the reply, even if some of the information is not understood by the service"
- `a:Action`: `Enumerate`, indicates what to do (see table at DSP0226 - 5.4.5).
- `w:MaxEnvelopeSize`: the client needs a response with a SOAP envelope smaller than 5120000. The `mustUnderstand=true` indicates that this condition must be fulfilled and that a `wsman:EncodingLimit` error should be responded if the response is too big (DSP0226 - 6.2).
- `a:MessageID`: indicates that the format `uuid:xxxxxxxx-xxxx--xxxx--xxxx--xxxxxxxxxxxx` should be used. This field is required. If not present, a `wsa:InvalidMessageInformationHeader` error is returned (DSP0266 5.4.4). This field is case sensitive. If we received a `MessageID` in uppercase, then the `RelatesTo` must contains the ID in uppercase even if RFC 1422 tells to use lowercase (see MS-WSMV 3.1.4.1.5).
- `w:Locale`: Specify the language in which the client wants the reponse to be. MS-WSMV tells that `mustUnderstand` must be "false", otherwise it sends back a `wsman:UnsupportedFeature` error. The language is defined in `xml:lang` and must be a valid code according to RFC 3066.
- `p:DataLocale`: Microsoft specific. Indicates the language used for numeric data. `mustUnderstand` must be "false".
- `p:SessionId`: Microsoft specific. Unique session id.
- `p:OperationID`: Microsoft specific. Indicates that the client supports "Robust-Connection/full-duplex" (cf MS-WSMV 3.1.4.1.39: the server caches request responses, enabling the client to retrieve previous responses even if there was a network issue). The server also have to specify this field to indicate that it is supported. If both the client and the server know this mode is supported, all future messages will be "Robust-Connections/full-duplex". If `mustUnderstand` is "true", it means it is a retransmission of a previous message, and in this case `p:SequenceId` must not be 1 (otherwise `wsa:InvalidMessageInformationHeader` error) and the server must send again its previous response.
- `p:SequenceId`: Microsoft specific, used in "Robust-Connections/full-duplex" mode (MS-WSMV 3.1.4.1.39)
- `w:OperationTimeout`: If not specified, Microsoft uses a default value in configuration. Specified in DSP0226 6.1. It uses the `xs:duration` format (<https://www.ibm.com/docs/en/i/7.2?topic=types-xsduration>).
- `w:OptimizeEnumeration`: "OptimizeEnumeration" means sending enumeration results immediately after the EnumerateResponse message, without using a `Pull` request (DSP0266 - 8.2.3).
- `w:MaxElements`: indicates the maximum number of elements to send using OptimizeEnumeration (DSP0266 - 8.2.3).

For more details see documentation:
- MS-WSMV - 3.1.4.8 Enumerate
- DSP0226 - 8.2

mustUnderstand = "must comply" (DSP0266 - 5.2) is implicit for:
- wsa:To
- wsa:MessageID
- wsa:RelatesTo
- wsa:Action

### The collector answers "EnumerateResponse"

```
Frame 3738: 9255 bytes on wire (74040 bits), 9255 bytes captured (74040 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_62:f7:34 (08:00:27:62:f7:34), Dst: PcsCompu_a6:35:47 (08:00:27:a6:35:47)
Internet Protocol Version 4, Src: 192.168.58.103, Dst: 192.168.58.100
Transmission Control Protocol, Src Port: 5985, Dst Port: 65091, Seq: 342, Ack: 6781, Len: 9201
Hypertext Transfer Protocol
    HTTP/1.1 200 \r\n
    Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"\r\n
    Server: Microsoft-HTTPAPI/2.0\r\n
    Date: Thu, 22 Sep 2022 08:05:18 GMT\r\n
    Content-Length: 8974\r\n
    \r\n
    [HTTP response 2/3]
    [Time since request: 0.003282000 seconds]
    [Prev request in frame: 3730]
    [Prev response in frame: 3732]
    [Request in frame: 3736]
    [Next request in frame: 3755]
    [Next response in frame: 3757]
    [Request URI: http://srv.windomain.local:5985/wsman/SubscriptionManager/WEC]
    File Data: 8974 bytes
MIME Multipart Media Encapsulation, Type: multipart/encrypted, Boundary: "Encrypted Boundary"
    [Type: multipart/encrypted]
    First boundary: --Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/http-kerberos-session-encrypted)
        Content-Type: application/HTTP-Kerberos-session-encrypted\r\n
        OriginalContent: type=application/soap+xml;charset=UTF-16;Length=8672
    Boundary: \r\n--Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/octet-stream)
        Content-Type: application/octet-stream\r\n
        Length of security token: 60
        GSS-API Generic Security Service Application Program Interface
        Media Type
            Media type: application (8672 bytes)
    Last boundary: --Encrypted Boundary--\r\n

```

The content is also encrypted with Kerberos. After deciphering and decoding it we have:

```xml
<s:Envelope xml:lang="en-US"
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:Action>http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse</a:Action>
		<a:MessageID>uuid:45697184-34FA-4722-BF84-AF362DAF7832</a:MessageID>
		<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
		<p:OperationID s:mustUnderstand="false">uuid:03A3D1BB-9B16-4847-9F04-C9A8ED38E1E4</p:OperationID>
		<p:SequenceId>1</p:SequenceId>
		<a:RelatesTo>uuid:E9802257-6A7D-4C0D-BFA4-E81C7B1C447E</a:RelatesTo>
	</s:Header>
	<s:Body>
		<n:EnumerateResponse>
			<n:EnumerationContext></n:EnumerationContext>
			<w:Items>
				<m:Subscription
					xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/subscription">
					<m:Version>uuid:219C5353-5F3D-4CD7-A644-F6B69E57C1C1</m:Version>
					<s:Envelope
						xmlns:s="http://www.w3.org/2003/05/soap-envelope"
						xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
						xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
						xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
						xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
						xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
						<s:Header>
							<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
							<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</w:ResourceURI>
							<a:ReplyTo>
								<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
							</a:ReplyTo>
							<a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe</a:Action>
							<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
							<a:MessageID>uuid:A666D835-B462-465E-ACEE-BA6354EA0E58</a:MessageID>
							<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
							<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
							<p:OperationID s:mustUnderstand="false">uuid:24C4926E-F0EB-4F5A-A75F-5F1FA212F124</p:OperationID>
							<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
							<w:OptionSet
								xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
								<w:Option Name="SubscriptionName">Toto</w:Option>
								<w:Option Name="Compression">SLDC</w:Option>
								<w:Option Name="CDATA" xsi:nil="true"/>
								<w:Option Name="ContentFormat">RenderedText</w:Option>
								<w:Option Name="IgnoreChannelError" xsi:nil="true"/>
							</w:OptionSet>
						</s:Header>
						<s:Body>
							<e:Subscribe>
								<e:EndTo>
									<a:Address>HTTP://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1</a:Address>
									<a:ReferenceProperties>
										<e:Identifier>219C5353-5F3D-4CD7-A644-F6B69E57C1C1</e:Identifier>
									</a:ReferenceProperties>
								</e:EndTo>
								<e:Delivery Mode="http://schemas.dmtf.org/wbem/wsman/1/wsman/Events">
									<w:Heartbeats>PT3600.000S</w:Heartbeats>
									<e:NotifyTo>
										<a:Address>HTTP://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1</a:Address>
										<a:ReferenceProperties>
											<e:Identifier>219C5353-5F3D-4CD7-A644-F6B69E57C1C1</e:Identifier>
										</a:ReferenceProperties>
										<c:Policy
											xmlns:c="http://schemas.xmlsoap.org/ws/2002/12/policy"
											xmlns:auth="http://schemas.microsoft.com/wbem/wsman/1/authentication">
											<c:ExactlyOne>
												<c:All>
													<auth:Authentication Profile="http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/http/spnego-kerberos"></auth:Authentication>
												</c:All>
											</c:ExactlyOne>
										</c:Policy>
									</e:NotifyTo>
									<w:ConnectionRetry Total="5">PT60.0S</w:ConnectionRetry>
									<w:MaxTime>PT30.000S</w:MaxTime>
									<w:MaxEnvelopeSize Policy="Notify">512000</w:MaxEnvelopeSize>
									<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
									<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
									<w:ContentEncoding>UTF-16</w:ContentEncoding>
								</e:Delivery>
								<w:Filter Dialect="http://schemas.microsoft.com/win/2004/08/events/eventquery">
									<QueryList>
										<Query Id="0">
											<Select Path="Microsoft-Windows-WinRM/Operational">*[System[(Level=1  or Level=2 or Level=3 or Level=4 or Level=0 or Level=5)]]</Select>
										</Query>
									</QueryList>
								</w:Filter>
								<w:Bookmark>
									<BookmarkList>
										<Bookmark Channel="Microsoft-Windows-WinRM/Operational" RecordId="149140" IsCurrent="true"/>
									</BookmarkList>
								</w:Bookmark>
								<w:SendBookmarks/>
							</e:Subscribe>
						</s:Body>
					</s:Envelope>
				</m:Subscription>
			</w:Items>
			<w:EndOfSequence/>
		</n:EnumerateResponse>
	</s:Body>
</s:Envelope>
```

In the Header we have:
- `a:Action`: `EnumerateResponse`. According to DSP0266 8.2.3, if the client asks for an OptimizeEnumeration, the server will respond something like:

```xml
<s:Body>
    <wsen:EnumerateResponse>
        <wsen:EnumerationContext> ... </wsen:EnumerationContext>
        <wsman:Items>
            ...same as for wsen:Items in wsen:PullResponse
        </wsman:Items>
        <wsman:EndOfSequence/>
    </wsen:EnumerateResponse>
</s:Body>
```

- `a:MessageID`: message UUID.
- `p:OperationID`: the request UUID, implies that the server supports "Robust-Connection/full-duplex".
- `a:RelatesTo`: must contain the `a:MessageID` of the request (case sensitive).

As specified in MS-WSMV, when the collector receives an Enumerate message, it must retrieve its enabled "subscriptions" and send a "Subscribe requests" list to the client. Items in this list are of type SubscriptionType (2.2.4.41 de MS-WSMV):

```xml
<xs:complexType name="SubscriptionType">
    <xs:sequence>
        <xs:element name="Version" type="xs:string" />
        <xs:element name="Envelope" type="s:Envelope" />
    </xs:sequence>
</xs:complexType>
```

`Version` is a GUID which changes each time the Subscription is modified.
`Envelope` must contain a `SubscribeMsg`.

The client then needs to extracts those `SubscribeMsg`.

In its Header we have:
- `a:Action`: `http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe` (cf MS-WSMV 3.1.4.6)
- `w:ResourceURI`: `http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog` (only resource supported by `Subscribe` action)
- `a:MessageID`: a new UUID
- `p:OperationID`: again a new UUID
- `p:SequenceId`: 1
- `w:OptionSet`: options specific to Subscribe as defined in MS-WSMV 3.1.4.1.30.1:
    - `SubscriptionName`
    - `Compression`: compression algorithm to use. The only authorised value is SLDC.
    - `CDATA`: should the data be parsed/validated or sent without any processing.
        - If `xsi:nil` is "true", data should not be parsed. In this case, data are only sent to "Event subscriber".
    - `ContentFormat`:
        - `RenderedText`: raw data and printable informations are sent (in EventData and RenderingInfo).
        - `Raw`: default, only raw data are sent.
    - `IgnoreChannelError`: should we stop processing if there are errors in query options. If `xsi:nil` is true, we do not stop.
    - `ReadExistingEvents`: if this option is "true", all already existing events that matches query options should be sent.

In its Body we have:
- `e:EndTo`: if there is an issue with the subscription, the client sends a `SubscriptionEnd` at the specified address.
    - `a:Address`: an URL on the collector specific to the current client (ended with a specific UUID).
    - `a:ReferenceProperties`/`e:Identifier`: the subscription version GUID.
- `e:Delivery`: According to Microsoft documentation, the following mode are supported:
    - `http://schemas.xmlsoap.org/ws/2004/08/eventing/DeliveryModes/Push`: every SOAP message contains one event, without ACK or SOAP response. Event transmission is asynchronous.
    - `http://schemas.dmtf.org/wbem/wsman/1/wsman/PushWithAck`: every SOAP message contains one event, each one needs to be acknowledged before the next one is sent. The sender has a waiting list of events to send.
    - `http://schemas.dmtf.org/wbem/wsman/1/wsman/Events`: every SOAP message can contain multiple events, each batch of events needs to be acknowledged before the next one is sent.
    - `http://schemas.dmtf.org/wbem/wsman/1/wsman/Pull`: every SOAP message can contain multiple events, each batch of events needs to be acknowledged before the next one is sent. This mode implies that the collector uses "Pull" to retrieve events so acknowledgment is implicit.
    - Windows collector uses the `Events` mode (detailed in DSP0226 - 10.2.9.4). In this mode, `e:Delivery` should look like:
    ```xml
    <wse:Delivery Mode="http://schemas.dmtf.org/wbem/wsman/1/wsman/Events">
        <wse:NotifyTo>
            wsa:EndpointReferenceType
        </wse:NotifyTo>
        <wsman:MaxElements> xs:positiveInteger </wsman:MaxElements> ?
        <wsman:MaxTime> xs:duration </wsman:MaxTime> ?
        <wsman:MaxEnvelopeSize Policy="enumConstant">
            xs:positiveInteger
        </wsman:MaxEnvelopeSize> ?
    </wse:Delivery>
    ```
    - `e:NotifyTo`: endpoint to send events to.
    - `w:MaxTime`: max time between the moment the sender starts encoding the first event and the moment it sends the batch of events. PT30.000S is equivalent to "Minimize Latency" configuration.
    - `w:MaxEnvelopeSize`: max size in bytes of SOAP envelopes.
        - `@Policy`: defines what to do when events are too big:
            - `CancelSubscription`: stop subscription.
            - `Skip`: do not send those events.
            - `Notify`: notify that events were deleted (default).
    - `w:Heartbeats`: "Heartbeats" are sent periodically if there is no event to send. The collector should ensure it always receives either events or hearbeats. The Windows collector configures the heartbeat frequency to PT3600.000S, which means every hour (DSP0226 - 10.2.5).
    - `w:ConnectionRetry`: if the subscriber is not joignable, retry "`@count` attribute" times every "`w:ConnectionRetry`" before giving up and considering the subscription as expired (DSP0226 - 10.2.3).
    - `w:ContentEncoding`: Windows collector uses UTF-16 (DSP0226 - 10.2.1-7).
    - `c:Policy`: specify how the client should authenticate to send events. Syntax is defined in [WS-Policy](https://www.w3.org/Submission/2006/SUBM-WS-Policy-20060425/). MS-WSMV - 3.1.4.1.30.3 suggests to use this minimal version:
        ```xml
        <wsp:Policy>
            <wsp:ExactlyOne>
                <wsp:all>
                ... assertions ...
                </wsp:all>
            </wsp:ExactlyOne>
        </wsp:Policy>
        ```
        Every assertion is an authentication element.
        Schema of each assertion is specified in MS-WSMV - 2.2.41:
        ```xml
        <xs:complexType name="ThumbprintType">
            <xs:simpleContent>
                <xs:extension base="xs:string">
                    <xs:attribute name="Role" type="xs:string" use="required"/>
                </xs:extension>
            </xs:simpleContent>
        </xs:complexType>
        <xs:complexType name="ClientCertificateType">
            <xs:sequence>
                <xs:element name="Thumbprint" type="ThumbprintType"/>
            </xs:sequence>
        </xs:complexType>
        <xs:complexType name="AuthenticationType">
            <xs:sequence>
                <xs:element name="ClientCertificate" type="ClientCertificateType" minOccurs="0" />
            </xs:sequence>
            <xs:attribute name="Profile" type="xs:anyURI" use="required" />
        </xs:complexType>
        ```
        `Profile` tells which security profil is used. It can be `http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual` or `http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/http/mutual` for TLS authentication, and can be `http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/http/spnego-kerberos` or `http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/spnego-kerberos` for Kerberos authentication. In our example we have Kerberos authentication.
- `w:Filter`: defines the filter to fetch events. According to documentation, this is not always required. If it is required, we would receive a `FilteringRequired` error.
    - By default, the filter uses XPath language. In our example it is `http://schemas.microsoft.com/win/2004/08/events/eventquery`.
    - The filter contains a `QueryList` element of type `QueryListType` (MS-WSMV 2.2.4.24). Every `Query` contains an unique `Id` attribute, and its child elements are of type `SelectType`. `Select` element has a `Path` attribute which contains an event source. Its value should be a level 1 XPath query (DSP0226 - Annexe D.1). We can easily export a valid query using Event Viewer (in the XML tab).
- `w:Bookmark`: ensures we do not miss any event. The sender sends an updated bookmark each time it sends events. The collector needs to save the bookmark (kind of "cookie"). Then if something goes wrong (a network issue for example) the collector can tell the sender which is the last bookmark it received. The sender will then know which events were missed and need to be sent (DSP0226 10.2.6).
- `w:SendBookmarks`: indicates to sender to send bookmarks everytime it sends events.

### The client sends an `End` request

```
Frame 3755: 330 bytes on wire (2640 bits), 330 bytes captured (2640 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_a6:35:47 (08:00:27:a6:35:47), Dst: PcsCompu_62:f7:34 (08:00:27:62:f7:34)
Internet Protocol Version 4, Src: 192.168.58.100, Dst: 192.168.58.103
Transmission Control Protocol, Src Port: 65091, Dst Port: 5985, Seq: 8523, Ack: 9543, Len: 276
[3 Reassembled TCP Segments (2018 bytes): #3753(282), #3754(1460), #3755(276)]
Hypertext Transfer Protocol
    POST /wsman/SubscriptionManager/WEC HTTP/1.1\r\n
    Connection: Keep-Alive\r\n
    Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"\r\n
    User-Agent: Microsoft WinRM Client\r\n
    Content-Length: 1736\r\n
    Host: srv.windomain.local:5985\r\n
    \r\n
    [Full request URI: http://srv.windomain.local:5985/wsman/SubscriptionManager/WEC]
    [HTTP request 3/3]
    [Prev request in frame: 3736]
    [Response in frame: 3757]
    File Data: 1736 bytes
MIME Multipart Media Encapsulation, Type: multipart/encrypted, Boundary: "Encrypted Boundary"
    [Type: multipart/encrypted]
    First boundary: --Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/http-kerberos-session-encrypted)
        Content-Type: application/HTTP-Kerberos-session-encrypted\r\n
        OriginalContent: type=application/soap+xml;charset=UTF-16;Length=1434
    Boundary: \r\n--Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/octet-stream)
        Content-Type: application/octet-stream\r\n
        Length of security token: 60
        GSS-API Generic Security Service Application Program Interface
        Media Type
            Media type: application (1434 bytes)
    Last boundary: --Encrypted Boundary--\r\n
```

Deciphered and decoded content:

```
<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
		<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wsman/FullDuplex</w:ResourceURI>
		<a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wsman/End</a:Action>
		<a:MessageID>uuid:5A622A71-B73A-426E-B1CB-048A6079EB23</a:MessageID>
		<p:OperationID>uuid:03A3D1BB-9B16-4847-9F04-C9A8ED38E1E4</p:OperationID>
	</s:Header>
	<s:Body></s:Body>
</s:Envelope>
```

- `a:Action`: `http://schemas.microsoft.com/wbem/wsman/1/wsman/End`, connection ends here (voir MS-WSMV 3.1.4.19).

### The collector sends back "No Content"

```
Frame 3757: 139 bytes on wire (1112 bits), 139 bytes captured (1112 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_62:f7:34 (08:00:27:62:f7:34), Dst: PcsCompu_a6:35:47 (08:00:27:a6:35:47)
Internet Protocol Version 4, Src: 192.168.58.103, Dst: 192.168.58.100
Transmission Control Protocol, Src Port: 5985, Dst Port: 65091, Seq: 9543, Ack: 8799, Len: 85
Hypertext Transfer Protocol
    HTTP/1.1 204 \r\n
    Server: Microsoft-HTTPAPI/2.0\r\n
    Date: Thu, 22 Sep 2022 08:05:18 GMT\r\n
    \r\n
    [HTTP response 3/3]
    [Time since request: 0.000364000 seconds]
    [Prev request in frame: 3736]
    [Prev response in frame: 3738]
    [Request in frame: 3755]
    [Request URI: http://srv.windomain.local:5985/wsman/SubscriptionManager/WEC]
```

204 => No-Content

### The client closes the TCP connection

### The client opens a new TCP connection (source port 65092)

### The client sends a POST request to the URL found in `DeliveryTo/Address` and authenticates in Kerberos

```
Frame 3745: 143 bytes on wire (1144 bits), 143 bytes captured (1144 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_a6:35:47 (08:00:27:a6:35:47), Dst: PcsCompu_62:f7:34 (08:00:27:62:f7:34)
Internet Protocol Version 4, Src: 192.168.58.100, Dst: 192.168.58.103
Transmission Control Protocol, Src Port: 65092, Dst Port: 5985, Seq: 2921, Ack: 1, Len: 89
[3 Reassembled TCP Segments (3009 bytes): #3743(1460), #3744(1460), #3745(89)]
Hypertext Transfer Protocol
    POST /wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1 HTTP/1.1\r\n
    Connection: Keep-Alive\r\n
    Content-Type: application/soap+xml;charset=UTF-16\r\n
    Content-Encoding: SLDC\r\n
     [truncated]Authorization: Kerberos YIIH9AYJKoZIhvcSAQICAQBuggfjMIIH36ADAgEFoQMCAQ6iBwMFACAAAACjggYOYYIGCjCCBgagAwIBBaERGw9XSU5ET01BSU4uTE9DQUyiJjAkoAMCAQKhHTAbGwRIVFRQGxNzcnYud2luZG9tYWluLmxvY2Fso4IFwjCCBb6gAwIBEqEDAgEFooIFsASCBazWEk8V/Bh
    User-Agent: Microsoft WinRM Client\r\n
    Content-Length: 0\r\n
    Host: srv.windomain.local:5985\r\n
    \r\n
    [Full request URI: http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1]
    [HTTP request 1/12]
    [Response in frame: 3747]
    [Next request in frame: 3749]
```

### The collector validates the authentication

```
Frame 3747: 395 bytes on wire (3160 bits), 395 bytes captured (3160 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_62:f7:34 (08:00:27:62:f7:34), Dst: PcsCompu_a6:35:47 (08:00:27:a6:35:47)
Internet Protocol Version 4, Src: 192.168.58.103, Dst: 192.168.58.100
Transmission Control Protocol, Src Port: 5985, Dst Port: 65092, Seq: 1, Ack: 3010, Len: 341
Hypertext Transfer Protocol
    HTTP/1.1 200 \r\n
    WWW-Authenticate: Kerberos YIGXBgkqhkiG9xIBAgICAG+BhzCBhKADAgEFoQMCAQ+ieDB2oAMCARKibwRtZd61blB9k7a2pmdvwbUxdztFcuYUccZERJQkCicXOfvL75j/xnc6gq8StyY5Fw5aXbMcyJmVywrlH2bXPMTlNv8393/0KQ3iaQwxE9lU/uZqErxGqk/cUPho8AMuFk9kygcZArduQoM6A3eF3A==\r\n
    Server: Microsoft-HTTPAPI/2.0\r\n
    Date: Thu, 22 Sep 2022 08:05:18 GMT\r\n
    Content-Length: 0\r\n
    \r\n
    [HTTP response 1/12]
    [Time since request: 0.000689000 seconds]
    [Request in frame: 3745]
    [Next request in frame: 3749]
    [Next response in frame: 3751]
    [Request URI: http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1]
```

### The client sends a Heartbeat (may not always happen)

```
Frame 3749: 1362 bytes on wire (10896 bits), 1362 bytes captured (10896 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_a6:35:47 (08:00:27:a6:35:47), Dst: PcsCompu_62:f7:34 (08:00:27:62:f7:34)
Internet Protocol Version 4, Src: 192.168.58.100, Dst: 192.168.58.103
Transmission Control Protocol, Src Port: 65092, Dst Port: 5985, Seq: 3345, Ack: 342, Len: 1308
[2 Reassembled TCP Segments (1643 bytes): #3748(335), #3749(1308)]
Hypertext Transfer Protocol
    POST /wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1 HTTP/1.1\r\n
    Connection: Keep-Alive\r\n
    Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"\r\n
    Content-Encoding: SLDC\r\n
    User-Agent: Microsoft WinRM Client\r\n
    Content-Length: 1308\r\n
    Host: srv.windomain.local:5985\r\n
    \r\n
    [Full request URI: http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1]
    [HTTP request 2/12]
    [Prev request in frame: 3745]
    [Response in frame: 3751]
    [Next request in frame: 3778]
    File Data: 1308 bytes
MIME Multipart Media Encapsulation, Type: multipart/encrypted, Boundary: "Encrypted Boundary"
    [Type: multipart/encrypted]
    First boundary: --Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/http-kerberos-session-encrypted)
        Content-Type: application/HTTP-Kerberos-session-encrypted\r\n
        OriginalContent: type=application/soap+xml;charset=UTF-16;Length=1006
    Boundary: \r\n--Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/octet-stream)
        Content-Type: application/octet-stream\r\n
        Length of security token: 60
        GSS-API Generic Security Service Application Program Interface
        Media Type
    Last boundary: --Encrypted Boundary--\r\n
```

The `Content-Encoding` header contains `SLDC`. This means the body is compressed with `SLDC` (https://www.ecma-international.org/wp-content/uploads/ECMA-321_1st_edition_june_2001.pdf). In this case, we first need to decipher it with Kerberos, only the cleartext is compressed (otherwise it would not be really useful :D).

Wireshark does not understand that it is SLDC and that it need to be deciphered first. We just need to patch it to explain to him "no worry bro', it's only water":

```diff
diff --git a/epan/dissectors/packet-http.c b/epan/dissectors/packet-http.c
index 1c9d5d5610..e71f4b3da7 100644
--- a/epan/dissectors/packet-http.c
+++ b/epan/dissectors/packet-http.c
@@ -1813,7 +1813,8 @@ dissect_http_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
                 * we handle it in any case).
                 */
                if (headers.content_encoding != NULL &&
-                   g_ascii_strcasecmp(headers.content_encoding, "identity") != 0) {
+                   g_ascii_strcasecmp(headers.content_encoding, "identity") != 0 &&
+                   g_ascii_strcasecmp(headers.content_encoding, "SLDC") != 0) {
                        /*
                         * We currently don't handle, for example, "compress";
                         * just handle them as data for now.
```

With this patch, Wireshark deciphers the body:

```
ffabfdfc3c001cc003a00114006e001d80065001b0006f001c281a20001e0006da079bb2019cc003d000880068001d00074a098e8002f000bc0077001de8722ea1e8ce87e6f001c80067a1b8c80030000c28862fa298d68ae73a239868622da0af602845dc1730f8c2739800c748f32d1fcc349d176c7de03072118ef4b3e0270d322b8e29a661001900064a5f99698e73001a690667f08f265f9891665c8da6ea84f98ea3bfc0d01325634e80033754c4c5962f49d618e3756bc63d5afc24473acaf8162387c0d7336d56cc75a137e5293357b45d60b37edadf863543e00680224589f06e196c1b8948c36572a58747de17a4e5553c0818570c99874c39a2c5d91c4c76953659ec6a001cd53702e748b8e6003ad8970fc1cad2e70cab26fcbba2f001080036b6d912dbe42cd522d0011adca30000dedd634a03916dce2db568d2c7246b7f916dde450010edd244b6e8dee2244b8ae14818d99f06d709b0796b71d0009b72bc3f58a60ca0024dc7fb3ac6df9cbcb8eab968069dba3ad60eb7cb3a000ab9a3713163d4c75864ceba66cd4673c8ee3edd1231b78fc0288c651e6ce384cc52a1d9c284a79e397e04620f5377e0de51d290675dfeff2c41b12f721934ae0bf3c29b29e783a8dd9b4cf34bf37e475e1947618302c6920f409463e367fcc06e32569ce97efe8667c0a2617ee593956cf0e2186bdfc91ee4ab614c3bec2d3c5c3cdd68532e41d385884a76073d58a7e24b00d6bafa3706197e7e0509705309bb4b4c35bde01e1d6cbb8f10759be487937c8d7191a5c24836691bdabf17b10c0033b67e2ce22db1f17f10adb635b76e2e81a5b746b713215b8f83f5e4a83508133883f88cb45f0eae738940cf9954cb74116d904a7f15f1c41707c64186608997d4c3f4dc9ca7bc3f504126fd3f12f2ba56439a738c73778ced8646cdd645b68e2e01a51bc83469c0d041a2ee07a1b5194859b648945b20d24f03a10b382f9804e00013f3459cb3caf02c089f1f0648b9b3f15f0d690e36a428ca91e43a4be0721cd45c619b846f527c2498bb88b9b4f16e6120c0d832e24ff98c2e8001c732e9baf3f8c6be2c0c0c7a93fe06238641e2598a95fd36d7d4df5db3a57a4a16031b54dc5db9aca7c671f813e43cb228eb2f2e1dec47066b2fe232e1d41bb2cc9972dc9a2cba74cba22fb139cebc268b3b9b6c6a73b0dea6c39d91cc3683175a8ce57b7c45073b588cb30f8d2d6e30a2c8bed2276e32ce3b6c39032ae58e762ee2e616dba48d6eb22652fc12037ca7236b7c8d2e0246b8290ae1e39ca3a37ca578c7b1137a252e0f5106d1a6b0014b8baf86c0cb72fd7fd8a287400245d74c3b6a71b2636a215aacc8003cf1d048bc6cb39ef63f371de0dfb5dc116f5b8ea8d97bfc4603e007fd0000e20b0000
```

We can then install sldc lib implemented by Romain Carré (and the python module https://github.com/rom1sqr/sldc).

A python script that eats the Wireshark "stream hex" and decompresses it:

```python
#!/usr/bin/python3
# decompress.py

import sldc
import sys

while line := sys.stdin.readline():
    data = bytes.fromhex(line)
    print(sldc.decompress(data).decode('utf-16'))
```

```
$ ./decompress.py 
ffabfdfc3c001cc003a00114006e001d80065001b0006f001c281a20001e0006da079bb2019cc003d000880068001d00074a098e8002f000bc0077001de8722ea1e8ce87e6f001c80067a1b8c80030000c28862fa298d68ae73a239868622da0af602845dc1730f8c2739800c748f32d1fcc349d176c7de03072118ef4b3e0270d322b8e29a661001900064a5f99698e73001a690667f08f265f9891665c8da6ea84f98ea3bfc0d01325634e80033754c4c5962f49d618e3756bc63d5afc24473acaf8162387c0d7336d56cc75a137e5293357b45d60b37edadf863543e00680224589f06e196c1b8948c36572a58747de17a4e5553c0818570c99874c39a2c5d91c4c76953659ec6a001cd53702e748b8e6003ad8970fc1cad2e70cab26fcbba2f001080036b6d912dbe42cd522d0011adca30000dedd634a03916dce2db568d2c7246b7f916dde450010edd244b6e8dee2244b8ae14818d99f06d709b0796b71d0009b72bc3f58a60ca0024dc7fb3ac6df9cbcb8eab968069dba3ad60eb7cb3a000ab9a3713163d4c75864ceba66cd4673c8ee3edd1231b78fc0288c651e6ce384cc52a1d9c284a79e397e04620f5377e0de51d290675dfeff2c41b12f721934ae0bf3c29b29e783a8dd9b4cf34bf37e475e1947618302c6920f409463e367fcc06e32569ce97efe8667c0a2617ee593956cf0e2186bdfc91ee4ab614c3bec2d3c5c3cdd68532e41d385884a76073d58a7e24b00d6bafa3706197e7e0509705309bb4b4c35bde01e1d6cbb8f10759be487937c8d7191a5c24836691bdabf17b10c0033b67e2ce22db1f17f10adb635b76e2e81a5b746b713215b8f83f5e4a83508133883f88cb45f0eae738940cf9954cb74116d904a7f15f1c41707c64186608997d4c3f4dc9ca7bc3f504126fd3f12f2ba56439a738c73778ced8646cdd645b68e2e01a51bc83469c0d041a2ee07a1b5194859b648945b20d24f03a10b382f9804e00013f3459cb3caf02c089f1f0648b9b3f15f0d690e36a428ca91e43a4be0721cd45c619b846f527c2498bb88b9b4f16e6120c0d832e24ff98c2e8001c732e9baf3f8c6be2c0c0c7a93fe06238641e2598a95fd36d7d4df5db3a57a4a16031b54dc5db9aca7c671f813e43cb228eb2f2e1dec47066b2fe232e1d41bb2cc9972dc9a2cba74cba22fb139cebc268b3b9b6c6a73b0dea6c39d91cc3683175a8ce57b7c45073b588cb30f8d2d6e30a2c8bed2276e32ce3b6c39032ae58e762ee2e616dba48d6eb22652fc12037ca7236b7c8d2e0246b8290ae1e39ca3a37ca578c7b1137a252e0f5106d1a6b0014b8baf86c0cb72fd7fd8a287400245d74c3b6a71b2636a215aacc8003cf1d048bc6cb39ef63f371de0dfb5dc116f5b8ea8d97bfc4603e007fd0000e20b0000
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:To>http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1</a:To><m:MachineID xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid" s:mustUnderstand="false">win10.windomain.local</m:MachineID><a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat</a:Action><w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize><a:MessageID>uuid:EEC04F74-A27D-4C3A-AEF5-BC5BF54359BA</a:MessageID><w:Locale xml:lang="en-US" s:mustUnderstand="false" /><p:DataLocale xml:lang="en-US" s:mustUnderstand="false" /><p:SessionId s:mustUnderstand="false">uuid:981C530F-BE2A-4AAB-BACB-6FB4CD1A14AB</p:SessionId><p:OperationID s:mustUnderstand="false">uuid:EA2EE566-2CC1-49A0-A726-BCE7DC356E22</p:OperationID><p:SequenceId s:mustUnderstand="false">1</p:SequenceId><w:OperationTimeout>PT60.000S</w:OperationTimeout><e:Identifier xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing">219C5353-5F3D-4CD7-A644-F6B69E57C1C1</e:Identifier><w:AckRequested/></s:Header><s:Body><w:Events></w:Events></s:Body></s:Envelope>
```

We get this first message:

```xml
<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:To>http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1</a:To>
		<m:MachineID
			xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid" s:mustUnderstand="false">win10.windomain.local
		</m:MachineID>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
		<a:MessageID>uuid:EEC04F74-A27D-4C3A-AEF5-BC5BF54359BA</a:MessageID>
		<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
		<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
		<p:SessionId s:mustUnderstand="false">uuid:981C530F-BE2A-4AAB-BACB-6FB4CD1A14AB</p:SessionId>
		<p:OperationID s:mustUnderstand="false">uuid:EA2EE566-2CC1-49A0-A726-BCE7DC356E22</p:OperationID>
		<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
		<w:OperationTimeout>PT60.000S</w:OperationTimeout>
		<e:Identifier
			xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing">219C5353-5F3D-4CD7-A644-F6B69E57C1C1
		</e:Identifier>
		<w:AckRequested/>
	</s:Header>
	<s:Body>
		<w:Events></w:Events>
	</s:Body>
</s:Envelope>
```

- `a:To` : same address as `NotifyTo/Address`
- `m:MachineID`: again the machine DNS name
- `a:Action`: `http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat` (DSP0266 - 10.2.5)
- `p:SessionId`: a new UUID
- `p:OperationID`: a new UUID
- `e:Identifier`: identifier asked in `e:NotifyTo/a:Address/a:ReferenceProperties` (which the current subscription version)
- `w:AckRequested`: we need to respond a Ack

So the first message we received was a Heartbeat and not a batch of events.

### The collector acknowledges

```
Frame 3751: 2013 bytes on wire (16104 bits), 2013 bytes captured (16104 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_62:f7:34 (08:00:27:62:f7:34), Dst: PcsCompu_a6:35:47 (08:00:27:a6:35:47)
Internet Protocol Version 4, Src: 192.168.58.103, Dst: 192.168.58.100
Transmission Control Protocol, Src Port: 5985, Dst Port: 65092, Seq: 342, Ack: 4653, Len: 1959
Hypertext Transfer Protocol
    HTTP/1.1 200 \r\n
    Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"\r\n
    Server: Microsoft-HTTPAPI/2.0\r\n
    Date: Thu, 22 Sep 2022 08:05:18 GMT\r\n
    Content-Length: 1732\r\n
    \r\n
    [HTTP response 2/12]
    [Time since request: 0.000993000 seconds]
    [Prev request in frame: 3745]
    [Prev response in frame: 3747]
    [Request in frame: 3749]
    [Next request in frame: 3778]
    [Next response in frame: 3780]
    [Request URI: http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1]
    File Data: 1732 bytes
MIME Multipart Media Encapsulation, Type: multipart/encrypted, Boundary: "Encrypted Boundary"
    [Type: multipart/encrypted]
    First boundary: --Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/http-kerberos-session-encrypted)
        Content-Type: application/HTTP-Kerberos-session-encrypted\r\n
        OriginalContent: type=application/soap+xml;charset=UTF-16;Length=1430
    Boundary: \r\n--Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/octet-stream)
        Content-Type: application/octet-stream\r\n
        Length of security token: 60
        GSS-API Generic Security Service Application Program Interface
        Media Type
    Last boundary: --Encrypted Boundary--\r\n
```

This time, the content is not SLDC compressed:

```xml
<s:Envelope xml:lang="en-US"
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack</a:Action>
		<a:MessageID>uuid:12AAFC00-5BB5-42B5-BE85-077D7C02B8E9</a:MessageID>
		<p:OperationID s:mustUnderstand="false">uuid:EA2EE566-2CC1-49A0-A726-BCE7DC356E22</p:OperationID>
		<p:SequenceId>1</p:SequenceId>
		<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
		<a:RelatesTo>uuid:EEC04F74-A27D-4C3A-AEF5-BC5BF54359BA</a:RelatesTo>
	</s:Header>
	<s:Body></s:Body>
</s:Envelope>
```

What is interesting:
- `a:Action`: `http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack` (DSP0266 - 10.7)
- `p:OperationID`: same UUID as the previous message
- `a:RelatesTo`: contains the `MessageID` of the Heartbeat

### The client sends a POST request containing a batch of events

```
Frame 3778: 932 bytes on wire (7456 bits), 932 bytes captured (7456 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_a6:35:47 (08:00:27:a6:35:47), Dst: PcsCompu_62:f7:34 (08:00:27:62:f7:34)
Internet Protocol Version 4, Src: 192.168.58.100, Dst: 192.168.58.103
Transmission Control Protocol, Src Port: 65092, Dst Port: 5985, Seq: 23969, Ack: 2301, Len: 878
[15 Reassembled TCP Segments (20194 bytes): #3761(336), #3762(1460), #3763(1460), #3764(1460), #3765(1460), #3766(1460), #3767(1460), #3768(1460), #3769(1460), #3770(1460), #3772(1460), #3773(1460), #3774(1460), #3777(1460), #3778(878)]
Hypertext Transfer Protocol
    POST /wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1 HTTP/1.1\r\n
    Connection: Keep-Alive\r\n
    Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"\r\n
    Content-Encoding: SLDC\r\n
    User-Agent: Microsoft WinRM Client\r\n
    Content-Length: 19858\r\n
    Host: srv.windomain.local:5985\r\n
    \r\n
    [Full request URI: http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1]
    [HTTP request 3/12]
    [Prev request in frame: 3749]
    [Response in frame: 3780]
    [Next request in frame: 3972]
    File Data: 19858 bytes
MIME Multipart Media Encapsulation, Type: multipart/encrypted, Boundary: "Encrypted Boundary"
    [Type: multipart/encrypted]
    First boundary: --Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/http-kerberos-session-encrypted)
        Content-Type: application/HTTP-Kerberos-session-encrypted\r\n
        OriginalContent: type=application/soap+xml;charset=UTF-16;Length=19555
    Boundary: \r\n--Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/octet-stream)
        Content-Type: application/octet-stream\r\n
        Length of security token: 60
        GSS-API Generic Security Service Application Program Interface
        Media Type
    Last boundary: --Encrypted Boundary--\r\n
```

It is again compressed in SLDC and encrypted with Kerberos. We decipher it and decompress it using `decompress.py` and get:

```xml
<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:To>http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1</a:To>
		<m:MachineID
			xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid" s:mustUnderstand="false">win10.windomain.local
		</m:MachineID>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wsman/1/wsman/Events</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
		<a:MessageID>uuid:31652DEB-C9E8-45D6-B3E8-90AC64D48422</a:MessageID>
		<w:Locale xml:lang="en-US" s:mustUnderstand="false" />
		<p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
		<p:SessionId s:mustUnderstand="false">uuid:981C530F-BE2A-4AAB-BACB-6FB4CD1A14AB</p:SessionId>
		<p:OperationID s:mustUnderstand="false">uuid:C7F39CB2-8FFD-4DA3-A111-CDB303EEA098</p:OperationID>
		<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
		<w:OperationTimeout>PT60.000S</w:OperationTimeout>
		<e:Identifier
			xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing">219C5353-5F3D-4CD7-A644-F6B69E57C1C1
		</e:Identifier>
		<w:Bookmark>
			<BookmarkList>
				<Bookmark Channel="Microsoft-Windows-WinRM/Operational" RecordId="149161" IsCurrent="true"/>
			</BookmarkList>
		</w:Bookmark>
		<w:AckRequested/>
	</s:Header>
	<s:Body>
		<w:Events>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>254</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000026</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:21.6986159Z\'/><EventRecordID>149141</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-e5a0-11c2c7cdd801}\' RelatedActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1452\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData></EventData><RenderingInfo Culture=\'en-US\'><Message>Activity Transfer</Message><Level>Information</Level><Task></Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Server</Keyword><Keyword>Activity Transfer</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>161</EventID><Version>0</Version><Level>2</Level><Task>7</Task><Opcode>0</Opcode><Keywords>0x400000000000000a</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:21.6986177Z\'/><EventRecordID>149142</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-e5a0-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1452\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'authFailureMessage\'>The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Message><Level>Error</Level><Task>User authentication</Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Security</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>142</EventID><Version>0</Version><Level>2</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:21.6987077Z\'/><EventRecordID>149143</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1452\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'errorCode\'>2150858770</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration failed, error code 2150858770</Message><Level>Error</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>145</EventID><Version>0</Version><Level>4</Level><Task>5</Task><Opcode>1</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:22.2319758Z\'/><EventRecordID>149144</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1408\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'resourceUri\'>http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration started with resourceUri http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Message><Level>Information</Level><Task>WSMan API call</Task><Opcode>Start</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>145</EventID><Version>0</Version><Level>4</Level><Task>5</Task><Opcode>1</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:22.2326413Z\'/><EventRecordID>149145</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1436\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'resourceUri\'>http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration started with resourceUri http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Message><Level>Information</Level><Task>WSMan API call</Task><Opcode>Start</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>132</EventID><Version>0</Version><Level>4</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:22.2378561Z\'/><EventRecordID>149146</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1516\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration completed successfully</Message><Level>Information</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>132</EventID><Version>0</Version><Level>4</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:22.3280595Z\'/><EventRecordID>149147</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1408\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>EventDelivery</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation EventDelivery completed successfully</Message><Level>Information</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>254</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000026</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:24.2790340Z\'/><EventRecordID>149148</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-e3a2-11c2c7cdd801}\' RelatedActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1516\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData></EventData><RenderingInfo Culture=\'en-US\'><Message>Activity Transfer</Message><Level>Information</Level><Task></Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Server</Keyword><Keyword>Activity Transfer</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>161</EventID><Version>0</Version><Level>2</Level><Task>7</Task><Opcode>0</Opcode><Keywords>0x400000000000000a</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:24.2790354Z\'/><EventRecordID>149149</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-e3a2-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1516\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'authFailureMessage\'>The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Message><Level>Error</Level><Task>User authentication</Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Security</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>142</EventID><Version>0</Version><Level>2</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:24.2790637Z\'/><EventRecordID>149150</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1516\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'errorCode\'>2150858770</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration failed, error code 2150858770</Message><Level>Error</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>145</EventID><Version>0</Version><Level>4</Level><Task>5</Task><Opcode>1</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:25.2324872Z\'/><EventRecordID>149151</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1452\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'resourceUri\'>http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration started with resourceUri http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Message><Level>Information</Level><Task>WSMan API call</Task><Opcode>Start</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>145</EventID><Version>0</Version><Level>4</Level><Task>5</Task><Opcode>1</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:25.2331238Z\'/><EventRecordID>149152</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1332\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'resourceUri\'>http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration started with resourceUri http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription</Message><Level>Information</Level><Task>WSMan API call</Task><Opcode>Start</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>132</EventID><Version>0</Version><Level>4</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:25.2370488Z\'/><EventRecordID>149153</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1168\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration completed successfully</Message><Level>Information</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>211</EventID><Version>0</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x4000000000000004</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:26.4699756Z\'/><EventRecordID>149154</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1408\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData></EventData><RenderingInfo Culture=\'en-US\'><Message>The Winrm service is stopping</Message><Level>Information</Level><Task>Winrm service start/stop</Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Server</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>132</EventID><Version>0</Version><Level>4</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:26.7571617Z\'/><EventRecordID>149155</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1436\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>EventDelivery</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation EventDelivery completed successfully</Message><Level>Information</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>142</EventID><Version>0</Version><Level>2</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:26.8116276Z\'/><EventRecordID>149156</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'2484\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'errorCode\'>995</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration failed, error code 995</Message><Level>Error</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>212</EventID><Version>0</Version><Level>4</Level><Task>11</Task><Opcode>2</Opcode><Keywords>0x4000000000000004</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:27.0165994Z\'/><EventRecordID>149157</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1408\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData></EventData><RenderingInfo Culture=\'en-US\'><Message>The Winrm service was stopped successfully</Message><Level>Information</Level><Task>Winrm service start/stop</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Server</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>145</EventID><Version>0</Version><Level>4</Level><Task>5</Task><Opcode>1</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-22T07:49:27.3451670Z\'/><EventRecordID>149158</EventRecordID><Correlation ActivityID=\'{8cb1229f-ce57-0000-8437-b18c57ced801}\'/><Execution ProcessID=\'352\' ThreadID=\'2248\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-18\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'resourceUri\'>http://schemas.microsoft.com/wbem/wsman/1/config/listener</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration started with resourceUri http://schemas.microsoft.com/wbem/wsman/1/config/listener</Message><Level>Information</Level><Task>WSMan API call</Task><Opcode>Start</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>254</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000026</Keywords><TimeCreated SystemTime=\'2022-09-22T07:49:32.0355931Z\'/><EventRecordID>149159</EventRecordID><Correlation ActivityID=\'{8cb1229f-ce57-0000-8c37-b18c57ced801}\' RelatedActivityID=\'{8cb1229f-ce57-0000-8437-b18c57ced801}\'/><Execution ProcessID=\'352\' ThreadID=\'2468\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-18\'/></System><EventData></EventData><RenderingInfo Culture=\'en-US\'><Message>Activity Transfer</Message><Level>Information</Level><Task></Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Server</Keyword><Keyword>Activity Transfer</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>161</EventID><Version>0</Version><Level>2</Level><Task>7</Task><Opcode>0</Opcode><Keywords>0x400000000000000a</Keywords><TimeCreated SystemTime=\'2022-09-22T07:49:32.0355942Z\'/><EventRecordID>149160</EventRecordID><Correlation ActivityID=\'{8cb1229f-ce57-0000-8c37-b18c57ced801}\'/><Execution ProcessID=\'352\' ThreadID=\'2468\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-18\'/></System><EventData><Data Name=\'authFailureMessage\'>The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Message><Level>Error</Level><Task>User authentication</Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Security</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
			<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event">
				<![CDATA[<Event
				xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM\' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>142</EventID><Version>0</Version><Level>2</Level><Task>10</Task><Opcode>2</Opcode><Keywords>0x4000000000000002</Keywords><TimeCreated SystemTime=\'2022-09-22T07:49:32.0356778Z\'/><EventRecordID>149161</EventRecordID><Correlation ActivityID=\'{8cb1229f-ce57-0000-8437-b18c57ced801}\'/><Execution ProcessID=\'352\' ThreadID=\'2468\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-18\'/></System><EventData><Data Name=\'operationName\'>Enumeration</Data><Data Name=\'errorCode\'>2150858770</Data></EventData><RenderingInfo Culture=\'en-US\'><Message>WSMan operation Enumeration failed, error code 2150858770</Message><Level>Error</Level><Task>Response handling</Task><Opcode>Stop</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword></Keywords></RenderingInfo></Event>]]>
			</w:Event>
		</w:Events>
	</s:Body>
</s:Envelope>'
```

And at last we have the events :D

In the Header we can find:
- `a:Action`: `http://schemas.dmtf.org/wbem/wsman/1/wsman/Events` (see DSP226 10.2.9.4)
- `w:Bookmark`: keeps track of the last events we received, used to know what to send next. It should be sent during the next EnumerateResponse.
- `w:AckRequested`: the client requires an acknowledgment from the collector (mandatory in this mode).

In the body, there is table that contains events. Each event is a CDATA (as ask using `w:OptionSet`).

Inside one event we can see:

```xml
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
</Event>
```

As expected we have both `EventData` and `RenderingInfo` (because we specified `ContentFormat=RenderedText`).

Some other examples:

```xml
<Event
	xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	<System>
		<Provider Name="Microsoft-Windows-WinRM" Guid="{a7975c8f-ac13-49f1-87da-5a984a4ab417}"/>
		<EventID>161</EventID>
		<Version>0</Version>
		<Level>2</Level>
		<Task>7</Task>
		<Opcode>0</Opcode>
		<Keywords>0x400000000000000a</Keywords>
		<TimeCreated SystemTime="2022-09-22T07:49:32.0355942Z"/>
		<EventRecordID>149160</EventRecordID>
		<Correlation ActivityID="{8cb1229f-ce57-0000-8c37-b18c57ced801}"/>
		<Execution ProcessID="352" ThreadID="2468"/>
		<Channel>Microsoft-Windows-WinRM/Operational</Channel>
		<Computer>win10.windomain.local</Computer>
		<Security UserID="S-1-5-18"/>
	</System>
	<EventData>
		<Data Name="authFailureMessage">The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Data>
	</EventData>
	<RenderingInfo Culture="en-US">
		<Message>The client cannot connect to the destination specified in the request. Verify that the service on the destination is running and is accepting requests. Consult the logs and documentation for the WS-Management service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM service, run the following command on the destination to analyze and configure the WinRM service: "winrm quickconfig".</Message>
		<Level>Error</Level>
		<Task>User authentication</Task>
		<Opcode>Info</Opcode>
		<Channel>Microsoft-Windows-WinRM/Operational</Channel>
		<Provider>Microsoft-Windows-Windows Remote Management</Provider>
		<Keywords>
			<Keyword>Client</Keyword>
			<Keyword>Security</Keyword>
		</Keywords>
	</RenderingInfo>
</Event>
```

```xml
<Event
	xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	<System>
		<Provider Name="Microsoft-Windows-WinRM" Guid="{a7975c8f-ac13-49f1-87da-5a984a4ab417}"/>
		<EventID>208</EventID>
		<Version>0</Version>
		<Level>4</Level>
		<Task>11</Task>
		<Opcode>1</Opcode>
		<Keywords>0x4000000000000004</Keywords>
		<TimeCreated SystemTime="2022-09-22T07:49:34.3155529Z"/>
		<EventRecordID>149162</EventRecordID>
		<Correlation/>
		<Execution ProcessID="1080" ThreadID="728"/>
		<Channel>Microsoft-Windows-WinRM/Operational</Channel>
		<Computer>win10.windomain.local</Computer>
		<Security UserID="S-1-5-20"/>
	</System>
	<EventData></EventData>
	<RenderingInfo Culture="en-US">
		<Message>The Winrm service is starting</Message>
		<Level>Information</Level>
		<Task>Winrm service start/stop</Task>
		<Opcode>Start</Opcode>
		<Channel>Microsoft-Windows-WinRM/Operational</Channel>
		<Provider>Microsoft-Windows-Windows Remote Management</Provider>
		<Keywords>
			<Keyword>Server</Keyword>
		</Keywords>
	</RenderingInfo>
</Event>
```

```xml
<Event
	xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	<System>
		<Provider Name="Microsoft-Windows-WinRM" Guid="{a7975c8f-ac13-49f1-87da-5a984a4ab417}"/>
		<EventID>161</EventID>
		<Version>0</Version>
		<Level>2</Level>
		<Task>7</Task>
		<Opcode>0</Opcode>
		<Keywords>0x400000000000000a</Keywords>
		<TimeCreated SystemTime="2022-09-22T07:49:34.3642689Z"/>
		<EventRecordID>149166</EventRecordID>
		<Correlation ActivityID="{8cb1229f-ce57-0000-bb37-b18c57ced801}"/>
		<Execution ProcessID="1080" ThreadID="1560"/>
		<Channel>Microsoft-Windows-WinRM/Operational</Channel>
		<Computer>win10.windomain.local</Computer>
		<Security UserID="S-1-5-20"/>
	</System>
	<EventData>
		<Data Name="authFailureMessage">WinRM cannot process the request. The following error with errorcode 0x80090311 occurred while using Kerberos authentication: We can"t sign you in with this credential because your domain isn"t available. Make sure your device is connected to your organization"s network and try again. If you previously signed in on this device with another credential, you can sign in with that credential.  \r\n Possible causes are:\r\n  -The user name or password specified are invalid.\r\n  -Kerberos is used when no authentication method and no user name are specified.\r\n  -Kerberos accepts domain user names, but not local user names.\r\n  -The Service Principal Name (SPN) for the remote computer name and port does not exist.\r\n  -The client and remote computers are in different domains and there is no trust between the two domains.\r\n After checking for the above issues, try the following:\r\n  -Check the Event Viewer for events related to authentication.\r\n  -Change the authentication method; add the destination computer to the WinRM TrustedHosts configuration setting or use HTTPS transport.\r\n Note that computers in the TrustedHosts list might not be authenticated.\r\n   -For more information about WinRM configuration, run the following command: winrm help config.</Data>
	</EventData>
	<RenderingInfo Culture="en-US">
		<Message>WinRM cannot process the request. The following error with errorcode 0x80090311 occurred while using Kerberos authentication: We can"t sign you in with this credential because your domain isn"t available. Make sure your device is connected to your organization"s network and try again. If you previously signed in on this device with another credential, you can sign in with that credential.  \r\n Possible causes are:\r\n  -The user name or password specified are invalid.\r\n  -Kerberos is used when no authentication method and no user name are specified.\r\n  -Kerberos accepts domain user names, but not local user names.\r\n  -The Service Principal Name (SPN) for the remote computer name and port does not exist.\r\n  -The client and remote computers are in different domains and there is no trust between the two domains.\r\n After checking for the above issues, try the following:\r\n  -Check the Event Viewer for events related to authentication.\r\n  -Change the authentication method; add the destination computer to the WinRM TrustedHosts configuration setting or use HTTPS transport.\r\n Note that computers in the TrustedHosts list might not be authenticated.\r\n   -For more information about WinRM configuration, run the following command: winrm help config.</Message>
		<Level>Error</Level>
		<Task>User authentication</Task>
		<Opcode>Info</Opcode>
		<Channel>Microsoft-Windows-WinRM/Operational</Channel>
		<Provider>Microsoft-Windows-Windows Remote Management</Provider>
		<Keywords>
			<Keyword>Client</Keyword>
			<Keyword>Security</Keyword>
		</Keywords>
	</RenderingInfo>
</Event>
```

```xml
<Event
	xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	<System>
		<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
		<EventID>4688</EventID>
		<Version>2</Version>
		<Level>0</Level>
		<Task>13312</Task>
		<Opcode>0</Opcode>
		<Keywords>0x8020000000000000</Keywords>
		<TimeCreated SystemTime="2022-09-23T11:53:47.7604403Z"/>
		<EventRecordID>72206</EventRecordID>
		<Correlation/>
		<Execution ProcessID="4" ThreadID="288"/>
		<Channel>Security</Channel>
		<Computer>win10.windomain.local</Computer>
		<Security/>
	</System>
	<EventData>
		<Data Name="SubjectUserSid">S-1-5-18</Data>
		<Data Name="SubjectUserName">WIN10$</Data>
		<Data Name="SubjectDomainName">WINDOMAIN</Data>
		<Data Name="SubjectLogonId">0x3e7</Data>
		<Data Name="NewProcessId">0x7ec</Data>
		<Data Name="NewProcessName">C:\\Windows\\System32\\svchost.exe</Data>
		<Data Name="TokenElevationType">%%1936</Data>
		<Data Name="ProcessId">0x244</Data>
		<Data Name="CommandLine"></Data>
		<Data Name="TargetUserSid">S-1-0-0</Data>
		<Data Name="TargetUserName">WIN10$</Data>
		<Data Name="TargetDomainName">WINDOMAIN</Data>
		<Data Name="TargetLogonId">0x3e4</Data>
		<Data Name="ParentProcessName">C:\\Windows\\System32\\services.exe</Data>
		<Data Name="MandatoryLabel">S-1-16-16384</Data>
	</EventData>
	<RenderingInfo Culture="en-US">
		<Message>A new process has been created.\r\n\r\nCreator Subject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tWIN10$\r\n\tAccount Domain:\t\tWINDOMAIN\r\n\tLogon ID:\t\t0x3E7\r\n\r\nTarget Subject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\tWIN10$\r\n\tAccount Domain:\t\tWINDOMAIN\r\n\tLogon ID:\t\t0x3E4\r\n\r\nProcess Information:\r\n\tNew Process ID:\t\t0x7ec\r\n\tNew Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\tToken Elevation Type:\t%%1936\r\n\tMandatory Label:\t\tS-1-16-16384\r\n\tCreator Process ID:\t0x244\r\n\tCreator Process Name:\tC:\\Windows\\System32\\services.exe\r\n\tProcess Command Line:\t\r\n\r\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\r\n\r\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\r\n\r\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\r\n\r\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.</Message>
		<Level>Information</Level>
		<Task>Process Creation</Task>
		<Opcode>Info</Opcode>
		<Channel>Security</Channel>
		<Provider>Microsoft Windows security auditing.</Provider>
		<Keywords>
			<Keyword>Audit Success</Keyword>
		</Keywords>
	</RenderingInfo>
</Event>
```

```xml
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
</Event>
```

### The collector acknowledges

```
Frame 3780: 2013 bytes on wire (16104 bits), 2013 bytes captured (16104 bits) on interface \Device\NPF_{D0B586C7-BCDD-4989-9F90-8AD183BA1268}, id 0
Ethernet II, Src: PcsCompu_62:f7:34 (08:00:27:62:f7:34), Dst: PcsCompu_a6:35:47 (08:00:27:a6:35:47)
Internet Protocol Version 4, Src: 192.168.58.103, Dst: 192.168.58.100
Transmission Control Protocol, Src Port: 5985, Dst Port: 65092, Seq: 2301, Ack: 24847, Len: 1959
Hypertext Transfer Protocol
    HTTP/1.1 200 \r\n
    Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"\r\n
    Server: Microsoft-HTTPAPI/2.0\r\n
    Date: Thu, 22 Sep 2022 08:05:18 GMT\r\n
    Content-Length: 1732\r\n
    \r\n
    [HTTP response 3/12]
    [Time since request: 0.000914000 seconds]
    [Prev request in frame: 3749]
    [Prev response in frame: 3751]
    [Request in frame: 3778]
    [Next request in frame: 3972]
    [Next response in frame: 3977]
    [Request URI: http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1]
    File Data: 1732 bytes
MIME Multipart Media Encapsulation, Type: multipart/encrypted, Boundary: "Encrypted Boundary"
    [Type: multipart/encrypted]
    First boundary: --Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/http-kerberos-session-encrypted)
        Content-Type: application/HTTP-Kerberos-session-encrypted\r\n
        OriginalContent: type=application/soap+xml;charset=UTF-16;Length=1430
    Boundary: \r\n--Encrypted Boundary\r\n
    Encapsulated multipart part:  (application/octet-stream)
        Content-Type: application/octet-stream\r\n
        Length of security token: 60
        GSS-API Generic Security Service Application Program Interface
        Media Type
    Last boundary: --Encrypted Boundary--\r\n
```

Deciphered, it gives us:

```xml
<s:Envelope xml:lang="en-US"
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	<s:Header>
		<a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack</a:Action>
		<a:MessageID>uuid:1FE15160-9BB5-4CAB-B200-CDCC83F77FCB</a:MessageID>
		<p:OperationID s:mustUnderstand="false">uuid:C7F39CB2-8FFD-4DA3-A111-CDB303EEA098</p:OperationID>
		<p:SequenceId>1</p:SequenceId>
		<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
		<a:RelatesTo>uuid:31652DEB-C9E8-45D6-B3E8-90AC64D48422</a:RelatesTo>
	</s:Header>
	<s:Body></s:Body>
</s:Envelope>
```

### And so on...

The client keeps sending POST requests containing events and/or hearbeat.

At the same time, every "Refresh" secondes the client connects to the collector to check if subscriptions configuration has changed (is there new subscriptions ? has an existing subscription been updated ?).

### The client can end the subscription

This can happen, for example, when the computer is turned off.

In this case, the client sends a `SubscriptionEnd` to the collector:

```
Received HTTP request from 192.168.58.100:56842: POST /wsman/subscriptions/0C98CAE1-EDA4-4C92-82D9-A8A20EB518D2
```
```xml
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <a:To>http://wec.windomain.local:5985/wsman/subscriptions/0C98CAE1-EDA4-4C92-82D9-A8A20EB518D2</a:To>
        <m:MachineID
            xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid" s:mustUnderstand="false">win10.windomain.local
        </m:MachineID>
        <a:ReplyTo>
            <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
        </a:ReplyTo>
        <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscriptionEnd</a:Action>
        <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
        <a:MessageID>uuid:21DF76D2-A1ED-4333-BEAB-378AFB012DEE</a:MessageID>
        <w:Locale xml:lang="en-US" s:mustUnderstand="false" />
        <p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
        <p:SessionId s:mustUnderstand="false">uuid:B2FA79EC-9D29-4DFF-9BB4-D12809DC935D</p:SessionId>
        <p:OperationID s:mustUnderstand="false">uuid:50485065-8F54-44F2-8525-DBCBE293E317</p:OperationID>
        <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
        <w:OperationTimeout>PT0.500S</w:OperationTimeout>
        <e:Identifier
            xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing">0C98CAE1-EDA4-4C92-82D9-A8A20EB518D2
        </e:Identifier>
        <w:AckRequested/>
    </s:Header>
    <s:Body>
        <e:SubscriptionEnd>
            <e:SubscriptionManager>
                <a:Address>http://wec.windomain.local:5985/wsman/subscriptions/0C98CAE1-EDA4-4C92-82D9-A8A20EB518D2</a:Address>
                <a:ReferenceProperties>
                    <e:Identifier>820FEC3F-E3BD-4064-A4FD-BA8D550C4432</e:Identifier>
                </a:ReferenceProperties>
            </e:SubscriptionManager>
            <e:Status>http://schemas.xmlsoap.org/ws/2004/08/eventing/SourceCancelling</e:Status>
            <f:WSManFault
                xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="1717" Machine="win10.windomain.local">
                <f:Message>
                    <f:ProviderFault provider="Unknown provider" path="Unknown path">
                        <t:ProviderError
                            xmlns:t="http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog">Windows Event Forward Plugin failed to read events.
                        </t:ProviderError>
                    </f:ProviderFault>
                </f:Message>
            </f:WSManFault>
        </e:SubscriptionEnd>
    </s:Body>
</s:Envelope>
```

The next message is a `http://schemas.microsoft.com/wbem/wsman/1/wsman/End`. Fun fact: the client indicates that it is SLDC compressed but it is not.

```xml
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
    xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
        <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wsman/FullDuplex</w:ResourceURI>
        <a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wsman/End</a:Action>
        <a:MessageID>uuid:3244F96B-8ECA-4A06-90DE-8A1DED23AB1F</a:MessageID>
        <p:OperationID>uuid:50485065-8F54-44F2-8525-DBCBE293E317</p:OperationID>
    </s:Header>
    <s:Body></s:Body>
</s:Envelope>
```

# Side note

We always had trouble understanding where to put WinRM while reading Microsoft documentation.

We understood that the built-in Windows Event Forwarding plugin and the Windows Event Collector use the WinRM service and it is this service that implements [MS-WSMV].

We thought it was worth mentioning it here as we could not find this information clearly stated anywhere else.
