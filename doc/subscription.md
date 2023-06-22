# Subscription

A subscription enables a Windows Event Collector to retrieve a set of events from a set of machines using a dedicated configuration. 

The set of events is defined by a list of XPath filter queries. For example, here is a query list composed of a single query which retrieves all event logs within channels `Application`, `Security`, `Setup` and `System`:
```xml
<QueryList>
    <Query Id="0" Path="Application">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
```

In Windows Event Forwarding protocol, a subscription is identified by its `version`, a GUID which must be updated each time changes are made to the subscription.

In OpenWEC, each subscription has a `version`, but because `version` is updated at each modification, each subscription is actually identified by another attribute called `uuid`, which is another GUID unique to a subscription and never updated. A subscription can also be identified using its `name` (user defined).

Each Windows machine configured to contact a Windows Event Collector server will send an `Enumerate` request to get a list of subscriptions. It will then create locally these subscriptions and fullfill them.

## Parameters 

Subscriptions and their parameters are not defined in OpenWEC configuration file but in OpenWEC database. Therefore, you **must** use `openwec` cli to edit them. You should **never update subscription parameters directly in database**.


| Parameter | Required | Default value | Description
|---|---|---|---|
| `name`  | **Yes** | - | the name of subscription. This name can be used to identify a subscription using openwec cli, but it also identifies the subscription for Windows machines. When analyzing Microsoft-Windows-Forwarding event logs, you may search for events with `EventData.Id` element text equals to `name`. |
| `query` | **Yes** | - | the XPath filter queries of the subscription, defining the set of events retrieved. See [query](query.md). |
| `uri` | No | *Undefined* | when configuring Windows machines to connect to the collector, you define a Server url, for example `Server=http://wec.windomain.local:5985/this/is/my/custom/uri`. As shown here, you may chose a custom URI. Each Windows machine will regularly send an Enumerate request to the collector to retrieve the set of Subscriptions that it must fullfill. <ul><li>If the `uri` parameter is `Undefined` (default), the subscription will always be sent.</li><li>If the `uri` parameter is defined, the subscription will be sent only if the request URI matches the subscription uri.</li></ul> |
| `heartbeat_interval` | No | 3600 | The maximum allowable time, in seconds, before the client will send an heartbeat message if it has no new events to send. This is used by OpenWEC to determine the "status" of each machine. |
| `connection_retry_count` | No | 5 | Number of times the client will attempt to connect if the subscriber is unreachable. |
| `connection_retry_interval` | No | 60 | Interval observed between each connection attempt if the subscriber is unreachable. |
| `max_time` | No | 30 | The maximum time, in seconds, that the client should aggregate new events before sending them. |
| `max_envelope_size` | No | 512000 | The maximum number of bytes in the SOAP envelope used to deliver the events. |
| `enabled` | No | `False` | Whether the subscription is enabled or not. Not that a new subscription is **disabled** by default, and **can not** be enabled unless you configure at least one output. As a safe guard, subscriptions without outputs are ignored by openwec server. |
| `read_existing_events` | No | `False` | If `True`, the event source should replay all possible events that match the filter and any events that subsequently occur for that event source. |
| `content_format` | No | `Raw` | This option determines whether rendering information are to be passed with events or not. `Raw` means that only event data will be passed without any rendering information, whereas `RenderedText` adds rendering information. |
| `ignore_channel_error` | No | `true` | This option determines if various filtering options resulting in errors are to result in termination of the processing by clients. |

## Subscription management

On launch, OpenWEC retrieves currently active subscriptions from database and instantiates tasks for managing their outputs. Parameters of these subscriptions are cached. A refresh of active subscriptions is done regularly (see [`db_sync_interval` setting](../openwec.conf.sample.toml)) to react to any changes. During a refresh, subscriptions that have been changed (parameters, outputs, ...) will get their outputs instances dropped and created again.

When you edit a subscription, it is not applied immediatly but only on the next "refresh" on the active subscriptions. The refresh interval is quite short by default (a few seconds) so this seems fine, but if required you can force a refresh by sending a `SIGHUP` signal to `openwecd` process.

Sometimes, you may want to force every subscriptions to drop and create again their outputs. This can be done using `openwec subscriptions reload` (see [Available Commands](subscription.md#available-commands)). Same as any change, it will be applied on the next refresh (or `SIGHUP` signal received).

## Event Delivery Optimization Options

In its configuration UI, Microsoft WEC enables users to choose between three event delivery optimization options. These options are pre-defined subscription parameters set which can be reproduced on OpenWEC.


| Option  | Microsoft description | Parameters  |
|---|---|---|
| Normal  | This option ensures reliable delivery of events and does not attempt to conserve bandwidth. It is the appropriate choice unless you need tighter control over bandwidth usage or need forwarded events delivered as quickly as possible. | <ul><li>`max_time`: 900 (15 minutes)</li><li>`heartbeat_interval`: 900 (15 minutes)</li><li>TODO: Batch item max size!</li></ul> |
| Minimize Bandwidth | This option ensures reliable delivery of events and does not attempt to conserve bandwidth. It is the appropriate choice unless you need tighter control over bandwidth usage or need forwarded events delivered as quickly as possible. | <ul><li>`max_time`: 21600 (6 hours)</li><li>`heartbeat_interval`: 21600 (6 hours)</li></ul> |
| Minimize Latency | This option ensures that events are delivered with minimal delay. It is an appropriate choice if you are collecting alerts or critical events. | <ul><li>`max_time`: 30 (30 seconds)</li><li>`heartbeat_interval`: 3600 (1 hour)</li></ul> |


In its documentation, Microsoft states that Normal mode uses a Pull delivery mode (meaning that its the collector who connects to Windows machines and retrieve their event logs). It seems to be a mistake, as the exported configuration of a subscription configured in Normal mode clearly specifies that it is SourceInitiated in Push mode.

## Principals filter

It is possible to filter the client Kerberos principals that can see a subscription. The comparison is **case-sensitive**.

There are three filtering modes:
* `None` (default): no filtering based on Kerberos principal
* `Only [princ, ...]`: the subscription will only be shown to the listed principals
* `Except [princ, ...]`: the subscription will be shown to everyone except the listed principals

The principals filter can be configured using openwec cli:
*  `openwec subscriptions edit <subscription> filter set <mode> [princ, ...]` configures the principals filter.
*  `openwec subscriptions edit <subscription> filter princs {add,delete,set} [princ, ...]` manages the principals in the filter.


## Available commands

### `openwec subscriptions`

List subscriptions in a "short" format. Each line represents a subscription, with its status (enabled or not), its name and its URI.

#### Usage 

```
$ openwec subscriptions
[-] Old subscription (*)
[+] My-new-subscription (*)
[+] Subscription-toto (/toto)
```

There are 3 subscriptions: 
- A subscription named `Old subscription`, disabled with no URI defined.
- A subscription named `My-new-subscription`, enabled with no URI defined.
- A subscription named `Subscription-toto`, enabled with a URI set to `/toto`.

It means that when a Windows machine sends an Enumerate request using URI `/hello-world`, it gets an Enumerate reponse containing only the subscription `My-new-subscription`.
Otherwise, if a Windows machine sends an Enumerate request using URI `/toto`, it gets an Enumerate response containing subscriptions `My-new-subscription` **and** `Subscription-toto`.

### `openwec subscriptions new`

This command enables you to create a new subscription.

There are 2 required parameters:
- `name`: the name of the subscription. Must be unique.
- `query`: the path a file containing the xml query list of this subscription.

You can optionnally set all subscription parameters, except the `enabled` one because a newly created subscription is **always** `disabled`.

#### Usage

```
$ openwec subscriptions new my-super-subscription query_simple.xml --uri /super --max-time 600 --heartbeat-interval 600
Subscription my-super-subscription has been created successfully. You need to configure its outputs using `openwec subscriptions edit my-super-subscription outputs add --help`. When you are ready, you can enable it using `openwec subscriptions edit my-super-subscription --enable`
```

This command creates a new subscription named `my-super-subscription`, based on the query list contained in `query_simple.xml`, with URI `/super` and its `max_time` and `heartbeat_interval` configured both to `600`. Other parameters will get their default values. The newly created subscription is **disabled** and contains no outputs.

You may add some using `openwec subscriptions output`, which is detailed in [Outputs documentation](outputs.md).

### `openwec subscriptions edit`

This command enables you to edit an already existing subscription.

You must provide the identifier of the subscription to edit, which can be either its `name` or its `uuid`.

You can edit every parameters of the subscription, even its name.

You should be very careful when editing a subscription query, especially when adding new event log channels (see [Query known issues](query.md#known-issues)).

Subscriptions update are not immediatly applied. openwec server maintains an in-memory cache of the current subscriptions, and refreshes its cache regularly. Your changes will only be applied when the cache is refreshed. You can force a cache refresh by sending a SIGHUP signal to openwec server process.

#### Usage

```
$ openwec subscriptions edit my-super-subscription --uri /new-uri --connection-retry-count 10
```

This command edits the subscription named `my-super-subscription`, changing its uri to `/new-uri` and its `connection_retry_count` parameter to `10`.

```
$ openwec subscriptions edit my-super-subscription filter set only 'SUSPICIOUS$@WINDOMAIN.LOCAL' 'INFECTED$@WINDOMAIN.LOCAL'
```

This command edits the subscription named `my-super-subscription`, changing its filter to _only_ retrieve events from `SUSPICIOUS$@WINDOMAIN.LOCAL` and `INFECTED$@WINDOMAIN.LOCAL`.

### `openwec subscriptions show`

This command prints all parameters of a subscription, including its query.

#### Usage

```
$ openwec subscriptions show my-super-subscription
Subscription my-super-subscription
	UUID: 27D8CE0B-CAFE-44CA-9FE1-4B9D6EE45AE8
	Version: 3366A5BD-9E71-482E-9359-9505EA1F8400
	URI: /new-uri
	Heartbeat interval: 600s
	Connection retry count: 10
	Connection retry interval: 60s
	Max time without heartbeat/events: 600s
	Max envelope size: 512000 bytes
	ReadExistingEvents: false
	ContentFormat: Raw
	IgnoreChannelError: true
	Principal filter: Not configured
	Outputs: Not configured 
	Enabled: false

Event filter query:

<QueryList>
    <Query Id="0" Path="Application">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
```

### `openwec subscriptions duplicate`

This command duplicates an existing subscription.

The newly created subscriptions will inherit all the parameters and outputs of its parent, but :
- it will be disabled.
- it will get a new unique `uuid`.
- it will get a new `version`.


#### Usage

```
$ openwec subscriptions duplicate my-super-subscription this-is-a-clone

$ openwec subscriptions show this-is-a-clone
Subscription this-is-a-clone
	UUID: 88C9BADD-BCB1-4324-98DC-2D56E4A893DA
	Version: C460B829-C50F-42E1-8275-F9AB62A5058C
	URI: /new-uri
	Heartbeat interval: 600s
	Connection retry count: 10
	Connection retry interval: 60s
	Max time without heartbeat/events: 600s
	Max envelope size: 512000 bytes
	ReadExistingEvents: false
	ContentFormat: Raw
	IgnoreChannelError: true
	Principal filter: Not configured
	Outputs: None
	Enabled: false

Event filter query:

<QueryList>
    <Query Id="0" Path="Application">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
```

### `openwec subscriptions export`

This command exports the currently configured subscriptions in a `json` format. You may export only one subscription using `--subscription <identifier>`.

These subscriptions can be imported in another openwec installation.

**Warning: Importing subscriptions exported from another openwec version might not work.**


#### Usage

```
$ openwec subscriptions export
[{"uuid":"27D8CE0B-CAFE-44CA-9FE1-4B9D6EE45AE8","version":"3366A5BD-9E71-482E-9359-9505EA1F8400","name":"my-super-subscription","uri":"/new-uri","query":"<QueryList>\n    <Query Id=\"0\" Path=\"Application\">\n        <Select Path=\"Application\">*</Select>\n        <Select Path=\"Security\">*</Select>\n        <Select Path=\"Setup\">*</Select>\n        <Select Path=\"System\">*</Select>\n    </Query>\n</QueryList>\n","heartbeat_interval":600,"connection_retry_count":10,"connection_retry_interval":60,"max_time":600,"max_envelope_size":512000,"enabled":false,"read_existing_events":false,"content_format":"Raw","ignore_channel_error":true,"princs_filter":{"operation":null,"princs":[]},"outputs":[]},[...]]
```

### `openwec subscriptions import`

This command imports subscriptions from a file. Two formats are supported:
* `openwec`: the format generated by `openwec subscriptions export`. **Importing subscriptions exported from another openwec version might not work.**
* `windows`: the format generated on a Windows Server Windows Event Collector with `wecutil.exe /gs <my subscription> /format:xml`. Note that `openwec` only supports source initiated mode and does not support client filtering.

Imported subscriptions are disabled by default.

#### Usage

```
$ openwec subscriptions import -f windows windows-subscription.xml
1 subscription has been imported. You may want to enable it using `openwec subscriptions edit <name> --enable`.
```

### `openwec subscriptions delete`

This command deletes subscriptions, and all associated bookmarks and heartbeats. There is no way to undo this action (unless you backup your database, and **you should definitely do it**).

#### Usage

```
$ openwec subscriptions delete windows-subscription
Are you sure that you want to delete "windows-subscription" (92A7836D-96FC-4EE5-9E45-03D0618607DE) ? [y/n] y
```

### `openwec subscriptions machines`

This command enables you to retrieve the list of clients attached to a subscription.

You may filter on status:
* `--active`: only show active clients, that is to say clients that sent events since `--interval` seconds ago (defaults to `heartbeat-interval`).
* `--alive`: only show alive clients, that is to say clients that sent heartbeats since `--interval` seconds ago, but no events. This probably means that these machines did not procude events matching the filter query of the subscription.
* `--dead`: only show dead clients, that is to say clients that did not sent heartbeats nor events since at least `--interval` seconds ago. Most of the time, this means that the machine is turned off or can not reach the collector due to network outage.

If you only want numbers, check `openwec stats` command.

The output format is `<IP ADDRESS>:<PRINCIPAL>`.

#### Usage

```
$ openwec subscriptions machines my-super-subscription
192.168.58.102:DC$@WINDOMAIN.LOCAL
192.168.58.100:WIN10$@WINDOMAIN.LOCAL
```

### `openwec subscriptions enable`

This command enables one or many subscriptions. You may also want to enable all configured subscriptions without listing them using `--all`.

For one subscription (`openwec subscriptions enable <subscription>`), you can alternatively use `openwec subscriptions edit <subscription> --enable`.

Subscriptions with no outputs configured can not be enabled and will not be enabled by this command. However, this command will fail only if no subscriptions could be enabled, and print warnings otherwise.

Subscriptions update are not immediatly applied. openwec server maintains an in-memory cache of the current subscriptions, and refreshes its cache regularly. Your changes will only be applied when the cache is refreshed. You can force a cache refresh by sending a SIGHUP signal to openwec server process.

#### Usage

```
$ openwec subscriptions enable my-super-subscription this-is-a-clone
```

### `openwec subscriptions disable`

This command disables one or many subscriptions. You may also want to disable all configured subscriptions without listing them using `--all`.

For one subscription (`openwec subscriptions disable <subscription>`), you can alternatively use `openwec subscriptions edit <subscription> --disable`.

Subscriptions update are not immediatly applied. openwec server maintains an in-memory cache of the current subscriptions, and refreshes its cache regularly. Your changes will only be applied when the cache is refreshed. You can force a cache refresh by sending a SIGHUP signal to openwec server process.

#### Usage

```
$ openwec subscriptions disable my-super-subscription this-is-a-clone
```


### `openwec subscriptions reload`

This command updates the version of one or many subscriptions. You may also want to reload all configured subscriptions without listing them using `--all`.

This has two main effects:
* all running outputs will be killed and started again.
* Windows clients will close their "events" TCP connection and open a new one.

In case of a multi-node setup, this command may be useful to "balance" clients between openwec nodes after a load balancing configuration change. It may also be used with `Files` output to close and re-open all file descriptors.


#### Usage

```
$ openwec subscriptions reload my-super-subscription this-is-a-clone
$ openwec subscriptions reload --all
```
