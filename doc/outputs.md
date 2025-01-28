# Outputs

Outputs answer the question "*what should openwec do with collected events?*". For one subscription, you may configure multiple outputs.

Each output is composed of two elements: a **driver** and a **format**.

The driver determines where the event will be sent or stored, whereas the format describes how it will be formatted. Formarts are described in [Formats](formats.md).

When an event is received for one subscription, it must be processed successfully by all its outputs. If one output fails, for example if there is no space left on device for a `Files` type output, an error is returned to the client which will try to resend the event later.

When OpenWEC server starts, it retrieves all currently active subscriptions from its database. For each subscription, every output is initialized.

When a subscription is updated or reloaded, all its outputs instances are dropped and initialized again.

Note: OpenWEC does not guarantee that an event will not be written multiple times. Indeed, if one output fails to write a batch of events, these events will not be acknowledged to the client that sent them and it will try to send them again later.

Subscription outputs can be configured using:
- **subscription configuration files** (see [Subscription](subscription.md))
- ~~openwec command line interface~~ (deprecated)

## Drivers 

### Files

The Files driver stores events in files on the collector filesystem.

For a given subscription, all events will be written to the configured `path`. This path can contain variables that will be replaced by their values at runtime, using the syntax `{variable}`.

Available variables are:

| **Name** | **Description** |
|:----:|-----------------|
| `ip` | The Windows client IP address |
| `ip:<n>` | The Windows client IP address until the `<n>`-th separator where `<n>` is an integer between 1 and 4.<br/>- `ip:2` would transform `127.0.0.1` into `127.0`<br/>- `ip:3` would transform `192.168.2.1` into `192.168.2`<br/>- `ip:4` would transform `2001:0:130F:0:0:9C0:876A:130B` into `2001:0:130F:0`.
| `principal` | The Kerberos principal of the Windows client. Because this principal is used to build a path, all the characters that do not match `[a-zA-Z0-9.\-_@]` are deleted. |
| `node` | The OpenWEC node's name which is configured in OpenWEC setting `server.node_name`. If the node does not have a name, the string `{node}` is left unchanged and a warning is generated. |

The `Files` driver uses a unique thread (even if there are multiple instances of the driver) to write files. This thread maintains a hash table which contains every opened file descriptors. A garbage collector is run regularly (see `outputs.garbage_collect_interval` setting) to close the file descriptors that have not been used in a while (see `outputs.files.file_descriptors_close_timeout`).

Multiple Files outputs can safely write to the same file (even in different subscriptions).

You may want to tell OpenWEC to close all its file descriptors and to open them again (for example if you use `logrotate`). You can do that by sending a `SIGHUP` signal to the `openwecd` process.

#### Examples

| **Path** | **Description** |
|----------|-----------------|
| `/var/events/forwarded.log` | Store events in `/var/events/forwarded.log`
| `/var/events/{ip}/{principal}/messages` | Store events in `/var/events/<ip>/<principal>/messages`
| `/var/events/{ip:3}/{ip}/{principal}/messages` | With `<ip> = A.B.C.D`, store events in `/var/events/A.B.C/A.B.C.D/<principal>/messages`
| `/var/events/{ip:2}/{ip:3}/{ip}/{principal}/my-events` | With `<ip> = A.B.C.D`, store events in `/var/events/A.B/A.B.C/A.B.C.D/<principal>/my-events`
| `/var/events/{ip:1}/{ip:2}/{ip:3}/{ip}/{principal}/{node}/my-events` | With `<ip> = A.B.C.D`, store events in `/var/events/A/A.B/A.B.C/A.B.C.D/<principal>/<node_name>/my-events`

#### Configuration

```toml
[[outputs]]
driver = "Files"
format = "<format>" # To replace
config = { path = "<path>" } # To replace
```

#### Command

> [!WARNING]
> Using commands to manage subscriptions and there outputs is **deprecated** and will be removed in future releases. Use subscription configuration files instead. 

```
$ openwec subscriptions edit <subscription> outputs add --format <format> files <path> 
```

### Kafka

The Kafka driver sends events in a Kafka topic.

For a given subscription, all events will be sent in the configured Kafka topic. You may want to add additionnal options to the inner Kafka client, such as `bootstrap.servers`. This options will be directly given to `librdkafka` (available options are listed here: https://docs.confluent.io/platform/current/clients/librdkafka/html/md_CONFIGURATION.html).

> [!TIP]
> If multiple outputs use the Kafka driver and connect to the same Kafka cluster, it is recommended to configure the additional options in OpenWEC settings (`outputs.kafka.options`) **and** to omit the `options` parameter in Kafka output configuration. This way, only one Kafka client will be used by all the outputs, which is more resource efficient.

#### Configuration

```toml
[[outputs]]
driver = "Kafka"
format = "<format>" # To replace
config = { topic = "<topic>", options = { "bootstrap.servers" = "<bootstrap-servers-comma-separated>" } } # To replace
```

#### Command

> [!WARNING]
> Using commands to manage subscriptions and there outputs is **deprecated** and will be removed in future releases. Use subscription configuration files instead. 

```
$ openwec subscriptions edit <subscription> outputs add --format <format> kafka <topic> -o <option_key_1> <option_value_1> -o <option_key_2> <option_value_2>
```

### TCP

The TCP driver send events in a "raw" TCP connection.

The TCP connection is established when the first event has to be sent. It is kept opened as long as possible, and re-established if required. There is one TCP connection per output using TCP driver.

You must provide an IP address or a hostname (`host`) and a port to connect to.

The TCP connection can optionally be secured using TLS (`tls_enabled`). The TCP driver verifies the server certificate against the specified certificate authorities (`tls_certificate_authorities`). The TCP driver can optionally use a client certificate `tls_certificate` (and its associated key `tls_key`) if the server requires client authentication.

#### Configuration

```toml
[[outputs]]
driver = "Tcp"
format = "<format>" # To replace
# - host (required): Hostname or IP Address to send events to
# - port (required): Tcp port to send events to
# - tls_enabled (optional, defaults to false): wrap the TCP stream in a TLS channel.
#       Must be set for other tls_ options to take effect
# - tls_certificate_authorities (optional, defaults to undefined): Validate server certificate
#       chain against these authorities. You can define multiple files or paths.
#       All the certificates will be read and added to the trust store.
# - tls_certificate (optional, defaults to undefined): Path to certificate in PEM format.
#       This certificate will be presented to the server.
# - tls_key (optional, defaults to undefined): Path to the private key corresponding to the
#       specified certificate (PEM format).
config = { host = "<hostname>", port = <port> } # To replace
```

#### Command

> [!WARNING]
> Using commands to manage subscriptions and there outputs is **deprecated** and will be removed in future releases. Use subscription configuration files instead. 

```
$ openwec subscriptions edit <subscription> outputs add --format <format> tcp <hostname or IP> <port>
```

### UNIX domain socket

The Unix datagram driver sends events to a Unix domain socket of type `SOCK_DGRAM`.

The connection is established when the first event has to be sent. There is one connection per output using the `UnixDatagram` driver.

The path of the receiver socket is the only mandatory parameter.

#### Configuration

```toml
[[outputs]]
driver = "UnixDatagram"
format = "<format>" # To replace
config = { path = "<path>"} # To replace
```

#### Command

> [!WARNING]
> Using commands to manage subscriptions and there outputs is **deprecated** and will be removed in future releases. Use subscription configuration files instead. 

```
$ openwec subscriptions edit <subscription> outputs add --format <format> unixdatagram <path>
```

### Redis

The Redis driver sends events to a Redis list using the [LPUSH command](https://redis.io/commands/lpush/)

You must provide:
- a redis server address containing the IP and port to connect to.
- a list name

> [!NOTE]
> The Redis driver does not support TLS connections to redis nor redis authentication yet.

#### Configuration

```toml
[[outputs]]
driver = "Redis"
format = "<format>" # To replace
config = { addr = "<redis server>", list = "<list>" } # To replace
```

#### Command

> [!WARNING]
> Using commands to manage subscriptions and there outputs is **deprecated** and will be removed in future releases. Use subscription configuration files instead. 

```
$ openwec subscriptions edit <subscription> outputs add --format <format> unixdatagram <path>
$ openwec subscriptions edit <subscription> outputs add --format <format> redis <redis server> <list>
```

## Commands (deprecated)

> [!WARNING]
> Using commands to manage subscriptions and there outputs is **deprecated** and will be removed in future releases. Use subscription configuration files instead. 

For each subscription, you can manipulate its outputs using `openwec subscriptions edit <identifier> outputs`.

### `openwec subscriptions edit <identifier> outputs`

This command prints the current outputs of the subscription.

#### Example

```
$ openwec subscriptions edit my-subscription outputs
0: Enabled: true, Format: Json, Driver: Files(FilesConfiguration { path: "/var/events/{ip}/{principal}/messages" })
1: Enabled: true, Format: Json, Driver: Tcp(dc.windomain.local:12000)
```

The subscription `my-subscription` has two outputs configured:
* the first uses the `Files` driver and the `Json` format.
* the second one uses the `Tcp` driver and the `Json` format.

The index number at the beginning of each line can be used to delete the corresponding output.

### `openwec subscriptions edit <identifier> outputs add`

This command adds an output to a subscription.

You must specify a format (see [Formats](formats.md)) and a driver (see below).

#### Example

```
$ openwec subscriptions edit my-subscription outputs add --format json files [...]
```

This command adds an output using `Files` driver and `Json` format.

### `openwec subscriptions edit <identifier> outputs delete`

This command deletes an output of a subscription.

You must specify the index of the output to delete, index shown in `openwec subscriptions edit <identifier> outputs` command.

##### Example

```
$ openwec subscriptions edit my-subscription outputs delete 0
```

This command deletes the first output of the subscription `my-subscription`.

## How to add a new driver ?

To add an output driver, you need to:
- in `common`:
    - add a new variant to `common::subscription::SubscriptionOutputDriver` with a decicated configuration structure.
    - adapt `common::models::config` and `common::models::export`.
- in `server`:
    - create a dedicated module in `server::drivers` that contains a struct which implements the `OutputDriver` trait.
    - initialize the output in `server::output::Output::new`.
- in `cli`:
    - add a subcommand to create an output using the driver in `cli::main` and handle it in `cli::subscriptions`.
    - add a config template of an output using the driver in `cli::skell`.
- add documentation in `doc/outputs.md`.