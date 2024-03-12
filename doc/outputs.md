# Outputs

Outputs answer the question "*what should openwec do with collected events?*". For one subscription, you may configure multiple outputs.

Each output is composed of two elements: a **driver** and a **format**.

The driver determines where the event will be sent or stored, whereas the format describes how it will be formatted. Formarts are described in [Formats](formats.md).

When an event is received for one subscription, it must be processed successfully by all its outputs. If one output fails, for example if there is no space left on device for a `Files` type output, an error is returned to the client which will try to resend the event later.

When OpenWEC server starts, it retrieves all currently active subscriptions from its database. For each subscription, every output is initialized.

When a subscription is updated or reloaded, all its outputs instances are dropped and initialized again.

Note: OpenWEC does not guarantee that an event will not be written multiple times. Indeed, if one output fails to write a batch of events, these events will not be acknowledged to the client that sent them and it will try to send them again later.

Subscription outputs can be configured using:
- subscription configuration files (see [Subscription](subscription.md))
- openwec command line interface

## Commands

For each subscription, you can manipulate its outputs using `openwec subscriptions edit <identifier> outputs`.

### `openwec subscriptions edit <identifier> outputs`

This command prints the current outputs of the subscription.

#### Example

```
$ openwec subscriptions edit my-subscription outputs
0: Enabled: true, Format: Json, Driver: Files(FilesConfiguration { base: "/var/events/", split_on_addr_index: None, append_node_name: false, filename: "messages" })
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


## Drivers 

### Files

The Files driver stores events in files on the collector filesystem.

For a given subscription, all events sent by a given Windows client will be stored in the following path:
```
<base>/<ip_path>/<principal>[/<node_name>]/<filename>
```
where:
* `base`: base path. It should be an absolute path. It must be configured in the output settings.
* `ip_path`: two formats can be configured in output settings:
    * `<ip>`: only the Windows client IP address (default).
    * The IP address of the client splitted on a given index to build a directory tree. For example, for an IPv4 address `A.B.C.D` and a split index equals to `1`, the resulting path will be `A/A.B/A.B.C/A.B.C.D`.
* `principal`: the Kerberos principal of the Windows client, without the `$` character. Example: `DC@WINDOMAIN.LOCAL`.
* `node_name` (optional): when you use a multi-node setup, you may want to add the node's name in the path. The node's name is configured in server settings, but you can choose to add it or not in each output settings.
* `filename`: the name of the file, configured in each output settings. It defaults to `messages`.

When the `Files` driver is initialized, it creates a blank hash table which will contain openned file descriptors. Therefore, each file is openned once.

You may want to tell OpenWEC to close all its file descriptors and to open them again. This can be done using `openwec subscriptions reload <subscription>`: the subscription outputs will be reloaded at the next "subscriptions reload" tick. You may want to reload subscriptions immediatly by sending a `SIGHUP` signal to `openwecd` process after executing the `openwec subscriptions reload` command.

#### Examples

* Store events in `/var/events/<ip>/<princ>/messages` for subscription `my-subscription`:

```
$ openwec subscriptions edit my-subscription outputs add --format <format> files /var/events/
```

* With `<ip> = A.B.C.D`, store events in `/var/events/A.B.C/A.B.C.D/<princ>/messages` for subscription `my-subscription`:

```
$ openwec subscriptions edit my-subscription outputs add --format <format> files /var/events/ --split-on-addr-index 3
```

* With `<ip> = A.B.C.D`, store events in `/var/events/A.B/A.B.C/A.B.C.D/<princ>/my-events` for subscription `my-subscription`:

```
$ openwec subscriptions edit my-subscription outputs add --format <format> files /var/events/ --split-on-addr-index 2 --filename my-events
```

* With `<ip> = A.B.C.D`, store events in `/var/events/A/A.B/A.B.C/A.B.C.D/<princ>/<node_name>/my-events` for subscription `my-subscription`:

```
$ openwec subscriptions edit my-subscription outputs add --format <format> files /var/events/ --split-on-addr-index 1 --filename my-events --append-node-name
```

### Kafka

The Kafka driver sends events in a Kafka topic.

For a given subscription, all events will be sent in the configured Kafka topic. You may want to add additionnal options to the inner Kafka client, such as `bootstrap.servers`.

#### Examples

* Send events to a Kafka cluster with two bootstrap servers `kafka1:9092` and `kafka2:9092` in topic `my-topic`:

```
$ openwec subscriptions edit my-subscription outputs add --format <format> kafka my-topic -o bootstrap.servers kafka1:9092,kafka2:9092
```

### TCP

The TCP driver send events in a "raw" TCP connection.

The TCP connection is established when the first event has to be sent. It is kept openned as long as possible, and re-established if required.

You must provide an IP address or a hostname and a port to connect to.

#### Examples

* Send events to a TCP server `my.server.windomain.local` using port `12000`:

```
$ openwec subscriptions edit my-subscription outputs add --format <format> tcp my.server.windomain.local 12000
```

### UNIX domain socket

The Unix datagram driver sends events to a Unix domain socket of type `SOCK_DGRAM`.

The connection is established when the first event has to be sent.

The path of the receiver socket is the only mandatory parameter.

#### Examples

* Send raw events to a UNIX datagram socket `/run/openwec.sock`:

```
$ openwec subscriptions edit my-subscription outputs add --format raw unixdatagram /run/openwec.sock
```

### Redis

The Redis driver sends events to a Redis list using the [LPUSH command](https://redis.io/commands/lpush/)

You must provide:
- a redis server address containing the IP and port to connect to.
- a list name

TODO:
- [ ] implement TLS connections to redis
- [ ] support redis auth
- [ ] ...

#### Examples

* Send events to a redis server into a list named "wec":

```
$ openwec subscriptions edit my-test-subscription outputs add --format <format> redis 127.0.0.1:6377 wec
```

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