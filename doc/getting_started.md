# Getting started

## Installing OpenWEC

OpenWEC is not yet packaged for any distribution we know about. Therefore, you can either use the official Docker image (see [docker.md](docker.md)), build it from source, get a precompiled binary or get a deb package from the release page.

### Building OpenWEC

To build OpenWEC, you will need:
* cargo and rustc
* libssl-dev
* libkrb5-dev
* libsasl2-dev

And you will need to run:

```bash
$ cargo build --release
$ strip target/release/openwec
$ strip target/release/openwecd
```

## Basic configuration example

This example uses Kerberos authentication. For a basic example using TLS, see [tls.md](tls.md).

In an Active Directory domain `DC=windomain,DC=local`, let's configure OpenWEC on a machine named `wec.windomain.local` using an SQLite database.

Requirements:
* A DNS entry for `wec.windomain.local`
* Authorise connections from your Windows machines to `wec.windomain.local` on TCP/5985
* An Active Directory account for OpenWEC with `http/wec.windomain.local@WINDOMAIN.LOCAL` **and** `host/wec.windomain.local@WINDOMAIN.LOCAL` Service Principal Name.
* A keytab file containing keys for `http/wec.windomain.local@WINDOMAIN.LOCAL` **or** `host/wec.windomain.local@WINDOMAIN.LOCAL` SPN, available in `/etc/wec.windomain.local.keytab`.

> [!note]
> The `host/<wec>` SPN is used by default by the WinRM client since Windows Server 2025.

Write the following content in `/etc/openwec.conf.toml`:
<!--
    WARNING!
    The following content is tested in `common/src/settings.rs`.
    If you update it, make sure to also do the update in the test.
-->
```toml
# /etc/openwec.conf.toml
[server]
keytab = "/etc/wec.windomain.local.keytab"

[database]
type = "SQLite"
# You need to create /var/db/openwec yourself
path = "/var/db/openwec/db.sqlite"

[[collectors]]
hostname = "wec.windomain.local"
listen_address = "0.0.0.0"

[collectors.authentication]
type = "Kerberos"
service_principal_name = "http/wec.windomain.local@WINDOMAIN.LOCAL"
```

> [!TIP]
> See [openwec.conf.sample.toml](../openwec.conf.sample.toml) for further information on available parameters.

We have configured OpenWEC to use the SQLite backend. The SQLite database will be stored on disk in `/var/db/openwec/db.sqlite`. 

We have set up a collector server. It listens on `0.0.0.0` (default port is `5985`) and can be contacted by Windows computers using `wec.windomain.local`.

Authentication is made using Kerberos. A valid keytab containing credentials for `http/wec.windomain.local@WINDOMAIN.LOCAL` must be present in `/etc/wec.windomain.local.keytab`.

## Initializing database

We have configured the SQLite database to be stored on disk in `/var/db/openwec/db.sqlite`. We need to make sure that `/var/db/openwec` exists:

```bash
$ mkdir -p /var/db/openwec
```

Then, the database schema needs to be initialized using:

```bash
$ openwec db init
```

## Creating subscriptions

To retrieve Windows events and handle them, we need to create subscriptions. A subscription consists of a list of event queries (what events to collect), a list of outputs (what OpenWEC should do with them) and some configuration.

In this example, we will create one subscription named `my-test-subscription`.

### Event Query

You need to build a query to retrieve events you are interested in. Event queries syntax is described by Microsoft [here](https://learn.microsoft.com/en-us/previous-versions/bb399427(v=vs.90)).

In this example, let's say we want to retrieve every events in *Security*, *System*, *Application* and *Setup* sources. Our query will be:
```xml
<Query Id="0">
    <Select Path="Application">*</Select>
    <Select Path="Security">*</Select>
    <Select Path="Setup">*</Select>
    <Select Path="System">*</Select>
</Query>
```

### Outputs

In this example, we want to:
- store events in `Raw` format in files in the path `/data/logs/<ip>/<client>/messages`, where `<ip>` is the IP address of the machine who sent the log messages and `<client>` its identifier (Kerberos Principal)
- send events in `RawJson` format in a Kafka topic (`my-kafka-topic`) on `localhost:9092` for further processing

We need to configure two outputs:
- one using the `Files` driver and the `Raw` format with path `/data/logs/{ip}/{client}/messages`
- one using the `Kafka` driver and the `RawJson` format with topic `my-kafka-topic` and option `bootstrap-servers=localhost:9092`

### Configuration file

It is typically advisable to use multiple subscriptions. It is recommended to create a directory `conf` containing each subscription configuration file.

Create a directory `conf` (wherever you want):
```bash
$ mkdir conf
```

Create a file `my-test-subscription.toml` representing the subscription:
<!--
    WARNING!
    The following content is tested in `common/src/models/config.rs`.
    If you update it, make sure to also do the update in the test.
-->

```toml
# conf/my-test-subscription.toml

# Unique identifier of the subscription
uuid = "28fcc206-1336-4e4a-b76b-18b0ab46e585"
# Unique name of the subscription
name = "my-test-subscription"

# Subscription query
query = """
<QueryList>
    <Query Id="0">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
"""

# Subscription outputs
[[outputs]]
driver = "Files"
format = "Raw"
config = { path = "/data/logs/{ip}/{client}/messages" }

# Subscription outputs
[[outputs]]
driver = "Kafka"
format = "RawJson"
# FIXME: `config.options` should be configured in OpenWEC settings (`outputs.kafka.options`)
# to use only one kafka producer client for all kafka outputs
config = { topic = "my-kafka-topic", options = { "bootstrap.servers" = "localhost:9092" } }
```

> [!TIP]
> See [subscription.sample.toml](../subscription.sample.toml) for further information on available parameters. You can also use `openwec subscriptions skell` to generate a subscription file.

## Loading subscriptions

Subscription files need to be loaded using the command `openwec subscriptions load <path>` (`path` can be a directory or a file).

```bash
$ openwec subscriptions load conf
```

> [!NOTE]
> You don't need `openwecd` to be running, restarted or reloaded to apply subscriptions.

You can print the loaded subscription using `openwec subscriptions show <name>`:
```bash
$ openwec subscriptions show my-test-subscription
```

## Running OpenWEC server

You should run `openwecd` (OpenWEC server) with an unprivileged user, for example `openwec`.

You may want to create a *systemd* service:

```ini
# openwec.service
[Unit]
Description=Windows Events Collector
After=network.target

[Service]
Type=simple
User=openwec
Restart=always
RestartSec=5s
ExecStart=/usr/bin/openwecd

[Install]
WantedBy=multi-user.target
```

```
# systemctl start openwec
```

OpenWEC is ready :clap:

## Configuring Windows machines

This configuration works for Kerberos authentication. For a configuration using TLS, see [tls.md](tls.md/) first, then follow the following steps by applying local policies instead of GPOs (use `gpedit.msc`).

You can configure Windows machines using a GPO.

This GPO will configure three things:
- start the WinRM service
- enable Windows Event Forwarding and configure it to look for subscriptions on your OpenWEC server
- authorise WinRM, i.e. the Network Service account, to read the wanted event channels

1. Start the WinRM service

Go to Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management), and select "Automatic" startup mode.

2. Configure Event Forwarding

- Go to Computer Configuration > Policies > Administrative Templates > Windows Components > Event Forwarding
- Double click on "Configure target Subscription Manager"
- Select "Enabled"
- Click on "Show"
- Add `Server=http://wec.windomain.local:5985/test,Refresh=30` which tells your Windows machines to
    - fetch subscriptions from `wec.windomain.local:5985`
    - use URI `/test`
    - look for subscriptions update every `30` seconds

> [!NOTE]
> 30 seconds is very low as a refresh interval but it can be useful if you want to test different subscription parameters. As soon as you reach a stable configuration,  it is recommended to set this parameter to 3600 seconds (1 hour).

3. Set event channels permissions

By default, WinRM is running as the Network Service account and therefore does not have the rights to read all event channels (such as the Security event channel).

In its configuration examples, Microsoft provides a GPO that adds Network Service account to the built-in Event Log Readers group: ["Minimum GPO for WEF Client configuration"](https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection#appendix-d---minimum-gpo-for-wef-client-configuration).

This enables WinRM to read all event channels but for this configuration to really apply every Windows machines has to reboot (in order for the Network Service account access token to contains the Event Log Readers group).

In order to have everything working as soon as the GPO applies we can also modify event channel security descriptors.

For example, to give the right to read the "Security" channel to Network Service account:

- Go to Computer Configuration > Policies > Administratives Templates > Windows Components > Event Log Service > Security
- Double click on "Configure log access"
- Select "Enabled"
- Add this security descriptor in SDDL format in the "Log Access" field: `O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)`
- Do the same for "Configure log access (legacy)"

> [!TIP]
> There is a lot of recommendations, explanations and tips on configuring WinRM and Windows Event Forwarding in the ANSSI guide ["Recommandations de sécurité pour la journalisation des systèmes Microsoft Windows en environnement Active Directory"](https://www.ssi.gouv.fr/uploads/2022/01/anssi-guide-recommandations_securite_journalisation_systemes_microsoft_windows_environnement_active_directory.pdf) (in french). We strongly recommend that you read it before deploying this GPO in a production environment.

Link your GPO and wait until it is applied on all Windows machines.

And that's it, you're done! :thumbsup:

To be sure that everything works well, you can:
- look at `openwecd` logs to see if Windows machines are connecting to your OpenWEC server
- check your subscription outputs to see if some events are being received

## Going further

Now that you have a basic working collector, you have multiple ways to improve your setup:
* Add additional sources in your event query and customize your subscriptions parameters
* Add multiple OpenWEC nodes for redundancy and horizontal scaling. You must use PostgreSQL backend to do that (we advise using CockroachDB). You also need to setup a load balancer such as haproxy in front of OpenWEC nodes.
* Use a gMSA (group Managed Service Account) instead of a standard Active Directory account (you may use [gmsad](https://github.com/cea-sec/gmsad) and [msktutil](https://github.com/msktutil/msktutil)).
* Create multiple subscriptions with different URIs, for example one by tier. Thus, you can monitor efficiently that you always receive logs from Tier 0 servers. You need to link one GPO per tier with the subscription URI.
