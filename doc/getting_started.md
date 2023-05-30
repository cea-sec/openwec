# Getting started

## Building OpenWEC

OpenWEC is not yet packaged for any distribution we know about. Therefore, you need to build it from source or get a precompiled binary from the release page.

To build OpenWEC, you will need:
* cargo and rustc
* openssl-dev
* libgssapi

And you will need to run:

```bash
$ cargo build --release
$ strip target/release/openwec
$ strip target/release/openwecd
```

## Basic configuration example

In an Active Directory domain `DC=windomain,DC=local`, let's configure OpenWEC on a machine named `wec.windomain.local` using an SQLite database.

Requirements:
* A DNS entry for `wec.windomain.local`
* Authorise connections from your Windows machines to `wec.windomain.local` on TCP/5985
* An Active Directory account for OpenWEC with `http/wec.windomain.local@WINDOMAIN.LOCAL` Service Principal Name.
* A keytab file containing keys for `http/wec.windomain.local@WINDOMAIN.LOCAL` SPN, available in `/etc/wec.windomain.local.keytab`.

Write the following content in `/etc/openwec.conf.toml`:

```toml
# /etc/openwec.conf.toml
[server]
verbosity = "info"
db_sync_interval = 5
flush_heartbeats_interval = 5

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
keytab = "/etc/wec.windomain.local.keytab"
```

See [openwec.conf.sample.toml](../openwec.conf.sample.toml) for further information on available parameters.

We have configured OpenWEC to use the SQLite backend. The SQLite database will be stored on disk in `/var/db/openwec/db.sqlite`. You need to make sure that `/var/db/openwec` exists.

We have set up a collector server. It listens on `0.0.0.0` (default port is `5985`) and can be contacted by Windows computers using `wec.windomain.local`.

Authentication is made using Kerberos. A valid keytab containing credentials for `http/wec.windomain.local@WINDOMAIN.LOCAL` must be present in `/etc/wec.windomain.local.keytab`.

## System configuration

You should run OpenWEC with an unprivileged user, for example `openwec`.

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

## Initializing database

Database schema needs to be initialized manually using:

```bash
$ openwec db init
```

## Creating a new subscription

You need to build a query to retrieve events you are interested in. Event queries syntax is described by Microsoft [here](https://learn.microsoft.com/en-us/previous-versions/bb399427(v=vs.90)).

In this example, let's say we want to retrieve every events in *Security*, *System*, *Application* and *Setup* sources.

Create a file `query.xml` containing:

```xml
<!-- query.xml -->
<QueryList>
    <Query Id="0">
        <Select Path="Application">*</Select>
        <Select Path="Security">*</Select>
        <Select Path="Setup">*</Select>
        <Select Path="System">*</Select>
    </Query>
</QueryList>
```

You can then create the subscription:

```bash
$ openwec subscriptions new my-test-subscription query.xml
```

You may provide additional arguments to customize the subscriptions settings (see [OpenWEC subscription settings](subscription.md)), but you will be able to edit it later.

Your newly created subscription is not yet enabled. You need to configure at least one [output](outputs.md).

## Configuring outputs for the subscription

Let's say we want to:
- store events in JSON format in files in the path `/data/logs/<ip>/<princ>/messages`, where `<ip>` is the IP address of the machine who sent the log messages and `<princ>` its Kerberos principal
- and send them in a Kafka topic (`my-kafka-topic`) on `localhost:9092` for further processing.

We need to create 2 outputs:
* `Files` with base path `/data/logs` using the `json` formatter:

```bash
$ openwec subscriptions edit my-test-subscription outputs add --format json files /data/logs
```

* `Kafka` also using the `Json` formatter:

```bash
$ openwec subscriptions edit my-test-subscription outputs add --format json kafka my-kafka-topic -o bootstrap.servers localhost:9092
```

## Enabling the subscription

You may want to check your subscription configuration using:

```bash
$ openwec subscriptions show my-test-subscription
```

If everything is OK, then you can enable the subscription:

```bash
$ openwec subscriptions enable my-test-subscription
```

## Configuring Windows machines

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
    - fetch subscriptions from wec.windomain.local:5985
    - use URI "/test"
    - look for subscriptions update every 30 seconds

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

There is a lot of recommendations, explanations and tips on configuring WinRM and Windows Event Forwarding in the ANSSI guide ["Recommandations de sécurité pour la journalisation des systèmes Microsoft Windows en environnement Active Directory"](https://www.ssi.gouv.fr/uploads/2022/01/anssi-guide-recommandations_securite_journalisation_systemes_microsoft_windows_environnement_active_directory.pdf) (in french). We strongly recommend that you read it before deploying this GPO in a production environment.

Link your GPO and wait until it is applied on all Windows machines.

And that's it, you're done! :thumbsup:

To be sure that everything works well, you can:
- look at `openwecd` logs to see if Windows machines are connecting to your OpenWEC server
- check your subscription outputs to see if some events are being received

## Going further

Now that you have a basic working collector, you have multiple ways to improve your setup:
* Add additional sources in your Event query
* Customize your subscriptions parameters
* Add multiple OpenWEC nodes for redundancy and scaling. You must use PostgreSQL backend to do that (we advise using CockroachDB). You need to setup a load balancer such as Nginx in front of OpenWEC nodes.
* Use a gMSA (group Managed Service Account) instead of a standard Active Directory account (you may use [gmsad](https://github.com/cea-sec/gmsad) and [msktutil](https://github.com/msktutil/msktutil)).
* Create multiple subscriptions with different URIs, for example one by tier. Thus, you can monitor efficiently that you always receive logs from Tier 0 servers. You need to link one GPO per tier with the subscription URI.

