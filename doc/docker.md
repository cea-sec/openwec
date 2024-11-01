# Docker image

The `openwec` docker image enables you to test and deploy openwec easily. It contains two precompiled binaries: `openwec` (cli) and `openwecd` (server).

## Getting `openwec` image

### From ghcr.io

The `openwec` docker image is automatically built using Github Actions:
- On each commit to the `main` branch, the image is built and pushed with the `main` tag.
- When a version tag is pushed, the image is built and pushed with a tag corresponding to that version. The latest version tag can be retrieved using the `latest` tag.

Example:
```bash
$ docker pull ghcr.io/cea-sec/openwec:latest
```

### Building the image by yourself 

A `Dockerfile` is present at the root of the repository. You can build it using:

```bash
$ docker build -t openwec .
```

## Using `openwec` image

The `openwec` image does not come with any predefined configuration.

### Configuration file

`openwec` reads its configuration from `/etc/openwec.conf.toml`. See [Getting Started](getting_started.md) for a basic configuration example.

- If you use `SQLite` backend, you should configure its `path` to `/var/lib/openwec/db/openwec.sqlite` (so that the `openwec` user used inside the container can write to it) and mount a Docker volume at this directory.
- If you use Kerberos authentication, make sure to mount the keytab file in the container (read-only).
- If you use TLS authentication, make sure to mount TLS certificates and keys in the container (read-only).

### Subscriptions

The `openwec` image entry point looks for subscription configuration files (see [Subscription](subscription.md)) in `/etc/openwec.d/` and loads them on startup. You should mount your configuration files in this directory (read-only).

If one of your outputs uses the `Files` driver, you should configure its path in `/var/lib/openwec/data/` (so that the `openwec` user used inside the container can write files).

## Example with SQLite, Kerberos authentication and Files driver

1. In a new directory, create a file named `openwec.conf.toml` with the following content:
```toml
# openwec.conf.toml
[[collectors]]
hostname = "openwec.realm.local" # FIXME
listen_address = "0.0.0.0"
listen_port = 5985

[collectors.authentication]
type = "Kerberos"
service_principal_name = "http/openwec.realm.local@REALM.LOCAL" # FIXME

[database]
type = "SQLite"
path = "/var/lib/openwec/db/db.sqlite"

[server]
keytab = "/etc/openwec.keytab"

[logging]
verbosity = "info"
access_logs = "stdout"
```

2. Get a keytab containing the keys for `http/openwec.realm.local@REALM.LOCAL` and name it `openwec.keytab`.

3. Create a directory `conf`, and put inside your subscription configuration files (see [Subscription](subscription.md)). For example, we configure two subscriptions:
- `simple`:
```toml
# conf/01-simple.toml

# Unique identifier of the subscription
uuid = "e493fa95-4810-4c61-8ac7-7fa8d028a144"
# Unique name of the subscription
name = "simple"

# Subscription query
query = """
<QueryList>
    <Query Id="0" Path="Application">
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
config = { path = "/var/lib/openwec/data/simple/{ip}/{principal}/messages" }
```
- `test`:
```toml
# conf/02-test.toml

# Unique identifier of the subscription
uuid = "b50df578-b814-4fad-9d6a-1215fddc0f96"
# Unique name of the subscription
name = "test"

# Subscription query
query = """
<QueryList>
    <Query Id="0" Path="Application">
        <Select Path="Microsoft-Windows-WinRM/Operational">*</Select>
    </Query>
</QueryList>
"""

[options]
content_format = "RenderedText"

[[outputs]]
driver = "Files"
format = "RawJson"
config = { path = "/var/lib/openwec/data/test/{ip}/{principal}/messages" }
```

You should end up with the following tree structure:
```
.
├── conf
│   ├── 01-simple.toml
│   └── 02-test.toml
├── openwec.conf.toml
└── openwec.keytab
```

5. Start the `openwec` container with named volumes for files (`openwec-data`) and the SQLite database (`openwec-db`):
```bash
$ docker run --rm -it \
    -v ./openwec.conf.toml:/etc/openwec.conf.toml:ro \
    -v openwec-db:/var/lib/openwec/db \
    -v openwec-data:/var/lib/openwec/data \
    -v ./openwec.keytab:/etc/openwec.keytab:ro \
    -v ./conf/:/etc/openwec.d/:ro \
    -p 5985:5985 \
    ghcr.io/cea-sec/openwec:latest
```
