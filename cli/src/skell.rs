use chrono::{DateTime, Local};
use common::subscription::{
    DEFAULT_CONNECTION_RETRY_COUNT, DEFAULT_CONNECTION_RETRY_INTERVAL, DEFAULT_CONTENT_FORMAT,
    DEFAULT_ENABLED, DEFAULT_FILE_APPEND_NODE_NAME, DEFAULT_FILE_NAME, DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_IGNORE_CHANNEL_ERROR, DEFAULT_MAX_ENVELOPE_SIZE, DEFAULT_MAX_TIME,
    DEFAULT_READ_EXISTING_EVENTS,
};
use uuid::Uuid;

fn format_bool(value: bool) -> String {
    if value {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

fn get_header(uuid: Uuid, name: &str, now: DateTime<Local>) -> String {
    format!(
        r#"# autogenerated by openwec {}
# {}

# Unique identifier of the subscription
uuid = "{}"
# Unique name of the subscription
name = "{}"

# Subscription query
query = """
<QueryList>
    <!-- Put your queries here -->
</QueryList>
"""
"#,
        env!("CARGO_PKG_VERSION"),
        now.to_rfc2822(),
        uuid,
        name
    )
}

fn get_options() -> String {
    format!(
        r#"
# Subscription options (optional)
# [options]
#
# Enable/disable the subscription
# enabled = {}

# If the uri parameter is undefined (default), the subscription will
# always be sent to clients. Otherwise, only clients sending enumerate
# requests to the URI will be able to get it.
# uri = 

# The maximum allowable time, in seconds, before the client will send
# an heartbeat message if it has no new events to send.
# heartbeat_interval = {}

# Number of times the client will attempt to connect if the subscriber
# is unreachable.
# connection_retry_count = {}

# Interval observed between each connection attempt if the subscriber
# is unreachable.
# connection_retry_interval = {}

# The maximum time, in seconds, that the client should aggregate new
# events before sending them.
# max_time = {}

# The maximum number of bytes in the SOAP envelope used to deliver
# the events.
# max_envelope_size = {}

# If `true`, the event source should replay all possible events that
# match the filter and any events that subsequently occur for that
# event source.
# read_existing_events = {}

# This option determines whether rendering information are to be passed
# with events or not. `Raw` means that only event data will be passed
# without any rendering information, whereas `RenderedText` adds
# rendering information.
# content_format = "{}"

# This option determines if various filtering options resulting in errors
# are to result in termination of the processing by clients.
# ignore_channel_error = {}

# This option determines the language in which openwec wants the
# rendering info data to be translated.
# Defaults to unset, meaning OpenWEC lets the clent choose.
# locale =

# This option determines the language in which openwec wants the
# numerical data to be formatted.
# Defaults to unset, meaning OpenWEC lets the clent choose.
# data_locale =
"#,
        format_bool(DEFAULT_ENABLED),
        DEFAULT_HEARTBEAT_INTERVAL,
        DEFAULT_CONNECTION_RETRY_COUNT,
        DEFAULT_CONNECTION_RETRY_INTERVAL,
        DEFAULT_MAX_TIME,
        DEFAULT_MAX_ENVELOPE_SIZE,
        format_bool(DEFAULT_READ_EXISTING_EVENTS),
        DEFAULT_CONTENT_FORMAT,
        format_bool(DEFAULT_IGNORE_CHANNEL_ERROR),
    )
}

fn get_filter() -> String {
    r#"
# Subscription filter (optional)
# 
# Filters enables you to choose which clients can read the subscription
# There are two operations available :
# - "Only": only the listed principals will be able to read the subscription
# - "Except": everyone but the listed principals will be able to read the subscription
#
# By default, everyone can read the subscription.
# 
# [filter]
# operation = "Only"
# princs = ["courgette@REALM", "radis@REALM"]

"#
    .to_string()
}

fn get_outputs() -> String {
    format!(
        r#"
#
# Outputs
#

# Configure a Files output
# [[outputs]]
# driver = "Files"
# format = "Raw"

# Files driver has the following parameters:
# - base (required): the base path in which files will be written
# - split_on_addr_index (optional, defaults to undefined): split the IP address
#       of the client on the given index to build a directory tree.
# - append_node_name (optional, defaults to {}): Add the openwec node's
#       name to the path.
# - filename (optional, defaults to "{}"): the name of the file containing events
#       for one client.
# config = {{ base = "/var/log/openwec/", split_on_addr_index = 2, append_node_name = {}, filename = "{}" }}


# Configure a Kafka output
# [[outputs]]
# driver = "Kafka"
# format = "Raw"

# Kafka driver has the following parameters:
# - topic (required): the Kafka topic to send events to
# - options (optional, defaults to undefined): additional kafka settings, directly
#      sent to librdkafka (https://docs.confluent.io/platform/current/clients/librdkafka/html/md_CONFIGURATION.html)
# config = {{ topic = "openwec", options = {{ "bootstrap.servers" = "localhost:9092" }} }}


# Configure a Tcp output
# [[outputs]]
# driver = "Tcp"
# format = "Raw"

# Tcp driver has the following paramters:
# - addr (required): Hostname or IP Address to send events to
# - port (required): Tcp port to send events to
# config = {{ addr = "localhost", port = 5000 }}


# Configure a Redis output
# [[outputs]]
# driver = "Redis"
# format = "Raw"

# Redis driver has the following parameters:
# - addr (required): Hostname or IP Address of the Redis server
# - list (required): Name of the Redis list to push events to
# config = {{ addr = "localhost", list = "openwec" }}


# Configure a UnixDatagram output
# [[outputs]]
# driver = "UnixDatagram"
# format = "Raw"

# UnixDatagram driver has the following parameters:
# - path (required): Path of the Unix socket to send events to
# config = {{ path = "/tmp/openwec.socket" }}
"#,
        format_bool(DEFAULT_FILE_APPEND_NODE_NAME),
        DEFAULT_FILE_NAME,
        format_bool(DEFAULT_FILE_APPEND_NODE_NAME),
        DEFAULT_FILE_NAME
    )
}

pub fn get_minimal_skell_content(uuid: Uuid, name: &str, now: DateTime<Local>) -> String {
    let mut content = get_header(uuid, name, now);
    content.push_str(
        r#"
# Configures a simple output which stores events in files (one per client) in Raw format
# (without parsing of XML Events)
[[outputs]]
driver = "Files"
format = "Raw"
config = { base = "/var/log/openwec/" }
"#,
    );
    content
}

pub fn get_full_skell_content(uuid: Uuid, name: &str, now: DateTime<Local>) -> String {
    let mut content = get_header(uuid, name, now);
    content.push_str(&get_options());
    content.push_str(&get_filter());
    content.push_str(&get_outputs());
    content
}
