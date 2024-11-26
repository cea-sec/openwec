use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use anyhow::Result;
use common::settings::Monitoring;
use log::info;
use metrics::{describe_counter, describe_histogram, Unit};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

// input metrics

pub const INPUT_MESSAGES_COUNTER: &str = "openwec_input_messages_total";
pub const MESSAGES_ACTION: &str = "action";
pub const MESSAGES_ACTION_HEARTBEAT: &str = "heartbeat";
pub const MESSAGES_ACTION_EVENTS: &str = "events";
pub const MESSAGES_ACTION_ENUMERATE: &str = "enumerate";

pub const INPUT_EVENTS_COUNTER: &str = "openwec_input_events_total";
pub const SUBSCRIPTION_UUID: &str = "subscription_uuid";
pub const SUBSCRIPTION_NAME: &str = "subscription_name";
pub const MACHINE: &str = "machine";

pub const INPUT_EVENT_BYTES_COUNTER: &str = "openwec_input_event_bytes_total";
pub const INPUT_EVENT_PARSING_FAILURES: &str = "openwec_input_event_parsing_failures_total";
pub const INPUT_EVENT_PARSING_FAILURE_ERROR_TYPE: &str = "type";

// http metrics

pub const HTTP_REQUESTS_COUNTER: &str = "openwec_http_requests_total";

pub const HTTP_REQUEST_DURATION_SECONDS_HISTOGRAM: &str = "openwec_http_request_duration_seconds";
pub const HTTP_REQUEST_URI: &str = "uri";
pub const HTTP_REQUEST_STATUS_CODE: &str = "code";

pub const HTTP_REQUEST_BODY_NETWORK_SIZE_BYTES_COUNTER: &str =
    "openwec_http_request_body_network_size_bytes_total";
pub const HTTP_REQUEST_BODY_REAL_SIZE_BYTES_COUNTER: &str =
    "openwec_http_request_body_real_size_bytes_total";

// output metrics

pub const OUTPUT_DRIVER_FAILURES: &str = "openwec_output_driver_failures_total";
pub const OUTPUT_DRIVER: &str = "driver";
pub const OUTPUT_FORMAT_FAILURES: &str = "openwec_output_format_failures_total";
pub const OUTPUT_FORMAT: &str = "format";

pub fn init(settings: &Monitoring) -> Result<()> {
    let addr = SocketAddr::from((
        IpAddr::from_str(settings.listen_address())
            .expect("Failed to parse monitoring.listen_address"),
        settings.listen_port(),
    ));

    let builder = PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets_for_metric(
            Matcher::Full(HTTP_REQUEST_DURATION_SECONDS_HISTOGRAM.to_string()),
            settings.http_request_duration_buckets(),
        )?;

    info!("Starting monitoring server on {}", addr);

    builder.install()?;

    // input
    describe_counter!(
        INPUT_EVENTS_COUNTER,
        Unit::Count,
        "The total number of events received by openwec"
    );
    describe_counter!(
        INPUT_EVENT_BYTES_COUNTER,
        Unit::Bytes,
        "The total size of all events received by openwec"
    );
    describe_counter!(
        INPUT_MESSAGES_COUNTER,
        Unit::Count,
        "The total number of messages received by openwec"
    );
    describe_counter!(
        INPUT_EVENT_PARSING_FAILURES,
        Unit::Count,
        "The total number of event parsing failures"
    );

    // http
    describe_counter!(
        HTTP_REQUESTS_COUNTER,
        Unit::Count,
        "The total number of HTTP requests handled by openwec"
    );
    describe_histogram!(
        HTTP_REQUEST_DURATION_SECONDS_HISTOGRAM,
        Unit::Seconds,
        "Histogram of response duration for HTTP requests"
    );
    describe_counter!(
        HTTP_REQUEST_BODY_NETWORK_SIZE_BYTES_COUNTER,
        Unit::Bytes,
        "The total size of all http requests body received by openwec"
    );
    describe_counter!(
        HTTP_REQUEST_BODY_REAL_SIZE_BYTES_COUNTER,
        Unit::Bytes,
        "The total size of all http requests body received by openwec after decryption and decompression"
    );

    // output
    describe_counter!(
        OUTPUT_DRIVER_FAILURES,
        Unit::Count,
        "The total number of output driver failures"
    );
    describe_counter!(
        OUTPUT_FORMAT_FAILURES,
        Unit::Count,
        "The total number of output format failures"
    );

    Ok(())
}
