use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use anyhow::Result;
use common::settings::Monitoring;
use log::info;
use metrics::{describe_counter, describe_histogram, Unit};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

pub const MESSAGES_COUNTER: &str = "openwec_messages_total";
pub const MESSAGES_ACTION: &str = "action";
pub const MESSAGES_ACTION_HEARTBEAT: &str = "heartbeat";
pub const MESSAGES_ACTION_EVENTS: &str = "events";
pub const MESSAGES_ACTION_ENUMERATE: &str = "enumerate";

pub const EVENTS_COUNTER: &str = "openwec_received_events_total";
pub const EVENTS_SUBSCRIPTION_UUID: &str = "subscription_uuid";
pub const EVENTS_SUBSCRIPTION_NAME: &str = "subscription_name";
pub const EVENTS_MACHINE: &str = "machine";

pub const FAILED_EVENTS_COUNTER: &str = "openwec_event_output_failures_total";

pub const HTTP_REQUESTS_DURATION_SECONDS_HISTOGRAM: &str = "http_request_duration_seconds";
pub const HTTP_REQUESTS_METHOD: &str = "method";
pub const HTTP_REQUESTS_URI: &str = "uri";
pub const HTTP_REQUESTS_STATUS: &str = "status";

pub fn init(settings: &Monitoring) -> Result<()> {
    let addr = SocketAddr::from((
        IpAddr::from_str(settings.listen_address())
            .expect("Failed to parse monitoring.listen_address"),
        settings.listen_port(),
    ));

    let builder = PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets_for_metric(
            Matcher::Full(HTTP_REQUESTS_DURATION_SECONDS_HISTOGRAM.to_string()),
            settings.http_requests_histogram_buckets(),
        )?;

    info!("Starting monitoring server on {}", addr);

    builder.install()?;

    describe_counter!(
        MESSAGES_COUNTER,
        Unit::Count,
        "Number of messages received by openwec"
    );
    describe_counter!(
        EVENTS_COUNTER,
        Unit::Count,
        "Number of events received by openwec"
    );
    describe_counter!(
        FAILED_EVENTS_COUNTER,
        Unit::Count,
        "Number of events that could not be written to outputs by openwec"
    );
    describe_histogram!(
        HTTP_REQUESTS_DURATION_SECONDS_HISTOGRAM,
        Unit::Seconds,
        "HTTP requests duration histogram"
    );

    Ok(())
}
