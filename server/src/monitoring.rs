use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use common::{database::Db, settings::Monitoring, subscription::SubscriptionMachineState};
use log::{debug, info};
use metrics::{describe_counter, describe_gauge, describe_histogram, gauge, Unit};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use tokio::time;

use crate::subscription::Subscriptions;

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

// machines metrics

pub const MACHINES_GAUGE: &str = "openwec_machines";
pub const MACHINES_STATE: &str = "state";

pub fn init(db: &Db, subscriptions: Subscriptions, settings: &Monitoring) -> Result<()> {
    let refresh_interval = settings.machines_refresh_interval();
    let refresh_task_db = db.clone();
    let refresh_task_subscriptions = subscriptions.clone();

    // Launch a task responsible for refreshing machines gauge
    tokio::spawn(async move {
        refresh_machines_task(
            refresh_task_db,
            refresh_task_subscriptions,
            refresh_interval,
        )
        .await
    });

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

    // machines
    describe_gauge!(
        MACHINES_GAUGE,
        Unit::Count,
        "The number of machines known by openwec"
    );

    Ok(())
}

async fn refresh_machines_task(
    db: Db,
    subscriptions: Subscriptions,
    refresh_interval: u64,
) -> Result<()> {
    info!("Starting refresh machines task for monitoring");
    let mut refresh = time::interval(Duration::from_secs(refresh_interval));
    // We don't want the first tick to complete immediatly
    refresh.reset_after(Duration::from_secs(refresh_interval));
    loop {
        tokio::select! {
            _ = refresh.tick() => {
                debug!("Refreshing machines stats for monitoring");

                // We can't await with the lock on "subscriptions"
                // So we first copy all data we need from "subscriptions"
                let subscriptions_data = {
                    let subscriptions_unlocked = subscriptions.read().unwrap();
                    let mut subscriptions_data = Vec::with_capacity(subscriptions_unlocked.len());
                    for (_, subscription) in subscriptions.read().unwrap().iter() {
                        subscriptions_data.push((subscription.uuid_string(), subscription.data().name().to_string(), subscription.data().heartbeat_interval()));
                    }
                    subscriptions_data
                };

                for (subscription_uuid, subscription_name, heartbeat_interval) in subscriptions_data {
                    let now: i64 = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)?
                        .as_secs()
                        .try_into()?;

                    let stats = db
                        .get_stats(&subscription_uuid, now - (heartbeat_interval as i64))
                        .await?;

                    debug!("Update {} values with active={}, alive={}, dead={}", MACHINES_GAUGE, stats.active_machines_count(), stats.alive_machines_count(), stats.dead_machines_count());

                    let alive_str: &'static str = SubscriptionMachineState::Alive.into();
                    gauge!(MACHINES_GAUGE,
                        SUBSCRIPTION_NAME => subscription_name.clone(),
                        SUBSCRIPTION_UUID => subscription_uuid.clone(),
                        MACHINES_STATE => alive_str)
                        .set(stats.alive_machines_count() as f64);

                    let active_str: &'static str = SubscriptionMachineState::Active.into();
                    gauge!(MACHINES_GAUGE,
                        SUBSCRIPTION_NAME => subscription_name.clone(),
                        SUBSCRIPTION_UUID => subscription_uuid.clone(),
                        MACHINES_STATE => active_str)
                        .set(stats.active_machines_count() as f64);

                    let dead_str: &'static str = SubscriptionMachineState::Dead.into();
                    gauge!(MACHINES_GAUGE,
                        SUBSCRIPTION_NAME => subscription_name.clone(),
                        SUBSCRIPTION_UUID => subscription_uuid.clone(),
                        MACHINES_STATE => dead_str)
                        .set(stats.dead_machines_count() as f64);
                }
            }
        }
    }
}
