use crate::{
    event::{EventData, EventMetadata},
    heartbeat::{store_heartbeat, WriteHeartbeatMessage},
    monitoring::{
        INPUT_EVENTS_COUNTER, INPUT_EVENT_BYTES_COUNTER, INPUT_EVENT_PARSING_FAILURES,
        INPUT_EVENT_PARSING_FAILURE_ERROR_TYPE, INPUT_MESSAGES_COUNTER, MACHINE, MESSAGES_ACTION,
        MESSAGES_ACTION_ENUMERATE, MESSAGES_ACTION_EVENTS, MESSAGES_ACTION_HEARTBEAT,
        OUTPUT_DRIVER, OUTPUT_DRIVER_FAILURES, OUTPUT_FORMAT, OUTPUT_FORMAT_FAILURES,
        SUBSCRIPTION_NAME, SUBSCRIPTION_UUID,
    },
    output::get_formatter,
    soap::{
        Body, Header, Message, OptionSetValue, Subscription as SoapSubscription, SubscriptionBody,
        ACTION_ACK, ACTION_END, ACTION_ENUMERATE, ACTION_ENUMERATE_RESPONSE, ACTION_EVENTS,
        ACTION_HEARTBEAT, ACTION_SUBSCRIBE, ACTION_SUBSCRIPTION_END, ANONYMOUS, RESOURCE_EVENT_LOG,
    },
    subscription::{Subscription, Subscriptions},
    AuthenticationContext, RequestCategory, RequestData,
};
use common::{
    database::Db,
    settings::{Collector, Monitoring, Server},
    subscription::{SubscriptionOutputFormat, SubscriptionUuid},
};
use hyper::http::status::StatusCode;
use log::{debug, error, warn};
use metrics::counter;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::{sync::mpsc, task::JoinSet};
use uuid::Uuid;

use anyhow::{anyhow, bail, Context, Result};

#[derive(Debug)]
struct OutputDriverError {
    pub driver: String,
    pub error: anyhow::Error,
}

pub enum Response {
    Ok(String, Option<Body>),
    Err(StatusCode),
}

impl Response {
    pub fn ok(action: &str, body: Option<Body>) -> Self {
        Response::Ok(action.to_owned(), body)
    }

    pub fn err(status_code: StatusCode) -> Self {
        Response::Err(status_code)
    }
}

fn create_subscription_body(
    subscription: &Arc<Subscription>,
    bookmark: Option<String>,
    collector: &Collector,
    collector_hostname: &str,
    auth_ctx: &AuthenticationContext,
) -> SubscriptionBody {
    let public_version = subscription.public_version_string();
    let identifier = subscription.uuid_string();
    let subscription_data = subscription.data();

    SubscriptionBody {
        heartbeat_interval: subscription_data.heartbeat_interval() as u64,
        identifier: identifier.clone(),
        public_version: public_version.clone(),
        revision: subscription_data.revision().cloned(),
        bookmark,
        query: subscription_data.query().to_owned(),
        address: match auth_ctx {
            AuthenticationContext::Kerberos(_) => format!(
                "http://{}:{}/wsman/subscriptions/{}",
                collector_hostname,
                collector.advertized_port(),
                identifier
            ),
            AuthenticationContext::Tls(_, _) => format!(
                "https://{}:{}/wsman/subscriptions/{}",
                collector_hostname,
                collector.advertized_port(),
                identifier
            ),
        },
        connection_retry_count: subscription_data.connection_retry_count(),
        connection_retry_interval: subscription_data.connection_retry_interval(),
        max_time: subscription_data.max_time(),
        max_elements: subscription_data.max_elements(),
        max_envelope_size: subscription_data.max_envelope_size(),
        thumbprint: match auth_ctx {
            AuthenticationContext::Tls(_, thumbprint) => Some(thumbprint.clone()),
            AuthenticationContext::Kerberos(_) => None,
        },
        locale: subscription_data.locale().cloned(),
        data_locale: subscription_data.data_locale().cloned(),
    }
}

async fn handle_enumerate(
    collector: &Collector,
    db: &Db,
    subscriptions: Subscriptions,
    request_data: &RequestData,
    auth_ctx: &AuthenticationContext,
    message: &Message,
) -> Result<Response> {
    // Check that URI corresponds to an enumerate Request
    let uri = match request_data.category() {
        RequestCategory::Enumerate(uri) => uri,
        _ => {
            error!("Invalid URI for Enumerate request");
            return Ok(Response::err(StatusCode::BAD_REQUEST));
        }
    };

    debug!(
        "Received Enumerate request from {}:{} ({}) with URI {}",
        request_data.remote_addr.ip(),
        request_data.remote_addr.port(),
        request_data.principal(),
        uri
    );

    let collector_hostname = if let Some(hostname) = collector.hostname() {
        hostname.to_owned()
    } else {
        let hostname_from_message = message.header().to().and_then(|to| {
            let url = url::Url::parse(to).ok()?;
            url.host_str().map(|s| s.to_owned())
        });

        let Some(hostname) = hostname_from_message else {
            warn!(
                "Collector hostname cannot be extracted from To header ({:?}), rejecting Enumerate request",
                message.header().to()
            );
            return Ok(Response::err(StatusCode::BAD_REQUEST));
        };

        hostname
    };

    // Clone subscriptions references into a new vec
    let current_subscriptions = {
        let subscriptions_unlocked = subscriptions.read().unwrap();
        let mut current = Vec::with_capacity(subscriptions_unlocked.len());
        for (_, subscription) in subscriptions.read().unwrap().iter() {
            current.push(subscription.clone());
        }
        current
    };

    // Build Enumerate Response
    let mut res_subscriptions = Vec::new();
    for subscription in current_subscriptions {
        let subscription_data = subscription.data();
        // Skip disabled subscriptions or subscriptions without enabled outputs
        if !subscription_data.is_active() {
            continue;
        }

        // Skip subscriptions that are not linked with the current URI (or with subscription.uri = None)
        match subscription_data.uri() {
            Some(subscription_uri) if uri != subscription_uri => {
                debug!(
                    "Skip subscription \"{}\" ({}) which uri {} does not match with {}",
                    subscription_data.name(),
                    subscription_data.uuid(),
                    subscription_uri,
                    uri
                );
                continue;
            }
            _ => (),
        }

        // Skip subscriptions that filter out this principal
        let machine_id = message.header().machine_id().map(|m| m.as_str());
        if !subscription_data.is_active_for(request_data.principal(), machine_id) {
            debug!(
                "Skip subscription \"{}\" ({}) which client filter {:?} rejects {} ({})",
                subscription_data.name(),
                subscription_data.uuid(),
                subscription_data.client_filter(),
                request_data.principal(),
                machine_id.unwrap_or("unknown MachineID"),
            );
            continue;
        }

        debug!(
            "Include subscription \"{}\" ({})",
            subscription_data.name(),
            subscription_data.uuid()
        );

        let mut options = HashMap::new();
        options.insert(
            "SubscriptionName".to_string(),
            OptionSetValue::String(subscription_data.name().to_string()),
        );
        options.insert(
            "Compression".to_string(),
            OptionSetValue::String("SLDC".to_string()),
        );
        options.insert(
            "ContentFormat".to_string(),
            OptionSetValue::String(subscription_data.content_format().to_string()),
        );
        options.insert(
            "IgnoreChannelError".to_string(),
            OptionSetValue::Boolean(subscription_data.ignore_channel_error()),
        );
        options.insert("CDATA".to_string(), OptionSetValue::Boolean(true));

        // Add ReadExistingEvents option
        if subscription_data.read_existing_events() {
            options.insert(
                "ReadExistingEvents".to_string(),
                OptionSetValue::Boolean(true),
            );
        }

        let header = Header::new(
            ANONYMOUS.to_string(),
            RESOURCE_EVENT_LOG.to_string(),
            ACTION_SUBSCRIBE.to_string(),
            subscription_data.max_envelope_size(),
            None,
            None,
            None,
            Some(1),
            options,
        );

        let mut bookmark: Option<String> = db
            .get_bookmark(request_data.principal(), &subscription_data.uuid_string())
            .await
            .context("Failed to retrieve current bookmark from database")?;

        if bookmark.is_none() && subscription_data.read_existing_events() {
            bookmark =
                Some("http://schemas.dmtf.org/wbem/wsman/1/wsman/bookmark/earliest".to_string())
        }

        debug!(
            "Load bookmark of {} for subscription {}: {:?}",
            request_data.principal(),
            subscription_data.uuid(),
            bookmark
        );

        let body = create_subscription_body(&subscription, bookmark, collector, &collector_hostname, auth_ctx,);

        res_subscriptions.push(SoapSubscription {
            version: subscription.public_version_string(),
            header,
            body,
        });
    }

    counter!(INPUT_MESSAGES_COUNTER, MESSAGES_ACTION => MESSAGES_ACTION_ENUMERATE).increment(1);

    Ok(Response::ok(
        ACTION_ENUMERATE_RESPONSE,
        Some(Body::EnumerateResponse(res_subscriptions)),
    ))
}

async fn handle_heartbeat(
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    request_data: &RequestData,
    message: &Message,
) -> Result<Response> {
    let subscription_uuid = if let Some(identifier) = message.header().identifier() {
        SubscriptionUuid(Uuid::parse_str(identifier)?)
    } else {
        error!("Could not find identifier in message header");
        return Ok(Response::err(StatusCode::BAD_REQUEST));
    };

    let subscription = {
        let subscriptions = subscriptions.read().unwrap();
        match subscriptions.get(&subscription_uuid) {
            Some(subscription) => subscription.to_owned(),
            None => {
                warn!(
                    "Received Heartbeat from {}:{} ({}) for unknown subscription {}",
                    request_data.remote_addr().ip(),
                    request_data.remote_addr().port(),
                    request_data.principal(),
                    subscription_uuid
                );
                return Ok(Response::err(StatusCode::NOT_FOUND));
            }
        }
    };

    let machine_id = message.header().machine_id().map(|m| m.as_str());
    if !subscription.data().is_active_for(request_data.principal(), machine_id) {
        debug!(
            "Received Heartbeat from {}:{} ({}, {}) for subscription {} ({}) but the client is not allowed to use the subscription.",
            request_data.remote_addr().ip(),
            request_data.remote_addr().port(),
            request_data.principal(),
            machine_id.unwrap_or("unknown MachineID"),
            subscription.data().name(),
            subscription.uuid_string()
        );
        return Ok(Response::err(StatusCode::FORBIDDEN));
    }

    debug!(
        "Received Heartbeat from {}:{} ({:?}) for subscription {} ({})",
        request_data.remote_addr().ip(),
        request_data.remote_addr().port(),
        request_data.principal(),
        subscription.data().name(),
        subscription.uuid_string(),
    );

    store_heartbeat(
        heartbeat_tx,
        request_data.principal(),
        request_data.remote_addr().ip().to_string(),
        &subscription.uuid_string(),
        false,
    )
    .await
    .context("Failed to store heartbeat")?;

    counter!(INPUT_MESSAGES_COUNTER, MESSAGES_ACTION => MESSAGES_ACTION_HEARTBEAT).increment(1);

    Ok(Response::ok(ACTION_ACK, None))
}

fn get_formatted_events(
    events: &[Arc<String>],
    need_to_parse_event: bool,
    formats: &HashSet<SubscriptionOutputFormat>,
    metadata: &Arc<EventMetadata>,
) -> HashMap<SubscriptionOutputFormat, Arc<Vec<Arc<String>>>> {
    let mut events_data = Vec::with_capacity(events.len());
    for raw in events.iter() {
        // EventData parses the raw event into an Event struct
        // (once for all formatters).
        let event_data = EventData::new(raw.clone(), need_to_parse_event);

        if need_to_parse_event {
            // Count failures
            match event_data.event() {
                Some(event) => {
                    if let Some(error) = &event.additional.error {
                        let error_type_str: &'static str = error.error_type.clone().into();
                        counter!(INPUT_EVENT_PARSING_FAILURES,
                            SUBSCRIPTION_NAME => metadata.subscription_name().to_owned(),
                            SUBSCRIPTION_UUID => metadata.subscription_uuid().to_owned(),
                            INPUT_EVENT_PARSING_FAILURE_ERROR_TYPE => error_type_str)
                        .increment(1);
                        warn!("Failed to parse an event: {:?}", error)
                    }
                }
                None => {
                    counter!(INPUT_EVENT_PARSING_FAILURES,
                        SUBSCRIPTION_NAME => metadata.subscription_name().to_owned(),
                        SUBSCRIPTION_UUID => metadata.subscription_uuid().to_owned(),
                        INPUT_EVENT_PARSING_FAILURE_ERROR_TYPE => "Unknown")
                    .increment(1);
                    warn!(
                        "Event should have been parsed but it was not: {}",
                        event_data.raw()
                    )
                }
            }
        }
        events_data.push(event_data)
    }

    let mut formatted_events: HashMap<SubscriptionOutputFormat, Arc<Vec<Arc<String>>>> =
        HashMap::new();
    for format in formats {
        let mut content = Vec::new();
        let formatter = get_formatter(format);
        for event_data in events_data.iter() {
            if let Some(str) = formatter.format(metadata, event_data) {
                content.push(str.clone())
            } else {
                let format_str: &'static str = format.into();
                counter!(OUTPUT_FORMAT_FAILURES,
                    SUBSCRIPTION_NAME => metadata.subscription_name().to_owned(),
                    SUBSCRIPTION_UUID => metadata.subscription_uuid().to_owned(),
                    OUTPUT_FORMAT => format_str)
                .increment(1);
                warn!("Failed to format an event using {}", format_str);
            }
        }
        formatted_events.insert(format.clone(), Arc::new(content));
    }
    formatted_events
}

async fn handle_events(
    server: &Server,
    monitoring: &Option<Monitoring>,
    db: &Db,
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    request_data: &RequestData,
    message: &Message,
) -> Result<Response> {
    if let Some(Body::Events(events)) = &message.body {
        let subscription_uuid = if let Some(identifier) = message.header().identifier() {
            SubscriptionUuid(Uuid::parse_str(identifier)?)
        } else {
            error!("Could not find identifier in message header");
            return Ok(Response::err(StatusCode::BAD_REQUEST));
        };

        let subscription: Arc<Subscription> = {
            let subscriptions = subscriptions.read().unwrap();
            let subscription = subscriptions.get(&subscription_uuid);
            match subscription {
                Some(subscription) => subscription.to_owned(),
                None => {
                    warn!("Unknown subscription uuid {}", subscription_uuid);
                    return Ok(Response::err(StatusCode::NOT_FOUND));
                }
            }
        };

        let machine_id = message.header().machine_id().map(|m| m.as_str());
        if !subscription.data().is_active_for(request_data.principal(), machine_id) {
            debug!(
                "Received Events from {}:{} ({}, {}) for subscription {} ({}) but the client is not allowed to use this subscription.",
                request_data.remote_addr().ip(),
                request_data.remote_addr().port(),
                request_data.principal(),
                machine_id.unwrap_or("unknown MachineID"),
                subscription.data().name(),
                subscription.uuid_string(),
            );
            return Ok(Response::err(StatusCode::FORBIDDEN));
        }

        // Retrieve the public version sent by the client, not the one stored in memory
        let public_version = if let Some(public_version) = message.header().version() {
            public_version
        } else {
            warn!("Missing subscription version in message events");
            return Ok(Response::err(StatusCode::BAD_REQUEST));
        };

        debug!(
            "Received {} events from {}:{} ({}) for subscription {} ({})",
            events.len(),
            request_data.remote_addr().ip(),
            request_data.remote_addr().port(),
            request_data.principal(),
            subscription.data().name(),
            subscription.uuid_string()
        );

        counter!(INPUT_MESSAGES_COUNTER, MESSAGES_ACTION => MESSAGES_ACTION_EVENTS).increment(1);

        let events_counter = match monitoring {
            Some(monitoring_conf) if monitoring_conf.count_input_events_per_machine() => {
                counter!(INPUT_EVENTS_COUNTER,
                    SUBSCRIPTION_NAME => subscription.data().name().to_owned(),
                    SUBSCRIPTION_UUID => subscription.uuid_string(),
                    MACHINE => request_data.principal().to_string())
            }
            _ => {
                counter!(INPUT_EVENTS_COUNTER,
                    SUBSCRIPTION_NAME => subscription.data().name().to_owned(),
                    SUBSCRIPTION_UUID => subscription.uuid_string())
            }
        };
        events_counter.increment(events.len().try_into()?);

        let event_size_counter = match monitoring {
            Some(monitoring_conf) if monitoring_conf.count_input_event_bytes_per_machine() => {
                counter!(INPUT_EVENT_BYTES_COUNTER,
                    SUBSCRIPTION_NAME => subscription.data().name().to_owned(),
                    SUBSCRIPTION_UUID => subscription.uuid_string(),
                    MACHINE => request_data.principal().to_string())
            }
            _ => {
                counter!(INPUT_EVENT_BYTES_COUNTER,
                    SUBSCRIPTION_NAME => subscription.data().name().to_owned(),
                    SUBSCRIPTION_UUID => subscription.uuid_string())
            }
        };
        event_size_counter.increment(
            events
                .iter()
                .fold(0, |acc, event| acc + event.len())
                .try_into()?,
        );

        let metadata = Arc::new(EventMetadata::new(
            request_data.remote_addr(),
            request_data.principal(),
            server.node_name().cloned(),
            &subscription,
            public_version.clone(),
            message.header().revision().cloned(),
        ));

        let need_to_parse_event = subscription
            .formats()
            .iter()
            .any(|format| format.needs_parsed_event());

        let formatted_events = if need_to_parse_event {
            // Parsing events takes time. In addition, if a formatter needs parsed events,
            // it probably performs some serialization which takes time and should be done in a
            // blocking task.
            let task_events = events.clone();
            let task_formats = subscription.formats().clone();
            let task_metadata = metadata.clone();
            tokio::task::spawn_blocking(move || {
                get_formatted_events(
                    &task_events,
                    need_to_parse_event,
                    &task_formats,
                    &task_metadata,
                )
            })
            .await?
        } else {
            get_formatted_events(
                events,
                need_to_parse_event,
                subscription.formats(),
                &metadata,
            )
        };

        let mut handles = JoinSet::new();

        // Spawn tasks to write events to every outputs of the subscription
        for output in subscription.outputs() {
            let output_cloned = output.clone();
            let metadata_cloned = metadata.clone();
            let content = formatted_events
                .get(output_cloned.format())
                .ok_or_else(|| {
                    anyhow!(
                        "Could not get formatted event for format {:?}",
                        output_cloned.format()
                    )
                })?
                .clone();

            handles.spawn(async move {
                output_cloned
                    .write(metadata_cloned, content)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to write event to output {}",
                            output_cloned.describe()
                        )
                    })
                    .map_err(|e| OutputDriverError {
                        driver: output_cloned.driver(),
                        error: e,
                    })
            });
        }

        // Wait for all tasks to finish
        let mut succeed = true;
        while let Some(res) = handles.join_next().await {
            match res {
                Ok(Ok(())) => (),
                Ok(Err(err)) => {
                    succeed = false;
                    warn!("Failed to process output and send event: {:?}", err.error);
                    counter!(OUTPUT_DRIVER_FAILURES,
                        SUBSCRIPTION_NAME => subscription.data().name().to_owned(),
                        SUBSCRIPTION_UUID => subscription.uuid_string(),
                        OUTPUT_DRIVER => err.driver.clone())
                    .increment(1);
                }
                Err(err) => {
                    succeed = false;
                    warn!("Something bad happened with a process task: {:?}", err);
                    counter!(OUTPUT_DRIVER_FAILURES,
                        SUBSCRIPTION_NAME => subscription.data().name().to_owned(),
                        SUBSCRIPTION_UUID => subscription.uuid_string(),
                        OUTPUT_DRIVER => "Unknown")
                    .increment(1);
                }
            }
        }

        if !succeed {
            return Ok(Response::err(StatusCode::SERVICE_UNAVAILABLE));
        }

        let bookmark = message
            .header()
            .bookmarks()
            .ok_or_else(|| anyhow!("Missing bookmarks in request payload"))?;
        // Store bookmarks and heartbeats
        db.store_bookmark(
            request_data.principal(),
            &subscription.uuid_string(),
            bookmark,
        )
        .await
        .context("Failed to store bookmarks")?;

        debug!(
            "Store bookmark from {}:{} ({}) for subscription {} ({}): {}",
            request_data.remote_addr().ip(),
            request_data.remote_addr().port(),
            request_data.principal(),
            subscription.data().name(),
            subscription.uuid_string(),
            bookmark
        );
        store_heartbeat(
            heartbeat_tx,
            request_data.principal(),
            request_data.remote_addr().ip().to_string(),
            &subscription.uuid_string(),
            true,
        )
        .await
        .context("Failed to store heartbeat")?;
        Ok(Response::ok(ACTION_ACK, None))
    } else {
        bail!("Invalid events message");
    }
}

pub async fn handle_message(
    server: &Server,
    collector: &Collector,
    monitoring: &Option<Monitoring>,
    db: Db,
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    request_data: &RequestData,
    message: &Message,
    auth_ctx: &AuthenticationContext,
) -> Result<Response> {
    let action = message.action()?;
    debug!("Received {} request", action);

    if action == ACTION_ENUMERATE {
        handle_enumerate(collector, &db, subscriptions, request_data, auth_ctx, message)
            .await
            .context("Failed to handle Enumerate action")
    } else if action == ACTION_END || action == ACTION_SUBSCRIPTION_END {
        Ok(Response::err(StatusCode::OK))
    } else if action == ACTION_HEARTBEAT {
        handle_heartbeat(subscriptions, heartbeat_tx, request_data, message)
            .await
            .context("Failed to handle Heartbeat action")
    } else if action == ACTION_EVENTS {
        handle_events(
            server,
            monitoring,
            &db,
            subscriptions,
            heartbeat_tx,
            request_data,
            message,
        )
        .await
        .context("Failed to handle Events action")
    } else {
        Err(anyhow!("Unsupported message {}", action))
    }
}
