use crate::{
    event::{EventData, EventMetadata}, get_subscription_uuid_with_regex, heartbeat::{store_heartbeat, WriteHeartbeatMessage}, output::get_formatter, soap::{
        Body, Header, Message, OptionSetValue, Subscription as SoapSubscription, SubscriptionBody,
        ACTION_ACK, ACTION_END, ACTION_ENUMERATE, ACTION_ENUMERATE_RESPONSE, ACTION_EVENTS,
        ACTION_HEARTBEAT, ACTION_SUBSCRIBE, ACTION_SUBSCRIPTION_END, ANONYMOUS, RESOURCE_EVENT_LOG,
    }, subscription::{Subscription, Subscriptions}, AuthenticationContext, RequestCategory, RequestData, URL_SUBSCRIPTION_RE
};
use common::{
    database::Db,
    settings::{Collector, Server}, subscription::{SubscriptionOutputFormat, SubscriptionUuid},
};
use http::status::StatusCode;
use log::{debug, error, warn};
use std::{collections::HashMap, sync::Arc};
use tokio::{sync::mpsc, task::JoinSet};

use anyhow::{anyhow, bail, Context, Result};

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

/// Retrieve subscription uuid from request URI and message Header,
/// check that both are equal and return the uuid
fn get_subscription_uuid(request_data: &RequestData, header: &Header) -> Result<SubscriptionUuid> {
    let uri_subscription_uuid = if let RequestCategory::Subscription(uuid) = request_data.category() {
        uuid
    } else {
        bail!("Request URI does not contain subscription uuid");
    };

    let header_subscription_uuid =  if let Some(to) = header.to() {
        get_subscription_uuid_with_regex(to, &URL_SUBSCRIPTION_RE)?
    } else {
        bail!("Could not find message header `To`");
    };

    if header_subscription_uuid != *uri_subscription_uuid {
        bail!(
            "Subscription UUID in URI and in message header do not match: {} != {}",
            uri_subscription_uuid, header_subscription_uuid 
        );
    }

    Ok(header_subscription_uuid)
}

async fn handle_enumerate(
    collector: &Collector,
    db: &Db,
    subscriptions: Subscriptions,
    request_data: &RequestData,
    auth_ctx: &AuthenticationContext,
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
        if !subscription_data.is_active_for(request_data.principal()) {
            debug!(
                "Skip subscription \"{}\" ({}) which principals filter {:?} rejects {}",
                subscription_data.name(),
                subscription_data.uuid(),
                subscription_data.princs_filter(),
                request_data.principal()
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

        let public_version = subscription.public_version_string();

        let body = SubscriptionBody {
            heartbeat_interval: subscription_data.heartbeat_interval() as u64,
            identifier: subscription.public_version_string(),
            bookmark,
            query: subscription_data.query().to_owned(),
            address: match auth_ctx {
                AuthenticationContext::Kerberos(_) => format!(
                    "http://{}:{}/wsman/subscriptions/{}",
                    collector.hostname(),
                    collector.listen_port(),
                    subscription_data.uuid_string(), 
                ),
                AuthenticationContext::Tls(_,_) => format!(
                    "https://{}:{}/wsman/subscriptions/{}",
                    collector.hostname(),
                    collector.listen_port(),
                    subscription_data.uuid_string(), 
                )
            },
            connection_retry_count: subscription_data.connection_retry_count(),
            connection_retry_interval: subscription_data.connection_retry_interval(),
            max_time: subscription_data.max_time(),
            max_envelope_size: subscription_data.max_envelope_size(),
            thumbprint: match auth_ctx {
                AuthenticationContext::Tls(_, thumbprint) => Some(thumbprint.clone()),
                AuthenticationContext::Kerberos(_) => None
            }
        };

        res_subscriptions.push(SoapSubscription {
            identifier: public_version,
            header,
            body,
        });
    }

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
    let subscription_uuid = match get_subscription_uuid(request_data, message.header()) {
        Ok(uuid) => uuid,
        Err(e) => {
            error!("{}", e);
            return Ok(Response::err(StatusCode::BAD_REQUEST));
        }
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

    if !subscription.data().is_active_for(request_data.principal()) {
        debug!(
            "Received Heartbeat from {}:{} ({}) for subscription {} ({}) but the principal is not allowed to use the subscription.",
            request_data.remote_addr().ip(),
            request_data.remote_addr().port(),
            request_data.principal(),
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
    Ok(Response::ok(ACTION_ACK, None))
}

async fn handle_events(
    server: &Server,
    db: &Db,
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    request_data: &RequestData,
    message: &Message,
) -> Result<Response> {
    if let Some(Body::Events(events)) = &message.body {
        let subscription_uuid = match get_subscription_uuid(request_data, message.header()) {
            Ok(uuid) => uuid,
            Err(e) => {
                error!("{}", e);
                return Ok(Response::err(StatusCode::BAD_REQUEST));
            }
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

        if !subscription.data().is_active_for(request_data.principal()) {
            debug!(
                "Received Events from {}:{} ({}) for subscription {} ({}) but the principal is not allowed to use this subscription.",
                request_data.remote_addr().ip(),
                request_data.remote_addr().port(),
                request_data.principal(), 
                subscription.data().name(),
                subscription.uuid_string(),
            );
            return Ok(Response::err(StatusCode::FORBIDDEN));
        }

        debug!(
            "Received Events from {}:{} ({}) for subscription {} ({})",
            request_data.remote_addr().ip(),
            request_data.remote_addr().port(),
            request_data.principal(),
            subscription.data().name(),
            subscription.uuid_string()
        );

        let metadata = Arc::new(EventMetadata::new(
            request_data.remote_addr(),
            request_data.principal(),
            server.node_name().cloned(),
            &subscription,
        ));

        let need_to_parse_event = subscription.formats().iter().any(|format| format.needs_parsed_event());

        let mut events_data = Vec::with_capacity(events.len());
        for raw in events.iter() {
            // If need_to_parse_event is set to true, EventData parses the raw event
            // into an Event struct (once for all formatters).
            events_data.push(EventData::new(raw.clone(), need_to_parse_event))
        }

        // Build event strings for all formats
        let mut formatted_events: HashMap<SubscriptionOutputFormat, Arc<Vec<Arc<String>>>> = HashMap::new();
        for format in subscription.formats() {
            let mut content = Vec::new();
            let formatter = get_formatter(format);
            for event_data in events_data.iter() {
                if let Some(str) = formatter.format(&metadata, event_data) {
                    content.push(str.clone())
                }
            }
            formatted_events.insert(format.clone(), Arc::new(content));
        }

        let mut handles = JoinSet::new();

        // Spawn tasks to write events to every outputs of the subscription
        for output in subscription.outputs() {
            let output_cloned = output.clone();
            let metadata_cloned = metadata.clone();
            let content = formatted_events
                .get(output_cloned.format())
                .ok_or_else(|| anyhow!("Could not get formatted event for format {:?}", output_cloned.format()))?
                .clone();

            handles.spawn(async move {
                output_cloned.write(metadata_cloned, content).await.with_context(|| {
                    format!("Failed to write event to output {}", output_cloned.describe())
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
                    warn!("Failed to process output and send event: {:?}", err);
                }
                Err(err) => {
                    succeed = false;
                    warn!("Something bad happened with a process task: {:?}", err)
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
        db.store_bookmark(request_data.principal(), &subscription.uuid_string(), bookmark)
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
        handle_enumerate(collector, &db, subscriptions, request_data, auth_ctx)
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
