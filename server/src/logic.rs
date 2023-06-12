use crate::{
    event::EventMetadata,
    formatter::Format,
    heartbeat::{store_heartbeat, WriteHeartbeatMessage},
    soap::{
        Body, Header, Message, OptionSetValue, Subscription as SoapSubscription, SubscriptionBody,
        ACTION_ACK, ACTION_END, ACTION_ENUMERATE, ACTION_ENUMERATE_RESPONSE, ACTION_EVENTS,
        ACTION_HEARTBEAT, ACTION_SUBSCRIBE, ACTION_SUBSCRIPTION_END, ANONYMOUS, RESOURCE_EVENT_LOG,
    },
    subscription::{Subscription, Subscriptions},
    RequestCategory, RequestData,
};
use common::{
    database::Db,
    settings::{Collector, Server},
};
use http::status::StatusCode;
use log::{debug, error, info, warn};
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

fn check_sub_request_data(request_data: &RequestData, version: &str) -> bool {
    let uri_version = if let RequestCategory::Subscription(version) = request_data.category() {
        version
    } else {
        error!("Request URI is incoherent with body message");
        return false;
    };

    if version != uri_version {
        error!(
            "URI identifier and message identifier do not match: {} != {}",
            uri_version, version
        );
        return false;
    }
    true
}

async fn handle_enumerate(
    collector: &Collector,
    db: &Db,
    subscriptions: Subscriptions,
    request_data: &RequestData,
) -> Result<Response> {
    // Check that URI corresponds to an enumerate Request
    let uri = match request_data.category() {
        RequestCategory::Enumerate(uri) => uri,
        _ => {
            error!("Invalid URI for Enumerate request");
            return Ok(Response::err(StatusCode::BAD_REQUEST));
        }
    };

    info!(
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
            OptionSetValue::Boolean(true),
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
            .get_bookmark(request_data.principal(), subscription_data.uuid())
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

        let body = SubscriptionBody {
            heartbeat_interval: subscription_data.heartbeat_interval() as u64,
            identifier: subscription_data.version().to_owned(),
            bookmark,
            query: subscription_data.query().to_owned(),
            address: format!(
                "http://{}:{}/wsman/subscriptions/{}",
                collector.hostname(),
                collector.listen_port(),
                subscription_data.version()
            ),
            connection_retry_count: subscription_data.connection_retry_count(),
            connection_retry_interval: subscription_data.connection_retry_interval(),
            max_time: subscription_data.max_time(),
            max_envelope_size: subscription_data.max_envelope_size(),
        };

        res_subscriptions.push(SoapSubscription {
            identifier: subscription_data.version().to_owned(),
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
    let version = message
        .header()
        .identifier()
        .ok_or_else(|| anyhow!("Missing field identifier"))?;

    if !check_sub_request_data(request_data, version) {
        return Ok(Response::err(StatusCode::BAD_REQUEST));
    }

    let subscription = {
        let subscriptions = subscriptions.read().unwrap();
        match subscriptions.get(version) {
            Some(subscription) => subscription.to_owned(),
            None => {
                warn!(
                    "Received Heartbeat of {}:{} ({}) for unknown subscription {}",
                    request_data.remote_addr().ip(),
                    request_data.remote_addr().port(),
                    request_data.principal(),
                    version
                );
                return Ok(Response::err(StatusCode::BAD_REQUEST));
            }
        }
    };

    info!(
        "Received Heartbeat of {}:{} ({:?}) for subscription {} ({})",
        request_data.remote_addr().ip(),
        request_data.remote_addr().port(),
        request_data.principal(),
        subscription.data().name(),
        subscription.uuid(),
    );

    store_heartbeat(
        heartbeat_tx,
        request_data.principal(),
        request_data.remote_addr().ip().to_string(),
        subscription.uuid(),
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
        let version = message
            .header()
            .identifier()
            .ok_or_else(|| anyhow!("Missing field identifier"))?;

        if !check_sub_request_data(request_data, version) {
            return Ok(Response::err(StatusCode::BAD_REQUEST));
        }

        let subscription: Arc<Subscription> = {
            let subscriptions = subscriptions.read().unwrap();
            let subscription = subscriptions.get(version);
            match subscription {
                Some(subscription) => subscription.to_owned(),
                None => {
                    warn!("Unknown subscription version {}", version);
                    return Ok(Response::err(StatusCode::NOT_FOUND));
                }
            }
        };
        info!(
            "Received Events from {}:{} ({}) for subscription {} ({})",
            request_data.remote_addr().ip(),
            request_data.remote_addr().port(),
            request_data.principal(),
            subscription.data().name(),
            subscription.uuid()
        );

        let metadata = Arc::new(EventMetadata::new(
            request_data.remote_addr(),
            request_data.principal(),
            server.node_name().cloned(),
            &subscription,
        ));

        // Build event strings for all formats
        let mut formatted_events: HashMap<Format, Arc<Vec<Arc<String>>>> = HashMap::new();
        for format in subscription.formats() {
            let mut content = Vec::new();
            for raw in events.iter() {
                content.push(
                    format
                        .format(&metadata, raw.clone())
                        .with_context(|| format!("Failed to format event with {:?}", format))?,
                );
            }
            formatted_events.insert(format.clone(), Arc::new(content));
        }

        let mut handles = JoinSet::new();

        // Spawn tasks to write events to every outputs of the subscription
        for output in subscription.outputs() {
            let output = output.clone();
            let metadata = metadata.clone();
            let format = output.format();
            let content = formatted_events
                .get(format)
                .ok_or_else(|| anyhow!("Could not get formatted event for format {:?}", format))?
                .clone();

            handles.spawn(async move {
                output.write(metadata, content).await.with_context(|| {
                    format!("Failed to write event to output {}", output.describe())
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
        db.store_bookmark(request_data.principal(), subscription.uuid(), bookmark)
            .await
            .context("Failed to store bookmarks")?;

        debug!(
            "Store bookmark from {}:{} ({}) for subscription {} ({}): {}",
            request_data.remote_addr().ip(),
            request_data.remote_addr().port(),
            request_data.principal(),
            subscription.data().name(),
            subscription.uuid(),
            bookmark
        );
        store_heartbeat(
            heartbeat_tx,
            request_data.principal(),
            request_data.remote_addr().ip().to_string(),
            subscription.uuid(),
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
    request_data: RequestData,
    message: &Message,
) -> Result<Response> {
    let action = message.action()?;
    debug!("Received {} request", action);

    if action == ACTION_ENUMERATE {
        handle_enumerate(collector, &db, subscriptions, &request_data)
            .await
            .context("Failed to handle Enumerate action")
    } else if action == ACTION_END || action == ACTION_SUBSCRIPTION_END {
        Ok(Response::err(StatusCode::OK))
    } else if action == ACTION_HEARTBEAT {
        handle_heartbeat(subscriptions, heartbeat_tx, &request_data, message)
            .await
            .context("Failed to handle Heartbeat action")
    } else if action == ACTION_EVENTS {
        handle_events(
            server,
            &db,
            subscriptions,
            heartbeat_tx,
            &request_data,
            message,
        )
        .await
        .context("Failed to handle Events action")
    } else {
        Err(anyhow!("Unsupported message {}", action))
    }
}
