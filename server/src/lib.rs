mod event;
mod formatter;
mod heartbeat;
mod kerberos;
mod logic;
mod multipart;
mod output;
mod outputs;
mod sldc;
mod soap;
mod subscription;

use anyhow::{anyhow, bail, Context, Result};
use common::database::{db_from_settings, schema_is_up_to_date, Db};
use common::settings::{Collector, Server as ServerSettings, Settings};
use futures_util::future::join_all;
use heartbeat::{heartbeat_task, WriteHeartbeatMessage};
use http::response::Builder;
use http::status::StatusCode;
use hyper::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use lazy_static::lazy_static;
use libgssapi::error::MajorFlags;
use log::{debug, error, info, trace, warn};
use quick_xml::writer::Writer;
use regex::Regex;
use soap::Serializable;
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use subscription::{reload_subscriptions_task, Subscriptions};
use tokio::signal::unix::SignalKind;
use tokio::sync::{mpsc, oneshot};

#[derive(Copy, Clone)]
pub enum AuthenticationMechanism {
    Kerberos,
    Tls,
}

pub enum RequestCategory {
    Enumerate(String),
    Subscription(String),
}

impl TryFrom<&Request<Body>> for RequestCategory {
    type Error = anyhow::Error;
    fn try_from(req: &Request<Body>) -> Result<Self, Self::Error> {
        if req.method() != "POST" {
            bail!("Invalid HTTP method {}", req.method());
        }

        lazy_static! {
            static ref SUBSCRIPTION_RE: Regex = Regex::new(r"^/wsman/subscriptions/([0-9A-Fa-f]{8}\b-[0-9A-Fa-f]{4}\b-[0-9A-Fa-f]{4}\b-[0-9A-Fa-f]{4}\b-[0-9A-F]{12})$").expect("Failed to compile SUBSCRIPTION regular expression");
        }
        if let Some(c) = SUBSCRIPTION_RE.captures(req.uri().path()) {
            return Ok(RequestCategory::Subscription(
                c.get(1)
                    .ok_or_else(|| anyhow!("Could not get identifier from URI"))?
                    .as_str()
                    .to_owned(),
            ));
        }

        return Ok(Self::Enumerate(req.uri().to_string()));
    }
}

pub struct RequestData {
    principal: String,
    remote_addr: SocketAddr,
    category: RequestCategory,
}

impl RequestData {
    fn new(principal: &str, remote_addr: &SocketAddr, req: &Request<Body>) -> Result<Self> {
        Ok(RequestData {
            principal: principal.to_owned(),
            remote_addr: remote_addr.to_owned(),
            category: RequestCategory::try_from(req)?,
        })
    }

    /// Get a reference to the request data's principal.
    pub fn principal(&self) -> &str {
        self.principal.as_ref()
    }

    /// Get a reference to the request data's remote addr.
    pub fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }

    /// Get a reference to the request data's category.
    pub fn category(&self) -> &RequestCategory {
        &self.category
    }
}

pub struct AuthenticationResult {
    principal: String,
    token: Option<String>,
}

async fn get_request_payload(
    auth_mech: AuthenticationMechanism,
    collector: &Collector,
    conn_state: &Arc<Mutex<kerberos::State>>,
    req: Request<Body>,
) -> Result<Option<String>> {
    match auth_mech {
        AuthenticationMechanism::Tls => bail!("TLS is not supported yet"),
        AuthenticationMechanism::Kerberos => {
            kerberos::get_request_payload(collector, conn_state, req).await
        }
    }
}

fn create_response(
    auth_mech: AuthenticationMechanism,
    conn_state: &Arc<Mutex<kerberos::State>>,
    mut response: Builder,
    payload: Option<String>,
) -> Result<Response<Body>> {
    match auth_mech {
        AuthenticationMechanism::Tls => bail!("TLS is not supported yet"),
        AuthenticationMechanism::Kerberos => {
            let boundary = "Encrypted Boundary";
            if payload.is_some() {
                response = response.header(CONTENT_TYPE, "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"".to_owned() + boundary + "\"");
            }
            let body = match payload {
                None => Body::empty(),
                Some(payload) => Body::from(
                    kerberos::get_response_payload(conn_state, payload, boundary)
                        .context("Failed to compute Kerberos encrypted payload")?,
                ),
            };
            Ok(response.body(body)?)
        }
    }
}

async fn authenticate(
    auth_mech: AuthenticationMechanism,
    conn_state: &Arc<Mutex<kerberos::State>>,
    req: &Request<Body>,
    addr: &SocketAddr,
) -> Result<(String, Builder)> {
    match auth_mech {
        AuthenticationMechanism::Tls => {
            error!("TLS is not supported yet");
            bail!("TLS is not supported yet")
        }
        AuthenticationMechanism::Kerberos => {
            let mut response = Response::builder();
            let auth_result = kerberos::authenticate(conn_state, req)
                .await
                .map_err(|err| {
                    match err.root_cause().downcast_ref::<libgssapi::error::Error>() {
                        Some(e) if e.major.bits() == MajorFlags::GSS_S_CONTEXT_EXPIRED.bits() => (),
                        _ => warn!(
                            "Authentication failed for {}:{} ({}:{}): {:?}",
                            addr.ip(),
                            addr.port(),
                            req.method(),
                            req.uri(),
                            err
                        ),
                    };
                    err
                })?;
            if let Some(token) = auth_result.token {
                response = response.header(WWW_AUTHENTICATE, format!("Kerberos {}", token))
            }
            Ok((auth_result.principal, response))
        }
    }
}

async fn handle_payload(
    server: &ServerSettings,
    collector: &Collector,
    db: Db,
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    request_data: RequestData,
    request_payload: Option<String>,
) -> Result<(StatusCode, Option<String>)> {
    match request_payload {
        None => Ok((StatusCode::OK, None)),
        Some(payload) => {
            let message = soap::parse(&payload).context("Failed to parse SOAP message")?;
            trace!("Parsed request: {:?}", message);
            let response = logic::handle_message(
                server,
                collector,
                db,
                subscriptions,
                heartbeat_tx,
                request_data,
                &message,
            )
            .await
            .context("Failed to handle SOAP message")?;

            match response {
                logic::Response::Err(status_code) => Ok((status_code, None)),
                logic::Response::Ok(action, body) => {
                    let payload = soap::Message::response_from(&message, &action, body)
                        .context("Failed to build a response payload")?;
                    let mut writer = Writer::new(Cursor::new(Vec::new()));
                    payload
                        .serialize(&mut writer)
                        .context("Failed to serialize response payload")?;
                    let result = String::from_utf8(writer.into_inner().into_inner())?;
                    trace!("Response is: {}", result);
                    Ok((StatusCode::OK, Some(result)))
                }
            }
        }
    }
}

fn log_response(addr: &SocketAddr, method: &str, uri: &str, start: &Instant, status: StatusCode) {
    let duration: f32 = start.elapsed().as_micros() as f32;
    info!(
        "Responded status {} to {}:{} (request was {}:{}) in {:.3}ms",
        status,
        addr.ip(),
        addr.port(),
        method,
        uri,
        duration / 1000.0
    );
}

async fn handle(
    server: ServerSettings,
    collector: Collector,
    db: Db,
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    auth_mech: AuthenticationMechanism,
    conn_state: Arc<Mutex<kerberos::State>>,
    addr: SocketAddr,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    let start = Instant::now();

    debug!(
        "Received HTTP request from {}:{}: {} {}",
        addr.ip(),
        addr.port(),
        req.method(),
        req.uri()
    );

    let method = req.method().to_string();
    let uri = req.uri().to_string();

    // Check authentication
    let (principal, mut response_builder) =
        match authenticate(auth_mech, &conn_state, &req, &addr).await {
            Ok((principal, builder)) => (principal, builder),
            Err(e) => {
                debug!(
                    "Authentication failed for {}:{} ({}:{}): {:?}",
                    addr.ip(),
                    addr.port(),
                    &method,
                    &uri,
                    e
                );
                let status = StatusCode::UNAUTHORIZED;
                log_response(&addr, &method, &uri, &start, status);
                return Ok(Response::builder()
                    .status(status)
                    .body(Body::empty())
                    .expect("Failed to build HTTP response"));
            }
        };

    debug!("Successfully authenticated {}", principal);

    let request_data = match RequestData::new(&principal, &addr, &req) {
        Ok(request_data) => request_data,
        Err(e) => {
            error!("Failed to compute request data: {:?}", e);
            let status = StatusCode::NOT_FOUND;
            log_response(&addr, &method, &uri, &start, status);
            return Ok(Response::builder()
                .status(status)
                .body(Body::empty())
                .expect("Failed to build HTTP response"));
        }
    };

    // Get request payload
    let request_payload = match get_request_payload(auth_mech, &collector, &conn_state, req).await {
        Ok(payload) => payload,
        Err(e) => {
            error!("Failed to retrieve request payload: {:?}", e);
            let status = StatusCode::BAD_REQUEST;
            log_response(&addr, &method, &uri, &start, status);
            return Ok(Response::builder()
                .status(status)
                .body(Body::empty())
                .expect("Failed to build HTTP response"));
        }
    };

    trace!(
        "Received payload: {:?}",
        request_payload.as_ref().unwrap_or(&String::from(""))
    );

    // Handle request payload, and retrieves response payload
    let (status, response_payload) = match handle_payload(
        &server,
        &collector,
        db,
        subscriptions,
        heartbeat_tx,
        request_data,
        request_payload,
    )
    .await
    {
        Ok((status, response_payload)) => (status, response_payload),
        Err(e) => {
            error!("Failed to compute a response payload to request: {:?}", e);
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            log_response(&addr, &method, &uri, &start, status);
            return Ok(Response::builder()
                .status(status)
                .body(Body::empty())
                .expect("Failed to build HTTP response"));
        }
    };

    trace!(
        "Send response {} with payload: {:?}",
        status,
        response_payload
    );

    response_builder = response_builder.status(status);
    // Create HTTP response
    let response = match create_response(auth_mech, &conn_state, response_builder, response_payload)
    {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to build HTTP response: {:?}", e);
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            log_response(&addr, &method, &uri, &start, status);
            return Ok(Response::builder()
                .status(status)
                .body(Body::empty())
                .expect("Failed to build HTTP response"));
        }
    };

    log_response(&addr, &method, &uri, &start, response.status());
    // debug!("Send response: {:?}", response);
    Ok(response)
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => { info!("Received CTRL+C") },
        _ = sigterm.recv() => { info!("Received SIGTERM signal") },
    };
}

pub async fn run(settings: Settings) {
    let mut servers = Vec::new();

    let db: Db = db_from_settings(&settings)
        .await
        .expect("Failed to initialize database");

    // Check that database schema is up to date
    match schema_is_up_to_date(db.clone()).await {
        Ok(true) => (),
        Ok(false) => panic!("Schema needs to be updated. Please check migration guide and then run `openwec db upgrade`"),
        Err(err) => panic!("An error occurred while checking schema version: {:?}.\nHelp: You may need to run `openwec db init` to setup your database.", err),
    };

    let subscriptions = Arc::new(RwLock::new(HashMap::new()));

    let interval = settings.server().db_sync_interval();
    let update_task_db = db.clone();
    let update_task_subscriptions = subscriptions.clone();
    let (update_task_subscription_exit_tx, update_task_subscription_exit_rx) = oneshot::channel();
    // Launch a task responsible for updating subscriptions
    tokio::spawn(async move {
        reload_subscriptions_task(
            update_task_db,
            update_task_subscriptions,
            interval,
            update_task_subscription_exit_rx,
        )
        .await
    });

    let interval = settings.server().flush_heartbeats_interval();
    let update_task_db = db.clone();
    // Channel to communicate with heartbeat task
    // TODO: why 32?
    let (heartbeat_tx, heartbeat_rx) = mpsc::channel(32);
    let (heartbeat_exit_tx, heartbeat_exit_rx) = oneshot::channel();

    // Launch a task responsible for managing heartbeats
    tokio::spawn(async move {
        heartbeat_task(update_task_db, interval, heartbeat_rx, heartbeat_exit_rx).await
    });

    for collector in settings.collectors() {
        let collector_db = db.clone();
        let collector_subscriptions = subscriptions.clone();
        let collector_settings = collector.clone();
        let collector_heartbeat_tx = heartbeat_tx.clone();
        let collector_server_settings = settings.server().clone();

        // Construct our SocketAddr to listen on...
        let addr = SocketAddr::from((
            IpAddr::from_str(collector.listen_address())
                .expect("Failed to parse server.listen_address"),
            collector.listen_port(),
        ));

        trace!("Listen address is {}", addr);

        // FIXME
        let kerberos = match collector.authentication() {
            common::settings::Authentication::Kerberos(kerberos) => kerberos,
            _ => panic!("Unsupported authentication type"),
        };

        env::set_var("KRB5_KTNAME", kerberos.keytab());

        let principal = kerberos.service_principal_name().to_owned();
        // Try to initialize a security context. This is to be sure that an error in
        // Kerberos configuration will be reported as soon as possible.
        let state = kerberos::State::new(&principal);
        if state.context_is_none() {
            panic!("Could not initialize Kerberos context");
        }

        // A `MakeService` that produces a `Service` to handle each connection.
        let make_service = make_service_fn(move |conn: &AddrStream| {
            // We have to clone the context to share it with each invocation of
            // `make_service`.

            // Initialise Kerberos context once for each TCP connection
            let conn_state = Arc::new(Mutex::new(kerberos::State::new(&principal)));
            let collector_settings = collector_settings.clone();
            let svc_db = collector_db.clone();
            let svc_server_settings = collector_server_settings.clone();
            let auth_mec = AuthenticationMechanism::Kerberos;
            let subscriptions = collector_subscriptions.clone();
            let collector_heartbeat_tx = collector_heartbeat_tx.clone();

            let addr = conn.remote_addr();

            debug!("Received TCP connection from {}", addr);

            // Create a `Service` for responding to the request.
            let service = service_fn(move |req| {
                handle(
                    svc_server_settings.clone(),
                    collector_settings.clone(),
                    svc_db.clone(),
                    subscriptions.clone(),
                    collector_heartbeat_tx.clone(),
                    auth_mec,
                    conn_state.clone(),
                    addr,
                    req,
                )
            });

            // Return the service to hyper.
            async move { Ok::<_, Infallible>(service) }
        });

        // Then bind and serve...
        let server = Server::bind(&addr)
            .serve(make_service)
            .with_graceful_shutdown(shutdown_signal());

        info!("Server listenning on {}", addr);
        servers.push(server);
    }

    let result = join_all(servers).await;

    for server in result {
        if let Err(e) = server {
            error!("Server error: {}", e);
        }
    }

    info!("HTTP server has been shutdown.");

    let (task_ended_tx, task_ended_rx) = oneshot::channel();
    if let Err(e) = heartbeat_exit_tx.send(task_ended_tx) {
        error!("Failed to shutdown heartbeat task: {:?}", e);
    };
    if let Err(e) = task_ended_rx.await {
        error!("Failed to wait for heartbeat task shutdown: {:?}", e);
    }

    info!("Heartbeat task has been terminated.");

    let (task_ended_tx, task_ended_rx) = oneshot::channel();
    if let Err(e) = update_task_subscription_exit_tx.send(task_ended_tx) {
        error!("Failed to shutdown update subscription task: {:?}", e);
    }
    if let Err(e) = task_ended_rx.await {
        error!("Failed to wait for heartbeat task shutdown: {:?}", e);
    }

    info!("Subscription update task has been terminated.");
}
