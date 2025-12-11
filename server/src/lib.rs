#![allow(clippy::too_many_arguments)]
#![deny(unsafe_code)]

mod drivers;
mod event;
mod formats;
mod heartbeat;
mod kerberos;
mod logging;
mod logic;
mod monitoring;
mod multipart;
mod output;
mod proxy_protocol;
mod sldc;
mod soap;
mod subscription;
mod tls;

use anyhow::{anyhow, bail, Context, Result};
use common::database::{db_from_settings, schema_is_up_to_date, Db};
use common::encoding::decode_utf16le;
use common::settings::{Authentication, Kerberos, Monitoring, Tls};
use common::settings::{Collector, Server as ServerSettings, Settings};
use core::pin::Pin;
use futures::Future;
use futures_util::future::join_all;
use heartbeat::{heartbeat_task, WriteHeartbeatMessage};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::http::response::Builder;
use hyper::http::status::StatusCode;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use kerberos::AuthenticationError;
use libgssapi::error::MajorFlags;
use log::{debug, error, info, trace, warn};
use metrics::{counter, histogram};
use monitoring::{
    HTTP_REQUESTS_COUNTER, HTTP_REQUEST_BODY_NETWORK_SIZE_BYTES_COUNTER,
    HTTP_REQUEST_BODY_REAL_SIZE_BYTES_COUNTER, HTTP_REQUEST_DURATION_SECONDS_HISTOGRAM,
    HTTP_REQUEST_STATUS_CODE, HTTP_REQUEST_URI, MACHINE,
};
use quick_xml::writer::Writer;
use soap::Serializable;
use socket2::{SockRef, TcpKeepalive};
use std::boxed::Box;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::{env, future, mem};
use subscription::{reload_subscriptions_task, Subscriptions};
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::pin;
use tokio::runtime::Handle;
use tokio::signal::unix::SignalKind;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::logging::ACCESS_LOGGER;
use crate::proxy_protocol::read_proxy_header;
use crate::tls::{make_config, subject_from_cert};

pub enum RequestCategory {
    Enumerate(String),
    Subscription,
}

impl TryFrom<&Request<Incoming>> for RequestCategory {
    type Error = anyhow::Error;
    fn try_from(req: &Request<Incoming>) -> Result<Self, Self::Error> {
        if req.method() != "POST" {
            bail!("Invalid HTTP method {}", req.method());
        }

        if req.uri().path().starts_with("/wsman/subscriptions/") {
            Ok(Self::Subscription)
        } else {
            Ok(Self::Enumerate(req.uri().to_string()))
        }
    }
}

pub struct RequestData {
    principal: String,
    remote_addr: SocketAddr,
    category: RequestCategory,
    uri: String,
    method: String,
}

impl RequestData {
    fn new(principal: &str, remote_addr: &SocketAddr, req: &Request<Incoming>) -> Result<Self> {
        Ok(RequestData {
            principal: principal.to_owned(),
            remote_addr: remote_addr.to_owned(),
            category: RequestCategory::try_from(req)?,
            method: req.method().to_string(),
            uri: req.uri().to_string(),
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

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn method(&self) -> &str {
        &self.method
    }
}

#[derive(Debug, Clone)]
/// Kerberos : state
/// Tls : subject, thumbprint
pub enum AuthenticationContext {
    Kerberos(Arc<Mutex<kerberos::State>>),
    Tls(Vec<(String, String)>),
}

fn empty() -> BoxBody<Bytes, Infallible> {
    // Empty::new().map_err(|never| match never {}).boxed()
    Empty::new().boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into())
        // .map_err(|never| match never {})
        .boxed()
}

async fn get_request_payload(
    collector: &Collector,
    monitoring: &Option<Monitoring>,
    auth_ctx: &AuthenticationContext,
    request_data: &RequestData,
    req: Request<Incoming>,
) -> Result<Option<String>> {
    let (parts, body) = req.into_parts();

    let response_content_length = body
        .size_hint()
        .upper()
        .ok_or_else(|| anyhow!("Header Content-Length is not present"))
        .context("Could not check Content-Length header of request")?;

    let max_content_length = collector.max_content_length();

    if response_content_length > max_content_length {
        bail!(
            "HTTP request body is too large ({} bytes larger than the maximum allowed {} bytes).",
            response_content_length,
            max_content_length
        );
    }

    let data = body
        .collect()
        .await
        .context("Could not retrieve request body")?
        .to_bytes();

    if data.is_empty() {
        return Ok(None);
    }

    let http_request_body_network_size_bytes_counter = match monitoring {
        Some(monitoring_conf)
            if monitoring_conf.count_http_request_body_network_size_per_machine() =>
        {
            counter!(HTTP_REQUEST_BODY_NETWORK_SIZE_BYTES_COUNTER,
                HTTP_REQUEST_URI => request_data.uri().to_string(),
                MACHINE => request_data.principal().to_string())
        }
        _ => {
            counter!(HTTP_REQUEST_BODY_NETWORK_SIZE_BYTES_COUNTER,
                HTTP_REQUEST_URI => request_data.uri().to_string())
        }
    };
    http_request_body_network_size_bytes_counter.increment(data.len().try_into()?);

    let message = match auth_ctx {
        AuthenticationContext::Tls(_) => tls::get_request_payload(parts, data).await?,
        AuthenticationContext::Kerberos(conn_state) => {
            kerberos::get_request_payload(conn_state.to_owned(), parts, data).await?
        }
    };

    match message {
        Some(bytes) => {
            let http_request_body_real_size_bytes_counter = match monitoring {
                Some(monitoring_conf)
                    if monitoring_conf.count_http_request_body_real_size_per_machine() =>
                {
                    counter!(HTTP_REQUEST_BODY_REAL_SIZE_BYTES_COUNTER,
                        HTTP_REQUEST_URI => request_data.uri().to_string(),
                        MACHINE => request_data.principal().to_string())
                }
                _ => {
                    counter!(HTTP_REQUEST_BODY_REAL_SIZE_BYTES_COUNTER,
                        HTTP_REQUEST_URI => request_data.uri().to_string())
                }
            };
            http_request_body_real_size_bytes_counter.increment(bytes.len().try_into()?);

            // Spawn a blocking task to decode utf16
            tokio::task::spawn_blocking(|| Ok(Some(decode_utf16le(bytes)?))).await?
        }
        _ => Ok(None),
    }
}

async fn create_response(
    auth_ctx: &AuthenticationContext,
    mut response: Builder,
    payload: Option<String>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    match auth_ctx {
        AuthenticationContext::Tls(_) => {
            if payload.is_some() {
                response = response.header(CONTENT_TYPE, "application/soap+xml;charset=UTF-16");
            }
            let body = match payload {
                None => empty(),
                Some(payload) => full(
                    tls::get_response_payload(payload)
                        .await
                        .context("Failed to compute TLS payload")?,
                ),
            };
            Ok(response.body(body)?)
        }
        AuthenticationContext::Kerberos(conn_state) => {
            let boundary = "Encrypted Boundary".to_owned();
            if payload.is_some() {
                response = response.header(CONTENT_TYPE, "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"".to_owned() + &boundary + "\"");
            }
            let body = match payload {
                None => empty(),
                Some(payload) => full(
                    kerberos::get_response_payload(conn_state.clone(), payload, boundary)
                        .await
                        .context("Failed to compute Kerberos encrypted payload")?,
                ),
            };
            Ok(response.body(body)?)
        }
    }
}

fn log_auth_error(addr: &SocketAddr, req: &Request<Incoming>, err_str: String, do_warn: bool) {
    let str_format = format!(
        "Authentication failed for {}:{} ({}:{}): {}",
        addr.ip(),
        addr.port(),
        req.method(),
        req.uri(),
        err_str.replace('\n', " ")
    );

    if do_warn {
        warn!("{}", str_format);
    } else {
        debug!("{}", str_format);
    }
}

async fn authenticate(
    auth_ctx: &AuthenticationContext,
    req: &Request<Incoming>,
    addr: &SocketAddr,
) -> Result<(String, Builder)> {
    match auth_ctx {
        AuthenticationContext::Tls(thumbprints) => {
            //FIXME: allow multiple certs
            let subject = thumbprints
                .first()
                .map(|(subject, _)| subject.clone())
                .unwrap_or_default();
            // if subject is empty, show unauthorized error
            if subject.is_empty() {
                log_auth_error(addr, req, "Empty certificate".to_owned(), true);
                bail!("Empty certificate")
            }

            let response = Response::builder();
            Ok((subject.to_owned(), response))
        }
        AuthenticationContext::Kerberos(conn_state) => {
            let auth_result = kerberos::authenticate(conn_state, req)
                .await
                .map_err(|err| {
                    match err {
                        AuthenticationError::Gssapi(gssapi_err)
                            if gssapi_err.major.bits()
                                != MajorFlags::GSS_S_CONTEXT_EXPIRED.bits() =>
                        {
                            log_auth_error(addr, req, format!("{:?}", err), true)
                        }
                        AuthenticationError::Other(_) => {
                            log_auth_error(addr, req, format!("{:?}", err), true)
                        }
                        _ => log_auth_error(addr, req, format!("{:?}", err), false),
                    }
                    err
                })?;

            let mut response = Response::builder();

            if let Some(token) = auth_result.token() {
                response = response.header(WWW_AUTHENTICATE, format!("Kerberos {}", token))
            }
            Ok((auth_result.principal().to_owned(), response))
        }
    }
}

async fn handle_payload(
    server: &ServerSettings,
    collector: &Collector,
    monitoring: &Option<Monitoring>,
    db: Db,
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    request_data: &RequestData,
    request_payload: Option<String>,
    auth_ctx: &AuthenticationContext,
) -> Result<(StatusCode, Option<String>)> {
    match request_payload {
        None => Ok((StatusCode::OK, None)),
        Some(payload) => {
            // Parsing xml takes some time
            let message = tokio::task::spawn_blocking(move || {
                soap::parse(&payload).context("Failed to parse SOAP message")
            })
            .await??;

            trace!("Parsed request: {:?}", message);
            let response = logic::handle_message(
                server,
                collector,
                monitoring,
                db,
                subscriptions,
                heartbeat_tx,
                request_data,
                &message,
                auth_ctx,
            )
            .await
            .context("Failed to handle SOAP message")?;

            match response {
                logic::Response::Err(status_code) => Ok((status_code, None)),
                logic::Response::Ok(action, body) => {
                    let payload = soap::Message::response_from(&message, &action, body)
                        .context("Failed to build a response payload")?;
                    // If body is Some(), it means that we send EnumerationResponse
                    // In this case, message serialization takes some time and should be executed
                    // in a blocking task
                    let result: Result<String> = if payload.body.is_some() {
                        tokio::task::spawn_blocking(move || {
                            let mut writer = Writer::new(Cursor::new(Vec::new()));
                            payload
                                .serialize(&mut writer)
                                .context("Failed to serialize response payload")?;
                            let result = String::from_utf8(writer.into_inner().into_inner())?;
                            Ok(result)
                        })
                        .await?
                    } else {
                        let mut writer = Writer::new(Cursor::new(Vec::new()));
                        payload
                            .serialize(&mut writer)
                            .context("Failed to serialize response payload")?;
                        let result = String::from_utf8(writer.into_inner().into_inner())?;
                        Ok(result)
                    };
                    let response_payload = result?;
                    trace!("Response is: {}", response_payload);
                    Ok((StatusCode::OK, Some(response_payload)))
                }
            }
        }
    }
}

enum ConnectionStatus {
    // Connection aborted before the response completed.
    Aborted,
    // Connection may be kept alive after the response is sent.
    Alive,
}

impl ConnectionStatus {
    pub fn as_str(&self) -> &str {
        // This is inspired by %X of Apache httpd:
        // https://httpd.apache.org/docs/current/mod/mod_log_config.html
        match self {
            Self::Aborted => "X",
            Self::Alive => "+",
        }
    }
}

fn log_response(
    addr: &SocketAddr,
    method: &str,
    uri: &str,
    start: &Instant,
    status: StatusCode,
    principal: &str,
    conn_status: ConnectionStatus,
) {
    let duration = start.elapsed().as_secs_f64();

    histogram!(HTTP_REQUEST_DURATION_SECONDS_HISTOGRAM,
        HTTP_REQUEST_URI => uri.to_owned())
    .record(duration);

    counter!(HTTP_REQUESTS_COUNTER,
        HTTP_REQUEST_STATUS_CODE => status.as_str().to_owned(),
        HTTP_REQUEST_URI => uri.to_owned())
    .increment(1);

    // MDC is thread related, so it should be safe to use it in a non-async
    // function.
    log_mdc::insert("http_status", status.as_str());
    log_mdc::insert("http_method", method);
    log_mdc::insert("http_uri", uri);
    log_mdc::insert("response_time", format!("{:.3}", duration * 1000.0));
    log_mdc::insert("ip", addr.ip().to_string());
    log_mdc::insert("port", addr.port().to_string());
    log_mdc::insert("principal", principal);
    log_mdc::insert("conn_status", conn_status.as_str());

    // Empty message, logging pattern should use MDC
    info!(target: ACCESS_LOGGER, "");
    log_mdc::clear();
}

fn build_error_response(status: StatusCode) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(status)
        .body(empty())
        .expect("Failed to build HTTP response")
}

async fn handle(
    server: ServerSettings,
    collector: Collector,
    monitoring: Option<Monitoring>,
    db: Db,
    subscriptions: Subscriptions,
    heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    auth_ctx: AuthenticationContext,
    addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
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
    let (principal, mut response_builder) = match authenticate(&auth_ctx, &req, &addr).await {
        Ok((principal, builder)) => (principal, builder),
        Err(_) => {
            let status = StatusCode::UNAUTHORIZED;
            log_response(
                &addr,
                &method,
                &uri,
                &start,
                status,
                "-",
                ConnectionStatus::Alive,
            );
            if let AuthenticationContext::Kerberos(_ctx) = auth_ctx {
                return Ok(Response::builder()
                    .status(status)
                    .header(WWW_AUTHENTICATE, "Kerberos")
                    .body(empty())
                    .expect("Failed to build HTTP response"));
            } else {
                return Ok(build_error_response(status));
            }
        }
    };

    debug!("Successfully authenticated {}", principal);

    let request_data = match RequestData::new(&principal, &addr, &req) {
        Ok(request_data) => request_data,
        Err(e) => {
            error!("Failed to compute request data: {:?}", e);
            let status = StatusCode::NOT_FOUND;
            log_response(
                &addr,
                &method,
                &uri,
                &start,
                status,
                &principal,
                ConnectionStatus::Alive,
            );
            return Ok(build_error_response(status));
        }
    };

    // Get request payload
    let request_payload =
        match get_request_payload(&collector, &monitoring, &auth_ctx, &request_data, req).await {
            Ok(payload) => payload,
            Err(e) => {
                error!("Failed to retrieve request payload: {:?}", e);
                let status = StatusCode::BAD_REQUEST;
                log_response(
                    &addr,
                    &method,
                    &uri,
                    &start,
                    status,
                    &principal,
                    ConnectionStatus::Alive,
                );
                return Ok(build_error_response(status));
            }
        };

    trace!(
        "Received payload: {:?}",
        request_payload.as_ref().unwrap_or(&String::from(""))
    );

    // Handle request payload, and retrieves response payload
    //
    // It seems that Hyper can abort the Service future at any time (for example if the client
    // closes the connection), meaning that any ".await" can be a dead end.
    // We want to ensure that the payload handling cannot be aborted unexpectedly resulting
    // in an inconsistent state.
    // To achieve that, the handle_payload function is executed in an independent Tokio task.
    //
    // In practice, Windows clients appear to close connections to their configured WEC server
    // when they (re-)apply group policies.

    // handle_payload task result will be returned using a oneshot channel
    let (tx, rx) = oneshot::channel();

    // The following variables need to be cloned because they are moved in the spawned closure
    let auth_ctx_cloned = auth_ctx.clone();
    let method_cloned = method.clone();
    let uri_cloned = uri.clone();
    let principal_cloned = principal.clone();

    tokio::spawn(async move {
        let res = handle_payload(
            &server,
            &collector,
            &monitoring,
            db,
            subscriptions,
            heartbeat_tx,
            &request_data,
            request_payload,
            &auth_ctx_cloned,
        )
        .await;
        if let Err(e) = &res {
            error!(
                "Failed to compute a response payload to request (from {}:{}): {:?}",
                request_data.remote_addr().ip(),
                request_data.remote_addr().port(),
                e
            );
        }
        if let Err(value) = tx.send(res) {
            debug!(
                "Could not send handle_payload result to handling Service for {}:{} (receiver dropped). Result was: {:?}",
                request_data.remote_addr().ip(),
                request_data.remote_addr().port(),
                value
            );
            // Log this response with conn_status = Aborted
            let status = match value {
                Ok((status, _)) => status,
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            log_response(
                request_data.remote_addr(),
                &method_cloned,
                &uri_cloned,
                &start,
                status,
                &principal_cloned,
                ConnectionStatus::Aborted,
            );
        }
    });

    // Wait for the handle_payload task to answer using the oneshot channel
    let (status, response_payload) = match rx.await {
        Ok(Ok((status, response_payload))) => (status, response_payload),
        Ok(Err(_)) => {
            // Ok(Err(_)): the handle_payload task returned an Err
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            log_response(
                &addr,
                &method,
                &uri,
                &start,
                status,
                &principal,
                ConnectionStatus::Alive,
            );
            return Ok(build_error_response(status));
        }
        Err(_) => {
            // Err(_): the handle_payload task "sender" has been dropped (should not happen)
            error!("handle_payload task sender has been dropped. Maybe the task panicked?");
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            log_response(
                &addr,
                &method,
                &uri,
                &start,
                status,
                &principal,
                ConnectionStatus::Alive,
            );
            return Ok(build_error_response(status));
        }
    };

    trace!(
        "Send response {} with payload: {:?}",
        status,
        response_payload
    );

    response_builder = response_builder.status(status);
    // Create HTTP response
    let response = match create_response(&auth_ctx, response_builder, response_payload).await {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to build HTTP response: {:?}", e);
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            log_response(
                &addr,
                &method,
                &uri,
                &start,
                status,
                &principal,
                ConnectionStatus::Alive,
            );
            return Ok(build_error_response(status));
        }
    };

    log_response(
        &addr,
        &method,
        &uri,
        &start,
        response.status(),
        &principal,
        ConnectionStatus::Alive,
    );
    Ok(response)
}

fn create_keepalive_settings(collector_server_settings: &ServerSettings) -> TcpKeepalive {
    let tcp_keepalive_time = Duration::from_secs(collector_server_settings.tcp_keepalive_time());
    let tcp_keepalive_interval = collector_server_settings
        .tcp_keepalive_intvl()
        .map(Duration::from_secs);
    let tcp_keepalive_probes = collector_server_settings.tcp_keepalive_probes();

    let keep_alive = TcpKeepalive::new().with_time(tcp_keepalive_time);
    let keep_alive = if let Some(tcp_keepalive_interval) = tcp_keepalive_interval {
        keep_alive.with_interval(tcp_keepalive_interval)
    } else {
        keep_alive
    };
    if let Some(tcp_keepalive_retries) = tcp_keepalive_probes {
        keep_alive.with_retries(tcp_keepalive_retries)
    } else {
        keep_alive
    }
}

async fn read_proxy_protocol_header<I>(stream: I) -> Result<SocketAddr>
where
    I: AsyncRead + Unpin,
{
    match read_proxy_header(stream).await {
        Ok((_, addr_opt)) => match addr_opt {
            Some(addr) => {
                debug!("Real client address is {:?}", addr);
                Ok(addr)
            }
            None => {
                bail!("Failed to retrieve client address");
            }
        },
        Err(err) => Err(anyhow!(err)),
    }
}

fn create_kerberos_server(
    kerberos_settings: &Kerberos,
    collector_settings: Collector,
    collector_db: Db,
    collector_subscriptions: Subscriptions,
    collector_heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    collector_server_settings: ServerSettings,
    monitoring_settings: Option<Monitoring>,
    collector_shutdown_ct: CancellationToken,
    server_addr: SocketAddr,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    let server_principal = kerberos_settings.service_principal_name().to_owned();
    // Try to initialize a security context. This is to be sure that an error in
    // Kerberos configuration will be reported as soon as possible.
    let state = kerberos::State::new(&server_principal);
    if state.context_is_none() {
        panic!("Could not initialize Kerberos context");
    }

    let server = async move {
        let listener = TcpListener::bind(server_addr).await?;
        info!("Server listenning on {}", server_addr);

        // Each accepted TCP connection gets a channel 'rx', which is closed when
        // the connections ends (whether because the client closed the connection
        // or if a shutdown signal has been received).
        // On shutdown, the server waits for all 'rx' to be dropped before
        // resolving terminating using `close_tx.closed().await`.
        let (close_tx, close_rx) = watch::channel(());
        loop {
            let shutdown_ct = collector_shutdown_ct.clone();

            // Accept new clients and wait for shutdown signal to stop accepting
            let (mut stream, client_addr) = tokio::select! {
                conn = listener.accept() => match conn {
                   Ok(conn) => conn,
                   Err(err) => {
                        warn!("Could not get client: {:?}", err);
                        continue;
                   }
                },
                _ = shutdown_ct.cancelled() => {
                    debug!("Shutdown signal received, stop accepting new clients connections");
                    break;
                }
            };

            debug!("Received TCP connection from {}", client_addr);

            // Configure connected socket with keepalive parameters
            let keep_alive = create_keepalive_settings(&collector_server_settings);
            let socket_ref = SockRef::from(&stream);
            socket_ref.set_tcp_keepalive(&keep_alive)?;

            // We have to clone the context to move it into the tokio task
            // responsible for handling the client
            let collector_settings = collector_settings.clone();
            let svc_db = collector_db.clone();
            let svc_server_settings = collector_server_settings.clone();
            let svc_server_principal = server_principal.clone();
            let svc_monitoring_settings = monitoring_settings.clone();
            let subscriptions = collector_subscriptions.clone();
            let collector_heartbeat_tx = collector_heartbeat_tx.clone();

            // Create a "rx" channel end for the task
            let close_rx = close_rx.clone();

            tokio::task::spawn(async move {
                // Parse proxy protocol if enabled
                let real_client_addr = if collector_settings.enable_proxy_protocol() {
                    match read_proxy_protocol_header(&mut stream).await {
                        Ok(addr) => addr,
                        Err(err) => {
                            bail!("Failed to read Proxy Protocol header: {}", err);
                        }
                    }
                } else {
                    client_addr
                };

                // Initialize Kerberos context once for each TCP connection
                // This operation takes time so we run it in a blocking task
                let auth_ctx = tokio::task::spawn_blocking(move || {
                    AuthenticationContext::Kerberos(Arc::new(Mutex::new(kerberos::State::new(
                        &svc_server_principal,
                    ))))
                })
                .await?;

                // Hyper needs a wrapper for the stream
                let io = TokioIo::new(stream);

                // Handle the connection using Hyper http1
                // conn is a Future that ends when the connection is closed
                let conn = http1::Builder::new().serve_connection(
                    io,
                    service_fn(move |req| {
                        handle(
                            svc_server_settings.clone(),
                            collector_settings.clone(),
                            svc_monitoring_settings.clone(),
                            svc_db.clone(),
                            subscriptions.clone(),
                            collector_heartbeat_tx.clone(),
                            auth_ctx.clone(),
                            real_client_addr,
                            req,
                        )
                    }),
                );
                // conn needs to be pinned to be able to use tokio::select!
                pin!(conn);

                // This loop is required to continue to poll the connection after calling
                // graceful_shutdown().
                tokio::select! {
                    res = conn.as_mut() => {
                        if let Err(err) = res {
                            debug!("Error serving connection: {:?}", err);
                        }
                    },
                    _ = shutdown_ct.cancelled() => {
                        debug!("Shutdown signal received, closing connection with {:?}", client_addr);
                        conn.as_mut().graceful_shutdown();
                        if let Err(err) = conn.as_mut().await {
                            debug!("Error serving connection: {:?}", err);
                        };
                    }
                }
                // Connection is closed, drop "task" rx to inform the server that this task
                // is ending
                drop(close_rx);

                Ok(())
            });
        }

        // Drop "server" rx to keep only "tasks" rx
        drop(close_rx);

        info!(
            "Waiting for {} task(s) to finish",
            close_tx.receiver_count()
        );
        close_tx.closed().await;

        Ok(())
    };

    Box::pin(server)
}

fn create_tls_server(
    tls_settings: &Tls,
    collector_settings: Collector,
    collector_db: Db,
    collector_subscriptions: Subscriptions,
    collector_heartbeat_tx: mpsc::Sender<WriteHeartbeatMessage>,
    collector_server_settings: ServerSettings,
    monitoring_settings: Option<Monitoring>,
    collector_shutdown_ct: CancellationToken,
    server_addr: SocketAddr,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    // make TLS connection config
    let tls_config = make_config(tls_settings).expect("Error while configuring server");
    // create acceptor from config
    let tls_acceptor: TlsAcceptor = tls_config.server.into();

    let server = async move {
        let listener = TcpListener::bind(server_addr).await?;
        info!("Server listenning on {}", server_addr);

        // Each accepted TCP connection gets a channel 'rx', which is closed when
        // the connections ends (whether because the client closed the connection
        // or if a shutdown signal has been received).
        // On shutdown, the server waits for all 'rx' to be dropped before
        // resolving terminating using `close_tx.closed().await`.
        let (close_tx, close_rx) = watch::channel(());
        loop {
            let shutdown_ct = collector_shutdown_ct.clone();

            // Accept new clients and wait for shutdown signal to stop accepting
            let (mut stream, client_addr) = tokio::select! {
                conn = listener.accept() => match conn {
                    Ok(conn) => conn,
                    Err(err) => {
                        warn!("Could not get client: {:?}", err);
                        continue;
                    }
                },
                _ = shutdown_ct.cancelled() => {
                    debug!("Shutdown signal received, stop accepting new clients connections");
                    break;
                }
            };

            debug!("Received TCP connection from {}", client_addr);

            // Configure connected socket with keepalive parameters
            let keep_alive = create_keepalive_settings(&collector_server_settings);
            let socket_ref = SockRef::from(&stream);
            socket_ref.set_tcp_keepalive(&keep_alive)?;

            // We have to clone the context to move it into the tokio task
            // responsible for handling the client
            let collector_settings = collector_settings.clone();
            let svc_db = collector_db.clone();
            let svc_server_settings = collector_server_settings.clone();
            let svc_monitoring_settings = monitoring_settings.clone();
            let subscriptions = collector_subscriptions.clone();
            let collector_heartbeat_tx = collector_heartbeat_tx.clone();
            //FIXME: allow multiple certs
            let thumbprint = tls_config.thumbprints.first().cloned().unwrap_or_default();
            let tls_acceptor = tls_acceptor.clone();

            // Create a "rx" channel end for the task
            let close_rx = close_rx.clone();

            tokio::task::spawn(async move {
                // Parse proxy protocol if enabled
                let real_client_addr = if collector_settings.enable_proxy_protocol() {
                    match read_proxy_protocol_header(&mut stream).await {
                        Ok(addr) => addr,
                        Err(err) => {
                            debug!("Failed to read Proxy Protocol header: {}", err);
                            // Exit task
                            return;
                        }
                    }
                } else {
                    client_addr
                };

                let stream = match tls_acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        match err.into_inner() {
                            Some(str) if str.to_string() == "tls handshake eof" => {
                                // happens sometimes, not problematic
                                debug!(
                                    "Error while establishing a connection with '{}': {:?}",
                                    real_client_addr, str
                                )
                            }
                            other => warn!(
                                "Error while establishing a connection with '{}': {:?}",
                                real_client_addr, other
                            ),
                        };
                        return;
                    }
                };

                // get peer certificate
                let cert = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .expect("Peer certificate should exist") // client auth has to happen, so this should not fail
                    .first()
                    .expect("Peer certificate should not be empty") // client cert cannot be empty if authentication succeeded
                    .clone();

                let subject =
                    subject_from_cert(cert.as_ref()).expect("Could not parse client certificate");

                // Initialize Authentication context once for each TCP connection
                let auth_ctx = AuthenticationContext::Tls(vec![(subject, thumbprint.clone())]);

                // Hyper needs a wrapper for the stream
                let io = TokioIo::new(stream);

                // Handle the connection using Hyper http1
                // conn is a Future that ends when the connection is closed
                let conn = http1::Builder::new().serve_connection(
                    io,
                    service_fn(move |req| {
                        handle(
                            svc_server_settings.clone(),
                            collector_settings.clone(),
                            svc_monitoring_settings.clone(),
                            svc_db.clone(),
                            subscriptions.clone(),
                            collector_heartbeat_tx.clone(),
                            auth_ctx.clone(),
                            real_client_addr,
                            req,
                        )
                    }),
                );
                // conn needs to be pinned to be able to use tokio::select!
                pin!(conn);

                // This loop is required to continue to poll the connection after calling
                // graceful_shutdown().
                tokio::select! {
                    res = conn.as_mut() => {
                        if let Err(err) = res {
                            debug!("Error serving connection: {:?}", err);
                        }
                    },
                    _ = shutdown_ct.cancelled() => {
                        debug!("Shutdown signal received, closing connection with {:?}", client_addr);
                        conn.as_mut().graceful_shutdown();
                        if let Err(err) = conn.as_mut().await {
                            debug!("Error serving connection: {:?}", err);
                        };
                    }
                }
                // Connection is closed, drop "task" rx to inform the server that this task
                // is ending
                drop(close_rx);
            });
        }

        // Drop "server" rx to keep only "tasks" rx
        drop(close_rx);

        info!(
            "Waiting for {} task(s) to finish",
            close_tx.receiver_count()
        );
        close_tx.closed().await;

        Ok(())
    };

    Box::pin(server)
}

enum ShutdownReason {
    CtrlC,
    Sigterm,
}

async fn shutdown_signal_task(ct: CancellationToken) {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => {
            info!("Received CTRL+C");
            ShutdownReason::CtrlC
        },
        _ = sigterm.recv() => {
            info!("Received SIGTERM signal");
            ShutdownReason::Sigterm
        }
    };

    // Send the cancellation signal
    ct.cancel();
}

fn monitoring_thread(rt_handle: Handle) {
    info!("Monitoring thread started");
    loop {
        std::thread::sleep(Duration::from_secs(3));
        debug!("Monitoring thread injected dummy task");
        rt_handle.spawn(future::ready(()));
    }
}

async fn force_shutdown_timeout(ct: CancellationToken) {
    // Wait for the shutdown signal
    ct.cancelled().await;
    debug!("Start 10 secs timeout before killing HTTP servers");
    tokio::time::sleep(Duration::from_secs(10)).await;
}

pub async fn run(settings: Settings, verbosity: u8) {
    // Initialize loggers
    if let Err(e) = logging::init(&settings, verbosity) {
        panic!("Failed to setup logging: {:?}", e);
    }

    let rt_handle = Handle::current();

    // Start monitoring thread
    // This ensures the whole progress does not get stop if the
    // tokio runtime is accidently blocked by a "bad" task
    // See https://github.com/tokio-rs/tokio/issues/4730
    std::thread::spawn(move || monitoring_thread(rt_handle));

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

    if let Some(monitoring_settings) = settings.monitoring() {
        monitoring::init(&db, subscriptions.clone(), monitoring_settings)
            .expect("Failed to initialize metrics exporter");
    }

    let reload_interval = settings.server().db_sync_interval();
    let outputs_settings = settings.outputs().clone();
    let update_task_db = db.clone();
    let update_task_subscriptions = subscriptions.clone();
    // Launch a task responsible for updating subscriptions
    tokio::spawn(async move {
        reload_subscriptions_task(
            update_task_db,
            update_task_subscriptions,
            reload_interval,
            outputs_settings,
        )
        .await
    });

    // To reduce database load, heartbeats are not saved immediately.
    // Heartbeats data "to store" are cached in memory before being saved in database periodically.
    // To "store" a heartbeat, request handlers send a message to the heartbeat task
    // using a MPSC channel.
    // The database store operation may take some time. During this operation, new heartbeats message
    // are not popped from the channel. The channel must be large enough to enable the request handlers to enqueue
    // their heartbeat messages without waiting.
    let interval = settings.server().flush_heartbeats_interval();
    let update_task_db = db.clone();
    let (heartbeat_tx, heartbeat_rx) =
        mpsc::channel(settings.server().heartbeats_queue_size() as usize);

    // We use a CancellationToken to tell the task to shutdown, so
    // that it is able to store cached heartbeats.
    let heartbeat_ct = CancellationToken::new();
    let cloned_heartbaat_ct = heartbeat_ct.clone();

    // Launch the task responsible for managing heartbeats
    let heartbeat_task = tokio::spawn(async move {
        heartbeat_task(update_task_db, interval, heartbeat_rx, cloned_heartbaat_ct).await
    });

    let shutdown_ct = CancellationToken::new();
    let cloned_shutdown_ct = shutdown_ct.clone();

    // Shutdown task: waits for shutdown signal and cancel the given CancellationToken
    tokio::spawn(async move {
        shutdown_signal_task(cloned_shutdown_ct).await;
    });

    // Set KRB5_KTNAME env variable if necessary (i.e. if at least one collector uses
    // Kerberos authentication)
    if settings.collectors().iter().any(|x| {
        mem::discriminant(x.authentication())
            == mem::discriminant(&Authentication::Kerberos(Kerberos::empty()))
    }) {
        env::set_var(
            "KRB5_KTNAME",
            settings
                .server()
                .keytab()
                .expect("Kerberos authentication requires the server.keytab setting to be set"),
        );
    }

    info!("Server settings: {:?}", settings.server());

    let mut servers: Vec<Pin<Box<dyn Future<Output = Result<()>> + Send>>> = Vec::new();

    for collector in settings.collectors() {
        let collector_db = db.clone();
        let collector_subscriptions = subscriptions.clone();
        let collector_settings = collector.clone();
        let collector_heartbeat_tx = heartbeat_tx.clone();
        let collector_server_settings = settings.server().clone();
        let collector_shutdown_ct = shutdown_ct.clone();
        let collector_monitoring_settings = settings.monitoring().cloned();

        // Construct our SocketAddr to listen on...
        let addr = SocketAddr::from((
            IpAddr::from_str(collector.listen_address())
                .expect("Failed to parse server.listen_address"),
            collector.listen_port(),
        ));

        trace!("Listen address is {}", addr);

        // create server depending on connection type it allows
        match collector.authentication() {
            Authentication::Kerberos(kerberos) => {
                servers.push(create_kerberos_server(
                    kerberos,
                    collector_settings,
                    collector_db,
                    collector_subscriptions,
                    collector_heartbeat_tx,
                    collector_server_settings,
                    collector_monitoring_settings,
                    collector_shutdown_ct,
                    addr,
                ));
            }
            Authentication::Tls(tls) => {
                servers.push(create_tls_server(
                    tls,
                    collector_settings,
                    collector_db,
                    collector_subscriptions,
                    collector_heartbeat_tx,
                    collector_server_settings,
                    collector_monitoring_settings,
                    collector_shutdown_ct,
                    addr,
                ));
            }
        };
    }

    tokio::select! {
        _ = force_shutdown_timeout(shutdown_ct) => {
            warn!("HTTP servers graceful shutdown timed out.");
        },
        result = join_all(servers) => {
            for server in result {
                if let Err(e) = server {
                    error!("HTTP server error: {}", e);
                }
            }
            info!("HTTP servers have been shutdown gracefully.");
        }
    }

    // Signal the task that we want to shutdown
    heartbeat_ct.cancel();
    // Wait for the task to shutdown gracefully
    if let Err(e) = heartbeat_task.await {
        error!("Failed to wait for heartbeat task to shutdown: {:?}", e)
    }
}
