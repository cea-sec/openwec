use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use common::encoding::encode_utf16le;
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::http::request::Parts;
use hyper::{body::Bytes, Request};
use libgssapi::{
    context::{CtxFlags, SecurityContext, ServerCtx},
    credential::{Cred, CredUsage},
    error::Error,
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_KRB5_PRINCIPAL},
    util::{GssIov, GssIovType},
};
use log::{debug, error};
use mime::Mime;
use std::sync::Arc;
use std::sync::Mutex;
use thiserror::Error;

use crate::multipart;
use crate::sldc;

#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    Kerberos,
    #[allow(clippy::upper_case_acronyms)]
    SPNEGO,
}

#[derive(Debug)]
pub struct State {
    context: Option<ServerCtx>,
    method: Option<Method>,
}

impl State {
    pub fn new(principal: &str) -> Self {
        let context = setup_server_ctx(principal.as_bytes());

        match context {
            Ok(ctx) => State {
                context: Some(ctx),
                method: None,
            },
            Err(e) => {
                error!("Could not setup Kerberos server context: {:?}", e);
                State {
                    context: None,
                    method: None,
                }
            }
        }
    }

    pub fn context_is_none(&self) -> bool {
        self.context.is_none()
    }
}

fn setup_server_ctx(principal: &[u8]) -> Result<ServerCtx, Error> {
    let desired_mechs = {
        let mut s = OidSet::new()?;
        s.add(&GSS_MECH_KRB5)?;
        s.add(&GSS_MECH_SPNEGO)?;
        s
    };
    let name = Name::new(principal, Some(&GSS_NT_KRB5_PRINCIPAL))?;
    let cname = name.canonicalize(Some(&GSS_MECH_KRB5))?;
    let server_cred = Cred::acquire(Some(&cname), None, CredUsage::Accept, Some(&desired_mechs))?;
    debug!("Acquired server credentials: {:?}", server_cred.info());
    Ok(ServerCtx::new(server_cred))
}

pub struct AuthenticationData {
    principal: String,
    token: Option<String>,
    method: Method,
}

impl AuthenticationData {
    pub fn principal(&self) -> &str {
        self.principal.as_ref()
    }

    pub fn token(&self) -> Option<&String> {
        self.token.as_ref()
    }

    pub fn method(&self) -> &Method {
        &self.method
    }
}

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Client request does not contain authorization header")]
    MissingAuthorizationHeader,
    #[error("Client request authorization header is invalid")]
    InvalidAuthorizationHeader,
    #[error(transparent)]
    Gssapi(#[from] libgssapi::error::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

///
/// Perform Kerberos authentication
///
pub async fn authenticate(
    conn_state: &Arc<Mutex<State>>,
    req: &Request<Incoming>,
) -> Result<AuthenticationData, AuthenticationError> {
    {
        let mut state = conn_state.lock().unwrap();
        let method = state.method.clone();
        let server_ctx = state
            .context
            .as_mut()
            .ok_or_else(|| anyhow!("Kerberos server context is empty"))?;

        // Server context has already been established for this TCP connection
        if server_ctx.is_complete() {
            return Ok(AuthenticationData {
                principal: server_ctx.source_name()?.to_string(),
                token: None,
                method: method.ok_or_else(|| anyhow!("GSSAPI method is not set"))?,
            });
        }
    }

    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or_else(|| AuthenticationError::MissingAuthorizationHeader)?
        .to_str()
        .context("Failed to convert authorization header to str")?
        .to_owned();
    let cloned_conn_state = conn_state.clone();

    tokio::task::spawn_blocking(move || {
        let (b64_token_opt, method) = if auth_header.starts_with("Kerberos ") {
            (auth_header.strip_prefix("Kerberos "), Method::Kerberos)
        } else if auth_header.starts_with("Negotiate ") {
            (auth_header.strip_prefix("Negotiate "), Method::SPNEGO)
        } else {
            return Err(AuthenticationError::InvalidAuthorizationHeader);
        };

        let b64_token = b64_token_opt
            .ok_or_else(|| anyhow!("Authorization header is invalid: {}", auth_header))?;

        let mut state = cloned_conn_state.lock().unwrap();
        state.method = Some(method.clone());
        let server_ctx = state
            .context
            .as_mut()
            .ok_or_else(|| anyhow!("Kerberos server context is empty"))?;
        let token = base64::engine::general_purpose::STANDARD
            .decode(b64_token)
            .context("Failed to decode authorization header token as base64")?;

        match server_ctx
            .step(&token)
            .context("Failed to perform Kerberos operation")?
        {
            // TODO: should we return Ok in this case ?
            None => Ok(AuthenticationData {
                principal: server_ctx.source_name()?.to_string(),
                token: None,
                method,
            }),
            Some(step) => {
                // TODO: support multiple steps
                // see RFC4559 "5.  Negotiate Operation Example"
                if !server_ctx.is_complete() {
                    return Err(anyhow!(
                        "Authentication is not complete after first round. Multiple rounds
                        are not supported"
                    )
                    .into());
                }
                let flags = server_ctx.flags().context("Error in server ctx")?;
                let required_flags = CtxFlags::GSS_C_CONF_FLAG
                    | CtxFlags::GSS_C_MUTUAL_FLAG
                    | CtxFlags::GSS_C_INTEG_FLAG;
                if flags & required_flags != required_flags {
                    return Err(anyhow!("Kerberos flags not compliant").into());
                }

                debug!("Server context info: {:?}", server_ctx.info());
                Ok(AuthenticationData {
                    principal: server_ctx.source_name()?.to_string(),
                    token: Some(base64::engine::general_purpose::STANDARD.encode(&*step)),
                    method,
                })
            }
        }
    })
    .await
    .map_err(|e| anyhow!("{}", e))?
}

fn get_boundary(mime: &Mime, method: &Method) -> Result<String> {
    if mime.type_() != "multipart" {
        bail!("Top level media type must be multipart");
    }

    if mime.subtype() != "encrypted" {
        bail!("Sub media type must be encrypted");
    }

    match mime.get_param("protocol") {
        Some(protocol)
            if *method == Method::Kerberos
                && protocol == "application/HTTP-Kerberos-session-encrypted" => {}
        Some(protocol)
            if *method == Method::SPNEGO
                && protocol == "application/HTTP-SPNEGO-session-encrypted" => {}
        _ => bail!("Invalid or missing parameter 'protocol' in Content-Type"),
    }

    match mime.get_param("boundary") {
        Some(boundary) => Ok(boundary.to_string()),
        _ => bail!("Missing parameter 'boundary' in Content-Type"),
    }
}

fn decrypt_payload(encrypted_payload: Vec<u8>, server_ctx: &mut ServerCtx) -> Result<Vec<u8>> {
    log::debug!("Try to decrypt Kerberos payload");
    let i32_size = std::mem::size_of::<i32>();
    let (signature_length_bytes, _) = encrypted_payload.split_at(i32_size);
    let signature_length = i32::from_le_bytes(signature_length_bytes.try_into()?) as usize;
    let mut signature = Vec::with_capacity(signature_length);
    signature.extend_from_slice(
        encrypted_payload
            .get(i32_size..signature_length + i32_size)
            .ok_or_else(|| anyhow!("Failed to retrieve encrypted message signature"))?,
    );
    let mut encrypted_message =
        Vec::with_capacity(encrypted_payload.len() - signature_length - i32_size);
    encrypted_message.extend_from_slice(
        encrypted_payload
            .get(i32_size + signature_length..)
            .ok_or_else(|| anyhow!("Failed to retrieve encrypted message payload"))?,
    );
    let mut iovs = [
        GssIov::new(GssIovType::Header, &mut signature),
        GssIov::new(GssIovType::Data, &mut encrypted_message),
    ];
    server_ctx.unwrap_iov(&mut iovs)?;
    drop(iovs);

    log::debug!("Kerberos payload decrypted successfully");
    Ok(encrypted_message)
}

fn encrypt_payload(mut payload: Vec<u8>, server_ctx: &mut ServerCtx) -> Result<Vec<u8>> {
    let mut iovs = [
        GssIov::new_alloc(GssIovType::Header),
        GssIov::new(GssIovType::Data, &mut payload),
        GssIov::new_alloc(GssIovType::Padding),
        // TODO: should we add a trailer
        // see https://web.mit.edu/kerberos/krb5-1.18/doc/appdev/gssapi.html
        // and https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi
    ];
    server_ctx.wrap_iov(true, &mut iovs)?;

    let mut encrypted_payload = Vec::with_capacity(
        std::mem::size_of::<i32>() + iovs[0].len() + iovs[1].len() + iovs[2].len(),
    );

    encrypted_payload.extend_from_slice(&i32::try_from(iovs[0].len())?.to_le_bytes());
    encrypted_payload.extend_from_slice(&iovs[0]);
    encrypted_payload.extend_from_slice(&iovs[1]);
    encrypted_payload.extend_from_slice(&iovs[2]);
    drop(iovs);

    Ok(encrypted_payload)
}

pub async fn get_request_payload(
    conn_state: Arc<Mutex<State>>,
    parts: Parts,
    data: Bytes,
) -> Result<Option<Vec<u8>>> {
    // Multiple blocking operations are done here:
    // - retrieve encrypted payload from multipart request
    // - decrypt payload
    // - decompress payload

    let get_payload_task = tokio::task::spawn_blocking(move || {
        let content_type = match parts.headers.get("Content-Type") {
            Some(content_type) => content_type,
            None => bail!("Request does not contain 'Content-Type' header"),
        };

        let mime = content_type
            .to_str()?
            .parse::<Mime>()
            .context("Could not parse Content-Type header")?;

        let method = {
            let state = conn_state.lock().unwrap();
            state
                .method
                .as_ref()
                .ok_or_else(|| anyhow!("Unknown GSSAPI method"))?
                .clone()
        };

        let boundary =
            get_boundary(&mime, &method).context("Could not get multipart boundaries")?;
        let encrypted_payload = multipart::read_multipart_body(&mut &*data, &boundary, &method)
            .context("Could not retrieve encrypted payload")?;

        let decrypted_message = {
            let mut state = conn_state.lock().unwrap();
            let server_ctx = state
                .context
                .as_mut()
                .ok_or_else(|| anyhow!("Kerberos server context is empty"))?;

            decrypt_payload(encrypted_payload, server_ctx).context("Could not decrypt payload")?
        };

        let message = match parts.headers.get("Content-Encoding") {
            Some(value) if value == "SLDC" => {
                sldc::decompress(&decrypted_message).unwrap_or(decrypted_message)
            }
            None => decrypted_message,
            value => bail!("Unsupported Content-Encoding {:?}", value),
        };
        Ok(message)
    });
    let message = get_payload_task.await??;

    Ok(Some(message))
}

pub async fn get_response_payload(
    conn_state: Arc<Mutex<State>>,
    payload: String,
    boundary: String,
) -> Result<Vec<u8>> {
    // Multiple blocking operations are done here:
    // - encode payload
    // - encrypt payload
    // - generate multipart body

    tokio::task::spawn_blocking(move || {
        let mut payload = encode_utf16le(payload).context("Failed to encode payload in utf16le")?;

        let cleartext_payload_len = payload.len();

        let (payload, method) = {
            let mut state = conn_state.lock().unwrap();
            let method = state
                .method
                .as_ref()
                .ok_or_else(|| anyhow!("Unknown GSSAPI method"))?
                .clone();
            let server_ctx = &mut state
                .context
                .as_mut()
                .ok_or_else(|| anyhow!("Kerberos server context is empty"))?;
            payload = encrypt_payload(payload, server_ctx).context("Failed to encrypt payload")?;
            (payload, method)
        };

        Ok(multipart::get_multipart_body(
            &payload,
            cleartext_payload_len,
            &boundary,
            &method,
        ))
    })
    .await?
}

pub fn get_response_content_type(conn_state: Arc<Mutex<State>>, boundary: &str) -> Result<String> {
    let state = conn_state.lock().unwrap();
    match state.method {
        Some(Method::Kerberos) => Ok("multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"".to_owned() + boundary + "\""),
        Some(Method::SPNEGO)=> Ok("multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"".to_owned() + boundary + "\""),
        _ => bail!("Invalid GSSAPI Method")
    }
}
