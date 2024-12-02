use std::{pin::Pin, sync::Arc};

use crate::{
    event::EventMetadata,
    output::OutputDriver,
    tls::{load_certs, load_priv_key},
};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use common::subscription::TcpConfiguration;
use log::{debug, info, warn};
use tokio::{
    io::AsyncWrite,
    net::TcpStream,
    sync::{mpsc, oneshot},
};

use tokio::io::AsyncWriteExt;
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct WriteTCPMessage {
    content: String,
    resp: oneshot::Sender<Result<()>>,
}

fn send_response(sender: oneshot::Sender<Result<()>>, msg: Result<()>) {
    if let Err(e) = sender.send(msg) {
        warn!(
            "Failed to send TCP write result because the receiver dropped. Result was: {:?}",
            e
        );
    }
}

pub async fn connect(
    config: &TcpConfiguration,
) -> Result<Pin<Box<dyn AsyncWrite + std::marker::Send>>> {
    if config.tls_enabled() {
        let mut certificate_authorities = Vec::new();
        for certificate_authority_file in config.tls_certificate_authorities() {
            certificate_authorities.extend(load_certs(certificate_authority_file)?);
        }
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add_parsable_certificates(certificate_authorities.clone());

        let tls_config_builder = ClientConfig::builder().with_root_certificates(root_cert_store);

        let tls_config = if let Some(tls_certificate_file) = config.tls_certificate() {
            let tls_certificate = load_certs(tls_certificate_file)?;
            let tls_key_file = config.tls_key().ok_or_else(|| anyhow!("Missing tls_key"))?;
            let tls_private_key = load_priv_key(tls_key_file)?;
            tls_config_builder.with_client_auth_cert(tls_certificate, tls_private_key)?
        } else {
            tls_config_builder.with_no_client_auth()
        };
        let connector = TlsConnector::from(Arc::new(tls_config));
        let dnsname = ServerName::try_from(config.host().to_owned())?;

        let stream = TcpStream::connect((config.host(), config.port()))
            .await
            .context("Failed to establish TCP connection")?;
        Ok(Box::pin(connector.connect(dnsname, stream).await?))
    } else {
        Ok(Box::pin(
            TcpStream::connect((config.host(), config.port()))
                .await
                .context("Failed to establish TCP connection")?,
        ))
    }
}

pub async fn run(
    config: TcpConfiguration,
    mut task_rx: mpsc::Receiver<WriteTCPMessage>,
    cancellation_token: CancellationToken,
) {
    let mut stream_opt: Option<Pin<Box<dyn AsyncWrite + std::marker::Send>>> = None;

    loop {
        tokio::select! {
            Some(message) = task_rx.recv() => {
                // Establish TCP connection if not already done
                if stream_opt.is_none() {
                    match connect(&config).await {
                        Ok(stream) => {
                            stream_opt = Some(stream);
                        },
                        Err(e) => {
                            warn!("Failed to connect to {}:{}: {}", config.host(), config.port(), e);
                            send_response(message.resp, Err(anyhow!(format!("Failed to connect to {}:{}: {}", config.host(), config.port(), e))));
                            continue;
                        }
                    };
                }
                // This should never fail
                let stream = match stream_opt.as_mut() {
                    Some(stream) => stream,
                    None => {
                        warn!("TCP stream is unset !");
                        send_response(message.resp, Err(anyhow!(format!("TCP stream of {}:{} is unset!", config.host(), config.port()))));
                        continue;
                    }
                };

                // Write data to stream
                if let Err(e) = stream.write_all(message.content.as_bytes()).await {
                    stream_opt = None;
                    send_response(message.resp, Err(anyhow!(format!("Failed to write in TCP connection ({}:{}): {}", config.host(), config.port(), e))));
                    continue;
                }

                send_response(message.resp, Ok(()));
            },
            _ = cancellation_token.cancelled() => {
                break;
            }
        };
    }
    info!("Exiting TCP output task ({:?})", config);
}

pub struct OutputTcp {
    task_tx: mpsc::Sender<WriteTCPMessage>,
    task_ct: CancellationToken,
}

impl OutputTcp {
    pub fn new(config: &TcpConfiguration) -> Result<Self> {
        debug!("Initialize TCP output with config {:?}", config,);

        // Create a communication channel with the task responsible for file management
        // TODO: Why 32?
        let (task_tx, task_rx) = mpsc::channel(32);

        // Use a CancellationToken to tell the task to end itself
        let task_ct = CancellationToken::new();
        let cloned_task_ct = task_ct.clone();

        let config_cloned = config.clone();

        // Launch the task responsible for handling the TCP connection
        tokio::spawn(async move { run(config_cloned, task_rx, cloned_task_ct).await });

        Ok(OutputTcp { task_tx, task_ct })
    }
}

#[async_trait]
impl OutputDriver for OutputTcp {
    async fn write(
        &self,
        _metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {
        // Build the "content" string to write
        let mut content = String::new();
        for event in events.iter() {
            content.push_str(event);
            content.push('\n');
        }

        // Create a oneshot channel to retrieve the result of the operation
        let (tx, rx) = oneshot::channel();
        self.task_tx
            .send(WriteTCPMessage { content, resp: tx })
            .await?;

        // Wait for the result
        rx.await??;

        Ok(())
    }
}

impl Drop for OutputTcp {
    fn drop(&mut self) {
        self.task_ct.cancel();
    }
}
