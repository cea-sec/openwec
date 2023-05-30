use std::sync::Arc;

use crate::{event::EventMetadata, formatter::Format, output::Output};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use common::subscription::TcpConfiguration;
use log::{debug, info, warn};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};

use tokio::io::AsyncWriteExt;

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

pub async fn run(
    addr: String,
    port: u16,
    mut task_rx: mpsc::Receiver<WriteTCPMessage>,
    mut task_exit_rx: oneshot::Receiver<()>,
) {
    let mut stream_opt: Option<TcpStream> = None;
    loop {
        tokio::select! {
            Some(message) = task_rx.recv() => {
                // Establish TCP connection if not already done
                if stream_opt.is_none() {
                    match TcpStream::connect((addr.as_str(), port)).await {
                        Ok(stream) => {
                            stream_opt = Some(stream);
                        },
                        Err(e) => {
                            warn!("Failed to connect to {}:{}: {}", addr, port, e);
                            send_response(message.resp, Err(anyhow!(format!("Failed to connect to {}:{}: {}", addr, port, e))));
                            continue;
                        }
                    };
                }
                // This should never fail
                let stream = match stream_opt.as_mut() {
                    Some(stream) => stream,
                    None => {
                        warn!("TCP stream is unset !");
                        send_response(message.resp, Err(anyhow!(format!("TCP stream of {}:{} is unset!", addr, port))));
                        continue;
                    }
                };

                // Write data to stream
                if let Err(e) = stream.write_all(message.content.as_bytes()).await {
                    stream_opt = None;
                    send_response(message.resp, Err(anyhow!(format!("Failed to write in TCP connection ({}:{}): {}", addr, port, e))));
                    continue;
                }

                send_response(message.resp, Ok(()));
            },
            _ = &mut task_exit_rx => {
                break
            },
        };
    }
    info!("Exiting TCP output task ({}:{})", addr, port);
}

pub struct OutputTcp {
    format: Format,
    addr: String,
    port: u16,
    task_tx: mpsc::Sender<WriteTCPMessage>,
    task_exit_tx: Option<oneshot::Sender<()>>,
}

impl OutputTcp {
    pub fn new(format: Format, config: &TcpConfiguration) -> Result<Self> {
        debug!(
            "Initialize TCP output with format {:?} and peer {}:{}",
            format,
            config.addr(),
            config.port()
        );

        // Create a communication channel with the task responsible for file management
        // TODO: Why 32?
        let (task_tx, task_rx) = mpsc::channel(32);

        // Create a oneshot channel to ask to the ask to end itself
        let (task_exit_tx, task_exit_rx) = oneshot::channel();

        let addr = config.addr().to_string();
        let port = config.port();

        // Launch the task responsible for handling the TCP connection
        tokio::spawn(async move { run(addr, port, task_rx, task_exit_rx).await });

        Ok(OutputTcp {
            format,
            addr: config.addr().to_string(),
            port: config.port(),
            task_tx,
            task_exit_tx: Some(task_exit_tx),
        })
    }
}

#[async_trait]
impl Output for OutputTcp {
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

    fn describe(&self) -> String {
        format!("TCP ({}:{})", self.addr, self.port)
    }

    fn format(&self) -> &Format {
        &self.format
    }
}

impl Drop for OutputTcp {
    fn drop(&mut self) {
        if let Some(sender) = self.task_exit_tx.take() {
            // Using `let _ =` to ignore send errors.
            let _ = sender.send(());
        }
    }
}
