use std::sync::Arc;

use crate::{event::EventMetadata, formatter::Format, output::Output};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use common::subscription::UnixDatagramConfiguration;
use log::{debug, info, warn};
use std::path::Path;
use tokio::{
    net::UnixDatagram,
    sync::{mpsc, oneshot},
};

use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct WriteUnixDatagramMessage {
    events: Arc<Vec<Arc<String>>>,
    resp: oneshot::Sender<Result<()>>,
}

fn send_response(sender: oneshot::Sender<Result<()>>, msg: Result<()>) {
    if let Err(e) = sender.send(msg) {
        warn!(
            "Failed to send UnixDatagram write result because the receiver dropped. Result was: {:?}",
            e
        );
    }
}

pub async fn run(
    path: String,
    mut task_rx: mpsc::Receiver<WriteUnixDatagramMessage>,
    cancellation_token: CancellationToken,
) {
    let mut dgram_opt: Option<UnixDatagram> = None;
    'mainloop: loop {
        tokio::select! {
            Some(message) = task_rx.recv() => {
                if dgram_opt.is_none() {
                    let dgram = match UnixDatagram::unbound() {
                        Ok(dgram) => dgram,
                        Err(e) => {
                            warn!("Failed to create UnixDatagram socket: {}", e);
                            send_response(message.resp, Err(anyhow!(format!("Failed to create UnixDatagram socket: {}", e))));
                            continue;
                        }
                    };

                    match dgram.connect(Path::new(&path)) {
                        Ok(_) => {
                            dgram_opt = Some(dgram);
                        },
                        Err(e) => {
                            warn!("Failed to connect to {}: {}", path, e);
                            send_response(message.resp, Err(anyhow!(format!("Failed to connect to {}: {}", path, e))));
                            continue;
                        }
                    };
                }

                // This should never fail
                let dgram = match dgram_opt.as_mut() {
                    Some(dgram) => dgram,
                    None => {
                        warn!("UnixDatagram is unset !");
                        send_response(message.resp, Err(anyhow!(format!("UnixDatagram of {} is unset!", path))));
                        continue;
                    }
                };

                for event in message.events.iter() {
                    if let Err(e) = dgram.send(event.as_bytes()).await {
                        dgram_opt = None;
                        send_response(message.resp, Err(anyhow!(format!("Failed to write to UnixDatagram ({}): {}", path, e))));
                        continue 'mainloop;
                    }
                }

                send_response(message.resp, Ok(()));
            },
            _ = cancellation_token.cancelled() => {
                break;
            }
        };
    }
    info!("Exiting UnixDatagram output task ({})", path);
}

pub struct OutputUnixDatagram {
    format: Format,
    path: String,
    task_tx: mpsc::Sender<WriteUnixDatagramMessage>,
    task_ct: CancellationToken,
}

impl OutputUnixDatagram {
    pub fn new(format: Format, config: &UnixDatagramConfiguration) -> Result<Self> {
        debug!("Initialize UnixDatagram output with format {:?} and path {}", format, config.path());

        let (task_tx, task_rx) = mpsc::channel(32);

        let task_ct = CancellationToken::new();
        let cloned_task_ct = task_ct.clone();

        let path = config.path().to_string();

        tokio::spawn(async move { run(path, task_rx, cloned_task_ct).await });

        Ok(OutputUnixDatagram {
            format,
            path: config.path().to_string(),
            task_tx,
            task_ct,
        })
    }
}

#[async_trait]
impl Output for OutputUnixDatagram {
    async fn write(
        &self,
        _metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.task_tx
            .send(WriteUnixDatagramMessage { events, resp: tx })
            .await?;

        rx.await??;

        Ok(())
    }

    fn describe(&self) -> String {
        format!("UnixDatagram ({})", self.path)
    }

    fn format(&self) -> &Format {
        &self.format
    }
}

impl Drop for OutputUnixDatagram {
    fn drop(&mut self) {
        self.task_ct.cancel();
    }
}
