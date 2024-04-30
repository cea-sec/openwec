use async_trait::async_trait;
use log::{debug, info, warn};
use tokio::sync::oneshot;

use crate::event::EventMetadata;
use crate::output::OutputDriver;
use anyhow::{anyhow, bail, Context, Result};
use common::subscription::FilesConfiguration;
use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::{path::PathBuf, str::FromStr};

enum WriteFilesMessage {
    Write(WriteMessage),
    Stop,
}

#[derive(Debug)]
pub struct WriteMessage {
    path: PathBuf,
    content: String,
    resp: oneshot::Sender<Result<()>>,
}

fn handle_message(file_handles: &mut HashMap<PathBuf, File>, message: &WriteMessage) -> Result<()> {
    let parent = message
        .path
        .parent()
        .ok_or_else(|| anyhow!("Failed to retrieve messages parent folder"))?;
    let path = &message.path;
    let file = match file_handles.get_mut(path) {
        Some(file) => {
            debug!("File {} is already opened", path.display());
            // The path already exists in file_handles map
            file
        }
        None => {
            // Create directory (if it does not already exist)
            debug!("Create directory {}", parent.display());
            create_dir_all(parent)?;
            // Open file
            debug!("Open file {}", path.display());
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("Failed to open file {}", path.display()))?;
            // Insert it into file_buffers map
            file_handles.insert(path.clone(), file);
            // Retrieve it
            file_handles
                .get_mut(path)
                .ok_or_else(|| anyhow!("Could not find newly inserted File in file handles"))?
        }
    };
    file.write_all(message.content.as_bytes())?;
    Ok(())
}

fn run(rx: Receiver<WriteFilesMessage>) {
    info!("File output thread started");
    let mut file_handles: HashMap<PathBuf, File> = HashMap::new();
    while let Ok(WriteFilesMessage::Write(message)) = rx.recv() {
        let result = handle_message(&mut file_handles, &message);
        if let Err(e) = message.resp.send(result) {
            warn!(
                "Failed to send File write result because the receiver dropped. Result was: {:?}",
                e
            );
        }
    }
    info!("Exiting File output thread");
}

pub struct OutputFiles {
    config: FilesConfiguration,
    tx: mpsc::Sender<WriteFilesMessage>,
}

impl OutputFiles {
    pub fn new(config: &FilesConfiguration) -> Self {
        debug!("Initialize Files driver with config {:?}", config);
        // Create a communication channel with the task responsible for file management
        let (tx, rx) = mpsc::channel();

        // Launch a dedicated thread responsible for handling file system operations
        std::thread::spawn(move || {
            run(rx);
        });

        OutputFiles {
            config: config.clone(),
            tx,
        }
    }

    fn build_path(
        &self,
        ip: &IpAddr,
        principal: &str,
        node_name: Option<&String>,
    ) -> Result<PathBuf> {
        let mut path: PathBuf = PathBuf::from_str(self.config.base())?;

        match self.config.split_on_addr_index() {
            Some(index) => {
                match ip {
                    IpAddr::V4(ipv4) => {
                        // Sanitize index
                        let index = if index < 1 {
                            warn!("File configuration split_on_addr_index can not be inferior as 1: found {}", index);
                            1
                        } else if index > 4 {
                            warn!("File configuration split_on_addr_index can not be superior as 4 for IPv4: found {}", index);
                            4
                        } else {
                            index
                        };

                        // Split on "."
                        // a.b.c.d
                        // 1 => a/a.b/a.b.c/a.b.c.d
                        // 2 => a.b/a.b.c/a.b.c.d
                        // 3 => a.b.c/a.b.c.d
                        // 4 => a.b.c.d
                        let octets = ipv4.octets();
                        for i in index..5 {
                            let mut fname = String::new();
                            for j in 0..i {
                                fname.push_str(
                                    format!(
                                        "{}",
                                        octets.get(j as usize).ok_or_else(|| anyhow!(
                                            "Could not get segment {} of ipv4 addr {:?}",
                                            j,
                                            ipv4
                                        ))?
                                    )
                                    .as_ref(),
                                );
                                // There is probably a better way to write this
                                if j != i - 1 {
                                    fname.push('.');
                                }
                            }
                            path.push(&fname);
                        }
                    }
                    IpAddr::V6(ipv6) => {
                        // Sanitize index
                        let index = if index < 1 {
                            warn!("File configuration split_on_addr_index can not be inferior as 1: found {}", index);
                            1
                        } else if index > 8 {
                            warn!("File configuration split_on_addr_index can not be superior as 8 for IPv6: found {}", index);
                            8
                        } else {
                            index
                        };

                        // Split on ":"
                        // a:b:c:d:e:f:g:h
                        // 1 => a/a:b/a:b:c/...
                        // 2 => a:b/a:b:c/...
                        // 3 => a:b:c/a:b:c:d/...
                        // 4 => a:b:c:d/...
                        // 5 => a:b:c:d:e/...
                        // 6 => a:b:c:d:e:f/...
                        // 7 => a:b:c:d:e:f:g/
                        // 8 => a:b:c:d:e:f:g:h
                        let segments = ipv6.segments();
                        for i in index..9 {
                            let mut fname = String::new();
                            for j in 0..i {
                                fname.push_str(
                                    format!(
                                        "{:x}",
                                        segments.get(j as usize).ok_or_else(|| anyhow!(
                                            "Could not get segment {} of ipv6 addr {:?}",
                                            j,
                                            ipv6
                                        ))?
                                    )
                                    .as_ref(),
                                );
                                // There is probably a better way to write this
                                if j != i - 1 {
                                    fname.push(':');
                                }
                            }
                            path.push(&fname);
                        }
                    }
                }
            }
            None => {
                path.push(ip.to_string());
            }
        }

        path.push(sanitize_name(principal));

        if self.config.append_node_name() {
            match node_name {
                Some(name) => path.push(name),
                None => bail!("Could not append node name to path because it is unset"),
            }
        }

        path.push(self.config.filename());
        Ok(path)
    }
}

#[async_trait]
impl OutputDriver for OutputFiles {
    async fn write(
        &self,
        metadata: Arc<EventMetadata>,
        events: Arc<Vec<Arc<String>>>,
    ) -> Result<()> {
        // Build path
        let path = self.build_path(
            &metadata.addr().ip(),
            metadata.principal(),
            metadata.node_name(),
        )?;
        debug!("Computed path is {}", path.display());

        // Build the "content" string to write
        let mut content = String::new();
        for event in events.iter() {
            content.push_str(event);
            content.push('\n');
        }

        // Create a oneshot channel to retrieve the result of the operation
        let (tx, rx) = oneshot::channel();
        self.tx.send(WriteFilesMessage::Write(WriteMessage {
            path,
            content,
            resp: tx,
        }))?;

        // Wait for the result
        rx.await??;

        Ok(())
    }
}

impl Drop for OutputFiles {
    fn drop(&mut self) {
        if let Err(e) = self.tx.send(WriteFilesMessage::Stop) {
            warn!("Failed to send Stop message to Files handler thread: {}", e);
        }
    }
}

fn sanitize_name(name: &str) -> String {
    // We only allow strings containing at most 255 chars within [a-z][A-Z][0-9][.-_@]
    let mut new_str = String::with_capacity(name.len());

    let mut count: usize = 0;
    for ch in name.chars() {
        if count >= 255 {
            warn!(
                "The string is too long. Keeping only 255 first chars: \"{}\"",
                new_str
            );
            break;
        }

        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' || ch == '@' {
            new_str.push(ch);
            count += 1;
        } else if ch == '$' {
            // Discard silently '$'
            // TODO: Are we sure that we want to do this?
            // The idea is to remove '$' from principals because it
            // may cause bugs with badly written shell scripts.
        } else {
            warn!(
                "An invalid char '{}' in \"{}\" has been removed",
                ch, new_str
            );
        }
    }

    new_str
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize() {
        assert_eq!(sanitize_name("test"), "test");
        assert_eq!(sanitize_name("wec.windomain.local"), "wec.windomain.local");
        assert_eq!(sanitize_name("/bad/dir"), "baddir");
        assert_eq!(
            sanitize_name("AcceptLettersANDN3293Mbers"),
            "AcceptLettersANDN3293Mbers"
        );
        assert_eq!(
            sanitize_name("test_underscore-and-hyphen"),
            "test_underscore-and-hyphen"
        );
        let too_long = sanitize_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(too_long.len(), 255);
        assert_eq!(sanitize_name("DC$@WINDOMAIN.LOCAL"), "DC@WINDOMAIN.LOCAL");
    }

    #[tokio::test]
    async fn test_build_path() -> Result<()> {
        let config =
            FilesConfiguration::new("/base".to_string(), None, false, "messages".to_string());
        let ip: IpAddr = "127.0.0.1".parse()?;

        let output_file = OutputFiles::new(&config);

        assert_eq!(
            output_file.build_path(&ip, "princ", None)?,
            PathBuf::from_str("/base/127.0.0.1/princ/messages")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), None, true, "messages".to_string());
        let output_file = OutputFiles::new(&config);

        assert_eq!(
            output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,
            PathBuf::from_str("/base/127.0.0.1/princ/node/messages")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), Some(1), true, "messages".to_string());
        let output_file = OutputFiles::new(&config);

        assert_eq!(
            output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,
            PathBuf::from_str("/base/127/127.0/127.0.0/127.0.0.1/princ/node/messages")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), Some(2), false, "other".to_string());
        let output_file = OutputFiles::new(&config);

        assert_eq!(
            output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,
            PathBuf::from_str("/base/127.0/127.0.0/127.0.0.1/princ/other")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), Some(3), false, "messages".to_string());
        let output_file = OutputFiles::new(&config);

        assert_eq!(
            output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,
            PathBuf::from_str("/base/127.0.0/127.0.0.1/princ/messages")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), Some(4), false, "messages".to_string());
        let output_file = OutputFiles::new(&config);

        assert_eq!(
            output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,
            PathBuf::from_str("/base/127.0.0.1/princ/messages")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), Some(5), false, "messages".to_string());
        let output_file = OutputFiles::new(&config);

        assert_eq!(
            output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,
            PathBuf::from_str("/base/127.0.0.1/princ/messages")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), None, true, "messages".to_string());
        let output_file = OutputFiles::new(&config);

        assert!(output_file.build_path(&ip, "princ", None).is_err());

        let ip: IpAddr = "1:2:3:4:5:6:7:8".parse()?;
        let config =
            FilesConfiguration::new("/base".to_string(), None, false, "messages".to_string());
        let output_file = OutputFiles::new(&config);
        assert_eq!(
            output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,
            PathBuf::from_str("/base/1:2:3:4:5:6:7:8/princ/messages")?
        );

        let config =
            FilesConfiguration::new("/base".to_string(), Some(3), false, "messages".to_string());
        let output_file = OutputFiles::new(&config);
        assert_eq!(output_file.build_path(&ip, "princ", Some(&"node".to_string()))?,PathBuf::from_str("/base/1:2:3/1:2:3:4/1:2:3:4:5/1:2:3:4:5:6/1:2:3:4:5:6:7/1:2:3:4:5:6:7:8/princ/messages")?);
        Ok(())
    }
}
