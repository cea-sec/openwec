use async_trait::async_trait;
use leon::Template;
use log::{debug, info, warn};
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::event::EventMetadata;
use crate::output::OutputDriver;
use anyhow::{anyhow, bail, Context, Result};
use common::subscription::FilesConfiguration;
use std::borrow::Cow;
use std::cmp::min;
use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;
use std::{path::PathBuf, str::FromStr};

pub struct OutputFilesContext {
    tx: mpsc::Sender<WriteFilesMessage>,
}

impl OutputFilesContext {
    pub fn new() -> Self {
        // Create a communication channel with the thread responsible for file management
        let (tx, rx) = mpsc::channel();

        // Launch a dedicated thread responsible for handling file system operations
        std::thread::spawn(move || {
            run(rx);
        });

        Self { tx }
    }

    pub fn clear(&mut self) {
        if let Err(e) = self.tx.send(WriteFilesMessage::ClearHandles) {
            warn!(
                "Failed to send ClearHandles message to Files handler thread: {}",
                e
            );
        }
    }

    pub fn garbage_collect(&mut self, files_descriptor_close_timeout: u64) {
        if let Err(e) = self.tx.send(WriteFilesMessage::GarbageCollect(
            files_descriptor_close_timeout,
        )) {
            warn!("Failed to send Stop message to Files handler thread: {}", e);
        }
    }
}

impl Drop for OutputFilesContext {
    fn drop(&mut self) {
        debug!("Dropping Files context");
        if let Err(e) = self.tx.send(WriteFilesMessage::Stop) {
            warn!("Failed to send Stop message to Files handler thread: {}", e);
        }
    }
}

enum WriteFilesMessage {
    Write(WriteMessage),
    GarbageCollect(u64),
    ClearHandles,
    Stop,
}

#[derive(Debug)]
pub struct WriteMessage {
    path: PathBuf,
    content: String,
    resp: oneshot::Sender<Result<()>>,
}

struct FileContainer {
    pub file: File,
    pub last_used: Instant,
}

impl FileContainer {
    pub fn new(file: File, last_used: Instant) -> Self {
        Self { file, last_used }
    }

    pub fn has_not_been_used_since(&self, instant: Instant) -> bool {
        self.last_used < instant
    }
}

fn handle_message(
    file_handles: &mut HashMap<PathBuf, FileContainer>,
    message: &WriteMessage,
) -> Result<()> {
    let now = Instant::now();
    let parent = message
        .path
        .parent()
        .ok_or_else(|| anyhow!("Failed to retrieve messages parent folder"))?;
    let path = &message.path;
    match file_handles.get_mut(path) {
        Some(file_container) => {
            debug!("File {} is already opened", path.display());
            file_container.last_used = now;
            // The path already exists in file_handles map
            file_container.file.write_all(message.content.as_bytes())?;
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

            let mut file_container = FileContainer::new(file, now);
            file_container.file.write_all(message.content.as_bytes())?;

            // Insert it into file_buffers map
            file_handles.insert(path.clone(), file_container);
        }
    };
    Ok(())
}

fn garbage_collect(
    file_handles: &mut HashMap<PathBuf, FileContainer>,
    files_descriptor_close_timeout: u64,
) {
    let instant = Instant::now() - Duration::from_secs(files_descriptor_close_timeout);
    let mut path_to_remove = Vec::new();
    for (path, file_container) in file_handles.iter() {
        if file_container.has_not_been_used_since(instant) {
            path_to_remove.push(path.clone())
        }
    }

    for path in path_to_remove {
        debug!(
            "Closing file descriptor of {} because it has not been used since {} seconds.",
            path.display(),
            files_descriptor_close_timeout
        );
        file_handles.remove(&path);
    }
}

fn run(rx: Receiver<WriteFilesMessage>) {
    info!("Files output thread started");

    let mut file_handles: HashMap<PathBuf, FileContainer> = HashMap::new();
    loop {
        match rx.recv() {
            Ok(WriteFilesMessage::Write(message)) => {
                let result = handle_message(&mut file_handles, &message);
                if let Err(e) = message.resp.send(result) {
                    warn!(
                        "Failed to send Files write result because the receiver dropped. Result was: {:?}",
                        e
                    );
                }
            }
            Ok(WriteFilesMessage::GarbageCollect(files_descriptor_close_timeout)) => {
                debug!("Files handler thread received a GarbageCollect command");
                garbage_collect(&mut file_handles, files_descriptor_close_timeout);
            }
            Ok(WriteFilesMessage::ClearHandles) => {
                debug!("Files handler thread received a ClearHandles command");
                file_handles.clear();
            }
            Ok(WriteFilesMessage::Stop) => {
                debug!("Files handler thread received a stop command");
                break;
            }
            Err(_) => {
                warn!("Files handler thread receive channel has hung up");
                break;
            }
        }
    }
    info!("Exiting Files output thread");
}

struct PathValues {
    metadata: Arc<EventMetadata>,
}

impl PathValues {
    fn split(&self, ip_str: &str, capacity: usize, index: u8, sep: char) -> String {
        let mut result = String::with_capacity(capacity);
        let mut count = 0;
        for ch in ip_str.chars() {
            if ch != sep {
                result.push(ch);
            } else {
                count += 1;
                if count >= index {
                    break;
                }
                result.push(sep);
            }
        }
        result
    }

    fn split_ip(&self, ip: &IpAddr, index: u8) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                // Sanitize index
                let index = if index < 1 {
                    warn!("index can not be inferior as 1: found {}", index);
                    1
                } else if index > 4 {
                    warn!("index can not be superior as 4 for IPv4: found {}", index);
                    4
                } else {
                    index
                };

                let ip_str = ipv4.to_string();
                self.split(&ip_str, ip_str.capacity(), index, '.')
            }
            IpAddr::V6(ipv6) => {
                // Sanitize index
                let index = if index < 1 {
                    warn!(
                        "File configuration split_on_addr_index can not be inferior as 1: found {}",
                        index
                    );
                    1
                } else if index > 8 {
                    warn!("File configuration split_on_addr_index can not be superior as 8 for IPv6: found {}", index);
                    8
                } else {
                    index
                };

                let ip_str = ipv6.to_string();
                self.split(&ip_str, ip_str.capacity(), index, ':')
            }
        }
    }
}

impl leon::Values for PathValues {
    fn get_value(&self, key: &str) -> Option<Cow<'_, str>> {
        if key == "ip" {
            Some(Cow::from(self.metadata.addr().ip().to_string()))
        } else if key == "principal" {
            Some(sanitize_name(self.metadata.principal()).into())
        } else if key == "node" {
            if let Some(node_name) = self.metadata.node_name() {
                Some(node_name.as_str().into())
            } else {
                warn!("node name is not configured on this node but is used to build a path in Files driver");
                Some("{node}".into())
            }
        } else if key.starts_with("ip:") {
            // unwrap is safe because we just checked that the string contains the separator
            let (_, index_str) = key.split_once(':').unwrap();
            if let Ok(index) = u8::from_str(index_str) {
                Some(Cow::from(self.split_ip(&self.metadata.addr().ip(), index)))
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub struct OutputFiles {
    config: FilesConfiguration,
    tx: mpsc::Sender<WriteFilesMessage>,
}

impl OutputFiles {
    pub fn new(config: &FilesConfiguration, context: &Option<OutputFilesContext>) -> Result<Self> {
        let tx = if let Some(files_context) = context {
            files_context.tx.clone()
        } else {
            bail!("Files output context has not been initialized")
        };

        debug!("Initialize Files driver with config {:?}", config);
        Ok(OutputFiles {
            config: config.clone(),
            tx: tx.clone(),
        })
    }

    fn build_path(&self, metadata: &Arc<EventMetadata>) -> Result<PathBuf> {
        let values = PathValues {
            metadata: metadata.clone(),
        };
        // It would be cool to parse the template only once
        // However, Template::parse takes a reference to a str and has the same
        // lifetime than the str. I don't know how to store that...
        let template = Template::parse(self.config.path())?;
        let path = template.render(&values)?;
        Ok(PathBuf::from_str(&path)?)
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
        let path = self.build_path(&metadata)?;

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

fn sanitize_name(name: &str) -> String {
    // We only allow strings containing at most 255 chars within [a-z][A-Z][0-9][.-_@]
    let mut new_str = String::with_capacity(min(name.len(), 255));

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
    use std::net::{IpAddr, SocketAddr};

    use common::{
        settings,
        subscription::{SubscriptionData, SubscriptionUuid},
    };
    use uuid::Uuid;

    use crate::{output::OutputDriversContext, subscription::Subscription};

    use super::*;

    fn create_event_metadata(
        addr: IpAddr,
        principal: &str,
        node_name: Option<String>,
    ) -> Arc<EventMetadata> {
        let addr = SocketAddr::new(addr, 8080);
        let mut output_context = OutputDriversContext::new(&settings::Outputs::default());
        let mut subscription_data = SubscriptionData::new("Test", "");
        subscription_data
            .set_uuid(SubscriptionUuid(
                Uuid::from_str("8B18D83D-2964-4F35-AC3B-6F4E6FFA727B").unwrap(),
            ))
            .set_uri(Some("/this/is/a/test".to_string()))
            .set_revision(Some("babar".to_string()));
        let subscription = Subscription::from_data(subscription_data, &mut output_context).unwrap();

        Arc::new(EventMetadata::new(
            &addr,
            principal,
            node_name,
            &subscription,
            subscription.public_version_string(),
            None,
        ))
    }

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
        let config = FilesConfiguration::new("/base/{ip}/{principal}/messages".to_string());

        let ip: IpAddr = "127.0.0.1".parse()?;
        let principal = "princ";
        let node = Some("node".to_string());
        let event_metadata_without_node = create_event_metadata(ip, principal, None);
        let event_metadata_with_node = create_event_metadata(ip, principal, node);

        let context = Some(OutputFilesContext::new());

        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/127.0.0.1/princ/messages")?
        );

        let config = FilesConfiguration::new("/base/{ip}/{node}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_with_node)?,
            PathBuf::from_str("/base/127.0.0.1/node/messages")?
        );

        let config =
            FilesConfiguration::new("/base/{ip:1}/{ip:2}/{ip:3}/{ip}/{node}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_with_node)?,
            PathBuf::from_str("/base/127/127.0/127.0.0/127.0.0.1/node/messages")?
        );

        let config =
            FilesConfiguration::new("/base/{ip:2}/{ip:3}/{ip}/{principal}/other".to_string());
        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_with_node)?,
            PathBuf::from_str("/base/127.0/127.0.0/127.0.0.1/princ/other")?
        );

        let config = FilesConfiguration::new("/base/{ip:3}/{ip}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/127.0.0/127.0.0.1/messages")?
        );

        let config = FilesConfiguration::new("/base/{ip:4}/{principal}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/127.0.0.1/princ/messages")?
        );

        let config = FilesConfiguration::new("/base/{ip:5}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/127.0.0.1/messages")?
        );

        let config = FilesConfiguration::new("/base/{node}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;

        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/{node}/messages")?
        );

        let ip: IpAddr = "1:2:3:4:5:6:7:8".parse()?;
        let event_metadata_without_node = create_event_metadata(ip, principal, None);
        let config = FilesConfiguration::new("/base/{ip}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;
        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/1:2:3:4:5:6:7:8/messages")?
        );

        let config = FilesConfiguration::new("/base/{ip:3}/{ip:6}/{ip:8}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;
        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/1:2:3/1:2:3:4:5:6/1:2:3:4:5:6:7:8/messages")?
        );

        let event_metadata_without_node = create_event_metadata(ip, "COMPUTER$@REALM", None);
        let config = FilesConfiguration::new("/base/{principal}/messages".to_string());
        let output_file = OutputFiles::new(&config, &context)?;
        assert_eq!(
            output_file.build_path(&event_metadata_without_node)?,
            PathBuf::from_str("/base/COMPUTER@REALM/messages")?
        );
        Ok(())
    }
}
