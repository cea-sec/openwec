use anyhow::{bail, Context, Result};
use common::{models::config::parse, subscription::SubscriptionData};
use log::info;
use std::{
    fs::{self},
    path::{Path, PathBuf},
};

fn visit_dirs(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        bail!("{} does not exist", path.display());
    }
    let mut config_files = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                config_files.append(&mut visit_dirs(&path)?);
            } else {
                config_files.push(entry.path())
            }
        }
    } else if path.is_file() {
        config_files.push(path.to_path_buf())
    }
    Ok(config_files)
}
pub fn load_from_path(path: &str, revision: Option<&String>) -> Result<Vec<SubscriptionData>> {
    let mut subscriptions = Vec::new();

    let root = Path::new(path);
    let config_files = visit_dirs(root).context("Failed to config load files")?;

    info!("Found config files: {:?}", config_files);
    for path in config_files {
        let content =
            fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))?;
        let content_str = String::from_utf8(content).with_context(|| {
            format!(
                "Failed to decode the content of {} using UTF-8",
                path.display()
            )
        })?;

        let subscription: SubscriptionData = parse(&content_str, revision)
            .with_context(|| format!("Failed to parse file {}", path.display()))?;
        info!(
            "{}: {} (uuid: {}, version: {})",
            path.display(),
            subscription.name(),
            subscription.uuid(),
            subscription.public_version()?
        );
        subscriptions.push(subscription);
    }

    Ok(subscriptions)
}
