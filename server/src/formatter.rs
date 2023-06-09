use std::sync::Arc;

use anyhow::{Context, Result};

use crate::event::{Event, EventMetadata};
use common::subscription::SubscriptionOutputFormat;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Format {
    Json,
    Raw,
}

impl From<&SubscriptionOutputFormat> for Format {
    fn from(sof: &SubscriptionOutputFormat) -> Self {
        match sof {
            SubscriptionOutputFormat::Json => Format::Json,
            SubscriptionOutputFormat::Raw => Format::Raw,
        }
    }
}

impl Format {
    pub fn format(&self, metadata: &EventMetadata, raw: Arc<String>) -> Result<Arc<String>> {
        match &self {
            Format::Json => format_json(metadata, raw),
            Format::Raw => format_raw(raw),
        }
    }
}

fn format_json(metadata: &EventMetadata, raw: Arc<String>) -> Result<Arc<String>> {
    let event = Event::from_str(metadata, raw.as_ref())
        .with_context(|| format!("Failed to parse event: {:?}", raw))?;
    Ok(Arc::new(serde_json::to_string(&event).with_context(
        || format!("Failed to format event: {:?}", event),
    )?))
}

fn format_raw(raw: Arc<String>) -> Result<Arc<String>> {
    Ok(raw)
}
