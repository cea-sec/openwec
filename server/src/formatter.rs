use std::sync::Arc;

use log::warn;

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
    pub fn format(&self, metadata: &EventMetadata, raw: Arc<String>) -> Option<Arc<String>> {
        // Formatters are allowed to return None when they can't do
        // anything else...
        match &self {
            Format::Json => format_json(metadata, raw),
            Format::Raw => Some(raw),
        }
    }
}

fn format_json(metadata: &EventMetadata, raw: Arc<String>) -> Option<Arc<String>> {
    let event = Event::from_str(metadata, raw.as_ref());
    match serde_json::to_string(&event) {
        Ok(str) => Some(Arc::new(str)),
        Err(e) => {
            warn!(
                "Failed to serialize event in JSON: {:?}. Event was: {:?}",
                e, event
            );
            None
        }
    }
}
