use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{Local, SecondsFormat};

use crate::{event::Event, subscription::Subscription, RequestData};
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
    pub fn format(
        &self,
        subscription: Arc<Subscription>,
        request_data: &RequestData,
        raw: Arc<String>,
    ) -> Result<Arc<String>> {
        match &self {
            Format::Json => format_json(subscription, request_data, raw),
            Format::Raw => format_raw(raw),
        }
    }
}

fn format_json(
    subscription: Arc<Subscription>,
    request_data: &RequestData,
    raw: Arc<String>,
) -> Result<Arc<String>> {
    let event = Event::from_str(
        &request_data.remote_addr().ip().to_string(),
        request_data.principal(),
        &Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        subscription.uuid(),
        subscription.version(),
        subscription.data().name(),
        subscription.data().uri(),
        raw.as_ref(),
    )
    .with_context(|| format!("Failed to parse event: {:?}", raw))?;
    Ok(Arc::new(serde_json::to_string(&event).with_context(
        || format!("Failed to format event: {:?}", event),
    )?))
}

fn format_raw(raw: Arc<String>) -> Result<Arc<String>> {
    Ok(raw)
}
