use anyhow::{anyhow, Result};
use chrono::{DateTime, Local, TimeZone};
use serde::{ser, Serializer};
use uuid::Uuid;

pub type Timestamp = i64;

pub fn new_uuid() -> String {
    format!("uuid:{}", Uuid::new_v4().to_string().to_uppercase())
}

pub fn timestamp_to_local_date(ts: i64) -> Result<DateTime<Local>> {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .ok_or_else(|| anyhow!("Invalid or ambiguous timestamp"))
}

pub fn serialize_timestamp<S>(timestamp: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let text = timestamp_to_local_date(*timestamp)
        .map_err(|err| {
            ser::Error::custom(format!("Could not retrieve date from timestamp: {}", err))
        })?
        .to_rfc3339();
    serializer.serialize_str(&text)
}

pub fn serialize_option_timestamp<S>(
    opt_ts: &Option<Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match opt_ts {
        Some(ts) => serialize_timestamp(ts, serializer),
        None => serializer.serialize_none(),
    }
}
