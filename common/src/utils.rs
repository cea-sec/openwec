use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Local, TimeZone};
use log::warn;
use openssl::hash::MessageDigest;
use serde::{ser, Serializer};

pub type Timestamp = i64;

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

pub struct VersionHasher {
    inner: openssl::hash::Hasher,
}

impl VersionHasher {
    pub fn new() -> Result<Self> {
        let hasher = Self {
            inner: openssl::hash::Hasher::new(MessageDigest::sha256())
                .context("Failed to initialize openssl sha256 hasher")?,
        };
        Ok(hasher)
    }
}

impl std::hash::Hasher for VersionHasher {
    fn finish(&self) -> u64 {
        // finish resets the internal buffer, which is not allowed
        // by std::hash::Hasher trait
        let mut inner_cloned = self.inner.clone();
        let hash_opt = inner_cloned.finish().ok();
        match hash_opt {
            Some(hash) => {
                let mut short_buf = [0u8; 8];
                short_buf.copy_from_slice(&hash[..8]);
                u64::from_le_bytes(short_buf)
            },
            None =>
                0u64
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        self.inner.update(bytes).unwrap_or_else(|e| {
            warn!("Failed to update version hash AAA: {}", e);
        });
    }
}
