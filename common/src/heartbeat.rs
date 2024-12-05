use std::collections::HashMap;

use serde::{ser::SerializeStruct, Serialize, Serializer};

use crate::{subscription::SubscriptionData, utils, utils::Timestamp};

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct HeartbeatData {
    machine: String,
    ip: String,
    #[serde(flatten, serialize_with = "serialize_subscription_data")]
    subscription: SubscriptionData,
    #[serde(serialize_with = "utils::serialize_timestamp")]
    first_seen: Timestamp,
    #[serde(serialize_with = "utils::serialize_timestamp")]
    pub last_seen: Timestamp,
    #[serde(serialize_with = "utils::serialize_option_timestamp")]
    pub last_event_seen: Option<Timestamp>,
}

fn serialize_subscription_data<S>(
    subscription: &SubscriptionData,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("Subscription", 2)?;
    state.serialize_field("subscription_uuid", subscription.uuid())?;
    state.serialize_field("subscription_name", subscription.name())?;
    state.end()
}

impl HeartbeatData {
    pub fn new(
        machine: String,
        ip: String,
        subscription: SubscriptionData,
        first_seen: i64,
        last_seen: i64,
        last_event_seen: Option<i64>,
    ) -> Self {
        HeartbeatData {
            machine,
            ip,
            subscription,
            first_seen,
            last_seen,
            last_event_seen,
        }
    }
    pub fn first_seen(&self) -> i64 {
        self.first_seen
    }

    pub fn last_seen(&self) -> i64 {
        self.last_seen
    }

    pub fn machine(&self) -> &str {
        self.machine.as_ref()
    }

    pub fn ip(&self) -> &str {
        self.ip.as_ref()
    }

    pub fn subscription(&self) -> &SubscriptionData {
        &self.subscription
    }

    pub fn last_event_seen(&self) -> Option<i64> {
        self.last_event_seen
    }
}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct HeartbeatKey {
    pub machine: String,
    pub subscription: String,
}

#[derive(Debug, Clone)]
pub struct HeartbeatValue {
    pub ip: String,
    pub last_seen: u64,
    pub last_event_seen: Option<u64>,
}

pub type HeartbeatsCache = HashMap<HeartbeatKey, HeartbeatValue>;
