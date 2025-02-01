use serde::{Deserialize, Serialize};
use crate::subscription::*;

use super::VERSION;

#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct SubscriptionRedisData {
    version: String,
    uuid: SubscriptionUuid,
    internal_version: InternalVersion,
    revision: Option<String>,
    uri: Option<String>,
    enabled: bool,
    princs_filter: PrincsFilter,
    parameters: SubscriptionParameters,
    outputs: Vec<SubscriptionOutput>,
}

impl SubscriptionRedisData {
    pub fn from_subscription_data(from: &SubscriptionData) -> Self {
        Self {
            version: VERSION.to_string(),
            uuid: *from.uuid(),
            internal_version: from.internal_version(),
            revision: from.revision().cloned(),
            uri: from.uri().cloned(),
            enabled: from.enabled(),
            princs_filter: from.princs_filter().clone(),
            parameters: from.parameters().clone(),
            outputs: from.outputs().to_vec(),
        }
    }
    pub fn into_subscription_data(self) -> SubscriptionData {
        let mut sd = SubscriptionData::new(&self.parameters.name, &self.parameters.query);
        sd.set_revision(self.revision).
        set_uuid(self.uuid).
        set_uri(self.uri).
        set_enabled(self.enabled).
        set_princs_filter(self.princs_filter).
        set_parameters(self.parameters).
        set_outputs(self.outputs);
        sd.set_internal_version(self.internal_version);
        sd
    }
}
