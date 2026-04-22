use serde::{Deserialize, Serialize};

/// Declarative upgrade allow-list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct UpgradePolicyConfig {
    /// Explicitly allowed HTTP upgrade protocols.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<UpgradeProtocolConfig>,
}

impl UpgradePolicyConfig {
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.protocols.is_empty()
    }
}

/// Supported HTTP upgrade protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeProtocolConfig {
    Websocket,
}