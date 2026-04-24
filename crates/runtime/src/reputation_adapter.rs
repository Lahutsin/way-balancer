use std::fmt;
use std::sync::Arc;

use crate::{RequestClassifierSignal, RequestClassifierSignalKind};

/// Input context forwarded to reputation providers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReputationSignalInput {
    pub source_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
}

/// Normalized verdict returned by a reputation provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationVerdict {
    Trusted,
    Suspicious,
    Malicious,
    Unknown,
}

/// Pluggable reputation provider contract.
pub trait ReputationSignalProvider: Send + Sync {
    fn provider_name(&self) -> &str;

    fn evaluate(&self, input: &ReputationSignalInput) -> Result<ReputationVerdict, String>;
}

/// Provider chain and fallback policy for reputation ingestion.
#[derive(Clone, Default)]
pub struct ReputationAdapterChain {
    providers: Vec<Arc<dyn ReputationSignalProvider>>,
    fallback_strength: Option<u8>,
}

impl fmt::Debug for ReputationAdapterChain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReputationAdapterChain")
            .field("provider_count", &self.providers.len())
            .field("fallback_strength", &self.fallback_strength)
            .finish()
    }
}

impl ReputationAdapterChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_provider(mut self, provider: Arc<dyn ReputationSignalProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    #[must_use]
    pub fn with_fallback_strength(mut self, fallback_strength: u8) -> Self {
        self.fallback_strength = Some(fallback_strength.min(100));
        self
    }

    #[must_use]
    pub fn score(&self, input: &ReputationSignalInput) -> Vec<RequestClassifierSignal> {
        let mut signals = Vec::new();
        for provider in &self.providers {
            match provider.evaluate(input) {
                Ok(ReputationVerdict::Trusted | ReputationVerdict::Unknown) => {}
                Ok(ReputationVerdict::Suspicious) => signals.push(RequestClassifierSignal {
                    kind: RequestClassifierSignalKind::Reputation,
                    strength: 45,
                    detail: format!(
                        "reputation provider {} reported suspicious source",
                        provider.provider_name()
                    ),
                }),
                Ok(ReputationVerdict::Malicious) => signals.push(RequestClassifierSignal {
                    kind: RequestClassifierSignalKind::Reputation,
                    strength: 90,
                    detail: format!(
                        "reputation provider {} reported malicious source",
                        provider.provider_name()
                    ),
                }),
                Err(reason) => {
                    if let Some(fallback_strength) = self.fallback_strength {
                        if fallback_strength > 0 {
                            signals.push(RequestClassifierSignal {
                                kind: RequestClassifierSignalKind::Reputation,
                                strength: fallback_strength,
                                detail: format!(
                                    "reputation provider {} failed ({}); fallback signal applied",
                                    provider.provider_name(),
                                    reason
                                ),
                            });
                        }
                    }
                }
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        ReputationAdapterChain, ReputationSignalInput, ReputationSignalProvider, ReputationVerdict,
    };

    struct StaticReputationProvider {
        name: String,
        verdict: ReputationVerdict,
    }

    impl StaticReputationProvider {
        fn new(name: &str, verdict: ReputationVerdict) -> Self {
            Self {
                name: name.to_string(),
                verdict,
            }
        }
    }

    impl ReputationSignalProvider for StaticReputationProvider {
        fn provider_name(&self) -> &str {
            &self.name
        }

        fn evaluate(&self, _input: &ReputationSignalInput) -> Result<ReputationVerdict, String> {
            Ok(self.verdict)
        }
    }

    struct FailingReputationProvider {
        name: String,
    }

    impl ReputationSignalProvider for FailingReputationProvider {
        fn provider_name(&self) -> &str {
            &self.name
        }

        fn evaluate(&self, _input: &ReputationSignalInput) -> Result<ReputationVerdict, String> {
            Err(String::from("upstream unavailable"))
        }
    }

    #[test]
    fn reputation_adapter_emits_signal_for_malicious_verdict() {
        let adapter = ReputationAdapterChain::new().with_provider(Arc::new(
            StaticReputationProvider::new("threat-db", ReputationVerdict::Malicious),
        ));

        let signals = adapter.score(&ReputationSignalInput::default());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].strength, 90);
        assert!(signals[0].detail.contains("threat-db"));
    }

    #[test]
    fn reputation_adapter_emits_fallback_when_provider_fails() {
        let adapter = ReputationAdapterChain::new()
            .with_provider(Arc::new(FailingReputationProvider {
                name: String::from("remote-feed"),
            }))
            .with_fallback_strength(55);

        let signals = adapter.score(&ReputationSignalInput::default());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].strength, 55);
        assert!(signals[0].detail.contains("fallback signal applied"));
    }
}
