use std::fmt;
use std::sync::Arc;

use crate::{RequestClassifierSignal, RequestClassifierSignalKind};

/// Input context forwarded to bot-signal providers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BotSignalInput {
    pub source_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub header_count: u16,
}

/// Normalized verdict returned by a bot-signal provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotSignalVerdict {
    HumanLike,
    AutomationLikely,
    AutomationConfirmed,
    Unknown,
}

/// Pluggable bot-signal provider contract.
pub trait BotSignalProvider: Send + Sync {
    fn provider_name(&self) -> &str;

    fn evaluate(&self, input: &BotSignalInput) -> Result<BotSignalVerdict, String>;
}

/// Provider chain and fallback policy for bot-signal ingestion.
#[derive(Clone, Default)]
pub struct BotSignalAdapterChain {
    providers: Vec<Arc<dyn BotSignalProvider>>,
    fallback_strength: Option<u8>,
}

impl fmt::Debug for BotSignalAdapterChain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BotSignalAdapterChain")
            .field("provider_count", &self.providers.len())
            .field("fallback_strength", &self.fallback_strength)
            .finish()
    }
}

impl BotSignalAdapterChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_provider(mut self, provider: Arc<dyn BotSignalProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    #[must_use]
    pub fn with_fallback_strength(mut self, fallback_strength: u8) -> Self {
        self.fallback_strength = Some(fallback_strength.min(100));
        self
    }

    #[must_use]
    pub fn score(&self, input: &BotSignalInput) -> Vec<RequestClassifierSignal> {
        let mut signals = Vec::new();
        for provider in &self.providers {
            match provider.evaluate(input) {
                Ok(BotSignalVerdict::HumanLike | BotSignalVerdict::Unknown) => {}
                Ok(BotSignalVerdict::AutomationLikely) => signals.push(RequestClassifierSignal {
                    kind: RequestClassifierSignalKind::BotSignal,
                    strength: 55,
                    detail: format!(
                        "bot provider {} reported likely automation",
                        provider.provider_name()
                    ),
                }),
                Ok(BotSignalVerdict::AutomationConfirmed) => {
                    signals.push(RequestClassifierSignal {
                        kind: RequestClassifierSignalKind::BotSignal,
                        strength: 85,
                        detail: format!(
                            "bot provider {} reported confirmed automation",
                            provider.provider_name()
                        ),
                    })
                }
                Err(reason) => {
                    if let Some(fallback_strength) = self.fallback_strength {
                        if fallback_strength > 0 {
                            signals.push(RequestClassifierSignal {
                                kind: RequestClassifierSignalKind::BotSignal,
                                strength: fallback_strength,
                                detail: format!(
                                    "bot provider {} failed ({}); fallback signal applied",
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

    use super::{BotSignalAdapterChain, BotSignalInput, BotSignalProvider, BotSignalVerdict};

    struct StaticBotProvider {
        name: String,
        verdict: BotSignalVerdict,
    }

    impl StaticBotProvider {
        fn new(name: &str, verdict: BotSignalVerdict) -> Self {
            Self {
                name: name.to_string(),
                verdict,
            }
        }
    }

    impl BotSignalProvider for StaticBotProvider {
        fn provider_name(&self) -> &str {
            &self.name
        }

        fn evaluate(&self, _input: &BotSignalInput) -> Result<BotSignalVerdict, String> {
            Ok(self.verdict)
        }
    }

    struct FailingBotProvider {
        name: String,
    }

    impl BotSignalProvider for FailingBotProvider {
        fn provider_name(&self) -> &str {
            &self.name
        }

        fn evaluate(&self, _input: &BotSignalInput) -> Result<BotSignalVerdict, String> {
            Err(String::from("provider timeout"))
        }
    }

    #[test]
    fn bot_signal_adapter_emits_signal_for_automation_verdict() {
        let adapter = BotSignalAdapterChain::new().with_provider(Arc::new(StaticBotProvider::new(
            "fingerprint",
            BotSignalVerdict::AutomationConfirmed,
        )));

        let signals = adapter.score(&BotSignalInput::default());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].strength, 85);
        assert!(signals[0].detail.contains("fingerprint"));
    }

    #[test]
    fn bot_signal_adapter_emits_fallback_when_provider_fails() {
        let adapter = BotSignalAdapterChain::new()
            .with_provider(Arc::new(FailingBotProvider {
                name: String::from("vendor-botnet"),
            }))
            .with_fallback_strength(40);

        let signals = adapter.score(&BotSignalInput::default());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].strength, 40);
        assert!(signals[0].detail.contains("fallback signal applied"));
    }
}
