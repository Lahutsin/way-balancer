use std::collections::BTreeMap;

use crate::{RequestClassifierSignal, RequestClassifierSignalKind};

/// Runtime header-anomaly scorer for request classification signals.
#[derive(Debug, Clone)]
pub struct HeaderAnomalyScorer {
    max_header_count: u16,
    max_header_value_length: u16,
    max_duplicate_headers_per_name: u8,
    suspicious_headers: Vec<String>,
    suspicious_user_agent_patterns: Vec<String>,
}

impl HeaderAnomalyScorer {
    #[must_use]
    pub fn from_config(config: &lb_config_model::HeaderAnomalyScoringConfig) -> Self {
        Self {
            max_header_count: config.max_header_count,
            max_header_value_length: config.max_header_value_length,
            max_duplicate_headers_per_name: config.max_duplicate_headers_per_name,
            suspicious_headers: config
                .suspicious_headers
                .iter()
                .map(|entry| entry.to_ascii_lowercase())
                .collect(),
            suspicious_user_agent_patterns: config
                .suspicious_user_agent_patterns
                .iter()
                .map(|entry| entry.to_ascii_lowercase())
                .collect(),
        }
    }

    #[must_use]
    pub fn score_headers<I, N, V>(&self, headers: I) -> Vec<RequestClassifierSignal>
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.as_ref().to_string(), value.as_ref().to_string()))
            .collect::<Vec<_>>();

        let mut signals = Vec::new();
        if headers.len() > self.max_header_count as usize {
            signals.push(RequestClassifierSignal {
                kind: RequestClassifierSignalKind::HeaderAnomaly,
                strength: score_to_u8((headers.len() * 100) / self.max_header_count.max(1) as usize),
                detail: format!(
                    "header count {} exceeds max_header_count {}",
                    headers.len(), self.max_header_count
                ),
            });
        }

        let mut header_occurrences: BTreeMap<String, usize> = BTreeMap::new();
        for (name, value) in &headers {
            let normalized = name.to_ascii_lowercase();
            *header_occurrences.entry(normalized.clone()).or_insert(0) += 1;

            if value.len() > self.max_header_value_length as usize {
                signals.push(RequestClassifierSignal {
                    kind: RequestClassifierSignalKind::HeaderAnomaly,
                    strength: score_to_u8(
                        (value.len() * 100) / self.max_header_value_length.max(1) as usize,
                    ),
                    detail: format!(
                        "header {} value length {} exceeds max_header_value_length {}",
                        normalized,
                        value.len(),
                        self.max_header_value_length
                    ),
                });
            }

            if self
                .suspicious_headers
                .iter()
                .any(|header| header == &normalized)
            {
                signals.push(RequestClassifierSignal {
                    kind: RequestClassifierSignalKind::HeaderAnomaly,
                    strength: 100,
                    detail: format!("suspicious header {} present", normalized),
                });
            }

            if normalized == "user-agent" {
                let ua_lower = value.to_ascii_lowercase();
                for pattern in &self.suspicious_user_agent_patterns {
                    if ua_lower.contains(pattern) {
                        signals.push(RequestClassifierSignal {
                            kind: RequestClassifierSignalKind::UserAgentAnomaly,
                            strength: 100,
                            detail: format!(
                                "user-agent matched suspicious pattern {}",
                                pattern
                            ),
                        });
                    }
                }
            }
        }

        for (name, count) in header_occurrences {
            if count > self.max_duplicate_headers_per_name as usize {
                signals.push(RequestClassifierSignal {
                    kind: RequestClassifierSignalKind::HeaderAnomaly,
                    strength: score_to_u8(
                        (count * 100) / self.max_duplicate_headers_per_name.max(1) as usize,
                    ),
                    detail: format!(
                        "header {} repeated {} times over max_duplicate_headers_per_name {}",
                        name, count, self.max_duplicate_headers_per_name
                    ),
                });
            }
        }

        signals
    }
}

fn score_to_u8(score: usize) -> u8 {
    score.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::HeaderAnomalyScorer;
    use crate::RequestClassifierSignalKind;

    fn scorer() -> HeaderAnomalyScorer {
        HeaderAnomalyScorer::from_config(&lb_config_model::HeaderAnomalyScoringConfig {
            max_header_count: 4,
            max_header_value_length: 16,
            max_duplicate_headers_per_name: 2,
            suspicious_headers: vec![String::from("x-original-url")],
            suspicious_user_agent_patterns: vec![String::from("sqlmap")],
        })
    }

    #[test]
    fn header_anomaly_scoring_detects_suspicious_headers_and_user_agents() {
        let scorer = scorer();
        let signals = scorer.score_headers([
            ("user-agent", "sqlmap/1.0"),
            ("x-original-url", "/admin"),
        ]);

        assert!(signals.iter().any(|signal| {
            signal.kind == RequestClassifierSignalKind::HeaderAnomaly
                && signal.detail.contains("suspicious header")
        }));
        assert!(signals.iter().any(|signal| {
            signal.kind == RequestClassifierSignalKind::UserAgentAnomaly
                && signal.detail.contains("suspicious pattern")
        }));
    }

    #[test]
    fn header_anomaly_scoring_respects_false_positive_sensitive_thresholds() {
        let scorer = scorer();
        let no_signal = scorer.score_headers([
            ("accept", "application/json"),
            ("user-agent", "Mozilla/5.0"),
            ("x-request-id", "abc123"),
        ]);
        assert!(no_signal.is_empty());

        let signals = scorer.score_headers([
            ("x-request-id", "a"),
            ("x-request-id", "b"),
            ("x-request-id", "c"),
            ("x-extra", "short"),
            ("x-over", "this-value-is-way-too-long-for-threshold"),
        ]);
        assert!(signals.iter().any(|signal| signal.detail.contains("repeated")));
        assert!(signals.iter().any(|signal| signal.detail.contains("value length")));
        assert!(signals.iter().any(|signal| signal.detail.contains("header count")));
    }
}
