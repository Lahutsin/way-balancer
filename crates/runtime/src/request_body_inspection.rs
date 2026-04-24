use crate::{RequestClassifierSignal, RequestClassifierSignalKind};

/// Bounded body-inspection scorer for request classification.
#[derive(Debug, Clone)]
pub struct RequestBodyInspector {
    config: lb_config_model::BodyInspectionScoringConfig,
    suspicious_patterns: Vec<String>,
    allowlisted_content_types: Vec<String>,
}

impl RequestBodyInspector {
    #[must_use]
    pub fn from_config(config: &lb_config_model::BodyInspectionScoringConfig) -> Self {
        Self {
            config: config.clone(),
            suspicious_patterns: config
                .suspicious_patterns
                .iter()
                .map(|pattern| pattern.trim().to_ascii_lowercase())
                .filter(|pattern| !pattern.is_empty())
                .collect(),
            allowlisted_content_types: config
                .allowlisted_content_types
                .iter()
                .map(|content_type| content_type.trim().to_ascii_lowercase())
                .filter(|content_type| !content_type.is_empty())
                .collect(),
        }
    }

    #[must_use]
    pub fn score_body(&self, body: &[u8], content_type: Option<&str>) -> Vec<RequestClassifierSignal> {
        let mut signals = Vec::new();

        if body.len() as u32 > self.config.max_body_bytes {
            signals.push(RequestClassifierSignal {
                kind: RequestClassifierSignalKind::BodyAnomaly,
                strength: 100,
                detail: format!(
                    "request body size {} exceeded configured max_body_bytes {}",
                    body.len(),
                    self.config.max_body_bytes
                ),
            });
        }

        let normalized_content_type = content_type
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let allowlisted = self
            .allowlisted_content_types
            .iter()
            .any(|prefix| normalized_content_type.starts_with(prefix));

        if allowlisted {
            return signals;
        }

        let inspect_len = (body.len() as u32).min(self.config.max_inspect_bytes) as usize;
        if inspect_len == 0 {
            return signals;
        }

        let inspected = &body[..inspect_len];
        let inspected_text = String::from_utf8_lossy(inspected).to_ascii_lowercase();

        let mut pattern_hits = 0u8;
        for pattern in &self.suspicious_patterns {
            if pattern.len() < self.config.min_suspicious_token_length as usize {
                continue;
            }
            if inspected_text.contains(pattern) {
                pattern_hits = pattern_hits.saturating_add(1);
            }
        }

        if pattern_hits > 0 {
            let strength = 25u8.saturating_add(pattern_hits.saturating_mul(20)).min(100);
            signals.push(RequestClassifierSignal {
                kind: RequestClassifierSignalKind::BodyAnomaly,
                strength,
                detail: format!(
                    "body inspection matched {} suspicious pattern(s) within {} inspected bytes",
                    pattern_hits, inspect_len
                ),
            });
        }

        if content_type_looks_textual(&normalized_content_type) {
            let non_printable = inspected.iter().filter(|byte| is_non_printable(**byte)).count();
            if non_printable.saturating_mul(100) / inspect_len > 35 {
                signals.push(RequestClassifierSignal {
                    kind: RequestClassifierSignalKind::BodyAnomaly,
                    strength: 45,
                    detail: String::from(
                        "textual request payload appears binary or highly obfuscated",
                    ),
                });
            }
        }

        signals
    }
}

fn content_type_looks_textual(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("form")
}

fn is_non_printable(byte: u8) -> bool {
    matches!(byte, 0..=8 | 11 | 12 | 14..=31)
}

#[cfg(test)]
mod tests {
    use super::RequestBodyInspector;
    use crate::RequestClassifierSignalKind;

    #[test]
    fn body_inspection_is_bounded_and_detects_size_overflow() {
        let config = lb_config_model::BodyInspectionScoringConfig {
            max_inspect_bytes: 16,
            max_body_bytes: 32,
            min_suspicious_token_length: 6,
            suspicious_patterns: vec![String::from("drop table")],
            allowlisted_content_types: Vec::new(),
        };
        let inspector = RequestBodyInspector::from_config(&config);
        let payload = b"DROP TABLE users; -- plus more data for overflow";

        let signals = inspector.score_body(payload, Some("application/json"));

        assert!(signals
            .iter()
            .any(|signal| signal.detail.contains("max_body_bytes")));
        assert!(signals
            .iter()
            .any(|signal| signal.detail.contains("16 inspected bytes")));
    }

    #[test]
    fn body_inspection_uses_content_type_allowlist_for_false_positive_sensitive_paths() {
        let config = lb_config_model::BodyInspectionScoringConfig {
            suspicious_patterns: vec![String::from("union select")],
            allowlisted_content_types: vec![String::from("application/grpc")],
            ..lb_config_model::BodyInspectionScoringConfig::default()
        };
        let inspector = RequestBodyInspector::from_config(&config);

        let signals = inspector.score_body(
            b"union select 1,2,3",
            Some("application/grpc+proto"),
        );

        assert!(signals.is_empty());
    }

    #[test]
    fn body_inspection_detects_binary_like_payload_for_text_content_type() {
        let inspector = RequestBodyInspector::from_config(
            &lb_config_model::BodyInspectionScoringConfig::default(),
        );
        let payload = [0u8, 2, 3, 4, 5, 6, 7, 8, 120, 121, 122];

        let signals = inspector.score_body(&payload, Some("text/plain"));

        assert!(signals.iter().any(|signal| {
            signal.kind == RequestClassifierSignalKind::BodyAnomaly
                && signal.detail.contains("appears binary")
        }));
    }
}
