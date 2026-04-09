use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolAnomalyCategory {
    MalformedPreface,
    MalformedMessage,
    AmbiguousFraming,
    HeadSizeLimitExceeded,
    HeaderCountLimitExceeded,
    BodySizeLimitExceeded,
    StreamConcurrencyLimitExceeded,
}

impl fmt::Display for ProtocolAnomalyCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedPreface => formatter.write_str("malformed-preface"),
            Self::MalformedMessage => formatter.write_str("malformed-message"),
            Self::AmbiguousFraming => formatter.write_str("ambiguous-framing"),
            Self::HeadSizeLimitExceeded => formatter.write_str("head-size-limit-exceeded"),
            Self::HeaderCountLimitExceeded => formatter.write_str("header-count-limit-exceeded"),
            Self::BodySizeLimitExceeded => formatter.write_str("body-size-limit-exceeded"),
            Self::StreamConcurrencyLimitExceeded => {
                formatter.write_str("stream-concurrency-limit-exceeded")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlowClientStage {
    RequestHead,
    RequestBody,
}

impl fmt::Display for SlowClientStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestHead => formatter.write_str("request-head"),
            Self::RequestBody => formatter.write_str("request-body"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtocolAnomalyCategory, SlowClientStage};

    #[test]
    fn anomaly_categories_render_stable_names() {
        assert_eq!(ProtocolAnomalyCategory::MalformedPreface.to_string(), "malformed-preface");
        assert_eq!(ProtocolAnomalyCategory::MalformedMessage.to_string(), "malformed-message");
        assert_eq!(ProtocolAnomalyCategory::AmbiguousFraming.to_string(), "ambiguous-framing");
        assert_eq!(
            ProtocolAnomalyCategory::HeadSizeLimitExceeded.to_string(),
            "head-size-limit-exceeded"
        );
        assert_eq!(
            ProtocolAnomalyCategory::HeaderCountLimitExceeded.to_string(),
            "header-count-limit-exceeded"
        );
        assert_eq!(
            ProtocolAnomalyCategory::BodySizeLimitExceeded.to_string(),
            "body-size-limit-exceeded"
        );
        assert_eq!(
            ProtocolAnomalyCategory::StreamConcurrencyLimitExceeded.to_string(),
            "stream-concurrency-limit-exceeded"
        );
    }

    #[test]
    fn slow_client_stages_render_stable_names() {
        assert_eq!(SlowClientStage::RequestHead.to_string(), "request-head");
        assert_eq!(SlowClientStage::RequestBody.to_string(), "request-body");
    }
}
