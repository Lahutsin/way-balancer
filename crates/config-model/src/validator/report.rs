/// Stable validation error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCategory {
    /// Structural and resource-local validation failure.
    Schema,
    /// Cross-resource semantic validation failure.
    Semantic,
}

/// Stable machine-readable validation code catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    EmptyWorkspaceName,
    InvalidListenerDefaults,
    InvalidHttp1Defaults,
    InvalidHttp2Defaults,
    InvalidSecurityDefaults,
    InsecureModeGated,
    EmptyResourceName,
    DuplicateResourceName,
    InvalidListenerField,
    InvalidRouteMatch,
    InvalidUpstreamField,
    InvalidPolicyField,
    InvalidPolicyReference,
    DuplicatePolicyReference,
    InvalidPolicyScope,
    InvalidRouteReference,
    InvalidUpstreamReference,
    UnsupportedListenerRouting,
}

/// Actionable config validation error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationError {
    /// Validation category.
    pub category: ValidationCategory,
    /// Stable machine-readable validation code.
    pub code: ValidationCode,
    /// Resource path in the config document.
    pub path: String,
    /// Operator-facing actionable message.
    pub message: String,
}

impl ValidationError {
    fn schema(code: ValidationCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            category: ValidationCategory::Schema,
            code,
            path: path.into(),
            message: message.into(),
        }
    }

    fn semantic(code: ValidationCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            category: ValidationCategory::Semantic,
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Stable machine-readable validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ValidationReport {
    /// Ordered validation errors.
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    #[must_use]
    pub fn operator_summary(&self) -> String {
        self.errors
            .iter()
            .map(|error| {
                format!(
                    "{:?} {:?} at {}: {}",
                    error.category, error.code, error.path, error.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl std::fmt::Display for ValidationReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors.is_empty() {
            formatter.write_str("configuration validation succeeded")
        } else {
            formatter.write_str(&self.operator_summary())
        }
    }
}

impl std::error::Error for ValidationReport {}
