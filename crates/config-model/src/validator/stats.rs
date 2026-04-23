/// Minimal validation counters for config ingestion observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfigValidationStats {
    /// Count of successful validation attempts.
    pub success_count: u64,
    /// Count of schema validation errors observed.
    pub schema_error_count: u64,
    /// Count of semantic validation errors observed.
    pub semantic_error_count: u64,
}

/// Validator wrapper that exposes category counters alongside validation results.
#[derive(Debug, Default)]
pub struct WorkspaceConfigValidator {
    stats: ConfigValidationStats,
}

impl WorkspaceConfigValidator {
    /// Validates the workspace config and records category counters.
    pub fn validate(&mut self, config: &WorkspaceConfig) -> Result<(), ValidationReport> {
        let report = validate_workspace_config(config);
        if report.is_empty() {
            self.stats.success_count = self.stats.success_count.saturating_add(1);
            Ok(())
        } else {
            for error in &report.errors {
                match error.category {
                    ValidationCategory::Schema => {
                        self.stats.schema_error_count =
                            self.stats.schema_error_count.saturating_add(1);
                    }
                    ValidationCategory::Semantic => {
                        self.stats.semantic_error_count =
                            self.stats.semantic_error_count.saturating_add(1);
                    }
                }
            }
            Err(report)
        }
    }

    /// Returns the current validation counters.
    #[must_use]
    pub const fn stats(&self) -> ConfigValidationStats {
        self.stats
    }
}

