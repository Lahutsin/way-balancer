fn register_policy_name(
    name: &str,
    path: &str,
    resource_kind: &str,
    known: &mut BTreeSet<String>,
    report: &mut ValidationReport,
) {
    let normalized = name.trim();
    if normalized.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::EmptyResourceName,
            path,
            format!("{resource_kind} name must not be empty"),
        ));
        return;
    }
    if !known.insert(normalized.to_string()) {
        report.errors.push(ValidationError::schema(
            ValidationCode::DuplicateResourceName,
            path,
            format!("duplicate {resource_kind} name {normalized}"),
        ));
    }
}

fn normalize_component(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod helpers_coverage_regressions {
    use super::{ValidationCode, ValidationReport, normalize_component, register_policy_name};
    use std::collections::BTreeSet;

    #[test]
    fn normalizes_names_and_reports_empty_and_duplicate_policy_names() {
        assert_eq!(normalize_component("  API-Gateway  "), "api-gateway");
        let mut names = BTreeSet::new();
        let mut report = ValidationReport::default();
        register_policy_name(
            " retry ",
            "policies[0].name",
            "retry policy",
            &mut names,
            &mut report,
        );
        register_policy_name("retry", "policies[1].name", "retry policy", &mut names, &mut report);
        register_policy_name(" \t ", "policies[2].name", "retry policy", &mut names, &mut report);
        assert_eq!(names, BTreeSet::from([String::from("retry")]));
        assert_eq!(report.errors[0].code, ValidationCode::DuplicateResourceName);
        assert_eq!(report.errors[1].code, ValidationCode::EmptyResourceName);
    }
}
