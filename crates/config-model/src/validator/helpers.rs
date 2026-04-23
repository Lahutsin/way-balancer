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
