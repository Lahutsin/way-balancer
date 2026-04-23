fn collect_named_resources<I>(entries: I, report: &mut ValidationReport) -> BTreeSet<String>
where
    I: IntoIterator<Item = (String, String, &'static str)>,
{
    let mut names = BTreeSet::new();
    for (name, path, resource_kind) in entries {
        let normalized = name.trim();
        if normalized.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::EmptyResourceName,
                path,
                format!("{resource_kind} name must not be empty"),
            ));
            continue;
        }
        if !names.insert(normalized.to_string()) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                path,
                format!("duplicate {resource_kind} name {normalized}"),
            ));
        }
    }
    names
}

