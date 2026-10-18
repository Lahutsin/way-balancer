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

#[cfg(test)]
mod resource_collection_coverage_regressions {
    use super::{ValidationCode, ValidationReport, collect_named_resources};

    #[test]
    fn trims_names_and_reports_empty_and_duplicate_entries() {
        let mut report = ValidationReport::default();
        let names = collect_named_resources(
            [
                (String::from(" cache "), String::from("caches[0].name"), "cache"),
                (String::from("cache"), String::from("caches[1].name"), "cache"),
                (String::from("  "), String::from("caches[2].name"), "cache"),
                (String::from("origin"), String::from("caches[3].name"), "cache"),
            ],
            &mut report,
        );
        assert_eq!(
            names,
            std::collections::BTreeSet::from([String::from("cache"), String::from("origin")])
        );
        assert_eq!(report.errors[0].code, ValidationCode::DuplicateResourceName);
        assert_eq!(report.errors[1].code, ValidationCode::EmptyResourceName);
    }
}
