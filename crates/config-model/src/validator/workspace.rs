pub(crate) fn validate_workspace_config(config: &WorkspaceConfig) -> ValidationReport {
    let mut report = ValidationReport::default();

    validate_workspace_basics(config, &mut report);
    validate_defaults(config, &mut report);
    validate_security(config, &mut report);

    let _listener_names = collect_named_resources(
        config.listeners.iter().enumerate().map(|(index, listener)| {
            (listener.name.clone(), format!("listeners[{index}].name"), "listener")
        }),
        &mut report,
    );
    let route_names =
        collect_named_resources(
            config.routes.iter().enumerate().map(|(index, route)| {
                (route.name.clone(), format!("routes[{index}].name"), "route")
            }),
            &mut report,
        );
    let route_registry = config
        .routes
        .iter()
        .map(|route| (route.name.clone(), route))
        .collect::<BTreeMap<_, _>>();
    let upstream_names = collect_named_resources(
        config.upstream_clusters.iter().enumerate().map(|(index, cluster)| {
            (cluster.name.clone(), format!("upstream_clusters[{index}].name"), "upstream cluster")
        }),
        &mut report,
    );

    let policy_registry = PolicyRegistry::new(&config.policies, &upstream_names, &mut report);

    for (index, listener) in config.listeners.iter().enumerate() {
        validate_listener(
            listener,
            index,
            &route_names,
            &route_registry,
            &policy_registry,
            &mut report,
        );
    }
    for (index, route) in config.routes.iter().enumerate() {
        validate_route(route, index, &upstream_names, &policy_registry, &mut report);
    }
    for (index, cluster) in config.upstream_clusters.iter().enumerate() {
        validate_upstream_cluster(cluster, index, &policy_registry, &mut report);
    }

    report
}

