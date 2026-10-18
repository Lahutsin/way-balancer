#[derive(Clone)]
struct HttpCacheScopeRuntime {
    service: Arc<Mutex<lb_admin_api::HttpCacheAdminService>>,
    store: Arc<lb_runtime::HttpCacheStore>,
}

impl std::fmt::Debug for HttpCacheScopeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HttpCacheScopeRuntime(..)")
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AdminHttpCachePurgeTarget {
    ExactKey { key_material: String },
    PathPrefix { path_prefix: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminHttpCachePurgeRequest {
    scope: String,
    target: AdminHttpCachePurgeTarget,
    requested_by: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminHttpCachePurgeResponse {
    action: String,
    result: String,
    scope: String,
    purged_entries: usize,
    fanout_transport: Option<String>,
    fanout_subscriber_count: usize,
    fanout_delivery_success_count: usize,
    fanout_delivery_failure_count: usize,
    fanout_duplicate_count: usize,
    fanout_failed_targets: Vec<String>,
    degraded: bool,
    invalidation_event_id: Option<String>,
    occurred_at_unix_ms: u64,
}

async fn handle_admin_cache_purge(
    state: &WorkspaceServeState,
    request_body: &[u8],
) -> Result<AdminHttpCachePurgeResponse, String> {
    let request = serde_json::from_slice::<AdminHttpCachePurgeRequest>(request_body)
        .map_err(|error| format!("invalid cache purge request body: {error}"))?;
    let scope = state
        .http_cache_scope(&request.scope)
        .await
        .ok_or_else(|| format!("unknown cache scope {}", request.scope))?;
    let target = match request.target {
        AdminHttpCachePurgeTarget::ExactKey { key_material } => {
            lb_admin_api::HttpCachePurgeTarget::ExactKey(
                lb_runtime::HttpCacheKey::new(key_material)
                    .map_err(|error| format!("invalid exact cache key material: {error}"))?,
            )
        }
        AdminHttpCachePurgeTarget::PathPrefix { path_prefix } => {
            lb_admin_api::HttpCachePurgeTarget::PathPrefix(path_prefix)
        }
    };
    let telemetry = Arc::clone(&state.telemetry);
    let service = Arc::clone(&scope.service);
    let response = tokio::task::spawn_blocking(move || {
        service.blocking_lock().purge(
            lb_admin_api::HttpCachePurgeRequest {
                target,
                requested_by: request.requested_by,
                reason: request.reason,
            },
            Some(telemetry.as_ref()),
        )
    })
    .await
    .map_err(|error| format!("cache purge task failed: {error}"))?
    .map_err(|error| error.to_string())?;
    Ok(AdminHttpCachePurgeResponse {
        action: match response.action {
            lb_admin_api::HttpCachePurgeActionKind::ExactKey => String::from("exact_key"),
            lb_admin_api::HttpCachePurgeActionKind::PathPrefix => String::from("path_prefix"),
        },
        result: match response.result {
            lb_admin_api::HttpCachePurgeResultKind::Purged => String::from("purged"),
            lb_admin_api::HttpCachePurgeResultKind::NoMatch => String::from("no_match"),
            lb_admin_api::HttpCachePurgeResultKind::Rejected => String::from("rejected"),
        },
        scope: response.scope,
        purged_entries: response.purged_entries,
        fanout_transport: response.fanout_transport,
        fanout_subscriber_count: response.fanout_subscriber_count,
        fanout_delivery_success_count: response.fanout_delivery_success_count,
        fanout_delivery_failure_count: response.fanout_delivery_failure_count,
        fanout_duplicate_count: response.fanout_duplicate_count,
        fanout_failed_targets: response.fanout_failed_targets,
        degraded: response.degraded,
        invalidation_event_id: response.invalidation_event_id,
        occurred_at_unix_ms: response.occurred_at_unix_ms,
    })
}

async fn handle_admin_cache_invalidate(
    state: &WorkspaceServeState,
    request_body: &[u8],
) -> Result<lb_admin_api::HttpCachePeerInvalidationResponse, String> {
    let event = serde_json::from_slice::<lb_runtime::HttpCacheInvalidationEvent>(request_body)
        .map_err(|error| format!("invalid cache invalidation event body: {error}"))?;
    let scope = state
        .http_cache_scope(&event.scope)
        .await
        .ok_or_else(|| format!("unknown cache scope {}", event.scope))?;
    let apply = scope.store.apply_invalidation_event(&event).map_err(|error| error.to_string())?;
    let (result, purged_entries) = match apply {
        lb_runtime::HttpCacheInvalidationApplyResult::Applied { purged_entries } => {
            (lb_admin_api::HttpCachePeerInvalidationResult::Applied, purged_entries)
        }
        lb_runtime::HttpCacheInvalidationApplyResult::Duplicate => {
            (lb_admin_api::HttpCachePeerInvalidationResult::Duplicate, 0)
        }
    };
    Ok(lb_admin_api::HttpCachePeerInvalidationResponse {
        result,
        event_id: event.event_id,
        scope: event.scope,
        purged_entries,
        occurred_at_unix_ms: event.occurred_at_unix_ms,
    })
}

fn resolve_listener_http_cache_policy(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<Option<(String, lb_config_model::HttpCachePolicyConfig)>, DynError> {
    if let Some(cache_policy_name) = listener.policies.cache_policy.as_ref() {
        let policy = config
            .policies
            .http_caches
            .iter()
            .find(|policy| policy.name == *cache_policy_name)
            .ok_or_else(|| {
                to_dyn_error(format!(
                    "listener {} references unknown http cache policy {}",
                    listener.name, cache_policy_name
                ))
            })?;
        return Ok(Some((policy.name.clone(), policy.spec.clone())));
    }

    let mut route_cache_policy_names = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .and_then(|route| route.policies.cache_policy.clone())
        })
        .collect::<BTreeSet<_>>();

    if route_cache_policy_names.is_empty() {
        return Ok(None);
    }
    if route_cache_policy_names.len() > 1 {
        return Err(to_dyn_error(format!(
            "listener {} references multiple route-level http cache policies, which serve mode does not support on a single listener",
            listener.name
        )));
    }
    let Some(cache_policy_name) = route_cache_policy_names.pop_first() else {
        return Ok(None);
    };
    let policy = config
        .policies
        .http_caches
        .iter()
        .find(|policy| policy.name == cache_policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!(
                "listener {} references unknown http cache policy {}",
                listener.name, cache_policy_name
            ))
        })?;
    Ok(Some((policy.name.clone(), policy.spec.clone())))
}

fn build_http_cache_store(
    policy: &lb_config_model::HttpCachePolicyConfig,
) -> Result<Arc<lb_runtime::HttpCacheStore>, DynError> {
    let (max_entries, max_bytes) = match policy.storage {
        lb_config_model::HttpCacheStorageConfig::Memory { max_entries, max_bytes } => {
            (max_entries, usize::try_from(max_bytes).map_err(to_dyn_error)?)
        }
    };
    let max_object_bytes = usize::try_from(policy.max_object_bytes).map_err(to_dyn_error)?;
    lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
        max_entries,
        max_bytes,
        max_object_bytes,
    })
    .map(Arc::new)
    .map_err(to_dyn_error)
}

#[cfg(test)]
mod http_cache_scope_tests {
    use super::{
        handle_admin_cache_invalidate, handle_admin_cache_purge,
        resolve_listener_http_cache_policy, WorkspaceServeState,
    };

    #[tokio::test]
    async fn cache_admin_handlers_report_invalid_bodies_and_missing_scopes() {
        let state = WorkspaceServeState::new(String::from("unused-test-config")).unwrap();
        let error = handle_admin_cache_purge(&state, b"{").await.err().unwrap();
        assert!(error.starts_with("invalid cache purge request body:"));
        let purge = serde_json::json!({
            "scope": "missing",
            "target": {"type": "path_prefix", "path_prefix": "/assets"},
        });
        assert_eq!(
            handle_admin_cache_purge(&state, &serde_json::to_vec(&purge).unwrap())
                .await
                .err()
                .unwrap(),
            "unknown cache scope missing"
        );

        let error = handle_admin_cache_invalidate(&state, b"{}").await.err().unwrap();
        assert!(error.starts_with("invalid cache invalidation event body:"));
        let event = serde_json::json!({
            "event_id": "event-1",
            "scope": "missing",
            "issuer": "peer-a",
            "target": {"PathPrefix": "/assets"},
            "occurred_at_unix_ms": 1,
        });
        assert_eq!(
            handle_admin_cache_invalidate(&state, &serde_json::to_vec(&event).unwrap())
                .await
                .err()
                .unwrap(),
            "unknown cache scope missing"
        );
    }

    #[test]
    fn cache_policy_resolution_handles_absence_and_bad_listener_binding() {
        let config = lb_config_model::WorkspaceConfig::foundation();
        let listener = lb_config_model::ListenerResourceConfig::foundation(
            "public",
            lb_config_model::ListenerClassConfig::Public,
            8080,
        );
        assert!(resolve_listener_http_cache_policy(&config, &listener).unwrap().is_none());

        let mut listener = listener;
        listener.policies.cache_policy = Some(String::from("not-defined"));
        let error =
            resolve_listener_http_cache_policy(&config, &listener).err().unwrap().to_string();
        assert!(error.contains("references unknown http cache policy not-defined"));
    }
}
