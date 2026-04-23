#[derive(Debug, Clone)]
struct CompiledListenerOverloadPolicy {
    signal_window: Duration,
    constrained_signal_threshold: u64,
    shedding_signal_threshold: u64,
    brownout_signal_threshold: u64,
    brownout_features: Vec<CompiledBrownoutFeature>,
}

#[derive(Debug, Clone)]
struct CompiledBrownoutFeature {
    name: String,
    priority: lb_runtime::TrafficClass,
}

#[derive(Debug)]
struct ListenerOverloadRuntime {
    manager: lb_runtime::OverloadManager,
}

impl ListenerOverloadRuntime {
    fn new(policy: &CompiledListenerOverloadPolicy) -> Result<Self, DynError> {
        Ok(Self {
            manager: lb_runtime::OverloadManager::new(
                lb_runtime::OverloadPolicy {
                    signal_window: policy.signal_window,
                    constrained_signal_threshold: policy.constrained_signal_threshold,
                    shedding_signal_threshold: policy.shedding_signal_threshold,
                    brownout_signal_threshold: policy.brownout_signal_threshold,
                },
                lb_runtime::BrownoutHookRegistry::new(
                    policy
                        .brownout_features
                        .iter()
                        .map(|feature| lb_runtime::BrownoutFeature {
                            name: feature.name.clone(),
                            priority: feature.priority,
                        })
                        .collect(),
                )
                .map_err(to_dyn_error)?,
            )
            .map_err(to_dyn_error)?,
        })
    }

    fn record_concurrency_signal(
        &self,
        observed_at: Duration,
    ) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
        let snapshot = self.manager.record_signal(
            observed_at,
            lb_runtime::OverloadSignal {
                concurrency_limited: true,
                ..lb_runtime::OverloadSignal::default()
            },
        );
        (snapshot, self.manager.disabled_features().into_iter().collect())
    }

    fn snapshot(&self, observed_at: Duration) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
        let snapshot = self.manager.snapshot(observed_at);
        (snapshot, self.manager.disabled_features().into_iter().collect())
    }

    fn recent_events(&self) -> Vec<lb_observability::OverloadEvent> {
        self.manager.recent_events()
    }
}

#[derive(Debug, Clone)]

struct OverloadEventStatus {
    code: String,
    scope: String,
    detail: String,
}

impl OverloadEventStatus {
    fn from_telemetry(event: lb_observability::TelemetryEvent) -> Self {
        Self { code: String::from(event.code.as_str()), scope: event.scope, detail: event.detail }
    }

    fn from_overload_event(event: lb_observability::OverloadEvent) -> Self {
        Self {
            code: String::from(match event.kind {
                lb_observability::OverloadEventKind::StateChanged => "overload.state.changed",
                lb_observability::OverloadEventKind::RequestShed => "overload.request.shed",
                lb_observability::OverloadEventKind::BrownoutFeaturesChanged => {
                    "overload.brownout.features_changed"
                }
            }),
            scope: event.scope,
            detail: event.detail,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"code\":\"{}\",\"scope\":\"{}\",\"detail\":\"{}\"}}",
            crate::escape_json_string(&self.code),
            crate::escape_json_string(&self.scope),
            crate::escape_json_string(&self.detail),
        )
    }
}

fn build_listener_overload_runtime(
    policy: Option<&CompiledListenerOverloadPolicy>,
) -> Result<Option<ListenerOverloadRuntime>, DynError> {
    policy.map(ListenerOverloadRuntime::new).transpose()
}

fn snapshot_listener_overload(
    observed_at: Duration,
    counters: &ListenerRuntimeCounters,
    limit: usize,
    overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
    record_concurrency_signal: bool,
) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
    let guard = overload_runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(runtime) = guard.as_ref() {
        if record_concurrency_signal {
            runtime.record_concurrency_signal(observed_at)
        } else {
            runtime.snapshot(observed_at)
        }
    } else {
        let active = counters.active_connections.load(Ordering::SeqCst);
        let shed = counters.shed_connections.load(Ordering::SeqCst);
        let state = if active >= limit {
            lb_runtime::OverloadState::Shedding
        } else {
            lb_runtime::OverloadState::Normal
        };
        (
            lb_runtime::OverloadSnapshot {
                state,
                active_signal_count: if matches!(state, lb_runtime::OverloadState::Shedding) {
                    1
                } else {
                    0
                },
                rate_limited_count: 0,
                concurrency_limited_count: active as u64,
                breaker_open_count: 0,
                retry_budget_exhausted_count: 0,
                shed_request_count: shed,
                brownout_feature_count: 0,
            },
            Vec::new(),
        )
    }
}

fn snapshot_listener_overload_status(
    observed_at: Duration,
    counters: &ListenerRuntimeCounters,
    overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
) -> (lb_runtime::OverloadState, Vec<String>, Vec<OverloadEventStatus>) {
    let fallback_state = match counters.overload_state.load(Ordering::SeqCst) {
        1 => lb_runtime::OverloadState::Constrained,
        2 => lb_runtime::OverloadState::Shedding,
        3 => lb_runtime::OverloadState::Brownout,
        _ => lb_runtime::OverloadState::Normal,
    };
    let guard = overload_runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .as_ref()
        .map(|runtime| {
            let (snapshot, brownout_features) = runtime.snapshot(observed_at);
            (
                snapshot.state,
                brownout_features,
                runtime
                    .recent_events()
                    .into_iter()
                    .map(OverloadEventStatus::from_overload_event)
                    .collect(),
            )
        })
        .unwrap_or((fallback_state, Vec::new(), Vec::new()))
}

fn overload_state_name(state: lb_runtime::OverloadState) -> &'static str {
    match state {
        lb_runtime::OverloadState::Normal => "normal",
        lb_runtime::OverloadState::Constrained => "constrained",
        lb_runtime::OverloadState::Shedding => "shedding",
        lb_runtime::OverloadState::Brownout => "brownout",
    }
}

fn overload_scope(listener_name: &str) -> String {
    format!("workspace_listener_{}", listener_name)
}

fn http3_scope(listener_name: &str) -> String {
    format!("workspace_http3_{}", listener_name)
}

const fn overload_state_index(state: lb_runtime::OverloadState) -> usize {
    match state {
        lb_runtime::OverloadState::Normal => 0,
        lb_runtime::OverloadState::Constrained => 1,
        lb_runtime::OverloadState::Shedding => 2,
        lb_runtime::OverloadState::Brownout => 3,
    }
}

