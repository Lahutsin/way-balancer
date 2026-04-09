use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const MAX_OVERLOAD_EVENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrafficClass {
    Critical,
    Default,
    BestEffort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadState {
    Normal,
    Constrained,
    Shedding,
    Brownout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrownoutFeatureState {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrownoutFeature {
    pub name: String,
    pub priority: TrafficClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverloadPolicy {
    pub signal_window: Duration,
    pub constrained_signal_threshold: u64,
    pub shedding_signal_threshold: u64,
    pub brownout_signal_threshold: u64,
}

impl Default for OverloadPolicy {
    fn default() -> Self {
        Self {
            signal_window: Duration::from_secs(10),
            constrained_signal_threshold: 3,
            shedding_signal_threshold: 6,
            brownout_signal_threshold: 9,
        }
    }
}

impl OverloadPolicy {
    pub fn validate(&self) -> Result<(), OverloadManagementError> {
        if self.signal_window.is_zero() {
            return Err(OverloadManagementError::ZeroSignalWindow);
        }
        if self.constrained_signal_threshold == 0
            || self.shedding_signal_threshold == 0
            || self.brownout_signal_threshold == 0
        {
            return Err(OverloadManagementError::ZeroSignalThreshold);
        }
        if self.constrained_signal_threshold > self.shedding_signal_threshold
            || self.shedding_signal_threshold > self.brownout_signal_threshold
        {
            return Err(OverloadManagementError::InvalidSignalThresholdOrder);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OverloadSignalKind {
    RateLimited,
    ConcurrencyLimited,
    CircuitBreakerOpen,
    RetryBudgetExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OverloadSignal {
    pub rate_limited: bool,
    pub concurrency_limited: bool,
    pub breaker_open: bool,
    pub retry_budget_exhausted: bool,
}

impl OverloadSignal {
    #[must_use]
    pub fn active_count(self) -> u64 {
        u64::from(self.rate_limited)
            + u64::from(self.concurrency_limited)
            + u64::from(self.breaker_open)
            + u64::from(self.retry_budget_exhausted)
    }

    #[must_use]
    pub fn active_kinds(self) -> Vec<OverloadSignalKind> {
        let mut kinds = Vec::new();
        if self.rate_limited {
            kinds.push(OverloadSignalKind::RateLimited);
        }
        if self.concurrency_limited {
            kinds.push(OverloadSignalKind::ConcurrencyLimited);
        }
        if self.breaker_open {
            kinds.push(OverloadSignalKind::CircuitBreakerOpen);
        }
        if self.retry_budget_exhausted {
            kinds.push(OverloadSignalKind::RetryBudgetExhausted);
        }
        kinds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SheddingAction {
    Allow,
    Shed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShedReason {
    PriorityDrop,
    BrownoutActive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SheddingDecision {
    pub action: SheddingAction,
    pub state: OverloadState,
    pub reason: Option<ShedReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverloadSnapshot {
    pub state: OverloadState,
    pub active_signal_count: u64,
    pub rate_limited_count: u64,
    pub concurrency_limited_count: u64,
    pub breaker_open_count: u64,
    pub retry_budget_exhausted_count: u64,
    pub shed_request_count: u64,
    pub brownout_feature_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OverloadMetrics {
    pub state_change_count: u64,
    pub shed_request_count: u64,
    pub brownout_activation_count: u64,
    pub signal_counts: BTreeMap<OverloadSignalKind, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverloadManagementError {
    ZeroSignalWindow,
    ZeroSignalThreshold,
    InvalidSignalThresholdOrder,
    EmptyBrownoutFeatureName,
    DuplicateBrownoutFeature,
}

impl fmt::Display for OverloadManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSignalWindow => {
                formatter.write_str("overload signal window must be greater than zero")
            }
            Self::ZeroSignalThreshold => {
                formatter.write_str("overload signal thresholds must be greater than zero")
            }
            Self::InvalidSignalThresholdOrder => {
                formatter.write_str("overload thresholds must increase monotonically")
            }
            Self::EmptyBrownoutFeatureName => {
                formatter.write_str("brownout feature name must not be empty")
            }
            Self::DuplicateBrownoutFeature => {
                formatter.write_str("brownout feature names must be unique")
            }
        }
    }
}

impl std::error::Error for OverloadManagementError {}

#[derive(Debug, Clone)]
struct SignalSample {
    observed_at: Duration,
    signal: OverloadSignal,
}

#[derive(Debug)]
struct OverloadStateRecord {
    state: OverloadState,
    samples: VecDeque<SignalSample>,
    disabled_features: BTreeSet<String>,
}

#[derive(Debug)]
pub struct BrownoutHookRegistry {
    features: Vec<BrownoutFeature>,
}

impl BrownoutHookRegistry {
    pub fn new(features: Vec<BrownoutFeature>) -> Result<Self, OverloadManagementError> {
        let mut seen = BTreeSet::new();
        for feature in &features {
            let normalized = feature.name.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(OverloadManagementError::EmptyBrownoutFeatureName);
            }
            if !seen.insert(normalized) {
                return Err(OverloadManagementError::DuplicateBrownoutFeature);
            }
        }
        Ok(Self { features })
    }

    #[must_use]
    pub fn disabled_features_for(&self, state: OverloadState) -> BTreeSet<String> {
        let mut disabled = BTreeSet::new();
        for feature in &self.features {
            if should_disable_feature(state, feature.priority) {
                disabled.insert(feature.name.clone());
            }
        }
        disabled
    }

    #[must_use]
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }
}

#[derive(Debug)]
pub struct OverloadManager {
    policy: OverloadPolicy,
    hooks: BrownoutHookRegistry,
    state: Mutex<OverloadStateRecord>,
    state_change_count: AtomicU64,
    shed_request_count: AtomicU64,
    brownout_activation_count: AtomicU64,
    events: Mutex<VecDeque<lb_observability::OverloadEvent>>,
}

impl OverloadManager {
    pub fn new(
        policy: OverloadPolicy,
        hooks: BrownoutHookRegistry,
    ) -> Result<Self, OverloadManagementError> {
        policy.validate()?;
        Ok(Self {
            policy,
            hooks,
            state: Mutex::new(OverloadStateRecord {
                state: OverloadState::Normal,
                samples: VecDeque::new(),
                disabled_features: BTreeSet::new(),
            }),
            state_change_count: AtomicU64::new(0),
            shed_request_count: AtomicU64::new(0),
            brownout_activation_count: AtomicU64::new(0),
            events: Mutex::new(VecDeque::with_capacity(MAX_OVERLOAD_EVENTS)),
        })
    }

    pub fn record_signal(&self, now: Duration, signal: OverloadSignal) -> OverloadSnapshot {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.samples.push_back(SignalSample { observed_at: now, signal });
        evict_old_samples(&self.policy, now, &mut state.samples);
        let signal_counts = aggregate_signal_counts(&state.samples);
        let active_signal_count: u64 = signal_counts.values().sum();
        let next_state = classify_state(&self.policy, active_signal_count);
        if next_state != state.state {
            state.state = next_state;
            self.state_change_count.fetch_add(1, Ordering::SeqCst);
            push_overload_event(
                &self.events,
                lb_observability::OverloadEventKind::StateChanged,
                format!("overload state transitioned to {:?}", next_state),
            );
        }

        let disabled_features = self.hooks.disabled_features_for(state.state);
        if disabled_features != state.disabled_features {
            let brownout_entering =
                !disabled_features.is_empty() && state.disabled_features.is_empty();
            state.disabled_features = disabled_features.clone();
            if brownout_entering {
                self.brownout_activation_count.fetch_add(1, Ordering::SeqCst);
            }
            if !disabled_features.is_empty() {
                push_overload_event(
                    &self.events,
                    lb_observability::OverloadEventKind::BrownoutFeaturesChanged,
                    format!(
                        "brownout features disabled: {}",
                        disabled_features.iter().cloned().collect::<Vec<_>>().join(",")
                    ),
                );
            }
        }

        OverloadSnapshot {
            state: state.state,
            active_signal_count,
            rate_limited_count: *signal_counts.get(&OverloadSignalKind::RateLimited).unwrap_or(&0),
            concurrency_limited_count: *signal_counts
                .get(&OverloadSignalKind::ConcurrencyLimited)
                .unwrap_or(&0),
            breaker_open_count: *signal_counts
                .get(&OverloadSignalKind::CircuitBreakerOpen)
                .unwrap_or(&0),
            retry_budget_exhausted_count: *signal_counts
                .get(&OverloadSignalKind::RetryBudgetExhausted)
                .unwrap_or(&0),
            shed_request_count: self.shed_request_count.load(Ordering::SeqCst),
            brownout_feature_count: state.disabled_features.len(),
        }
    }

    pub fn decide(&self, traffic_class: TrafficClass) -> SheddingDecision {
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let action = match state.state {
            OverloadState::Normal => SheddingAction::Allow,
            OverloadState::Constrained => match traffic_class {
                TrafficClass::BestEffort => SheddingAction::Shed,
                TrafficClass::Critical | TrafficClass::Default => SheddingAction::Allow,
            },
            OverloadState::Shedding | OverloadState::Brownout => match traffic_class {
                TrafficClass::Critical => SheddingAction::Allow,
                TrafficClass::Default | TrafficClass::BestEffort => SheddingAction::Shed,
            },
        };
        let reason = match (state.state, action) {
            (_, SheddingAction::Allow) => None,
            (OverloadState::Brownout, SheddingAction::Shed) => Some(ShedReason::BrownoutActive),
            _ => Some(ShedReason::PriorityDrop),
        };
        drop(state);

        if matches!(action, SheddingAction::Shed) {
            self.shed_request_count.fetch_add(1, Ordering::SeqCst);
            push_overload_event(
                &self.events,
                lb_observability::OverloadEventKind::RequestShed,
                format!("shed {:?} traffic under overload", traffic_class),
            );
        }

        let state = self.current_state();
        SheddingDecision { action, state, reason }
    }

    #[must_use]
    pub fn disabled_features(&self) -> BTreeSet<String> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).disabled_features.clone()
    }

    #[must_use]
    pub fn current_state(&self) -> OverloadState {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).state
    }

    #[must_use]
    pub fn snapshot(&self, now: Duration) -> OverloadSnapshot {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        evict_old_samples(&self.policy, now, &mut state.samples);
        let signal_counts = aggregate_signal_counts(&state.samples);
        OverloadSnapshot {
            state: state.state,
            active_signal_count: signal_counts.values().sum(),
            rate_limited_count: *signal_counts.get(&OverloadSignalKind::RateLimited).unwrap_or(&0),
            concurrency_limited_count: *signal_counts
                .get(&OverloadSignalKind::ConcurrencyLimited)
                .unwrap_or(&0),
            breaker_open_count: *signal_counts
                .get(&OverloadSignalKind::CircuitBreakerOpen)
                .unwrap_or(&0),
            retry_budget_exhausted_count: *signal_counts
                .get(&OverloadSignalKind::RetryBudgetExhausted)
                .unwrap_or(&0),
            shed_request_count: self.shed_request_count.load(Ordering::SeqCst),
            brownout_feature_count: state.disabled_features.len(),
        }
    }

    #[must_use]
    pub fn metrics(&self, now: Duration) -> OverloadMetrics {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        evict_old_samples(&self.policy, now, &mut state.samples);
        OverloadMetrics {
            state_change_count: self.state_change_count.load(Ordering::SeqCst),
            shed_request_count: self.shed_request_count.load(Ordering::SeqCst),
            brownout_activation_count: self.brownout_activation_count.load(Ordering::SeqCst),
            signal_counts: aggregate_signal_counts(&state.samples),
        }
    }

    #[must_use]
    pub fn recent_events(&self) -> Vec<lb_observability::OverloadEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

fn classify_state(policy: &OverloadPolicy, active_signal_count: u64) -> OverloadState {
    if active_signal_count >= policy.brownout_signal_threshold {
        OverloadState::Brownout
    } else if active_signal_count >= policy.shedding_signal_threshold {
        OverloadState::Shedding
    } else if active_signal_count >= policy.constrained_signal_threshold {
        OverloadState::Constrained
    } else {
        OverloadState::Normal
    }
}

fn should_disable_feature(state: OverloadState, priority: TrafficClass) -> bool {
    match state {
        OverloadState::Normal | OverloadState::Constrained => false,
        OverloadState::Shedding => matches!(priority, TrafficClass::BestEffort),
        OverloadState::Brownout => !matches!(priority, TrafficClass::Critical),
    }
}

fn evict_old_samples(policy: &OverloadPolicy, now: Duration, samples: &mut VecDeque<SignalSample>) {
    while let Some(sample) = samples.front() {
        if now.saturating_sub(sample.observed_at) < policy.signal_window {
            break;
        }
        let _ = samples.pop_front();
    }
}

fn aggregate_signal_counts(samples: &VecDeque<SignalSample>) -> BTreeMap<OverloadSignalKind, u64> {
    let mut counts = BTreeMap::new();
    for sample in samples {
        for kind in sample.signal.active_kinds() {
            *counts.entry(kind).or_insert(0) += 1;
        }
    }
    counts
}

fn push_overload_event(
    events: &Mutex<VecDeque<lb_observability::OverloadEvent>>,
    kind: lb_observability::OverloadEventKind,
    detail: String,
) {
    let mut events = events.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if events.len() == MAX_OVERLOAD_EVENTS {
        let _ = events.pop_front();
    }
    events.push_back(lb_observability::OverloadEvent {
        kind,
        scope: String::from("dataplane"),
        detail,
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        BrownoutFeature, BrownoutHookRegistry, OverloadManager, OverloadPolicy, OverloadSignal,
        OverloadState, SheddingAction, TrafficClass,
    };

    fn manager() -> Result<OverloadManager, Box<dyn std::error::Error>> {
        Ok(OverloadManager::new(
            OverloadPolicy {
                signal_window: Duration::from_secs(10),
                constrained_signal_threshold: 2,
                shedding_signal_threshold: 4,
                brownout_signal_threshold: 6,
            },
            BrownoutHookRegistry::new(vec![
                BrownoutFeature {
                    name: String::from("expensive_search"),
                    priority: TrafficClass::BestEffort,
                },
                BrownoutFeature {
                    name: String::from("html_previews"),
                    priority: TrafficClass::Default,
                },
            ])?,
        )?)
    }

    #[test]
    fn overload_signals_transition_states() -> Result<(), Box<dyn std::error::Error>> {
        let manager = manager()?;
        let normal = manager.record_signal(Duration::ZERO, OverloadSignal::default());
        assert_eq!(normal.state, OverloadState::Normal);

        let constrained = manager.record_signal(
            Duration::from_secs(1),
            OverloadSignal {
                rate_limited: true,
                concurrency_limited: true,
                ..OverloadSignal::default()
            },
        );
        assert_eq!(constrained.state, OverloadState::Constrained);

        let shedding = manager.record_signal(
            Duration::from_secs(2),
            OverloadSignal {
                rate_limited: true,
                concurrency_limited: true,
                ..OverloadSignal::default()
            },
        );
        assert_eq!(shedding.state, OverloadState::Shedding);

        let brownout = manager.record_signal(
            Duration::from_secs(3),
            OverloadSignal {
                rate_limited: true,
                concurrency_limited: true,
                breaker_open: true,
                retry_budget_exhausted: true,
            },
        );
        assert_eq!(brownout.state, OverloadState::Brownout);
        Ok(())
    }

    #[test]
    fn shedding_is_priority_aware() -> Result<(), Box<dyn std::error::Error>> {
        let manager = manager()?;
        let _ = manager.record_signal(
            Duration::ZERO,
            OverloadSignal {
                rate_limited: true,
                concurrency_limited: true,
                breaker_open: true,
                retry_budget_exhausted: true,
            },
        );

        assert_eq!(manager.decide(TrafficClass::Critical).action, SheddingAction::Allow);
        assert_eq!(manager.decide(TrafficClass::Default).action, SheddingAction::Shed);
        assert_eq!(manager.decide(TrafficClass::BestEffort).action, SheddingAction::Shed);
        Ok(())
    }

    #[test]
    fn brownout_hooks_are_optional_and_isolated() -> Result<(), Box<dyn std::error::Error>> {
        let manager = manager()?;
        let _ = manager.record_signal(
            Duration::ZERO,
            OverloadSignal {
                rate_limited: true,
                concurrency_limited: true,
                breaker_open: true,
                retry_budget_exhausted: true,
            },
        );
        let _ = manager.record_signal(
            Duration::from_secs(1),
            OverloadSignal {
                rate_limited: true,
                concurrency_limited: true,
                breaker_open: true,
                retry_budget_exhausted: true,
            },
        );

        let disabled = manager.disabled_features();
        assert!(disabled.contains("expensive_search"));
        assert!(disabled.contains("html_previews"));
        Ok(())
    }
}
