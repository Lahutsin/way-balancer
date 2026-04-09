use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const MAX_FAILURE_EVENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryBudgetPolicy {
    pub min_retry_tokens: u32,
    pub retry_percent: u8,
    pub window: Duration,
}

impl Default for RetryBudgetPolicy {
    fn default() -> Self {
        Self { min_retry_tokens: 3, retry_percent: 20, window: Duration::from_secs(10) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutHierarchy {
    pub request_timeout: Duration,
    pub attempt_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

impl TimeoutHierarchy {
    pub fn validate(&self) -> Result<(), FailureManagementError> {
        if self.request_timeout.is_zero()
            || self.attempt_timeout.is_zero()
            || self.connect_timeout.is_zero()
            || self.idle_timeout.is_zero()
        {
            return Err(FailureManagementError::ZeroTimeout);
        }
        if self.attempt_timeout > self.request_timeout
            || self.connect_timeout > self.attempt_timeout
            || self.idle_timeout > self.attempt_timeout
        {
            return Err(FailureManagementError::InvalidTimeoutOrder);
        }
        Ok(())
    }

    #[must_use]
    pub fn effective_timeout(&self, category: TimeoutCategory) -> Duration {
        match category {
            TimeoutCategory::Request => self.request_timeout,
            TimeoutCategory::Attempt => self.attempt_timeout.min(self.request_timeout),
            TimeoutCategory::Connect => self.connect_timeout.min(self.attempt_timeout),
            TimeoutCategory::Idle => self.idle_timeout.min(self.attempt_timeout),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimeoutCategory {
    Request,
    Attempt,
    Connect,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamFailureClass {
    Connect,
    Timeout,
    Overloaded,
    Temporary,
    Permanent,
}

impl UpstreamFailureClass {
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Connect | Self::Timeout | Self::Overloaded | Self::Temporary)
    }

    #[must_use]
    pub const fn counts_toward_breaker(self) -> bool {
        !matches!(self, Self::Permanent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryBudgetSnapshot {
    pub base_request_count: u64,
    pub retry_count: u64,
    pub remaining_retry_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryDecision {
    pub allowed: bool,
    pub remaining_retry_tokens: u64,
}

#[derive(Debug, Clone)]
struct RetryBudgetState {
    window_started: Duration,
    base_request_count: u64,
    retry_count: u64,
}

#[derive(Debug)]
pub struct RetryBudget {
    policy: RetryBudgetPolicy,
    state: Mutex<RetryBudgetState>,
    exhausted_count: AtomicU64,
}

impl RetryBudget {
    pub fn new(policy: RetryBudgetPolicy) -> Result<Self, FailureManagementError> {
        if policy.window.is_zero() {
            return Err(FailureManagementError::ZeroRetryWindow);
        }
        Ok(Self {
            policy,
            state: Mutex::new(RetryBudgetState {
                window_started: Duration::ZERO,
                base_request_count: 0,
                retry_count: 0,
            }),
            exhausted_count: AtomicU64::new(0),
        })
    }

    pub fn record_base_request(&self, now: Duration) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_retry_window_if_needed(&self.policy, now, &mut state);
        state.base_request_count = state.base_request_count.saturating_add(1);
    }

    pub fn allow_retry(&self, now: Duration) -> RetryDecision {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_retry_window_if_needed(&self.policy, now, &mut state);
        let available = retry_capacity(&self.policy, &state).saturating_sub(state.retry_count);
        if available == 0 {
            self.exhausted_count.fetch_add(1, Ordering::SeqCst);
            return RetryDecision { allowed: false, remaining_retry_tokens: 0 };
        }

        state.retry_count = state.retry_count.saturating_add(1);
        RetryDecision { allowed: true, remaining_retry_tokens: available.saturating_sub(1) }
    }

    pub fn snapshot(&self, now: Duration) -> RetryBudgetSnapshot {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_retry_window_if_needed(&self.policy, now, &mut state);
        RetryBudgetSnapshot {
            base_request_count: state.base_request_count,
            retry_count: state.retry_count,
            remaining_retry_tokens: retry_capacity(&self.policy, &state)
                .saturating_sub(state.retry_count),
        }
    }

    #[must_use]
    pub fn exhausted_count(&self) -> u64 {
        self.exhausted_count.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerPolicy {
    pub open_failure_threshold: u32,
    pub open_duration: Duration,
    pub half_open_success_threshold: u32,
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self {
            open_failure_threshold: 3,
            open_duration: Duration::from_secs(30),
            half_open_success_threshold: 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerSnapshot {
    pub state: CircuitBreakerState,
    pub remaining_open_duration: Option<Duration>,
    pub consecutive_failures: u32,
    pub half_open_successes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FailureManagementMetrics {
    pub retry_budget_exhausted_count: u64,
    pub breaker_state_change_count: u64,
    pub breaker_open_rejection_count: u64,
    pub timeout_category_counts: BTreeMap<TimeoutCategory, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureManagementError {
    ZeroRetryWindow,
    ZeroTimeout,
    InvalidTimeoutOrder,
    InvalidBreakerThreshold,
}

impl fmt::Display for FailureManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRetryWindow => {
                formatter.write_str("retry budget window must be greater than zero")
            }
            Self::ZeroTimeout => formatter.write_str("timeout values must be greater than zero"),
            Self::InvalidTimeoutOrder => {
                formatter.write_str("timeout hierarchy precedence is invalid")
            }
            Self::InvalidBreakerThreshold => {
                formatter.write_str("circuit breaker thresholds must be greater than zero")
            }
        }
    }
}

impl std::error::Error for FailureManagementError {}

#[derive(Debug)]
struct CircuitBreakerRecord {
    state: CircuitBreakerState,
    consecutive_failures: u32,
    half_open_successes: u32,
    opened_at: Duration,
}

#[derive(Debug)]
pub struct CircuitBreaker {
    policy: CircuitBreakerPolicy,
    record: Mutex<CircuitBreakerRecord>,
    breaker_state_change_count: AtomicU64,
    breaker_open_rejection_count: AtomicU64,
    events: Mutex<VecDeque<lb_observability::FailureManagementEvent>>,
}

impl CircuitBreaker {
    pub fn new(policy: CircuitBreakerPolicy) -> Result<Self, FailureManagementError> {
        if policy.open_failure_threshold == 0
            || policy.half_open_success_threshold == 0
            || policy.open_duration.is_zero()
        {
            return Err(FailureManagementError::InvalidBreakerThreshold);
        }
        Ok(Self {
            policy,
            record: Mutex::new(CircuitBreakerRecord {
                state: CircuitBreakerState::Closed,
                consecutive_failures: 0,
                half_open_successes: 0,
                opened_at: Duration::ZERO,
            }),
            breaker_state_change_count: AtomicU64::new(0),
            breaker_open_rejection_count: AtomicU64::new(0),
            events: Mutex::new(VecDeque::with_capacity(MAX_FAILURE_EVENTS)),
        })
    }

    pub fn allow_request(&self, now: Duration) -> bool {
        let mut record = self.record.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(record.state, CircuitBreakerState::Open)
            && now.saturating_sub(record.opened_at) >= self.policy.open_duration
        {
            transition_breaker_state(
                &mut record,
                CircuitBreakerState::HalfOpen,
                &self.breaker_state_change_count,
                &self.events,
                lb_observability::FailureManagementEventKind::BreakerHalfOpened,
                "breaker cool-down elapsed; allowing probe traffic",
            );
        }

        if matches!(record.state, CircuitBreakerState::Open) {
            self.breaker_open_rejection_count.fetch_add(1, Ordering::SeqCst);
            return false;
        }

        true
    }

    pub fn record_success(&self) {
        let mut record = self.record.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match record.state {
            CircuitBreakerState::Closed => {
                record.consecutive_failures = 0;
            }
            CircuitBreakerState::Open => {}
            CircuitBreakerState::HalfOpen => {
                record.half_open_successes = record.half_open_successes.saturating_add(1);
                if record.half_open_successes >= self.policy.half_open_success_threshold {
                    transition_breaker_state(
                        &mut record,
                        CircuitBreakerState::Closed,
                        &self.breaker_state_change_count,
                        &self.events,
                        lb_observability::FailureManagementEventKind::BreakerClosed,
                        "breaker recovered after successful half-open probes",
                    );
                    record.consecutive_failures = 0;
                    record.half_open_successes = 0;
                }
            }
        }
    }

    pub fn record_failure(&self, now: Duration, class: UpstreamFailureClass) {
        if !class.counts_toward_breaker() {
            return;
        }

        let mut record = self.record.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match record.state {
            CircuitBreakerState::Closed => {
                record.consecutive_failures = record.consecutive_failures.saturating_add(1);
                if record.consecutive_failures >= self.policy.open_failure_threshold {
                    record.opened_at = now;
                    transition_breaker_state(
                        &mut record,
                        CircuitBreakerState::Open,
                        &self.breaker_state_change_count,
                        &self.events,
                        lb_observability::FailureManagementEventKind::BreakerOpened,
                        "breaker opened after repeated upstream failures",
                    );
                    record.half_open_successes = 0;
                }
            }
            CircuitBreakerState::HalfOpen => {
                record.opened_at = now;
                transition_breaker_state(
                    &mut record,
                    CircuitBreakerState::Open,
                    &self.breaker_state_change_count,
                    &self.events,
                    lb_observability::FailureManagementEventKind::BreakerOpened,
                    "breaker re-opened after failed half-open probe",
                );
                record.consecutive_failures = self.policy.open_failure_threshold;
                record.half_open_successes = 0;
            }
            CircuitBreakerState::Open => {
                record.opened_at = now;
            }
        }
    }

    pub fn snapshot(&self, now: Duration) -> CircuitBreakerSnapshot {
        let record = self.record.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let remaining_open_duration = if matches!(record.state, CircuitBreakerState::Open) {
            Some(self.policy.open_duration.saturating_sub(now.saturating_sub(record.opened_at)))
        } else {
            None
        };
        CircuitBreakerSnapshot {
            state: record.state,
            remaining_open_duration,
            consecutive_failures: record.consecutive_failures,
            half_open_successes: record.half_open_successes,
        }
    }

    #[must_use]
    pub fn recent_events(&self) -> Vec<lb_observability::FailureManagementEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn breaker_state_change_count(&self) -> u64 {
        self.breaker_state_change_count.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn breaker_open_rejection_count(&self) -> u64 {
        self.breaker_open_rejection_count.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub struct FailureManager {
    retry_budget: RetryBudget,
    timeout_hierarchy: TimeoutHierarchy,
    circuit_breaker: CircuitBreaker,
    timeout_category_counts: Mutex<BTreeMap<TimeoutCategory, u64>>,
}

impl FailureManager {
    pub fn new(
        retry_budget: RetryBudgetPolicy,
        timeout_hierarchy: TimeoutHierarchy,
        circuit_breaker: CircuitBreakerPolicy,
    ) -> Result<Self, FailureManagementError> {
        timeout_hierarchy.validate()?;
        Ok(Self {
            retry_budget: RetryBudget::new(retry_budget)?,
            timeout_hierarchy,
            circuit_breaker: CircuitBreaker::new(circuit_breaker)?,
            timeout_category_counts: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn record_base_request(&self, now: Duration) {
        self.retry_budget.record_base_request(now);
    }

    pub fn allow_retry(&self, now: Duration, failure: UpstreamFailureClass) -> RetryDecision {
        if !failure.is_retryable() {
            return RetryDecision { allowed: false, remaining_retry_tokens: 0 };
        }
        self.retry_budget.allow_retry(now)
    }

    #[must_use]
    pub fn effective_timeout(&self, category: TimeoutCategory) -> Duration {
        self.timeout_hierarchy.effective_timeout(category)
    }

    pub fn record_timeout(&self, category: TimeoutCategory) {
        let mut counts =
            self.timeout_category_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(category).or_insert(0) += 1;
    }

    pub fn allow_request(&self, now: Duration) -> bool {
        self.circuit_breaker.allow_request(now)
    }

    pub fn record_success(&self) {
        self.circuit_breaker.record_success();
    }

    pub fn record_failure(&self, now: Duration, class: UpstreamFailureClass) {
        self.circuit_breaker.record_failure(now, class);
    }

    #[must_use]
    pub fn metrics(&self) -> FailureManagementMetrics {
        FailureManagementMetrics {
            retry_budget_exhausted_count: self.retry_budget.exhausted_count(),
            breaker_state_change_count: self.circuit_breaker.breaker_state_change_count(),
            breaker_open_rejection_count: self.circuit_breaker.breaker_open_rejection_count(),
            timeout_category_counts: self
                .timeout_category_counts
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        }
    }

    pub fn breaker_snapshot(&self, now: Duration) -> CircuitBreakerSnapshot {
        self.circuit_breaker.snapshot(now)
    }

    pub fn retry_budget_snapshot(&self, now: Duration) -> RetryBudgetSnapshot {
        self.retry_budget.snapshot(now)
    }

    #[must_use]
    pub fn recent_events(&self) -> Vec<lb_observability::FailureManagementEvent> {
        self.circuit_breaker.recent_events()
    }
}

fn reset_retry_window_if_needed(
    policy: &RetryBudgetPolicy,
    now: Duration,
    state: &mut RetryBudgetState,
) {
    if now.saturating_sub(state.window_started) >= policy.window {
        state.window_started = now;
        state.base_request_count = 0;
        state.retry_count = 0;
    }
}

fn retry_capacity(policy: &RetryBudgetPolicy, state: &RetryBudgetState) -> u64 {
    let proportional = (state.base_request_count * u64::from(policy.retry_percent)) / 100;
    proportional.saturating_add(u64::from(policy.min_retry_tokens))
}

fn transition_breaker_state(
    record: &mut CircuitBreakerRecord,
    new_state: CircuitBreakerState,
    state_change_count: &AtomicU64,
    events: &Mutex<VecDeque<lb_observability::FailureManagementEvent>>,
    kind: lb_observability::FailureManagementEventKind,
    detail: &str,
) {
    if record.state == new_state {
        return;
    }

    record.state = new_state;
    state_change_count.fetch_add(1, Ordering::SeqCst);

    let mut events = events.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if events.len() == MAX_FAILURE_EVENTS {
        let _ = events.pop_front();
    }
    events.push_back(lb_observability::FailureManagementEvent {
        kind,
        scope: String::from("upstream"),
        detail: String::from(detail),
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        CircuitBreaker, CircuitBreakerPolicy, CircuitBreakerState, FailureManagementError,
        RetryBudget, RetryBudgetPolicy, TimeoutCategory, TimeoutHierarchy, UpstreamFailureClass,
    };

    #[test]
    fn retry_budget_caps_retries() -> Result<(), Box<dyn std::error::Error>> {
        let budget = RetryBudget::new(RetryBudgetPolicy {
            min_retry_tokens: 1,
            retry_percent: 50,
            window: Duration::from_secs(10),
        })?;

        budget.record_base_request(Duration::ZERO);
        budget.record_base_request(Duration::ZERO);

        assert!(budget.allow_retry(Duration::ZERO).allowed);
        assert!(budget.allow_retry(Duration::ZERO).allowed);
        assert!(!budget.allow_retry(Duration::ZERO).allowed);
        assert_eq!(budget.exhausted_count(), 1);
        Ok(())
    }

    #[test]
    fn timeout_hierarchy_enforces_precedence() -> Result<(), Box<dyn std::error::Error>> {
        let hierarchy = TimeoutHierarchy {
            request_timeout: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(3),
        };
        hierarchy.validate()?;
        assert_eq!(hierarchy.effective_timeout(TimeoutCategory::Connect), Duration::from_secs(2));
        assert_eq!(hierarchy.effective_timeout(TimeoutCategory::Attempt), Duration::from_secs(5));

        let invalid = TimeoutHierarchy {
            request_timeout: Duration::from_secs(5),
            attempt_timeout: Duration::from_secs(6),
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
        };
        assert_eq!(invalid.validate(), Err(FailureManagementError::InvalidTimeoutOrder));
        Ok(())
    }

    #[test]
    fn breaker_transitions_are_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let breaker = CircuitBreaker::new(CircuitBreakerPolicy {
            open_failure_threshold: 2,
            open_duration: Duration::from_secs(10),
            half_open_success_threshold: 2,
        })?;

        assert!(breaker.allow_request(Duration::ZERO));
        breaker.record_failure(Duration::ZERO, UpstreamFailureClass::Connect);
        breaker.record_failure(Duration::ZERO, UpstreamFailureClass::Timeout);
        assert_eq!(breaker.snapshot(Duration::ZERO).state, CircuitBreakerState::Open);
        assert!(!breaker.allow_request(Duration::from_secs(5)));
        assert!(breaker.allow_request(Duration::from_secs(10)));
        assert_eq!(breaker.snapshot(Duration::from_secs(10)).state, CircuitBreakerState::HalfOpen);
        breaker.record_success();
        breaker.record_success();
        assert_eq!(breaker.snapshot(Duration::from_secs(10)).state, CircuitBreakerState::Closed);
        Ok(())
    }
}
