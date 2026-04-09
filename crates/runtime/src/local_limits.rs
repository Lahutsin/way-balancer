use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const MAX_NORMALIZED_COMPONENT_LEN: usize = 64;

/// Dimension at which a local limit applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalLimitScope {
    /// Listener-wide limit.
    Listener { name: String },
    /// Route-specific limit.
    Route { name: String },
    /// Upstream-cluster-specific limit.
    UpstreamCluster { name: String },
}

/// Key kind used to shard local limit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLimitKeyKind {
    /// Single global bucket for the whole scope.
    Global,
    /// Partition by source IP address.
    SourceIp,
    /// Partition by normalized route name.
    RouteName,
    /// Partition by normalized upstream cluster name.
    UpstreamCluster,
}

/// Selection context used for limit key normalization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LimitContext {
    /// Source IP used for `SourceIp` keying.
    pub source_ip: Option<IpAddr>,
    /// Route name used for `RouteName` keying.
    pub route_name: Option<String>,
    /// Upstream cluster name used for `UpstreamCluster` keying.
    pub upstream_cluster: Option<String>,
}

/// Local fixed-window rate limit configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRateLimitConfig {
    /// Limit scope.
    pub scope: LocalLimitScope,
    /// Keying model.
    pub key_kind: LocalLimitKeyKind,
    /// Maximum number of requests per window.
    pub requests_per_window: u64,
    /// Window size.
    pub window: Duration,
    /// Maximum number of tracked keys.
    pub max_tracked_keys: usize,
}

impl LocalRateLimitConfig {
    /// Validates local rate limit invariants.
    pub fn validate(&self) -> Result<(), LocalLimitError> {
        validate_scope(&self.scope)?;
        if self.requests_per_window == 0 {
            return Err(LocalLimitError::ZeroRateLimit);
        }
        if self.window.is_zero() {
            return Err(LocalLimitError::ZeroRateWindow);
        }
        if self.max_tracked_keys == 0 {
            return Err(LocalLimitError::ZeroTrackedKeys);
        }
        Ok(())
    }
}

/// Local concurrency guard configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConcurrencyLimitConfig {
    /// Limit scope.
    pub scope: LocalLimitScope,
    /// Keying model.
    pub key_kind: LocalLimitKeyKind,
    /// Maximum concurrent in-flight operations per key.
    pub max_concurrent: usize,
    /// Maximum number of tracked keys.
    pub max_tracked_keys: usize,
}

impl LocalConcurrencyLimitConfig {
    /// Validates local concurrency guard invariants.
    pub fn validate(&self) -> Result<(), LocalLimitError> {
        validate_scope(&self.scope)?;
        if self.max_concurrent == 0 {
            return Err(LocalLimitError::ZeroConcurrencyLimit);
        }
        if self.max_tracked_keys == 0 {
            return Err(LocalLimitError::ZeroTrackedKeys);
        }
        Ok(())
    }
}

/// Observable rate-limiter metrics snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalRateLimiterMetrics {
    /// Count of allowed requests.
    pub allowed_count: u64,
    /// Count of rejected requests due to over-limit or bounded state exhaustion.
    pub rate_limited_count: u64,
    /// Number of currently tracked keys.
    pub tracked_keys: usize,
}

/// Observable concurrency-limiter metrics snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalConcurrencyLimiterMetrics {
    /// Count of successful acquires.
    pub acquired_count: u64,
    /// Count of rejected acquires.
    pub concurrency_rejection_count: u64,
    /// Number of currently active in-flight operations.
    pub active_concurrency: usize,
    /// Number of currently tracked keys.
    pub tracked_keys: usize,
}

/// Deterministic rate-limit decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining requests in the current window for the normalized key.
    pub remaining: u64,
    /// Retry-after hint when rejected.
    pub retry_after: Option<Duration>,
}

/// Errors returned by local limit primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalLimitError {
    /// Listener/route/upstream scope names must be non-empty after normalization.
    EmptyScopeName,
    /// Rate limit must be positive.
    ZeroRateLimit,
    /// Rate limit window must be positive.
    ZeroRateWindow,
    /// Concurrency limit must be positive.
    ZeroConcurrencyLimit,
    /// Tracked key capacity must be positive.
    ZeroTrackedKeys,
    /// Active concurrency reached the configured limit.
    ConcurrencyLimitExceeded,
    /// New key could not be tracked because bounded state is exhausted.
    StateSaturated,
}

impl fmt::Display for LocalLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScopeName => formatter.write_str("local limit scope name must not be empty"),
            Self::ZeroRateLimit => {
                formatter.write_str("local rate limit must be greater than zero")
            }
            Self::ZeroRateWindow => {
                formatter.write_str("local rate-limit window must be greater than zero")
            }
            Self::ZeroConcurrencyLimit => {
                formatter.write_str("local concurrency limit must be greater than zero")
            }
            Self::ZeroTrackedKeys => {
                formatter.write_str("local limit max_tracked_keys must be greater than zero")
            }
            Self::ConcurrencyLimitExceeded => {
                formatter.write_str("local concurrency limit was exceeded")
            }
            Self::StateSaturated => {
                formatter.write_str("local limit state is saturated and cannot track a new key")
            }
        }
    }
}

impl std::error::Error for LocalLimitError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedLimitKey(String);

#[derive(Debug, Clone)]
struct RateWindowState {
    window_started: Duration,
    count: u64,
    last_seen_tick: u64,
}

#[derive(Debug, Default)]
struct RateMetricsState {
    allowed_count: AtomicU64,
    rate_limited_count: AtomicU64,
}

/// Fixed-window local rate limiter with bounded state.
#[derive(Debug)]
pub struct LocalRateLimiter {
    config: LocalRateLimitConfig,
    state: Mutex<BTreeMap<NormalizedLimitKey, RateWindowState>>,
    metrics: RateMetricsState,
}

impl LocalRateLimiter {
    /// Creates a validated fixed-window rate limiter.
    pub fn new(config: LocalRateLimitConfig) -> Result<Self, LocalLimitError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(BTreeMap::new()),
            metrics: RateMetricsState::default(),
        })
    }

    /// Applies rate limiting to the normalized key at the given deterministic timestamp.
    pub fn check(
        &self,
        now: Duration,
        context: &LimitContext,
    ) -> Result<RateLimitDecision, LocalLimitError> {
        let key = normalize_limit_key(&self.config.scope, self.config.key_kind, context);
        let now_tick = duration_tick(now);
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let is_new_key = !state.contains_key(&key);
        if is_new_key && state.len() == self.config.max_tracked_keys {
            evict_oldest_key(&mut state);
        }
        if !state.contains_key(&key) && state.len() == self.config.max_tracked_keys {
            self.metrics.rate_limited_count.fetch_add(1, Ordering::SeqCst);
            return Err(LocalLimitError::StateSaturated);
        }

        let entry = state.entry(key).or_insert(RateWindowState {
            window_started: now,
            count: 0,
            last_seen_tick: now_tick,
        });
        if now.saturating_sub(entry.window_started) >= self.config.window {
            entry.window_started = now;
            entry.count = 0;
        }
        entry.last_seen_tick = now_tick;

        if entry.count >= self.config.requests_per_window {
            self.metrics.rate_limited_count.fetch_add(1, Ordering::SeqCst);
            let retry_after =
                self.config.window.saturating_sub(now.saturating_sub(entry.window_started));
            return Ok(RateLimitDecision {
                allowed: false,
                remaining: 0,
                retry_after: Some(retry_after),
            });
        }

        entry.count += 1;
        self.metrics.allowed_count.fetch_add(1, Ordering::SeqCst);
        Ok(RateLimitDecision {
            allowed: true,
            remaining: self.config.requests_per_window.saturating_sub(entry.count),
            retry_after: None,
        })
    }

    /// Returns current metrics.
    #[must_use]
    pub fn metrics(&self) -> LocalRateLimiterMetrics {
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        LocalRateLimiterMetrics {
            allowed_count: self.metrics.allowed_count.load(Ordering::SeqCst),
            rate_limited_count: self.metrics.rate_limited_count.load(Ordering::SeqCst),
            tracked_keys: state.len(),
        }
    }
}

#[derive(Debug)]
struct ConcurrencyState {
    counts: Mutex<BTreeMap<NormalizedLimitKey, usize>>,
    active_concurrency: AtomicU64,
    acquired_count: AtomicU64,
    concurrency_rejection_count: AtomicU64,
}

/// Local concurrency limiter with bounded key tracking.
#[derive(Debug, Clone)]
pub struct LocalConcurrencyLimiter {
    config: LocalConcurrencyLimitConfig,
    state: Arc<ConcurrencyState>,
}

impl LocalConcurrencyLimiter {
    /// Creates a validated local concurrency guard.
    pub fn new(config: LocalConcurrencyLimitConfig) -> Result<Self, LocalLimitError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Arc::new(ConcurrencyState {
                counts: Mutex::new(BTreeMap::new()),
                active_concurrency: AtomicU64::new(0),
                acquired_count: AtomicU64::new(0),
                concurrency_rejection_count: AtomicU64::new(0),
            }),
        })
    }

    /// Attempts to acquire concurrency capacity for the normalized key.
    pub fn try_acquire(
        &self,
        context: &LimitContext,
    ) -> Result<LocalConcurrencyLease, LocalLimitError> {
        let key = normalize_limit_key(&self.config.scope, self.config.key_kind, context);
        let mut counts = self.state.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        if !counts.contains_key(&key) && counts.len() == self.config.max_tracked_keys {
            self.state.concurrency_rejection_count.fetch_add(1, Ordering::SeqCst);
            return Err(LocalLimitError::StateSaturated);
        }

        let current = counts.entry(key.clone()).or_insert(0);
        if *current >= self.config.max_concurrent {
            self.state.concurrency_rejection_count.fetch_add(1, Ordering::SeqCst);
            return Err(LocalLimitError::ConcurrencyLimitExceeded);
        }

        *current += 1;
        self.state.active_concurrency.fetch_add(1, Ordering::SeqCst);
        self.state.acquired_count.fetch_add(1, Ordering::SeqCst);
        Ok(LocalConcurrencyLease { state: Arc::downgrade(&self.state), key })
    }

    /// Returns current metrics.
    #[must_use]
    pub fn metrics(&self) -> LocalConcurrencyLimiterMetrics {
        let counts = self.state.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        LocalConcurrencyLimiterMetrics {
            acquired_count: self.state.acquired_count.load(Ordering::SeqCst),
            concurrency_rejection_count: self
                .state
                .concurrency_rejection_count
                .load(Ordering::SeqCst),
            active_concurrency: self.state.active_concurrency.load(Ordering::SeqCst) as usize,
            tracked_keys: counts.len(),
        }
    }
}

/// RAII lease returned by the concurrency limiter.
#[derive(Debug)]
pub struct LocalConcurrencyLease {
    state: Weak<ConcurrencyState>,
    key: NormalizedLimitKey,
}

impl Drop for LocalConcurrencyLease {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let mut counts = state.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                let _ = counts.remove(&self.key);
            }
            state.active_concurrency.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn validate_scope(scope: &LocalLimitScope) -> Result<(), LocalLimitError> {
    let valid = match scope {
        LocalLimitScope::Listener { name }
        | LocalLimitScope::Route { name }
        | LocalLimitScope::UpstreamCluster { name } => !normalize_component(name).is_empty(),
    };
    if valid {
        Ok(())
    } else {
        Err(LocalLimitError::EmptyScopeName)
    }
}

fn normalize_limit_key(
    scope: &LocalLimitScope,
    key_kind: LocalLimitKeyKind,
    context: &LimitContext,
) -> NormalizedLimitKey {
    let scope_prefix = match scope {
        LocalLimitScope::Listener { name } => format!("listener:{}", normalize_component(name)),
        LocalLimitScope::Route { name } => format!("route:{}", normalize_component(name)),
        LocalLimitScope::UpstreamCluster { name } => {
            format!("upstream:{}", normalize_component(name))
        }
    };

    let key_value = match key_kind {
        LocalLimitKeyKind::Global => String::from("global"),
        LocalLimitKeyKind::SourceIp => context
            .source_ip
            .map(|value| value.to_string())
            .unwrap_or_else(|| String::from("missing")),
        LocalLimitKeyKind::RouteName => context
            .route_name
            .as_deref()
            .map(normalize_component)
            .unwrap_or_else(|| String::from("missing")),
        LocalLimitKeyKind::UpstreamCluster => context
            .upstream_cluster
            .as_deref()
            .map(normalize_component)
            .unwrap_or_else(|| String::from("missing")),
    };

    NormalizedLimitKey(format!("{scope_prefix}|key:{key_value}"))
}

fn normalize_component(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len().min(MAX_NORMALIZED_COMPONENT_LEN));
    for ch in value.trim().chars() {
        if normalized.len() == MAX_NORMALIZED_COMPONENT_LEN {
            break;
        }
        let normalized_ch = if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':') {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        normalized.push(normalized_ch);
    }
    if normalized.is_empty() {
        String::from("missing")
    } else {
        normalized
    }
}

fn duration_tick(value: Duration) -> u64 {
    value.as_millis().min(u128::from(u64::MAX)) as u64
}

fn evict_oldest_key(state: &mut BTreeMap<NormalizedLimitKey, RateWindowState>) {
    let oldest_key =
        state.iter().min_by_key(|(_, value)| value.last_seen_tick).map(|(key, _)| key.clone());
    if let Some(oldest_key) = oldest_key {
        let _ = state.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        LimitContext, LocalConcurrencyLimitConfig, LocalLimitError, LocalLimitKeyKind,
        LocalLimitScope, LocalRateLimitConfig, LocalRateLimiter,
    };

    #[test]
    fn rate_limiter_enforces_fixed_window() -> Result<(), Box<dyn std::error::Error>> {
        let limiter = LocalRateLimiter::new(LocalRateLimitConfig {
            scope: LocalLimitScope::Listener { name: String::from("public") },
            key_kind: LocalLimitKeyKind::Global,
            requests_per_window: 2,
            window: Duration::from_secs(1),
            max_tracked_keys: 8,
        })?;

        assert!(limiter.check(Duration::ZERO, &LimitContext::default())?.allowed);
        assert!(limiter.check(Duration::ZERO, &LimitContext::default())?.allowed);
        let rejected = limiter.check(Duration::ZERO, &LimitContext::default())?;
        assert!(!rejected.allowed);
        assert_eq!(rejected.retry_after, Some(Duration::from_secs(1)));

        assert!(limiter.check(Duration::from_secs(1), &LimitContext::default())?.allowed);
        Ok(())
    }

    #[test]
    fn rate_limiter_bounds_state_by_eviction() -> Result<(), Box<dyn std::error::Error>> {
        let limiter = LocalRateLimiter::new(LocalRateLimitConfig {
            scope: LocalLimitScope::Route { name: String::from("orders") },
            key_kind: LocalLimitKeyKind::RouteName,
            requests_per_window: 1,
            window: Duration::from_secs(10),
            max_tracked_keys: 2,
        })?;

        let _ = limiter.check(
            Duration::from_secs(0),
            &LimitContext { route_name: Some(String::from("A")), ..LimitContext::default() },
        )?;
        let _ = limiter.check(
            Duration::from_secs(1),
            &LimitContext { route_name: Some(String::from("B")), ..LimitContext::default() },
        )?;
        let _ = limiter.check(
            Duration::from_secs(2),
            &LimitContext { route_name: Some(String::from("C")), ..LimitContext::default() },
        )?;

        assert_eq!(limiter.metrics().tracked_keys, 2);
        Ok(())
    }

    #[test]
    fn concurrency_config_rejects_zero_limit() {
        let result = LocalConcurrencyLimitConfig {
            scope: LocalLimitScope::Listener { name: String::from("public") },
            key_kind: LocalLimitKeyKind::Global,
            max_concurrent: 0,
            max_tracked_keys: 1,
        }
        .validate();

        assert_eq!(result, Err(LocalLimitError::ZeroConcurrencyLimit));
    }
}
