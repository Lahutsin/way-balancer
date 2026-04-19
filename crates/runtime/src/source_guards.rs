use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceAggregation {
    ExactIp,
    Ipv4Subnet24,
    Ipv6Subnet64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceQuotaPolicy {
    pub aggregation: SourceAggregation,
    pub max_active_per_source: usize,
    pub max_tracked_sources: usize,
}

impl SourceQuotaPolicy {
    #[must_use]
    pub const fn new(
        aggregation: SourceAggregation,
        max_active_per_source: usize,
        max_tracked_sources: usize,
    ) -> Self {
        Self { aggregation, max_active_per_source, max_tracked_sources }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeGuardPolicy {
    pub max_inflight: usize,
    pub timeout: Duration,
}

impl HandshakeGuardPolicy {
    #[must_use]
    pub const fn new(max_inflight: usize, timeout: Duration) -> Self {
        Self { max_inflight, timeout }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListenerAbuseProtectionPolicy {
    pub source_quota: Option<SourceQuotaPolicy>,
    pub handshake_guard: Option<HandshakeGuardPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListenerAbuseProtectionSnapshot {
    pub source_quota_rejections: u64,
    pub tracked_source_limit_rejections: u64,
    pub handshake_guard_rejections: u64,
    pub tracked_sources: usize,
    pub active_handshakes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseRejectionReason {
    SourceQuotaExceeded,
    TrackedSourceLimitReached,
    HandshakeLimitReached,
}

impl AbuseRejectionReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceQuotaExceeded => "source_quota_exceeded",
            Self::TrackedSourceLimitReached => "tracked_source_limit_reached",
            Self::HandshakeLimitReached => "handshake_limit_reached",
        }
    }

    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::SourceQuotaExceeded => "source quota exhausted",
            Self::TrackedSourceLimitReached => "bounded source state exhausted",
            Self::HandshakeLimitReached => "handshake concurrency exhausted",
        }
    }
}

#[derive(Debug)]
pub struct ListenerAbuseProtectionState {
    source_quota: Option<Arc<SourceQuotaTracker>>,
    handshake_guard: Option<Arc<HandshakeGuard>>,
    source_quota_rejections: AtomicU64,
    tracked_source_limit_rejections: AtomicU64,
    handshake_guard_rejections: AtomicU64,
}

impl ListenerAbuseProtectionState {
    #[must_use]
    pub fn new(policy: ListenerAbuseProtectionPolicy) -> Self {
        Self {
            source_quota: policy.source_quota.map(SourceQuotaTracker::new).map(Arc::new),
            handshake_guard: policy.handshake_guard.map(HandshakeGuard::new).map(Arc::new),
            source_quota_rejections: AtomicU64::new(0),
            tracked_source_limit_rejections: AtomicU64::new(0),
            handshake_guard_rejections: AtomicU64::new(0),
        }
    }

    pub fn try_acquire_source(
        &self,
        peer_addr: SocketAddr,
    ) -> Result<Option<SourceQuotaLease>, AbuseRejectionReason> {
        let Some(tracker) = &self.source_quota else {
            return Ok(None);
        };

        tracker.try_acquire(peer_addr).map(Some).inspect_err(|error| {
            match error {
                AbuseRejectionReason::SourceQuotaExceeded => {
                    self.source_quota_rejections.fetch_add(1, Ordering::SeqCst);
                }
                AbuseRejectionReason::TrackedSourceLimitReached => {
                    self.tracked_source_limit_rejections.fetch_add(1, Ordering::SeqCst);
                }
                AbuseRejectionReason::HandshakeLimitReached => {}
            }
        })
    }

    pub fn try_acquire_handshake(&self) -> Result<Option<HandshakePermit>, AbuseRejectionReason> {
        let Some(guard) = &self.handshake_guard else {
            return Ok(None);
        };

        guard.try_acquire().map(Some).inspect_err(|_error| {
            self.handshake_guard_rejections.fetch_add(1, Ordering::SeqCst);
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> ListenerAbuseProtectionSnapshot {
        ListenerAbuseProtectionSnapshot {
            source_quota_rejections: self.source_quota_rejections.load(Ordering::SeqCst),
            tracked_source_limit_rejections: self
                .tracked_source_limit_rejections
                .load(Ordering::SeqCst),
            handshake_guard_rejections: self.handshake_guard_rejections.load(Ordering::SeqCst),
            tracked_sources: self
                .source_quota
                .as_ref()
                .map_or(0, |tracker| tracker.tracked_sources()),
            active_handshakes: self
                .handshake_guard
                .as_ref()
                .map_or(0, |guard| guard.active_handshakes()),
        }
    }

    #[must_use]
    pub fn handshake_timeout(&self) -> Option<Duration> {
        self.handshake_guard.as_ref().map(|guard| guard.timeout)
    }
}

impl Default for ListenerAbuseProtectionState {
    fn default() -> Self {
        Self::new(ListenerAbuseProtectionPolicy::default())
    }
}

#[derive(Debug)]
struct SourceQuotaTracker {
    policy: SourceQuotaPolicy,
    active_by_source: Mutex<BTreeMap<String, usize>>,
}

impl SourceQuotaTracker {
    fn new(policy: SourceQuotaPolicy) -> Self {
        Self { policy, active_by_source: Mutex::new(BTreeMap::new()) }
    }

    fn try_acquire(
        self: &Arc<Self>,
        peer_addr: SocketAddr,
    ) -> Result<SourceQuotaLease, AbuseRejectionReason> {
        let key = normalize_source_key(peer_addr.ip(), self.policy.aggregation);
        let mut active_by_source =
            self.active_by_source.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(active) = active_by_source.get_mut(&key) {
            if *active >= self.policy.max_active_per_source {
                return Err(AbuseRejectionReason::SourceQuotaExceeded);
            }
            *active = active.saturating_add(1);
            return Ok(SourceQuotaLease { tracker: Arc::clone(self), key });
        }

        if active_by_source.len() >= self.policy.max_tracked_sources {
            return Err(AbuseRejectionReason::TrackedSourceLimitReached);
        }

        active_by_source.insert(key.clone(), 1);
        Ok(SourceQuotaLease { tracker: Arc::clone(self), key })
    }

    fn tracked_sources(&self) -> usize {
        self.active_by_source.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    fn release(&self, key: &str) {
        let mut active_by_source =
            self.active_by_source.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(active) = active_by_source.get_mut(key) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                active_by_source.remove(key);
            }
        }
    }
}

#[derive(Debug)]
pub struct SourceQuotaLease {
    tracker: Arc<SourceQuotaTracker>,
    key: String,
}

impl Drop for SourceQuotaLease {
    fn drop(&mut self) {
        self.tracker.release(&self.key);
    }
}

#[derive(Debug)]
struct HandshakeGuard {
    semaphore: Arc<Semaphore>,
    max_inflight: usize,
    timeout: Duration,
}

impl HandshakeGuard {
    fn new(policy: HandshakeGuardPolicy) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(policy.max_inflight)),
            max_inflight: policy.max_inflight,
            timeout: policy.timeout,
        }
    }

    fn try_acquire(&self) -> Result<HandshakePermit, AbuseRejectionReason> {
        Arc::clone(&self.semaphore)
            .try_acquire_owned()
            .map(|permit| HandshakePermit { permit: Some(permit) })
            .map_err(|_| AbuseRejectionReason::HandshakeLimitReached)
    }

    fn active_handshakes(&self) -> usize {
        self.max_inflight.saturating_sub(self.semaphore.available_permits())
    }
}

#[derive(Debug)]
pub struct HandshakePermit {
    permit: Option<OwnedSemaphorePermit>,
}

impl HandshakePermit {
    pub fn release(&mut self) {
        let _ = self.permit.take();
    }
}

fn normalize_source_key(ip: IpAddr, aggregation: SourceAggregation) -> String {
    match (aggregation, ip) {
        (SourceAggregation::ExactIp, ip) => ip.to_string(),
        (SourceAggregation::Ipv4Subnet24, IpAddr::V4(ipv4)) => {
            let octets = ipv4.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        (SourceAggregation::Ipv4Subnet24, IpAddr::V6(ipv6)) => ipv6.to_string(),
        (SourceAggregation::Ipv6Subnet64, IpAddr::V6(ipv6)) => {
            let segments = ipv6.segments();
            Ipv6Addr::new(segments[0], segments[1], segments[2], segments[3], 0, 0, 0, 0)
                .to_string()
                + "/64"
        }
        (SourceAggregation::Ipv6Subnet64, IpAddr::V4(ipv4)) => ipv4.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    use super::{
        normalize_source_key, AbuseRejectionReason, HandshakeGuardPolicy,
        ListenerAbuseProtectionPolicy, ListenerAbuseProtectionState, SourceAggregation,
        SourceQuotaPolicy,
    };

    #[test]
    fn source_normalization_is_explicit_for_exact_and_subnet_modes() {
        let exact = normalize_source_key(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            SourceAggregation::ExactIp,
        );
        let subnet_v4 = normalize_source_key(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            SourceAggregation::Ipv4Subnet24,
        );
        let subnet_v6 = normalize_source_key(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 1, 2, 3, 4)),
            SourceAggregation::Ipv6Subnet64,
        );

        assert_eq!(exact, "192.0.2.10");
        assert_eq!(subnet_v4, "192.0.2.0/24");
        assert_eq!(subnet_v6, "2001:db8:0:1::/64");
    }

    #[test]
    fn per_source_quota_rejects_excess_connections() {
        let state = ListenerAbuseProtectionState::new(ListenerAbuseProtectionPolicy {
            source_quota: Some(SourceQuotaPolicy::new(SourceAggregation::ExactIp, 1, 8)),
            handshake_guard: None,
        });
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let first = state.try_acquire_source(peer);
        let second = state.try_acquire_source(peer);

        assert!(first.is_ok());
        assert!(matches!(second, Err(AbuseRejectionReason::SourceQuotaExceeded)));
        assert_eq!(state.snapshot().source_quota_rejections, 1);
    }

    #[test]
    fn subnet_aggregation_groups_ipv4_clients() {
        let state = ListenerAbuseProtectionState::new(ListenerAbuseProtectionPolicy {
            source_quota: Some(SourceQuotaPolicy::new(SourceAggregation::Ipv4Subnet24, 1, 8)),
            handshake_guard: None,
        });

        let first = state
            .try_acquire_source(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 1111));
        let second = state
            .try_acquire_source(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)), 2222));

        assert!(first.is_ok());
        assert!(matches!(second, Err(AbuseRejectionReason::SourceQuotaExceeded)));
    }

    #[test]
    fn handshake_guard_caps_concurrency() {
        let state = ListenerAbuseProtectionState::new(ListenerAbuseProtectionPolicy {
            source_quota: None,
            handshake_guard: Some(HandshakeGuardPolicy::new(1, Duration::from_secs(1))),
        });

        let first = state.try_acquire_handshake();
        let second = state.try_acquire_handshake();

        assert!(first.is_ok());
        assert!(matches!(second, Err(AbuseRejectionReason::HandshakeLimitReached)));
        assert_eq!(state.snapshot().handshake_guard_rejections, 1);
        assert_eq!(state.snapshot().active_handshakes, 1);
    }
}
