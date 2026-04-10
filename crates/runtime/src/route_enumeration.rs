use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::SourceAggregation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEnumerationProtectionPolicy {
    pub source_aggregation: SourceAggregation,
    pub evaluation_window: Duration,
    pub max_unmatched_route_events: usize,
    pub max_distinct_query_signatures_per_route: usize,
    pub base_ban_duration: Duration,
    pub max_ban_duration: Duration,
    pub max_tracked_sources: usize,
}

impl Default for RouteEnumerationProtectionPolicy {
    fn default() -> Self {
        Self {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: Duration::from_secs(30),
            max_unmatched_route_events: 3,
            max_distinct_query_signatures_per_route: 6,
            base_ban_duration: Duration::from_secs(60),
            max_ban_duration: Duration::from_secs(15 * 60),
            max_tracked_sources: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RouteEnumerationProtectionSnapshot {
    pub tracked_sources: usize,
    pub active_bans: usize,
    pub total_bans: u64,
    pub blocked_request_count: u64,
}

#[derive(Debug)]
pub struct RouteEnumerationProtectionState {
    policy: RouteEnumerationProtectionPolicy,
    sources: Mutex<BTreeMap<String, SourceState>>,
    total_bans: AtomicU64,
    blocked_request_count: AtomicU64,
}

#[derive(Debug)]
struct SourceState {
    last_seen: Instant,
    ban_level: u32,
    banned_until: Option<Instant>,
    unmatched_route_events: VecDeque<Instant>,
    distinct_query_signatures: BTreeMap<String, Instant>,
}

impl SourceState {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            ban_level: 0,
            banned_until: None,
            unmatched_route_events: VecDeque::new(),
            distinct_query_signatures: BTreeMap::new(),
        }
    }
}

impl RouteEnumerationProtectionState {
    #[must_use]
    pub fn new(policy: RouteEnumerationProtectionPolicy) -> Self {
        Self {
            policy,
            sources: Mutex::new(BTreeMap::new()),
            total_bans: AtomicU64::new(0),
            blocked_request_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn is_blocked(&self, peer_addr: SocketAddr) -> bool {
        let now = Instant::now();
        let key = normalize_source_key(peer_addr.ip(), self.policy.source_aggregation);
        let mut sources = self.sources.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(source) = sources.get_mut(&key) else {
            return false;
        };

        prune_source_state(source, now, self.policy.evaluation_window);
        source.last_seen = now;
        if source.banned_until.is_some_and(|until| until > now) {
            self.blocked_request_count.fetch_add(1, Ordering::SeqCst);
            return true;
        }

        false
    }

    #[must_use]
    pub fn record_unmatched_route(&self, peer_addr: SocketAddr) -> bool {
        let now = Instant::now();
        let key = normalize_source_key(peer_addr.ip(), self.policy.source_aggregation);
        let mut sources = self.sources.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = self.ensure_source_state(&mut sources, &key, now);
        prune_source_state(source, now, self.policy.evaluation_window);
        source.last_seen = now;
        if source.banned_until.is_some_and(|until| until > now) {
            self.blocked_request_count.fetch_add(1, Ordering::SeqCst);
            return true;
        }

        source.unmatched_route_events.push_back(now);
        if source.unmatched_route_events.len() > self.policy.max_unmatched_route_events {
            self.activate_ban(source, now);
            return true;
        }

        false
    }

    #[must_use]
    pub fn record_query_probe(
        &self,
        peer_addr: SocketAddr,
        host: Option<&str>,
        target: &str,
    ) -> bool {
        let Ok(canonical_target) = lb_proto_http::canonicalize_request_target(target) else {
            return false;
        };
        if canonical_target.query_pairs.is_empty() {
            return false;
        }

        let query_signature = canonical_query_signature(&canonical_target.query_pairs);
        if query_signature.is_empty() {
            return false;
        }

        let authority = host
            .and_then(|value| lb_proto_http::canonicalize_host(value).ok())
            .or(canonical_target.authority)
            .unwrap_or_else(|| String::from("_"));
        let route_key = format!("{authority}|{}", canonical_target.path);
        let route_key_prefix = format!("{route_key}?");
        let signature_key = format!("{route_key_prefix}{query_signature}");

        let now = Instant::now();
        let key = normalize_source_key(peer_addr.ip(), self.policy.source_aggregation);
        let mut sources = self.sources.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = self.ensure_source_state(&mut sources, &key, now);
        prune_source_state(source, now, self.policy.evaluation_window);
        source.last_seen = now;
        if source.banned_until.is_some_and(|until| until > now) {
            self.blocked_request_count.fetch_add(1, Ordering::SeqCst);
            return true;
        }

        source
            .distinct_query_signatures
            .entry(signature_key)
            .and_modify(|seen_at| *seen_at = now)
            .or_insert(now);

        let distinct_signature_count = source
            .distinct_query_signatures
            .keys()
            .filter(|entry_key| entry_key.starts_with(&route_key_prefix))
            .count();
        if distinct_signature_count > self.policy.max_distinct_query_signatures_per_route {
            self.activate_ban(source, now);
            return true;
        }

        false
    }

    #[must_use]
    pub fn snapshot(&self) -> RouteEnumerationProtectionSnapshot {
        let now = Instant::now();
        let mut sources = self.sources.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut active_bans = 0;
        for source in sources.values_mut() {
            prune_source_state(source, now, self.policy.evaluation_window);
            if source.banned_until.is_some_and(|until| until > now) {
                active_bans += 1;
            }
        }

        RouteEnumerationProtectionSnapshot {
            tracked_sources: sources.len(),
            active_bans,
            total_bans: self.total_bans.load(Ordering::SeqCst),
            blocked_request_count: self.blocked_request_count.load(Ordering::SeqCst),
        }
    }

    fn ensure_source_state<'a>(
        &self,
        sources: &'a mut BTreeMap<String, SourceState>,
        key: &str,
        now: Instant,
    ) -> &'a mut SourceState {
        if !sources.contains_key(key) {
            if sources.len() >= self.policy.max_tracked_sources {
                evict_oldest_source(sources);
            }
            sources.insert(key.to_string(), SourceState::new(now));
        }

        sources.get_mut(key).expect("source state must exist")
    }

    fn activate_ban(&self, source: &mut SourceState, now: Instant) {
        source.ban_level = source.ban_level.saturating_add(1);
        let shift = source.ban_level.saturating_sub(1).min(8);
        let duration = std::cmp::min(
            self.policy.base_ban_duration.saturating_mul(1_u32 << shift),
            self.policy.max_ban_duration,
        );
        source.banned_until = Some(now + duration);
        source.unmatched_route_events.clear();
        source.distinct_query_signatures.clear();
        self.total_bans.fetch_add(1, Ordering::SeqCst);
        self.blocked_request_count.fetch_add(1, Ordering::SeqCst);
    }
}

fn prune_source_state(source: &mut SourceState, now: Instant, window: Duration) {
    while source
        .unmatched_route_events
        .front()
        .is_some_and(|seen_at| now.duration_since(*seen_at) > window)
    {
        source.unmatched_route_events.pop_front();
    }
    source.distinct_query_signatures.retain(|_, seen_at| now.duration_since(*seen_at) <= window);
    if source.banned_until.is_some_and(|until| until <= now) {
        source.banned_until = None;
    }
}

fn evict_oldest_source(sources: &mut BTreeMap<String, SourceState>) {
    let oldest_key = sources
        .iter()
        .min_by_key(|(_, state)| state.last_seen)
        .map(|(key, _)| key.clone());
    if let Some(oldest_key) = oldest_key {
        sources.remove(&oldest_key);
    }
}

fn canonical_query_signature(query_pairs: &[(String, String)]) -> String {
    let mut names = query_pairs.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names.join("&")
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
            let masked = Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            );
            format!("{masked}/64")
        }
        (SourceAggregation::Ipv6Subnet64, IpAddr::V4(ipv4)) => ipv4.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread;

    use super::{
        RouteEnumerationProtectionPolicy, RouteEnumerationProtectionState,
        RouteEnumerationProtectionSnapshot,
    };
    use crate::SourceAggregation;

    #[test]
    fn query_probing_ignores_value_churn_but_bans_new_signatures() {
        let state = RouteEnumerationProtectionState::new(RouteEnumerationProtectionPolicy {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: std::time::Duration::from_secs(60),
            max_unmatched_route_events: 8,
            max_distinct_query_signatures_per_route: 1,
            base_ban_duration: std::time::Duration::from_secs(1),
            max_ban_duration: std::time::Duration::from_secs(8),
            max_tracked_sources: 16,
        });
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000);

        assert!(!state.record_query_probe(source, Some("example.test"), "/search?q=one"));
        assert!(!state.record_query_probe(source, Some("example.test"), "/search?q=two"));
        assert!(state.record_query_probe(source, Some("example.test"), "/search?debug=1&q=two"));
        assert!(state.is_blocked(source));

        let snapshot = state.snapshot();
        assert_eq!(snapshot.total_bans, 1);
        assert!(snapshot.blocked_request_count >= 2);
    }

    #[test]
    fn bans_escalate_progressively() {
        let state = RouteEnumerationProtectionState::new(RouteEnumerationProtectionPolicy {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: std::time::Duration::from_secs(60),
            max_unmatched_route_events: 0,
            max_distinct_query_signatures_per_route: 8,
            base_ban_duration: std::time::Duration::from_millis(25),
            max_ban_duration: std::time::Duration::from_millis(200),
            max_tracked_sources: 16,
        });
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001);

        assert!(state.record_unmatched_route(source));
        thread::sleep(std::time::Duration::from_millis(35));
        assert!(!state.is_blocked(source));

        assert!(state.record_unmatched_route(source));
        thread::sleep(std::time::Duration::from_millis(35));
        assert!(state.is_blocked(source));

        let RouteEnumerationProtectionSnapshot { total_bans, .. } = state.snapshot();
        assert_eq!(total_bans, 2);
    }

    #[test]
    fn query_probe_tracking_does_not_bleed_across_sibling_paths() {
        let state = RouteEnumerationProtectionState::new(RouteEnumerationProtectionPolicy {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: std::time::Duration::from_secs(60),
            max_unmatched_route_events: 8,
            max_distinct_query_signatures_per_route: 1,
            base_ban_duration: std::time::Duration::from_secs(1),
            max_ban_duration: std::time::Duration::from_secs(8),
            max_tracked_sources: 16,
        });
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40002);

        assert!(!state.record_query_probe(source, Some("example.test"), "/api?q=one"));
        assert!(!state.record_query_probe(source, Some("example.test"), "/api-v2?debug=1"));
        assert!(!state.is_blocked(source));
    }
}