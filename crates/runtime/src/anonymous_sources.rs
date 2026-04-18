use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use ipnet::IpNet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousSourceCategory {
    Direct,
    Vpn,
    Proxy,
    Socks,
    Tor,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnonymousSourceFilterPolicy {
    pub enabled: bool,
    pub deny_cidrs: Vec<IpNet>,
    pub deny_vpn: bool,
    pub deny_proxy: bool,
    pub deny_socks: bool,
    pub deny_tor: bool,
    pub vpn_cidrs: Vec<IpNet>,
    pub proxy_cidrs: Vec<IpNet>,
    pub socks_cidrs: Vec<IpNet>,
    pub tor_exit_cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnonymousSourceFilterSnapshot {
    pub blocked_direct_count: u64,
    pub blocked_vpn_count: u64,
    pub blocked_proxy_count: u64,
    pub blocked_socks_count: u64,
    pub blocked_tor_count: u64,
}

#[derive(Debug, Default)]
pub struct AnonymousSourceFilterState {
    policy: AnonymousSourceFilterPolicy,
    blocked_direct_count: AtomicU64,
    blocked_vpn_count: AtomicU64,
    blocked_proxy_count: AtomicU64,
    blocked_socks_count: AtomicU64,
    blocked_tor_count: AtomicU64,
}

impl AnonymousSourceFilterState {
    #[must_use]
    pub fn new(policy: AnonymousSourceFilterPolicy) -> Self {
        Self {
            policy,
            blocked_direct_count: AtomicU64::new(0),
            blocked_vpn_count: AtomicU64::new(0),
            blocked_proxy_count: AtomicU64::new(0),
            blocked_socks_count: AtomicU64::new(0),
            blocked_tor_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn classify_and_record(&self, ip: IpAddr) -> Option<AnonymousSourceCategory> {
        if !self.policy.enabled {
            return None;
        }

        if self.policy.deny_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            self.blocked_direct_count.fetch_add(1, Ordering::SeqCst);
            return Some(AnonymousSourceCategory::Direct);
        }

        if self.policy.deny_tor && self.policy.tor_exit_cidrs.iter().any(|cidr| cidr.contains(&ip))
        {
            self.blocked_tor_count.fetch_add(1, Ordering::SeqCst);
            return Some(AnonymousSourceCategory::Tor);
        }
        if self.policy.deny_socks && self.policy.socks_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            self.blocked_socks_count.fetch_add(1, Ordering::SeqCst);
            return Some(AnonymousSourceCategory::Socks);
        }
        if self.policy.deny_proxy && self.policy.proxy_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            self.blocked_proxy_count.fetch_add(1, Ordering::SeqCst);
            return Some(AnonymousSourceCategory::Proxy);
        }
        if self.policy.deny_vpn && self.policy.vpn_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            self.blocked_vpn_count.fetch_add(1, Ordering::SeqCst);
            return Some(AnonymousSourceCategory::Vpn);
        }

        None
    }

    #[must_use]
    pub fn snapshot(&self) -> AnonymousSourceFilterSnapshot {
        AnonymousSourceFilterSnapshot {
            blocked_direct_count: self.blocked_direct_count.load(Ordering::SeqCst),
            blocked_vpn_count: self.blocked_vpn_count.load(Ordering::SeqCst),
            blocked_proxy_count: self.blocked_proxy_count.load(Ordering::SeqCst),
            blocked_socks_count: self.blocked_socks_count.load(Ordering::SeqCst),
            blocked_tor_count: self.blocked_tor_count.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnet::IpNet;

    use super::{AnonymousSourceCategory, AnonymousSourceFilterPolicy, AnonymousSourceFilterState};

    #[test]
    fn blocks_direct_cidr_before_category_matches() {
        let filter = AnonymousSourceFilterState::new(AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("direct cidr")],
            deny_vpn: true,
            deny_proxy: true,
            deny_socks: true,
            deny_tor: true,
            vpn_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("vpn cidr")],
            proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("proxy cidr")],
            socks_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("socks cidr")],
            tor_exit_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("tor cidr")],
        });

        let category = filter.classify_and_record(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(category, Some(AnonymousSourceCategory::Direct));

        let snapshot = filter.snapshot();
        assert_eq!(snapshot.blocked_direct_count, 1);
        assert_eq!(snapshot.blocked_tor_count, 0);
    }

    #[test]
    fn blocks_ipv6_cidr_ranges() {
        let filter = AnonymousSourceFilterState::new(AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: vec!["2001:db8::/32".parse::<IpNet>().expect("ipv6 cidr")],
            deny_vpn: false,
            deny_proxy: false,
            deny_socks: false,
            deny_tor: false,
            vpn_cidrs: Vec::new(),
            proxy_cidrs: Vec::new(),
            socks_cidrs: Vec::new(),
            tor_exit_cidrs: Vec::new(),
        });

        let category = filter.classify_and_record("2001:db8::42".parse::<IpAddr>().expect("ipv6"));
        assert_eq!(category, Some(AnonymousSourceCategory::Direct));

        let snapshot = filter.snapshot();
        assert_eq!(snapshot.blocked_direct_count, 1);
    }

    #[test]
    fn blocks_first_matching_category_in_priority_order() {
        let filter = AnonymousSourceFilterState::new(AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: Vec::new(),
            deny_vpn: true,
            deny_proxy: true,
            deny_socks: true,
            deny_tor: true,
            vpn_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("vpn cidr")],
            proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("proxy cidr")],
            socks_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("socks cidr")],
            tor_exit_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("tor cidr")],
        });

        let category = filter.classify_and_record(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(category, Some(AnonymousSourceCategory::Tor));

        let snapshot = filter.snapshot();
        assert_eq!(snapshot.blocked_tor_count, 1);
        assert_eq!(snapshot.blocked_proxy_count, 0);
    }
}
