use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustedClientIpPolicy {
    pub enabled: bool,
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedClientIpError {
    UntrustedForwardingHeader,
    InvalidForwardingHeader,
}

impl TrustedClientIpPolicy {
    #[must_use]
    pub fn resolve_from_http1_headers(
        &self,
        peer_ip: IpAddr,
        headers: &[lb_proto_http::HttpHeader],
    ) -> Result<IpAddr, TrustedClientIpError> {
        self.resolve_from_header_iter(
            peer_ip,
            headers
                .iter()
                .map(|header| (header.name.as_str(), header.value.as_str())),
        )
    }

    #[must_use]
    pub fn resolve_from_http2_headers(
        &self,
        peer_ip: IpAddr,
        headers: &http::HeaderMap,
    ) -> Result<IpAddr, TrustedClientIpError> {
        self.resolve_from_header_iter(
            peer_ip,
            headers
                .iter()
                .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str(), value))),
        )
    }

    fn resolve_from_header_iter<'a>(
        &self,
        peer_ip: IpAddr,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<IpAddr, TrustedClientIpError> {
        if !self.enabled {
            return Ok(peer_ip);
        }

        let mut forwarded_values = Vec::new();
        let mut xff_values = Vec::new();
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("forwarded") {
                forwarded_values.push(value);
            } else if name.eq_ignore_ascii_case("x-forwarded-for") {
                xff_values.push(value);
            }
        }

        if forwarded_values.is_empty() && xff_values.is_empty() {
            return Ok(peer_ip);
        }

        if !self.is_trusted_proxy(peer_ip) {
            return Err(TrustedClientIpError::UntrustedForwardingHeader);
        }

        let chain = if !forwarded_values.is_empty() {
            parse_forwarded_chain(&forwarded_values)?
        } else {
            parse_x_forwarded_for_chain(&xff_values)?
        };
        if chain.is_empty() {
            return Err(TrustedClientIpError::InvalidForwardingHeader);
        }

        Ok(resolve_client_from_chain(peer_ip, &chain, &self.trusted_proxy_cidrs))
    }

    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxy_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }
}

fn resolve_client_from_chain(peer_ip: IpAddr, chain: &[IpAddr], trusted_proxy_cidrs: &[IpNet]) -> IpAddr {
    let mut current = peer_ip;
    for candidate in chain.iter().rev() {
        if trusted_proxy_cidrs.iter().any(|cidr| cidr.contains(&current)) {
            current = *candidate;
        } else {
            break;
        }
    }
    current
}

fn parse_x_forwarded_for_chain(values: &[&str]) -> Result<Vec<IpAddr>, TrustedClientIpError> {
    let mut chain = Vec::new();
    for value in values {
        for entry in value.split(',').map(str::trim) {
            if entry.is_empty() {
                return Err(TrustedClientIpError::InvalidForwardingHeader);
            }
            chain.push(parse_forwarded_ip_token(entry)?);
        }
    }
    Ok(chain)
}

fn parse_forwarded_chain(values: &[&str]) -> Result<Vec<IpAddr>, TrustedClientIpError> {
    let mut chain = Vec::new();
    for value in values {
        for element in value.split(',') {
            let mut found = false;
            for parameter in element.split(';') {
                let Some((name, raw_value)) = parameter.trim().split_once('=') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case("for") {
                    chain.push(parse_forwarded_ip_token(raw_value.trim())?);
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(TrustedClientIpError::InvalidForwardingHeader);
            }
        }
    }
    Ok(chain)
}

fn parse_forwarded_ip_token(token: &str) -> Result<IpAddr, TrustedClientIpError> {
    let token = token.trim().trim_matches('"');
    if token.is_empty() || token.eq_ignore_ascii_case("unknown") || token.starts_with('_') {
        return Err(TrustedClientIpError::InvalidForwardingHeader);
    }

    if let Some(inner) = token.strip_prefix('[') {
        let bracket_end = inner.find(']').ok_or(TrustedClientIpError::InvalidForwardingHeader)?;
        let host = &inner[..bracket_end];
        if !inner[bracket_end + 1..].is_empty() && !inner[bracket_end + 1..].starts_with(':') {
            return Err(TrustedClientIpError::InvalidForwardingHeader);
        }
        return host.parse::<IpAddr>().map_err(|_| TrustedClientIpError::InvalidForwardingHeader);
    }

    if let Ok(ip) = token.parse::<IpAddr>() {
        return Ok(ip);
    }

    if let Some((host, port)) = token.rsplit_once(':') {
        if port.chars().all(|character| character.is_ascii_digit()) {
            return host
                .parse::<IpAddr>()
                .map_err(|_| TrustedClientIpError::InvalidForwardingHeader);
        }
    }

    Err(TrustedClientIpError::InvalidForwardingHeader)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ipnet::IpNet;

    use super::{TrustedClientIpError, TrustedClientIpPolicy};

    #[test]
    fn rejects_forwarding_headers_from_untrusted_peer() {
        let policy = TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("cidr")],
        };
        let headers = vec![lb_proto_http::HttpHeader {
            name: String::from("x-forwarded-for"),
            value: String::from("198.51.100.10"),
        }];

        let result = policy.resolve_from_http1_headers("198.51.100.20".parse().expect("ip"), &headers);

        assert_eq!(result, Err(TrustedClientIpError::UntrustedForwardingHeader));
    }

    #[test]
    fn resolves_client_ip_through_trusted_xff_chain() {
        let policy = TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec![
                "127.0.0.0/8".parse::<IpNet>().expect("cidr"),
                "203.0.113.0/24".parse::<IpNet>().expect("cidr"),
            ],
        };
        let headers = vec![lb_proto_http::HttpHeader {
            name: String::from("x-forwarded-for"),
            value: String::from("198.51.100.10, 203.0.113.7"),
        }];

        let result = policy
            .resolve_from_http1_headers("127.0.0.1".parse().expect("ip"), &headers)
            .expect("client ip");

        assert_eq!(result, "198.51.100.10".parse::<IpAddr>().expect("ip"));
    }

    #[test]
    fn resolves_client_ip_from_forwarded_header() {
        let policy = TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("cidr")],
        };
        let headers = vec![lb_proto_http::HttpHeader {
            name: String::from("forwarded"),
            value: String::from("for=198.51.100.10;proto=https"),
        }];

        let result = policy
            .resolve_from_http1_headers("127.0.0.1".parse().expect("ip"), &headers)
            .expect("client ip");

        assert_eq!(result, "198.51.100.10".parse::<IpAddr>().expect("ip"));
    }

    #[test]
    fn rejects_malformed_forwarded_header() {
        let policy = TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("cidr")],
        };
        let headers = vec![lb_proto_http::HttpHeader {
            name: String::from("forwarded"),
            value: String::from("for=unknown"),
        }];

        let result = policy.resolve_from_http1_headers("127.0.0.1".parse().expect("ip"), &headers);

        assert_eq!(result, Err(TrustedClientIpError::InvalidForwardingHeader));
    }
}