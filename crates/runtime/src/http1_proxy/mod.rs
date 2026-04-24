use std::collections::BTreeMap;
use std::fmt;
use std::hash::Hasher;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{
    build_http_cache_key_material, AnonymousSourceFilterPolicy, AnonymousSourceFilterState,
    HttpCacheEntry, HttpCacheHeader, HttpCacheKey, HttpCacheMetadata, HttpCacheRequest,
    HttpCacheRequestOutcome, HttpCacheRevalidationResult, HttpCacheStore, HttpUpgradeResult,
    ProtocolAnomalyCategory, RouteEnumerationProtectionPolicy, RouteEnumerationProtectionState,
    RuntimeTelemetry, SlowClientStage, TrustedClientIpPolicy,
};
use http::{HeaderName, HeaderValue, StatusCode};
use httpdate::parse_http_date;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

include!("config_and_types.rs");
include!("errors_and_reports.rs");
include!("connection_proxy.rs");
include!("single_request.rs");
include!("route_selection.rs");
include!("request_auth.rs");
include!("request_transforms.rs");
include!("destination_policies.rs");
include!("traffic_mirroring.rs");
include!("fault_injection.rs");
include!("upgrades.rs");
include!("client_identity_and_affinity.rs");
include!("route_enumeration_and_anonymous_source.rs");
include!("passive_health.rs");
include!("cache_lookup.rs");
include!("cache_fill_and_revalidation.rs");
include!("cache_headers_and_freshness.rs");
include!("upstream_connection.rs");
include!("local_responses.rs");
include!("body_relay.rs");
include!("upgrade_relay.rs");
include!("tests.rs");
