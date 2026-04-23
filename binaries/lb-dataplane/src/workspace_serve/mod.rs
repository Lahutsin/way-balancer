#![allow(
	clippy::large_enum_variant,
	clippy::question_mark,
	clippy::result_large_err,
	clippy::too_many_arguments,
	clippy::type_complexity,
	clippy::useless_format
)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fs;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::Connection as H3Connection;
use ipnet::IpNet;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ProducesTickets, ResolvesServerCert};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch, Mutex, RwLock};
use tokio::task::JoinSet;
use tokio::time;
use tokio_rustls::TlsAcceptor;

use crate::{
	admin_bearer_secret, compile_anonymous_source_filter, compile_trusted_client_ip, ServeArgs,
};

type DynError = Box<dyn Error + Send + Sync>;

static TLS12_AND_TLS13: [&rustls::SupportedProtocolVersion; 2] =
	[&rustls::version::TLS13, &rustls::version::TLS12];
static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
const ACTIVE_HEALTH_PROBE_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVE_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(150);
const ROUTE_BACKEND_WARMUP_DURATION: Duration = Duration::from_secs(1);
const PROXY_PROTOCOL_V1_MAX_LEN: usize = 108;
const PROXY_PROTOCOL_V2_SIGNATURE: [u8; 12] = [
	0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, b'Q', b'U', b'I', b'T', 0x0a,
];
const ADMIN_AUDIT_DEFAULT_CAPACITY: usize = 64;
const CONTROL_PLANE_JOURNAL_VERSION: u32 = 1;
const RECOVERY_UNFINISHED_RELOAD_CODE: &str = "reload_recovered_unfinished";
const TLS_STATUS_EXPIRY_WARNING_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);
static NEXT_CONTROL_PLANE_JOURNAL_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static RUSTLS_CRYPTO_PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();

fn to_dyn_error(error: impl std::fmt::Display) -> DynError {
	Box::new(io::Error::other(error.to_string()))
}

fn ensure_rustls_crypto_provider() {
	RUSTLS_CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	});
}

include!("tls.rs");
include!("overload.rs");
include!("state.rs");
include!("listener_runtime.rs");
include!("listener_lifecycle.rs");
include!("listener_status.rs");
include!("readiness.rs");
include!("compile_runtime.rs");
include!("compile_routes.rs");
include!("compile_policies.rs");
include!("http_cache_scopes.rs");
include!("admin_api.rs");
include!("admin_auth.rs");
include!("admin_audit.rs");
include!("control_plane_journal.rs");
include!("recovery.rs");
include!("http3.rs");
include!("proxy_protocol.rs");
include!("abuse_protection.rs");
include!("active_health.rs");
include!("helpers.rs");
include!("supervisor.rs");
include!("tests.rs");