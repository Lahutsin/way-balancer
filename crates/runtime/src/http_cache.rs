use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::str;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use lb_config_model::{
    AuthorizationCacheBehaviorConfig, CacheQueryKeyBehaviorConfig, HttpCachePolicyConfig,
};
use lb_proto_http::{
    canonicalize_host, canonicalize_request_target, extract_host_header, HttpHeader,
    RequestTargetError,
};
use serde::{Deserialize, Serialize};

pub const HTTP_CACHE_INVALIDATION_MAX_EVENT_ID_LEN: usize = 256;
pub const HTTP_CACHE_INVALIDATION_MAX_SCOPE_LEN: usize = 128;
pub const HTTP_CACHE_INVALIDATION_MAX_ISSUER_LEN: usize = 128;
pub const HTTP_CACHE_INVALIDATION_MAX_PATH_PREFIX_LEN: usize = 512;

/// Store-level configuration for the bounded in-memory HTTP cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheStoreConfig {
    /// Maximum number of entries tracked by the store.
    pub max_entries: usize,
    /// Maximum total bytes consumed by all cached objects.
    pub max_bytes: usize,
    /// Maximum bytes allowed for a single cached object.
    pub max_object_bytes: usize,
}

impl HttpCacheStoreConfig {
    /// Validates cache store invariants.
    pub fn validate(&self) -> Result<(), HttpCacheStoreError> {
        if self.max_entries == 0 {
            return Err(HttpCacheStoreError::ZeroMaxEntries);
        }
        if self.max_bytes == 0 {
            return Err(HttpCacheStoreError::ZeroMaxBytes);
        }
        if self.max_object_bytes == 0 {
            return Err(HttpCacheStoreError::ZeroMaxObjectBytes);
        }
        if self.max_object_bytes > self.max_bytes {
            return Err(HttpCacheStoreError::MaxObjectBytesExceedsStoreBytes {
                max_object_bytes: self.max_object_bytes,
                max_bytes: self.max_bytes,
            });
        }
        Ok(())
    }
}

/// Opaque cache key used by the runtime store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HttpCacheKey(Bytes);

impl HttpCacheKey {
    /// Creates a new cache key from stable bytes.
    pub fn new(key: impl Into<Bytes>) -> Result<Self, HttpCacheStoreError> {
        let key = key.into();
        if key.is_empty() {
            return Err(HttpCacheStoreError::EmptyKey);
        }
        Ok(Self(key))
    }

    /// Returns the stable key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Individual response header stored with a cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheHeader {
    /// Header name.
    pub name: HeaderName,
    /// Header value.
    pub value: HeaderValue,
}

impl HttpCacheHeader {
    /// Creates a response header record.
    #[must_use]
    pub fn new(name: HeaderName, value: HeaderValue) -> Self {
        Self { name, value }
    }

    fn estimated_size(&self) -> usize {
        self.name.as_str().len() + self.value.as_bytes().len()
    }
}

/// Freshness and validator metadata required for later cache phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheMetadata {
    /// Response status code stored for the object.
    pub status: StatusCode,
    /// Deterministic storage timestamp.
    pub stored_at: Duration,
    /// Freshness deadline.
    pub fresh_until: Duration,
    /// Optional stale-while-revalidate deadline.
    pub stale_while_revalidate_until: Option<Duration>,
    /// Optional stale-if-error deadline.
    pub stale_if_error_until: Option<Duration>,
    /// Optional strong or weak validator.
    pub etag: Option<HeaderValue>,
    /// Optional last-modified validator.
    pub last_modified: Option<HeaderValue>,
}

impl HttpCacheMetadata {
    /// Returns the freshness state of the object at the provided time.
    #[must_use]
    pub fn freshness(&self, now: Duration) -> Option<HttpCacheFreshness> {
        if now > self.expires_at() {
            None
        } else if self.is_fresh(now) {
            Some(HttpCacheFreshness::Fresh)
        } else if self.allows_stale_while_revalidate(now) {
            Some(HttpCacheFreshness::StaleWhileRevalidate)
        } else if self.allows_stale_if_error(now) {
            Some(HttpCacheFreshness::StaleIfError)
        } else {
            None
        }
    }

    /// Returns the hard expiry deadline for the object.
    #[must_use]
    pub fn expires_at(&self) -> Duration {
        self.stale_while_revalidate_until
            .into_iter()
            .chain(self.stale_if_error_until)
            .max()
            .unwrap_or(self.fresh_until)
    }

    /// Whether the object is fresh at the provided time.
    #[must_use]
    pub fn is_fresh(&self, now: Duration) -> bool {
        now <= self.fresh_until
    }

    /// Whether stale-while-revalidate service is still allowed.
    #[must_use]
    pub fn allows_stale_while_revalidate(&self, now: Duration) -> bool {
        self.stale_while_revalidate_until.is_some_and(|deadline| now <= deadline)
    }

    /// Whether stale-if-error service is still allowed.
    #[must_use]
    pub fn allows_stale_if_error(&self, now: Duration) -> bool {
        self.stale_if_error_until.is_some_and(|deadline| now <= deadline)
    }

    fn validate(&self) -> Result<(), HttpCacheStoreError> {
        if self.fresh_until < self.stored_at {
            return Err(HttpCacheStoreError::FreshnessBeforeStoredAt);
        }
        if self.stale_while_revalidate_until.is_some_and(|deadline| deadline < self.fresh_until) {
            return Err(HttpCacheStoreError::StaleWhileRevalidateBeforeFreshness);
        }
        if self.stale_if_error_until.is_some_and(|deadline| deadline < self.fresh_until) {
            return Err(HttpCacheStoreError::StaleIfErrorBeforeFreshness);
        }
        Ok(())
    }

    fn estimated_size(&self) -> usize {
        let mut size = std::mem::size_of::<Self>();
        size += self.etag.as_ref().map_or(0, |value| value.as_bytes().len());
        size += self.last_modified.as_ref().map_or(0, |value| value.as_bytes().len());
        size
    }
}

/// Immutable cached response object stored by the runtime cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheEntry {
    /// Cache metadata and freshness windows.
    pub metadata: HttpCacheMetadata,
    /// Stored response headers.
    pub headers: Vec<HttpCacheHeader>,
    /// Stored response body bytes.
    pub body: Bytes,
}

impl HttpCacheEntry {
    /// Returns the estimated memory footprint tracked by the store.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        self.metadata.estimated_size()
            + self.headers.iter().map(HttpCacheHeader::estimated_size).sum::<usize>()
            + self.body.len()
    }

    fn validate(&self) -> Result<(), HttpCacheStoreError> {
        self.metadata.validate()
    }
}

/// Observable freshness state returned from cache lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpCacheFreshness {
    /// The object is fresh and can be served directly.
    Fresh,
    /// The object is stale but still allowed during background revalidation.
    StaleWhileRevalidate,
    /// The object is stale but still allowed for upstream error fallback.
    StaleIfError,
}

/// Result returned by a successful lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheLookup {
    /// Cached entry.
    pub entry: HttpCacheEntry,
    /// Freshness state at the lookup time.
    pub freshness: HttpCacheFreshness,
}

/// Request context used to build a deterministic cache key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheRequest<'a> {
    /// Request method.
    pub method: &'a str,
    /// Raw request target.
    pub target: &'a str,
    /// Normalized request headers.
    pub headers: &'a [HttpHeader],
}

/// Primary plus optional secondary vary key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheKeyMaterial {
    /// Primary cache key based on static policy dimensions.
    pub primary: HttpCacheKey,
    /// Optional vary-aware secondary key material.
    pub secondary: Option<HttpCacheKey>,
}

impl HttpCacheKeyMaterial {
    /// Returns the stable storage key that combines primary and secondary material.
    pub fn storage_key(&self) -> Result<HttpCacheKey, HttpCacheStoreError> {
        let key = match &self.secondary {
            Some(secondary) => {
                let mut bytes = Vec::with_capacity(
                    self.primary.as_bytes().len() + secondary.as_bytes().len() + 1,
                );
                bytes.extend_from_slice(self.primary.as_bytes());
                bytes.push(0);
                bytes.extend_from_slice(secondary.as_bytes());
                Bytes::from(bytes)
            }
            None => Bytes::copy_from_slice(self.primary.as_bytes()),
        };
        HttpCacheKey::new(key)
    }
}

/// Result returned after inserting or replacing an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheInsertResult {
    /// Whether an existing entry was replaced.
    pub replaced: bool,
    /// Number of entries evicted to satisfy store bounds.
    pub evicted_entries: usize,
}

/// Observable runtime cache metrics snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpCacheStoreMetrics {
    /// Current number of tracked entries.
    pub entry_count: usize,
    /// Current total tracked bytes.
    pub total_bytes: usize,
    /// Current largest cached object footprint.
    pub max_object_bytes: usize,
    /// Successful lookups.
    pub hit_count: u64,
    /// Missed lookups.
    pub miss_count: u64,
    /// Insertions of new keys.
    pub insert_count: u64,
    /// Replacements of existing keys.
    pub replace_count: u64,
    /// Evictions due to store bounds.
    pub eviction_count: u64,
    /// Expirations due to elapsed freshness windows.
    pub expiration_count: u64,
    /// Rejected insertions.
    pub rejected_insert_count: u64,
}

/// Immutable snapshot of a single cache entry state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCacheEntrySnapshot {
    /// Stable key bytes.
    pub key: Bytes,
    /// Estimated bytes consumed by the object.
    pub size: usize,
    /// Last deterministic access timestamp.
    pub last_accessed_at: Duration,
    /// Stored metadata.
    pub metadata: HttpCacheMetadata,
}

/// Immutable snapshot of the whole cache store.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpCacheStoreSnapshot {
    /// Aggregate metrics.
    pub metrics: HttpCacheStoreMetrics,
    /// Deterministic per-entry state.
    pub entries: Vec<HttpCacheEntrySnapshot>,
}

/// Distributed invalidation target for a cache event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpCacheInvalidationTarget {
    ExactKey(HttpCacheKey),
    PathPrefix(String),
}

/// Replay-safe invalidation event that may be applied across multiple nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCacheInvalidationEvent {
    pub event_id: String,
    pub scope: String,
    pub issuer: String,
    pub target: HttpCacheInvalidationTarget,
    pub occurred_at_unix_ms: u64,
}

impl HttpCacheInvalidationEvent {
    pub fn new(
        event_id: impl Into<String>,
        scope: impl Into<String>,
        issuer: impl Into<String>,
        target: HttpCacheInvalidationTarget,
        occurred_at_unix_ms: u64,
    ) -> Result<Self, HttpCacheInvalidationError> {
        let event = Self {
            event_id: event_id.into(),
            scope: scope.into(),
            issuer: issuer.into(),
            target,
            occurred_at_unix_ms,
        };
        validate_invalidation_event(&event)?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), HttpCacheInvalidationError> {
        validate_invalidation_event(self)
    }
}

/// Result of applying one invalidation event to a local cache instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCacheInvalidationApplyResult {
    Applied { purged_entries: usize },
    Duplicate,
}

/// Aggregate publish result across all local subscribers on a fan-out bus.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpCacheInvalidationPublishResult {
    pub subscriber_count: usize,
    pub applied_count: usize,
    pub duplicate_count: usize,
    pub purged_entries: usize,
    pub delivery_success_count: usize,
    pub delivery_failure_count: usize,
    pub failed_targets: Vec<String>,
}

pub trait HttpCacheInvalidationTransport: Send + Sync {
    fn name(&self) -> &str;

    fn publish(
        &self,
        event: &HttpCacheInvalidationEvent,
    ) -> Result<HttpCacheInvalidationPublishResult, HttpCacheInvalidationTransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCacheInvalidationTransportError {
    InvalidEvent(HttpCacheInvalidationError),
    PublishFailed { transport: String, detail: String },
}

impl fmt::Display for HttpCacheInvalidationTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvent(error) => {
                write!(formatter, "invalid cache invalidation event: {error}")
            }
            Self::PublishFailed { transport, detail } => {
                write!(formatter, "cache invalidation publish failed via {transport}: {detail}")
            }
        }
    }
}

impl std::error::Error for HttpCacheInvalidationTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEvent(error) => Some(error),
            Self::PublishFailed { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpCacheInvalidationBusTransport {
    bus: Arc<HttpCacheInvalidationBus>,
}

impl HttpCacheInvalidationBusTransport {
    #[must_use]
    pub fn new(bus: Arc<HttpCacheInvalidationBus>) -> Self {
        Self { bus }
    }
}

impl HttpCacheInvalidationTransport for HttpCacheInvalidationBusTransport {
    fn name(&self) -> &str {
        "in_memory_bus"
    }

    fn publish(
        &self,
        event: &HttpCacheInvalidationEvent,
    ) -> Result<HttpCacheInvalidationPublishResult, HttpCacheInvalidationTransportError> {
        self.bus.publish(event).map_err(HttpCacheInvalidationTransportError::InvalidEvent)
    }
}

/// Errors returned by cache invalidation modeling and application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCacheInvalidationError {
    EmptyEventId,
    EventIdTooLong,
    EmptyScope,
    ScopeTooLong,
    EmptyIssuer,
    IssuerTooLong,
    InvalidPathPrefix,
}

impl fmt::Display for HttpCacheInvalidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEventId => formatter.write_str("cache invalidation event_id must not be empty"),
            Self::EventIdTooLong => formatter.write_str("cache invalidation event_id exceeds max length"),
            Self::EmptyScope => formatter.write_str("cache invalidation scope must not be empty"),
            Self::ScopeTooLong => formatter.write_str("cache invalidation scope exceeds max length"),
            Self::EmptyIssuer => formatter.write_str("cache invalidation issuer must not be empty"),
            Self::IssuerTooLong => formatter.write_str("cache invalidation issuer exceeds max length"),
            Self::InvalidPathPrefix => formatter.write_str("cache invalidation path prefix must start with '/' and contain no query or fragment"),
        }
    }
}

impl std::error::Error for HttpCacheInvalidationError {}

pub trait HttpCacheInvalidationSubscriber: Send + Sync {
    fn scope(&self) -> &str;
    fn apply(
        &self,
        event: &HttpCacheInvalidationEvent,
    ) -> Result<HttpCacheInvalidationApplyResult, HttpCacheInvalidationError>;
}

#[derive(Debug)]
pub struct HttpCacheStoreInvalidationSubscriber {
    scope: String,
    store: Arc<HttpCacheStore>,
}

impl HttpCacheStoreInvalidationSubscriber {
    #[must_use]
    pub fn new(scope: impl Into<String>, store: Arc<HttpCacheStore>) -> Self {
        Self { scope: scope.into(), store }
    }
}

impl HttpCacheInvalidationSubscriber for HttpCacheStoreInvalidationSubscriber {
    fn scope(&self) -> &str {
        &self.scope
    }

    fn apply(
        &self,
        event: &HttpCacheInvalidationEvent,
    ) -> Result<HttpCacheInvalidationApplyResult, HttpCacheInvalidationError> {
        self.store.apply_invalidation_event(event)
    }
}

#[derive(Default)]
pub struct HttpCacheInvalidationBus {
    subscribers: Mutex<Vec<Arc<dyn HttpCacheInvalidationSubscriber>>>,
}

impl fmt::Debug for HttpCacheInvalidationBus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subscriber_count =
            self.subscribers.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len();
        formatter
            .debug_struct("HttpCacheInvalidationBus")
            .field("subscriber_count", &subscriber_count)
            .finish()
    }
}

impl HttpCacheInvalidationBus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, subscriber: Arc<dyn HttpCacheInvalidationSubscriber>) {
        let mut subscribers =
            self.subscribers.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        subscribers.push(subscriber);
    }

    pub fn publish(
        &self,
        event: &HttpCacheInvalidationEvent,
    ) -> Result<HttpCacheInvalidationPublishResult, HttpCacheInvalidationError> {
        validate_invalidation_event(event)?;
        let subscribers = self.subscribers.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut result = HttpCacheInvalidationPublishResult::default();
        for subscriber in subscribers.iter().filter(|subscriber| subscriber.scope() == event.scope)
        {
            result.subscriber_count += 1;
            match subscriber.apply(event)? {
                HttpCacheInvalidationApplyResult::Applied { purged_entries } => {
                    result.applied_count += 1;
                    result.delivery_success_count += 1;
                    result.purged_entries += purged_entries;
                }
                HttpCacheInvalidationApplyResult::Duplicate => {
                    result.duplicate_count += 1;
                    result.delivery_success_count += 1;
                }
            }
        }
        Ok(result)
    }
}

/// Errors returned by the bounded runtime cache store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCacheStoreError {
    /// Store must track at least one entry.
    ZeroMaxEntries,
    /// Store byte capacity must be positive.
    ZeroMaxBytes,
    /// Object byte capacity must be positive.
    ZeroMaxObjectBytes,
    /// Object capacity cannot exceed total store capacity.
    MaxObjectBytesExceedsStoreBytes { max_object_bytes: usize, max_bytes: usize },
    /// Cache keys must not be empty.
    EmptyKey,
    /// Freshness deadline must not precede storage time.
    FreshnessBeforeStoredAt,
    /// SWR deadline must not precede freshness deadline.
    StaleWhileRevalidateBeforeFreshness,
    /// SIE deadline must not precede freshness deadline.
    StaleIfErrorBeforeFreshness,
    /// Object exceeded the configured per-object byte limit.
    ObjectTooLarge { object_size: usize, max_object_bytes: usize },
    /// Cache key construction requires a host header.
    MissingHost,
    /// Request target or authority could not be canonicalized.
    InvalidRequestTarget(RequestTargetError),
    /// Host header could not be canonicalized.
    InvalidHost(RequestTargetError),
    /// Absolute-form target authority did not match the host header.
    HostAuthorityMismatch { host_header: String, target_authority: String },
}

impl fmt::Display for HttpCacheStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => {
                formatter.write_str("http cache max_entries must be greater than zero")
            }
            Self::ZeroMaxBytes => {
                formatter.write_str("http cache max_bytes must be greater than zero")
            }
            Self::ZeroMaxObjectBytes => {
                formatter.write_str("http cache max_object_bytes must be greater than zero")
            }
            Self::MaxObjectBytesExceedsStoreBytes { max_object_bytes, max_bytes } => write!(
                formatter,
                "http cache max_object_bytes {max_object_bytes} exceeds max_bytes {max_bytes}"
            ),
            Self::EmptyKey => formatter.write_str("http cache key must not be empty"),
            Self::FreshnessBeforeStoredAt => formatter
                .write_str("http cache fresh_until must not be earlier than stored_at"),
            Self::StaleWhileRevalidateBeforeFreshness => formatter.write_str(
                "http cache stale_while_revalidate_until must not be earlier than fresh_until",
            ),
            Self::StaleIfErrorBeforeFreshness => formatter.write_str(
                "http cache stale_if_error_until must not be earlier than fresh_until",
            ),
            Self::ObjectTooLarge { object_size, max_object_bytes } => write!(
                formatter,
                "http cache object size {object_size} exceeds max_object_bytes {max_object_bytes}"
            ),
            Self::MissingHost => formatter.write_str("http cache key construction requires a host header"),
            Self::InvalidRequestTarget(error) => {
                write!(formatter, "http cache key request-target is invalid: {error}")
            }
            Self::InvalidHost(error) => {
                write!(formatter, "http cache key host is invalid: {error}")
            }
            Self::HostAuthorityMismatch { host_header, target_authority } => write!(
                formatter,
                "http cache key host header {host_header} does not match request-target authority {target_authority}"
            ),
        }
    }
}

impl std::error::Error for HttpCacheStoreError {}

#[derive(Debug, Clone)]
struct CacheRecord {
    entry: HttpCacheEntry,
    size: usize,
    inserted_sequence: u64,
    last_accessed_tick: u64,
    last_accessed_at: Duration,
}

#[derive(Debug, Default)]
struct CacheStoreState {
    entries: BTreeMap<HttpCacheKey, CacheRecord>,
    total_bytes: usize,
    next_sequence: u64,
}

/// Deterministic bounded in-memory cache store for HTTP objects.
#[derive(Debug)]
pub struct HttpCacheStore {
    config: HttpCacheStoreConfig,
    created_at: Instant,
    state: Mutex<CacheStoreState>,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    insert_count: AtomicU64,
    replace_count: AtomicU64,
    eviction_count: AtomicU64,
    expiration_count: AtomicU64,
    rejected_insert_count: AtomicU64,
    applied_invalidations: Mutex<VecDeque<String>>,
}

impl HttpCacheStore {
    /// Creates a validated cache store.
    pub fn new(config: HttpCacheStoreConfig) -> Result<Self, HttpCacheStoreError> {
        config.validate()?;
        Ok(Self {
            config,
            created_at: Instant::now(),
            state: Mutex::new(CacheStoreState::default()),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            insert_count: AtomicU64::new(0),
            replace_count: AtomicU64::new(0),
            eviction_count: AtomicU64::new(0),
            expiration_count: AtomicU64::new(0),
            rejected_insert_count: AtomicU64::new(0),
            applied_invalidations: Mutex::new(VecDeque::new()),
        })
    }

    /// Returns the monotonic store-local time reference shared across cache operations.
    #[must_use]
    pub fn now(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Looks up a cache entry and removes it if the object has fully expired.
    #[must_use]
    pub fn lookup(&self, now: Duration, key: &HttpCacheKey) -> Option<HttpCacheLookup> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now_tick = duration_tick(now);

        let outcome = match state.entries.get_mut(key) {
            Some(record) if record.entry.metadata.freshness(now).is_none() => {
                let removed = state.entries.remove(key);
                if let Some(record) = removed {
                    state.total_bytes = state.total_bytes.saturating_sub(record.size);
                    self.expiration_count.fetch_add(1, Ordering::SeqCst);
                }
                self.miss_count.fetch_add(1, Ordering::SeqCst);
                return None;
            }
            Some(record) => {
                record.last_accessed_tick = now_tick;
                record.last_accessed_at = now;
                let freshness =
                    record.entry.metadata.freshness(now).unwrap_or(HttpCacheFreshness::Fresh);
                Some(HttpCacheLookup { entry: record.entry.clone(), freshness })
            }
            None => None,
        };

        if outcome.is_some() {
            self.hit_count.fetch_add(1, Ordering::SeqCst);
        } else {
            self.miss_count.fetch_add(1, Ordering::SeqCst);
        }
        outcome
    }

    /// Looks up only fresh entries, treating stale objects as misses for serving decisions.
    #[must_use]
    pub fn lookup_fresh(&self, now: Duration, key: &HttpCacheKey) -> Option<HttpCacheEntry> {
        self.lookup(now, key).and_then(|lookup| {
            (lookup.freshness == HttpCacheFreshness::Fresh).then_some(lookup.entry)
        })
    }

    /// Inserts or replaces a cache object and evicts older objects to satisfy bounds.
    pub fn insert(
        &self,
        now: Duration,
        key: HttpCacheKey,
        entry: HttpCacheEntry,
    ) -> Result<HttpCacheInsertResult, HttpCacheStoreError> {
        entry.validate()?;
        let size = entry.estimated_size();
        if size > self.config.max_object_bytes {
            self.rejected_insert_count.fetch_add(1, Ordering::SeqCst);
            return Err(HttpCacheStoreError::ObjectTooLarge {
                object_size: size,
                max_object_bytes: self.config.max_object_bytes,
            });
        }

        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now_tick = duration_tick(now);
        let replaced_record = state.entries.remove(&key);
        if let Some(record) = &replaced_record {
            state.total_bytes = state.total_bytes.saturating_sub(record.size);
        }

        let inserted_sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.total_bytes = state.total_bytes.saturating_add(size);
        state.entries.insert(
            key,
            CacheRecord {
                entry,
                size,
                inserted_sequence,
                last_accessed_tick: now_tick,
                last_accessed_at: now,
            },
        );

        let evicted_entries = evict_until_within_bounds(&mut state, &self.config);
        if replaced_record.is_some() {
            self.replace_count.fetch_add(1, Ordering::SeqCst);
        } else {
            self.insert_count.fetch_add(1, Ordering::SeqCst);
        }
        self.eviction_count.fetch_add(evicted_entries as u64, Ordering::SeqCst);

        Ok(HttpCacheInsertResult { replaced: replaced_record.is_some(), evicted_entries })
    }

    /// Removes a cache object explicitly.
    #[must_use]
    pub fn remove(&self, key: &HttpCacheKey) -> Option<HttpCacheEntry> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = state.entries.remove(key)?;
        state.total_bytes = state.total_bytes.saturating_sub(removed.size);
        Some(removed.entry)
    }

    /// Removes cached objects whose canonical path starts with the provided prefix.
    pub fn purge_path_prefix(&self, path_prefix: &str) -> usize {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        purge_path_prefix_from_state(&mut state, path_prefix)
    }

    pub fn apply_invalidation_event(
        &self,
        event: &HttpCacheInvalidationEvent,
    ) -> Result<HttpCacheInvalidationApplyResult, HttpCacheInvalidationError> {
        validate_invalidation_event(event)?;

        let mut applied =
            self.applied_invalidations.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if applied.iter().any(|event_id| event_id == &event.event_id) {
            return Ok(HttpCacheInvalidationApplyResult::Duplicate);
        }

        let purged_entries = {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match &event.target {
                HttpCacheInvalidationTarget::ExactKey(key) => {
                    usize::from(remove_from_state(&mut state, key).is_some())
                }
                HttpCacheInvalidationTarget::PathPrefix(prefix) => {
                    purge_path_prefix_from_state(&mut state, prefix)
                }
            }
        };

        applied.push_back(event.event_id.clone());
        while applied.len() > 256 {
            let _ = applied.pop_front();
        }

        Ok(HttpCacheInvalidationApplyResult::Applied { purged_entries })
    }

    /// Removes all fully expired entries and returns the number purged.
    pub fn purge_expired(&self, now: Duration) -> usize {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let keys_to_remove: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, record)| now > record.entry.metadata.expires_at())
            .map(|(key, _)| key.clone())
            .collect();

        for key in &keys_to_remove {
            if let Some(record) = state.entries.remove(key) {
                state.total_bytes = state.total_bytes.saturating_sub(record.size);
            }
        }
        self.expiration_count.fetch_add(keys_to_remove.len() as u64, Ordering::SeqCst);
        keys_to_remove.len()
    }

    /// Returns an immutable metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> HttpCacheStoreMetrics {
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        HttpCacheStoreMetrics {
            entry_count: state.entries.len(),
            total_bytes: state.total_bytes,
            max_object_bytes: state.entries.values().map(|record| record.size).max().unwrap_or(0),
            hit_count: self.hit_count.load(Ordering::SeqCst),
            miss_count: self.miss_count.load(Ordering::SeqCst),
            insert_count: self.insert_count.load(Ordering::SeqCst),
            replace_count: self.replace_count.load(Ordering::SeqCst),
            eviction_count: self.eviction_count.load(Ordering::SeqCst),
            expiration_count: self.expiration_count.load(Ordering::SeqCst),
            rejected_insert_count: self.rejected_insert_count.load(Ordering::SeqCst),
        }
    }

    /// Returns a deterministic snapshot of the store state.
    #[must_use]
    pub fn snapshot(&self) -> HttpCacheStoreSnapshot {
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = state
            .entries
            .iter()
            .map(|(key, record)| HttpCacheEntrySnapshot {
                key: key.0.clone(),
                size: record.size,
                last_accessed_at: record.last_accessed_at,
                metadata: record.entry.metadata.clone(),
            })
            .collect();

        HttpCacheStoreSnapshot {
            metrics: HttpCacheStoreMetrics {
                entry_count: state.entries.len(),
                total_bytes: state.total_bytes,
                max_object_bytes: state
                    .entries
                    .values()
                    .map(|record| record.size)
                    .max()
                    .unwrap_or(0),
                hit_count: self.hit_count.load(Ordering::SeqCst),
                miss_count: self.miss_count.load(Ordering::SeqCst),
                insert_count: self.insert_count.load(Ordering::SeqCst),
                replace_count: self.replace_count.load(Ordering::SeqCst),
                eviction_count: self.eviction_count.load(Ordering::SeqCst),
                expiration_count: self.expiration_count.load(Ordering::SeqCst),
                rejected_insert_count: self.rejected_insert_count.load(Ordering::SeqCst),
            },
            entries,
        }
    }
}

impl HttpCacheStoreSnapshot {
    #[must_use]
    pub fn render_diagnostics(&self, scope: &str, max_entries: usize) -> String {
        let mut lines = vec![
            format!("scope={scope}"),
            format!("entries={}", self.metrics.entry_count),
            format!("bytes={}", self.metrics.total_bytes),
            format!("max_object_bytes={}", self.metrics.max_object_bytes),
            format!("hits={}", self.metrics.hit_count),
            format!("misses={}", self.metrics.miss_count),
            format!("inserts={}", self.metrics.insert_count),
            format!("replacements={}", self.metrics.replace_count),
            format!("evictions={}", self.metrics.eviction_count),
            format!("expirations={}", self.metrics.expiration_count),
            format!("rejected_inserts={}", self.metrics.rejected_insert_count),
            String::from("objects:"),
        ];
        for (index, entry) in self.entries.iter().take(max_entries).enumerate() {
            lines.push(format!(
                "- index={index} size={} status={} last_accessed_ms={} fresh_until_ms={}",
                entry.size,
                entry.metadata.status.as_u16(),
                entry.last_accessed_at.as_millis(),
                entry.metadata.fresh_until.as_millis(),
            ));
        }
        lines.join("\n")
    }
}

/// Builds canonical key material for a request under the provided cache policy.
pub fn build_http_cache_key_material(
    policy: &HttpCachePolicyConfig,
    request: &HttpCacheRequest<'_>,
    vary_headers: &[String],
) -> Result<Option<HttpCacheKeyMaterial>, HttpCacheStoreError> {
    let host_header =
        extract_host_header(request.headers).ok_or(HttpCacheStoreError::MissingHost)?;
    let canonical_host =
        canonicalize_host(host_header).map_err(HttpCacheStoreError::InvalidHost)?;
    let target = canonicalize_request_target(request.target)
        .map_err(HttpCacheStoreError::InvalidRequestTarget)?;

    if let Some(authority) = &target.authority {
        if authority != &canonical_host {
            return Err(HttpCacheStoreError::HostAuthorityMismatch {
                host_header: canonical_host,
                target_authority: authority.clone(),
            });
        }
    }

    let authorization_header =
        request.headers.iter().find(|header| header.name.eq_ignore_ascii_case("authorization"));
    let cookie_header_present =
        request.headers.iter().any(|header| header.name.eq_ignore_ascii_case("cookie"));
    if authorization_header.is_some()
        && matches!(policy.authorization, AuthorizationCacheBehaviorConfig::Bypass)
    {
        return Ok(None);
    }
    if cookie_header_present {
        return Ok(None);
    }

    let mut primary_parts = Vec::new();
    primary_parts.push(format!("path={}", target.path));
    if policy.cache_key.include_host {
        primary_parts.push(format!("host={canonical_host}"));
    }
    if policy.cache_key.include_method {
        primary_parts.push(format!("method={}", request.method.trim().to_ascii_uppercase()));
    }
    if matches!(policy.cache_key.query, CacheQueryKeyBehaviorConfig::IncludeAll) {
        primary_parts.push(format!("query={}", target.canonical_query()));
    }
    if matches!(policy.authorization, AuthorizationCacheBehaviorConfig::Partition) {
        primary_parts.push(match authorization_header {
            Some(header) => format!("auth={}", stable_hex_hash(header.value.trim())),
            None => String::from("auth=anonymous"),
        });
    }
    for header_name in selected_header_names(&policy.cache_key.headers, &[]) {
        primary_parts.push(format!(
            "hdr:{header_name}={}",
            canonical_header_values(request.headers, &header_name)
        ));
    }

    let secondary = if vary_headers.is_empty() {
        None
    } else {
        let parts = selected_header_names(vary_headers, &[])
            .into_iter()
            .map(|header_name| {
                format!(
                    "vary:{header_name}={}",
                    canonical_header_values(request.headers, &header_name)
                )
            })
            .collect::<Vec<_>>();
        Some(HttpCacheKey::new(Bytes::from(parts.join("\n")))?)
    };

    Ok(Some(HttpCacheKeyMaterial {
        primary: HttpCacheKey::new(Bytes::from(primary_parts.join("\n")))?,
        secondary,
    }))
}

fn evict_until_within_bounds(state: &mut CacheStoreState, config: &HttpCacheStoreConfig) -> usize {
    let mut evicted_entries = 0;
    while state.entries.len() > config.max_entries || state.total_bytes > config.max_bytes {
        let Some(key) = oldest_entry_key(state) else {
            break;
        };
        if let Some(record) = state.entries.remove(&key) {
            state.total_bytes = state.total_bytes.saturating_sub(record.size);
            evicted_entries += 1;
        }
    }
    evicted_entries
}

fn oldest_entry_key(state: &CacheStoreState) -> Option<HttpCacheKey> {
    state
        .entries
        .iter()
        .min_by_key(|(_, record)| (record.last_accessed_tick, record.inserted_sequence))
        .map(|(key, _)| key.clone())
}

fn duration_tick(value: Duration) -> u64 {
    value.as_millis().min(u128::from(u64::MAX)) as u64
}

fn validate_invalidation_event(
    event: &HttpCacheInvalidationEvent,
) -> Result<(), HttpCacheInvalidationError> {
    if event.event_id.trim().is_empty() {
        return Err(HttpCacheInvalidationError::EmptyEventId);
    }
    if event.event_id.len() > HTTP_CACHE_INVALIDATION_MAX_EVENT_ID_LEN {
        return Err(HttpCacheInvalidationError::EventIdTooLong);
    }
    if event.scope.trim().is_empty() {
        return Err(HttpCacheInvalidationError::EmptyScope);
    }
    if event.scope.len() > HTTP_CACHE_INVALIDATION_MAX_SCOPE_LEN {
        return Err(HttpCacheInvalidationError::ScopeTooLong);
    }
    if event.issuer.trim().is_empty() {
        return Err(HttpCacheInvalidationError::EmptyIssuer);
    }
    if event.issuer.len() > HTTP_CACHE_INVALIDATION_MAX_ISSUER_LEN {
        return Err(HttpCacheInvalidationError::IssuerTooLong);
    }
    if let HttpCacheInvalidationTarget::PathPrefix(prefix) = &event.target {
        if prefix.trim().is_empty()
            || prefix.len() > HTTP_CACHE_INVALIDATION_MAX_PATH_PREFIX_LEN
            || !prefix.starts_with('/')
            || prefix.contains('?')
            || prefix.contains('#')
        {
            return Err(HttpCacheInvalidationError::InvalidPathPrefix);
        }
    }
    Ok(())
}

fn storage_key_matches_path_prefix(key: &HttpCacheKey, path_prefix: &str) -> bool {
    let primary = key.as_bytes().split(|byte| *byte == 0).next().unwrap_or_else(|| key.as_bytes());
    let Ok(primary) = str::from_utf8(primary) else {
        return false;
    };
    let Some(path) = primary.lines().find_map(|line| line.strip_prefix("path=")) else {
        return false;
    };
    path == path_prefix
        || path_prefix == "/"
        || path.strip_prefix(path_prefix).is_some_and(|suffix| suffix.starts_with('/'))
}

fn remove_from_state(state: &mut CacheStoreState, key: &HttpCacheKey) -> Option<HttpCacheEntry> {
    let removed = state.entries.remove(key)?;
    state.total_bytes = state.total_bytes.saturating_sub(removed.size);
    Some(removed.entry)
}

fn purge_path_prefix_from_state(state: &mut CacheStoreState, path_prefix: &str) -> usize {
    let keys_to_remove: Vec<_> = state
        .entries
        .keys()
        .filter(|key| storage_key_matches_path_prefix(key, path_prefix))
        .cloned()
        .collect();

    for key in &keys_to_remove {
        let _ = remove_from_state(state, key);
    }

    keys_to_remove.len()
}

fn canonical_header_values(headers: &[HttpHeader], name: &str) -> String {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .flat_map(|header| header.value.split(',').map(str::trim).filter(|value| !value.is_empty()))
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    values.sort();
    values.join("\u{1f}")
}

fn selected_header_names(primary: &[String], secondary: &[String]) -> Vec<String> {
    let mut names = primary
        .iter()
        .chain(secondary)
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn stable_hex_hash(value: &str) -> String {
    let mut hash = 14695981039346656037_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderName, HeaderValue, StatusCode};
    use lb_config_model::{
        AuthorizationCacheBehaviorConfig, CacheKeyPolicyConfig, HttpCachePolicyConfig,
    };
    use lb_proto_http::HttpHeader;

    use super::{
        build_http_cache_key_material, HttpCacheEntry, HttpCacheFreshness, HttpCacheHeader,
        HttpCacheInvalidationApplyResult, HttpCacheInvalidationBus,
        HttpCacheInvalidationBusTransport, HttpCacheInvalidationError, HttpCacheInvalidationEvent,
        HttpCacheInvalidationSubscriber, HttpCacheInvalidationTarget,
        HttpCacheInvalidationTransport, HttpCacheKey, HttpCacheMetadata, HttpCacheRequest,
        HttpCacheStore, HttpCacheStoreConfig, HttpCacheStoreError,
        HttpCacheStoreInvalidationSubscriber, HTTP_CACHE_INVALIDATION_MAX_EVENT_ID_LEN,
        HTTP_CACHE_INVALIDATION_MAX_ISSUER_LEN, HTTP_CACHE_INVALIDATION_MAX_PATH_PREFIX_LEN,
        HTTP_CACHE_INVALIDATION_MAX_SCOPE_LEN,
    };

    fn key(value: &str) -> Result<HttpCacheKey, HttpCacheStoreError> {
        HttpCacheKey::new(Bytes::copy_from_slice(value.as_bytes()))
    }

    fn entry(body: &str, stored_at: Duration, fresh_until: Duration) -> HttpCacheEntry {
        HttpCacheEntry {
            metadata: HttpCacheMetadata {
                status: StatusCode::OK,
                stored_at,
                fresh_until,
                stale_while_revalidate_until: Some(fresh_until + Duration::from_secs(10)),
                stale_if_error_until: Some(fresh_until + Duration::from_secs(20)),
                etag: Some(HeaderValue::from_static("\"v1\"")),
                last_modified: Some(HeaderValue::from_static("Tue, 09 Apr 2026 09:00:00 GMT")),
            },
            headers: vec![HttpCacheHeader::new(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("text/plain"),
            )],
            body: Bytes::copy_from_slice(body.as_bytes()),
        }
    }

    #[test]
    fn store_rejects_invalid_config() {
        assert_eq!(
            HttpCacheStore::new(HttpCacheStoreConfig {
                max_entries: 0,
                max_bytes: 1024,
                max_object_bytes: 512,
            })
            .expect_err("config must fail"),
            HttpCacheStoreError::ZeroMaxEntries
        );
        assert_eq!(
            HttpCacheStore::new(HttpCacheStoreConfig {
                max_entries: 1,
                max_bytes: 1024,
                max_object_bytes: 2048,
            })
            .expect_err("config must fail"),
            HttpCacheStoreError::MaxObjectBytesExceedsStoreBytes {
                max_object_bytes: 2048,
                max_bytes: 1024,
            }
        );
    }

    #[test]
    fn lookup_returns_freshness_and_tracks_hits() -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?;
        let key = key("GET:/orders")?;
        store.insert(
            Duration::from_secs(5),
            key.clone(),
            entry("body", Duration::from_secs(5), Duration::from_secs(10)),
        )?;

        let fresh = store.lookup(Duration::from_secs(8), &key).expect("fresh hit");
        assert_eq!(fresh.freshness, HttpCacheFreshness::Fresh);

        let stale = store.lookup(Duration::from_secs(12), &key).expect("stale hit");
        assert_eq!(stale.freshness, HttpCacheFreshness::StaleWhileRevalidate);

        let stale_if_error =
            store.lookup(Duration::from_secs(25), &key).expect("stale-if-error hit");
        assert_eq!(stale_if_error.freshness, HttpCacheFreshness::StaleIfError);

        let metrics = store.metrics();
        assert_eq!(metrics.hit_count, 3);
        assert_eq!(metrics.miss_count, 0);
        Ok(())
    }

    #[test]
    fn lookup_expires_entries_past_hard_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?;
        let key = key("GET:/healthz")?;
        store.insert(
            Duration::ZERO,
            key.clone(),
            entry("ok", Duration::ZERO, Duration::from_secs(2)),
        )?;

        assert!(store.lookup(Duration::from_secs(23), &key).is_none());
        assert_eq!(store.metrics().expiration_count, 1);
        assert_eq!(store.metrics().entry_count, 0);
        Ok(())
    }

    #[test]
    fn insert_replaces_existing_entry() -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?;
        let key = key("GET:/config")?;

        let inserted = store.insert(
            Duration::ZERO,
            key.clone(),
            entry("v1", Duration::ZERO, Duration::from_secs(30)),
        )?;
        assert!(!inserted.replaced);

        let replaced = store.insert(
            Duration::from_secs(1),
            key.clone(),
            entry("v2", Duration::from_secs(1), Duration::from_secs(30)),
        )?;
        assert!(replaced.replaced);
        assert_eq!(replaced.evicted_entries, 0);
        assert_eq!(store.metrics().replace_count, 1);
        assert_eq!(
            store.lookup(Duration::from_secs(2), &key).expect("entry").entry.body,
            Bytes::from_static(b"v2")
        );
        Ok(())
    }

    #[test]
    fn store_evicts_least_recently_used_entries_to_stay_bounded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 2,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?;
        let key_a = key("GET:/a")?;
        let key_b = key("GET:/b")?;
        let key_c = key("GET:/c")?;

        store.insert(
            Duration::from_secs(0),
            key_a.clone(),
            entry("a", Duration::ZERO, Duration::from_secs(30)),
        )?;
        store.insert(
            Duration::from_secs(1),
            key_b.clone(),
            entry("b", Duration::from_secs(1), Duration::from_secs(30)),
        )?;
        let _ = store.lookup(Duration::from_secs(2), &key_a);
        let result = store.insert(
            Duration::from_secs(3),
            key_c.clone(),
            entry("c", Duration::from_secs(3), Duration::from_secs(30)),
        )?;

        assert_eq!(result.evicted_entries, 1);
        assert!(store.lookup(Duration::from_secs(4), &key_a).is_some());
        assert!(store.lookup(Duration::from_secs(4), &key_b).is_none());
        assert!(store.lookup(Duration::from_secs(4), &key_c).is_some());
        assert_eq!(store.metrics().eviction_count, 1);
        Ok(())
    }

    #[test]
    fn store_rejects_objects_larger_than_limit() -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 2,
            max_bytes: 4096,
            max_object_bytes: 64,
        })?;

        let error = store
            .insert(
                Duration::ZERO,
                key("GET:/too-big")?,
                entry(&"x".repeat(128), Duration::ZERO, Duration::from_secs(10)),
            )
            .expect_err("insert must fail");
        assert!(matches!(error, HttpCacheStoreError::ObjectTooLarge { .. }));
        assert_eq!(store.metrics().rejected_insert_count, 1);
        Ok(())
    }

    #[test]
    fn purge_expired_removes_multiple_entries() -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?;

        store.insert(
            Duration::ZERO,
            key("GET:/x")?,
            entry("x", Duration::ZERO, Duration::from_secs(1)),
        )?;
        store.insert(
            Duration::ZERO,
            key("GET:/y")?,
            entry("y", Duration::ZERO, Duration::from_secs(2)),
        )?;

        assert_eq!(store.purge_expired(Duration::from_secs(25)), 2);
        assert_eq!(store.metrics().expiration_count, 2);
        assert_eq!(store.snapshot().entries.len(), 0);
        Ok(())
    }

    #[test]
    fn key_builder_partitions_authorized_requests_without_storing_secrets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = HttpCachePolicyConfig {
            authorization: AuthorizationCacheBehaviorConfig::Partition,
            cache_key: CacheKeyPolicyConfig {
                include_host: true,
                include_method: true,
                ..CacheKeyPolicyConfig::default()
            },
            ..HttpCachePolicyConfig::default()
        };
        let request = HttpCacheRequest {
            method: "GET",
            target: "/orders?b=2&a=1",
            headers: &[
                HttpHeader { name: String::from("host"), value: String::from("Example.TEST") },
                HttpHeader {
                    name: String::from("authorization"),
                    value: String::from("Bearer secret-token"),
                },
            ],
        };

        let material = build_http_cache_key_material(&policy, &request, &[])
            .expect("must build")
            .expect("must not bypass");
        let primary = std::str::from_utf8(material.primary.as_bytes())?;
        assert!(primary.contains("host=example.test"));
        assert!(primary.contains("method=GET"));
        assert!(primary.contains("auth="));
        assert!(!primary.contains("secret-token"));
        Ok(())
    }

    #[test]
    fn cookie_bypass_skips_cache_key_construction_by_default(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = HttpCachePolicyConfig::default();
        let request = HttpCacheRequest {
            method: "GET",
            target: "/profile",
            headers: &[
                HttpHeader { name: String::from("host"), value: String::from("example.test") },
                HttpHeader { name: String::from("cookie"), value: String::from("session=secret") },
            ],
        };

        assert!(build_http_cache_key_material(&policy, &request, &[])?.is_none());
        Ok(())
    }

    #[test]
    fn purge_path_prefix_removes_matching_entries_only() -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?;
        store.insert(
            Duration::from_secs(1),
            key("path=/images/logo.png\nhost=example.test")?,
            entry("logo", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        store.insert(
            Duration::from_secs(1),
            key("path=/images/banner.png\nhost=example.test")?,
            entry("banner", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        store.insert(
            Duration::from_secs(1),
            key("path=/api/items\nhost=example.test")?,
            entry("api", Duration::from_secs(1), Duration::from_secs(60)),
        )?;

        assert_eq!(store.purge_path_prefix("/images"), 2);
        assert!(store
            .lookup(Duration::from_secs(1), &key("path=/images/logo.png\nhost=example.test")?,)
            .is_none());
        assert!(store
            .lookup(Duration::from_secs(1), &key("path=/images/banner.png\nhost=example.test")?,)
            .is_none());
        assert!(store
            .lookup(Duration::from_secs(1), &key("path=/api/items\nhost=example.test")?)
            .is_some());
        Ok(())
    }

    #[test]
    fn purge_path_prefix_respects_path_segment_boundaries() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?;
        let exact_prefix_key = key("path=/images/logo.png\nhost=example.test")?;
        let sibling_prefix_key = key("path=/images-v2/logo.png\nhost=example.test")?;
        let bare_prefix_key = key("path=/images\nhost=example.test")?;
        store.insert(
            Duration::from_secs(1),
            exact_prefix_key.clone(),
            entry("logo", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        store.insert(
            Duration::from_secs(1),
            sibling_prefix_key.clone(),
            entry("logo-v2", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        store.insert(
            Duration::from_secs(1),
            bare_prefix_key.clone(),
            entry("index", Duration::from_secs(1), Duration::from_secs(60)),
        )?;

        assert_eq!(store.purge_path_prefix("/images"), 2);
        assert!(store.lookup(Duration::from_secs(1), &exact_prefix_key).is_none());
        assert!(store.lookup(Duration::from_secs(1), &bare_prefix_key).is_none());
        assert!(store.lookup(Duration::from_secs(1), &sibling_prefix_key).is_some());
        Ok(())
    }

    #[test]
    fn invalidation_event_is_replay_safe_across_multiple_subscribers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?);
        let second = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?);
        let purge_key = key("path=/shared/item\nhost=example.test")?;
        first.insert(
            Duration::from_secs(1),
            purge_key.clone(),
            entry("item", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        second.insert(
            Duration::from_secs(1),
            purge_key.clone(),
            entry("item", Duration::from_secs(1), Duration::from_secs(60)),
        )?;

        let bus = HttpCacheInvalidationBus::new();
        bus.register(Arc::new(HttpCacheStoreInvalidationSubscriber::new(
            "public-http",
            Arc::clone(&first),
        )));
        bus.register(Arc::new(HttpCacheStoreInvalidationSubscriber::new(
            "public-http",
            Arc::clone(&second),
        )));

        let event = HttpCacheInvalidationEvent::new(
            "evt-1",
            "public-http",
            "node-a",
            HttpCacheInvalidationTarget::ExactKey(purge_key.clone()),
            1,
        )?;

        let first_publish = bus.publish(&event)?;
        let duplicate_publish = bus.publish(&event)?;

        assert_eq!(first_publish.subscriber_count, 2);
        assert_eq!(first_publish.applied_count, 2);
        assert_eq!(first_publish.purged_entries, 2);
        assert_eq!(duplicate_publish.duplicate_count, 2);
        assert!(first.lookup(Duration::from_secs(1), &purge_key).is_none());
        assert!(second.lookup(Duration::from_secs(1), &purge_key).is_none());
        Ok(())
    }

    #[test]
    fn invalidation_prefix_fanout_converges_across_nodes() -> Result<(), Box<dyn std::error::Error>>
    {
        let first = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?);
        let second = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?);
        first.insert(
            Duration::from_secs(1),
            key("path=/assets/a.png\nhost=example.test")?,
            entry("a", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        first.insert(
            Duration::from_secs(1),
            key("path=/api/item\nhost=example.test")?,
            entry("api", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        second.insert(
            Duration::from_secs(1),
            key("path=/assets/a.png\nhost=example.test")?,
            entry("a", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        second.insert(
            Duration::from_secs(1),
            key("path=/api/item\nhost=example.test")?,
            entry("api", Duration::from_secs(1), Duration::from_secs(60)),
        )?;

        let subscriber =
            HttpCacheStoreInvalidationSubscriber::new("public-http", Arc::clone(&first));
        assert_eq!(
            subscriber.apply(&HttpCacheInvalidationEvent {
                event_id: String::from("evt-local"),
                scope: String::from("public-http"),
                issuer: String::from("node-a"),
                target: HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
                occurred_at_unix_ms: 1,
            })?,
            HttpCacheInvalidationApplyResult::Applied { purged_entries: 1 }
        );

        let bus = HttpCacheInvalidationBus::new();
        bus.register(Arc::new(HttpCacheStoreInvalidationSubscriber::new(
            "public-http",
            Arc::clone(&second),
        )));
        let publish = bus.publish(&HttpCacheInvalidationEvent::new(
            "evt-assets",
            "public-http",
            "node-b",
            HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
            2,
        )?)?;

        assert_eq!(publish.applied_count, 1);
        assert!(first
            .lookup(Duration::from_secs(1), &key("path=/assets/a.png\nhost=example.test")?,)
            .is_none());
        assert!(second
            .lookup(Duration::from_secs(1), &key("path=/assets/a.png\nhost=example.test")?,)
            .is_none());
        assert!(second
            .lookup(Duration::from_secs(1), &key("path=/api/item\nhost=example.test")?)
            .is_some());
        Ok(())
    }

    #[test]
    fn concurrent_duplicate_invalidation_is_applied_once() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?);
        let purge_key = key("path=/shared/item\nhost=example.test")?;
        store.insert(
            Duration::from_secs(1),
            purge_key.clone(),
            entry("item", Duration::from_secs(1), Duration::from_secs(60)),
        )?;
        let barrier = Arc::new(Barrier::new(8));
        let mut workers = Vec::new();

        for _ in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let purge_key = purge_key.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                store.apply_invalidation_event(&HttpCacheInvalidationEvent {
                    event_id: String::from("evt-concurrent"),
                    scope: String::from("public-http"),
                    issuer: String::from("node-a"),
                    target: HttpCacheInvalidationTarget::ExactKey(purge_key),
                    occurred_at_unix_ms: 1,
                })
            }));
        }

        let mut applied_count = 0;
        let mut duplicate_count = 0;
        for worker in workers {
            match worker.join().map_err(|_| "cache invalidation worker panicked")?? {
                HttpCacheInvalidationApplyResult::Applied { purged_entries } => {
                    applied_count += 1;
                    assert_eq!(purged_entries, 1);
                }
                HttpCacheInvalidationApplyResult::Duplicate => {
                    duplicate_count += 1;
                }
            }
        }

        assert_eq!(applied_count, 1);
        assert_eq!(duplicate_count, 7);
        assert!(store.lookup(Duration::from_secs(1), &purge_key).is_none());
        Ok(())
    }

    #[test]
    fn invalidation_event_serializes_and_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = HttpCacheInvalidationEvent::new(
            "evt-serde",
            "public-http",
            "node-a",
            HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
            42,
        )?;

        let encoded = serde_json::to_string(&event)?;
        let decoded: HttpCacheInvalidationEvent = serde_json::from_str(&encoded)?;

        assert_eq!(decoded, event);
        Ok(())
    }

    #[test]
    fn invalidation_event_validation_rejects_empty_or_oversized_metadata() {
        assert_eq!(
            HttpCacheInvalidationEvent::new(
                " ",
                "public-http",
                "node-a",
                HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
                1,
            )
            .expect_err("event_id must fail"),
            HttpCacheInvalidationError::EmptyEventId
        );
        assert_eq!(
            HttpCacheInvalidationEvent::new(
                "evt",
                " ",
                "node-a",
                HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
                1,
            )
            .expect_err("scope must fail"),
            HttpCacheInvalidationError::EmptyScope
        );
        assert_eq!(
            HttpCacheInvalidationEvent::new(
                "evt",
                "public-http",
                " ",
                HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
                1,
            )
            .expect_err("issuer must fail"),
            HttpCacheInvalidationError::EmptyIssuer
        );
        assert_eq!(
            HttpCacheInvalidationEvent::new(
                "x".repeat(HTTP_CACHE_INVALIDATION_MAX_EVENT_ID_LEN + 1),
                "public-http",
                "node-a",
                HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
                1,
            )
            .expect_err("event_id length must fail"),
            HttpCacheInvalidationError::EventIdTooLong
        );
        assert_eq!(
            HttpCacheInvalidationEvent::new(
                "evt",
                "x".repeat(HTTP_CACHE_INVALIDATION_MAX_SCOPE_LEN + 1),
                "node-a",
                HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
                1,
            )
            .expect_err("scope length must fail"),
            HttpCacheInvalidationError::ScopeTooLong
        );
        assert_eq!(
            HttpCacheInvalidationEvent::new(
                "evt",
                "public-http",
                "x".repeat(HTTP_CACHE_INVALIDATION_MAX_ISSUER_LEN + 1),
                HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
                1,
            )
            .expect_err("issuer length must fail"),
            HttpCacheInvalidationError::IssuerTooLong
        );
        assert_eq!(
            HttpCacheInvalidationEvent::new(
                "evt",
                "public-http",
                "node-a",
                HttpCacheInvalidationTarget::PathPrefix(
                    "x".repeat(HTTP_CACHE_INVALIDATION_MAX_PATH_PREFIX_LEN + 1,)
                ),
                1,
            )
            .expect_err("path prefix length must fail"),
            HttpCacheInvalidationError::InvalidPathPrefix
        );
    }

    #[test]
    fn bus_transport_preserves_local_publish_results() -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_object_bytes: 1024,
        })?);
        let purge_key = key("path=/shared/item\nhost=example.test")?;
        store.insert(
            Duration::from_secs(1),
            purge_key.clone(),
            entry("item", Duration::from_secs(1), Duration::from_secs(60)),
        )?;

        let bus = Arc::new(HttpCacheInvalidationBus::new());
        bus.register(Arc::new(HttpCacheStoreInvalidationSubscriber::new(
            "public-http",
            Arc::clone(&store),
        )));
        let transport = HttpCacheInvalidationBusTransport::new(Arc::clone(&bus));

        let publish = transport.publish(&HttpCacheInvalidationEvent::new(
            "evt-transport",
            "public-http",
            "node-a",
            HttpCacheInvalidationTarget::ExactKey(purge_key.clone()),
            1,
        )?)?;

        assert_eq!(publish.subscriber_count, 1);
        assert_eq!(publish.applied_count, 1);
        assert_eq!(publish.purged_entries, 1);
        assert!(store.lookup(Duration::from_secs(1), &purge_key).is_none());
        Ok(())
    }

    #[test]
    fn sustained_eviction_churn_stays_within_bounds() -> Result<(), Box<dyn std::error::Error>> {
        let store = HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 32,
            max_bytes: 8 * 1024,
            max_object_bytes: 512,
        })?;

        for index in 0..256 {
            let key = key(&format!("path=/churn/{index}\nhost=example.test"))?;
            let body = format!("payload-{index}");
            store.insert(
                Duration::from_secs(index as u64),
                key,
                entry(
                    &body,
                    Duration::from_secs(index as u64),
                    Duration::from_secs(index as u64 + 30),
                ),
            )?;

            if index % 17 == 0 {
                let _ = store.purge_expired(Duration::from_secs(index as u64 + 31));
            }

            let metrics = store.metrics();
            assert!(metrics.entry_count <= 32);
            assert!(metrics.total_bytes <= 8 * 1024);
            assert!(metrics.max_object_bytes <= 512);
        }

        Ok(())
    }

    #[test]
    fn concurrent_cache_churn_remains_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
            max_entries: 64,
            max_bytes: 16 * 1024,
            max_object_bytes: 512,
        })?);
        let mut workers = Vec::new();

        for worker_id in 0..4 {
            let store = Arc::clone(&store);
            workers.push(thread::spawn(move || -> Result<(), HttpCacheStoreError> {
                for iteration in 0..128 {
                    let key = HttpCacheKey::new(format!(
                        "path=/concurrency/{worker_id}/{iteration}\nhost=example.test"
                    ))?;
                    let now = Duration::from_millis((worker_id * 1_000 + iteration) as u64);
                    store.insert(
                        now,
                        key.clone(),
                        HttpCacheEntry {
                            metadata: HttpCacheMetadata {
                                status: StatusCode::OK,
                                stored_at: now,
                                fresh_until: now + Duration::from_secs(5),
                                stale_while_revalidate_until: Some(now + Duration::from_secs(10)),
                                stale_if_error_until: Some(now + Duration::from_secs(15)),
                                etag: None,
                                last_modified: None,
                            },
                            headers: Vec::new(),
                            body: Bytes::from(vec![b'x'; 64]),
                        },
                    )?;
                    let _ = store.lookup(now + Duration::from_millis(1), &key);
                }
                Ok(())
            }));
        }

        for worker in workers {
            worker.join().map_err(|_| "cache churn worker panicked")??;
        }

        let metrics = store.metrics();
        assert!(metrics.entry_count <= 64);
        assert!(metrics.total_bytes <= 16 * 1024);
        Ok(())
    }
}
