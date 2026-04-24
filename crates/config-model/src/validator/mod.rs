use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AdminAuthPolicyConfig, AdminAuthorizationScopeConfig, AffinityPolicyConfig,
    AnonymousSourceFilterConfig, ArtifactVerificationMode, CacheKeyPolicyConfig,
    HeaderMutationConfig, HostileEdgeProtectionPolicyConfig, HttpCachePolicyConfig,
    HttpCacheStorageConfig, ListenerAlpnProtocolConfig, ListenerBindModeConfig, ListenerClassConfig,
    ListenerProtocolConfig, LocalConcurrencyLimitPolicyConfig, LocalLimitScopeConfig,
    LocalRateLimitPolicyConfig, NamedOverloadResponsePolicyConfig, OverloadResponsePolicyConfig,
    PathRewriteTransformConfig, PolicyBindingConfig, PolicyResourcesConfig, RouteConfig,
    RouteMatchConfig, TransformPolicyConfig, TrustedClientIpConfig, WorkspaceConfig,
};

include!("report.rs");
include!("stats.rs");
include!("workspace.rs");
include!("defaults.rs");
include!("security.rs");
include!("listeners.rs");
include!("admin.rs");
include!("routes.rs");
include!("upstreams.rs");
include!("helpers.rs");
include!("policy_bindings.rs");
include!("scope_validation.rs");
include!("resource_collection.rs");
include!("policy_registry.rs");
include!("header_validation.rs");
include!("named_transforms.rs");
include!("named_http_caches.rs");
include!("named_fault_injections.rs");
include!("named_l7_auth_policies.rs");
include!("named_waf_policies.rs");
include!("named_local_limits.rs");
include!("named_resilience_policies.rs");
include!("named_overload_and_edge.rs");
include!("tests.rs");
