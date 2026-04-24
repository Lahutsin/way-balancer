use std::collections::{BTreeMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Stable phases where runtime extensions can hook request/response processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExtensionHookPhase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
}

/// Lifecycle state for one registered runtime extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionLifecycleState {
    Registered,
    Active,
    Draining,
    Stopped,
    Failed,
}

/// Metadata used to register one extension implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionDescriptor {
    pub name: String,
    pub version: String,
    pub api_version: String,
}

/// One hook binding declared by an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHookBinding {
    pub phase: ExtensionHookPhase,
    pub priority: u16,
}

/// Runtime compatibility policy for extension API versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionCompatibilityPolicy {
    supported_api_versions: HashSet<String>,
}

impl ExtensionCompatibilityPolicy {
    #[must_use]
    pub fn new<I, S>(supported_api_versions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut versions = HashSet::new();
        for version in supported_api_versions {
            versions.insert(version.into());
        }
        Self {
            supported_api_versions: versions,
        }
    }

    #[must_use]
    pub fn supports(&self, api_version: &str) -> bool {
        self.supported_api_versions.contains(api_version)
    }
}

impl Default for ExtensionCompatibilityPolicy {
    fn default() -> Self {
        Self::new(["v1"])
    }
}

/// One extension entry persisted in registry state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredExtension {
    pub descriptor: ExtensionDescriptor,
    pub hooks: Vec<ExtensionHookBinding>,
    pub state: ExtensionLifecycleState,
    pub failure_reason: Option<String>,
}

/// Ordered hook invocation entry for one phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookExecutionPlanEntry {
    pub extension_name: String,
    pub priority: u16,
}

/// Normalized request payload passed into an external-auth hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthHookRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: BTreeMap<String, String>,
}

/// Normalized external-auth hook decision used by transport adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthHookDecision {
    pub context: BTreeMap<String, String>,
    pub fail_open_applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthHookError {
    Denied,
    ServiceUnavailable,
    InvalidResponse,
}

/// Stable policy-plugin decisions returned by extension evaluators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPluginDecision {
    Allow,
    Deny,
    Abstain,
}

/// Metadata for one policy-plugin implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPluginDescriptor {
    pub name: String,
    pub version: String,
    pub api_version: String,
}

/// Request context passed to policy-plugin evaluators.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyPluginRequestContext {
    pub route_label: Option<String>,
    pub destination_label: Option<String>,
    pub headers: BTreeMap<String, String>,
}

/// Policy-plugin evaluation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPluginResponse {
    pub decision: PolicyPluginDecision,
    pub reason: Option<String>,
}

/// Execution-time fallback behavior when a plugin is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPluginDisabledFallback {
    Allow,
    Deny,
    Abstain,
}

/// Registration options for a policy plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPluginRegistration {
    pub plugin_name: String,
    pub required: bool,
    pub disabled_fallback: PolicyPluginDisabledFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPluginError {
    ExecutionFailed(String),
}

/// Stable contract implemented by policy plugins.
pub trait PolicyPlugin: Send + Sync {
    fn descriptor(&self) -> &PolicyPluginDescriptor;

    fn evaluate(
        &self,
        request: &PolicyPluginRequestContext,
    ) -> Result<PolicyPluginResponse, PolicyPluginError>;
}

/// Output of registry evaluation, including fallback usage visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPluginEvaluationOutcome {
    pub decision: PolicyPluginDecision,
    pub fallback_applied: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPluginRegistryError {
    DuplicatePlugin { name: String },
    UnknownPlugin { name: String },
    DescriptorNameMismatch {
        registration_name: String,
        descriptor_name: String,
    },
    IncompatibleApiVersion {
        plugin_name: String,
        api_version: String,
    },
    PluginDisabledRequired { name: String },
    PluginExecutionFailed { name: String, reason: String },
    PluginExecutionTimedOut { name: String },
    PluginPanicked { name: String },
}

struct RegisteredPolicyPlugin {
    registration: PolicyPluginRegistration,
    plugin: Arc<dyn PolicyPlugin>,
    disabled: bool,
    consecutive_failures: u32,
    isolated_until: Option<Instant>,
}

/// Isolation controls for plugin execution in the runtime process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyPluginIsolationPolicy {
    pub execution_timeout_ms: u64,
    pub max_consecutive_failures: u32,
    pub isolation_cooldown_secs: u64,
}

impl Default for PolicyPluginIsolationPolicy {
    fn default() -> Self {
        Self {
            execution_timeout_ms: 250,
            max_consecutive_failures: 3,
            isolation_cooldown_secs: 30,
        }
    }
}

/// Registry for stable policy-plugin contract evaluation.
#[derive(Default)]
pub struct PolicyPluginRegistry {
    compatibility_policy: ExtensionCompatibilityPolicy,
    isolation_policy: PolicyPluginIsolationPolicy,
    plugins: BTreeMap<String, RegisteredPolicyPlugin>,
}

impl PolicyPluginRegistry {
    #[must_use]
    pub fn new(compatibility_policy: ExtensionCompatibilityPolicy) -> Self {
        Self::new_with_isolation_policy(compatibility_policy, PolicyPluginIsolationPolicy::default())
    }

    #[must_use]
    pub fn new_with_isolation_policy(
        compatibility_policy: ExtensionCompatibilityPolicy,
        isolation_policy: PolicyPluginIsolationPolicy,
    ) -> Self {
        Self {
            compatibility_policy,
            isolation_policy,
            plugins: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        registration: PolicyPluginRegistration,
        plugin: Arc<dyn PolicyPlugin>,
    ) -> Result<(), PolicyPluginRegistryError> {
        let descriptor = plugin.descriptor();
        if registration.plugin_name != descriptor.name {
            return Err(PolicyPluginRegistryError::DescriptorNameMismatch {
                registration_name: registration.plugin_name,
                descriptor_name: descriptor.name.clone(),
            });
        }

        if self.plugins.contains_key(&descriptor.name) {
            return Err(PolicyPluginRegistryError::DuplicatePlugin {
                name: descriptor.name.clone(),
            });
        }

        if !self.compatibility_policy.supports(&descriptor.api_version) {
            return Err(PolicyPluginRegistryError::IncompatibleApiVersion {
                plugin_name: descriptor.name.clone(),
                api_version: descriptor.api_version.clone(),
            });
        }

        self.plugins.insert(
            descriptor.name.clone(),
            RegisteredPolicyPlugin {
                registration,
                plugin,
                disabled: false,
                consecutive_failures: 0,
                isolated_until: None,
            },
        );
        Ok(())
    }

    pub fn set_disabled(
        &mut self,
        plugin_name: &str,
        disabled: bool,
    ) -> Result<(), PolicyPluginRegistryError> {
        let Some(entry) = self.plugins.get_mut(plugin_name) else {
            return Err(PolicyPluginRegistryError::UnknownPlugin {
                name: plugin_name.to_string(),
            });
        };
        entry.disabled = disabled;
        Ok(())
    }

    pub fn evaluate(
        &mut self,
        plugin_name: &str,
        request: &PolicyPluginRequestContext,
    ) -> Result<PolicyPluginEvaluationOutcome, PolicyPluginRegistryError> {
        let Some(entry) = self.plugins.get_mut(plugin_name) else {
            return Err(PolicyPluginRegistryError::UnknownPlugin {
                name: plugin_name.to_string(),
            });
        };

        if entry
            .isolated_until
            .is_some_and(|deadline| Instant::now() < deadline)
        {
            if entry.registration.required {
                return Err(PolicyPluginRegistryError::PluginExecutionFailed {
                    name: plugin_name.to_string(),
                    reason: String::from("plugin is temporarily isolated after repeated failures"),
                });
            }
            let decision = match entry.registration.disabled_fallback {
                PolicyPluginDisabledFallback::Allow => PolicyPluginDecision::Allow,
                PolicyPluginDisabledFallback::Deny => PolicyPluginDecision::Deny,
                PolicyPluginDisabledFallback::Abstain => PolicyPluginDecision::Abstain,
            };
            return Ok(PolicyPluginEvaluationOutcome {
                decision,
                fallback_applied: true,
                reason: Some(String::from("plugin isolated; fallback decision applied")),
            });
        }

        if entry.disabled {
            if entry.registration.required {
                return Err(PolicyPluginRegistryError::PluginDisabledRequired {
                    name: plugin_name.to_string(),
                });
            }
            let decision = match entry.registration.disabled_fallback {
                PolicyPluginDisabledFallback::Allow => PolicyPluginDecision::Allow,
                PolicyPluginDisabledFallback::Deny => PolicyPluginDecision::Deny,
                PolicyPluginDisabledFallback::Abstain => PolicyPluginDecision::Abstain,
            };
            return Ok(PolicyPluginEvaluationOutcome {
                decision,
                fallback_applied: true,
                reason: Some(String::from("plugin disabled; fallback decision applied")),
            });
        }

        let timeout = Duration::from_millis(self.isolation_policy.execution_timeout_ms.max(1));
        let execution_result = execute_policy_plugin_with_timeout(
            plugin_name,
            entry.plugin.clone(),
            request.clone(),
            timeout,
        );

        let result = match execution_result {
            Ok(result) => result,
            Err(PolicyPluginRegistryError::PluginExecutionTimedOut { .. }) => {
                record_plugin_failure(entry, self.isolation_policy);
                return Err(PolicyPluginRegistryError::PluginExecutionTimedOut {
                    name: plugin_name.to_string(),
                });
            }
            Err(PolicyPluginRegistryError::PluginPanicked { .. }) => {
                record_plugin_failure(entry, self.isolation_policy);
                return Err(PolicyPluginRegistryError::PluginPanicked {
                    name: plugin_name.to_string(),
                });
            }
            Err(error) => {
                record_plugin_failure(entry, self.isolation_policy);
                return Err(error);
            }
        };

        match result {
            Ok(response) => {
                entry.consecutive_failures = 0;
                entry.isolated_until = None;
                Ok(PolicyPluginEvaluationOutcome {
                    decision: response.decision,
                    fallback_applied: false,
                    reason: response.reason,
                })
            }
            Err(PolicyPluginError::ExecutionFailed(reason)) => {
                record_plugin_failure(entry, self.isolation_policy);
                Err(PolicyPluginRegistryError::PluginExecutionFailed {
                    name: plugin_name.to_string(),
                    reason,
                })
            }
        }
    }
}

fn record_plugin_failure(entry: &mut RegisteredPolicyPlugin, policy: PolicyPluginIsolationPolicy) {
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    if entry.consecutive_failures >= policy.max_consecutive_failures.max(1) {
        entry.isolated_until = Some(
            Instant::now() + Duration::from_secs(policy.isolation_cooldown_secs.max(1)),
        );
        entry.consecutive_failures = 0;
    }
}

fn execute_policy_plugin_with_timeout(
    plugin_name: &str,
    plugin: Arc<dyn PolicyPlugin>,
    request: PolicyPluginRequestContext,
    timeout: Duration,
) -> Result<Result<PolicyPluginResponse, PolicyPluginError>, PolicyPluginRegistryError> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| plugin.evaluate(&request)));
        let _ = sender.send(outcome);
    });

    match receiver.recv_timeout(timeout) {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(PolicyPluginRegistryError::PluginPanicked {
            name: plugin_name.to_string(),
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Err(PolicyPluginRegistryError::PluginExecutionTimedOut {
                name: plugin_name.to_string(),
            })
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(PolicyPluginRegistryError::PluginExecutionFailed {
                name: plugin_name.to_string(),
                reason: String::from("plugin worker channel disconnected"),
            })
        }
    }
}

/// Runtime adapter that executes external auth through the stable hook request/decision model.
#[derive(Debug, Clone)]
pub struct RuntimeExternalAuthHook<'a> {
    policy: &'a crate::ExternalAuthPolicyRuntime,
}

impl<'a> RuntimeExternalAuthHook<'a> {
    #[must_use]
    pub fn new(policy: &'a crate::ExternalAuthPolicyRuntime) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn build_request<I, N, V>(
        &self,
        method: &str,
        path_and_query: &str,
        headers: I,
    ) -> ExternalAuthHookRequest
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let mut included_headers = BTreeMap::new();
        for (name, value) in headers {
            let name_ref = name.as_ref();
            let include = self
                .policy
                .include_headers()
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(name_ref));
            if include {
                included_headers.insert(name_ref.to_ascii_lowercase(), value.as_ref().to_string());
            }
        }

        ExternalAuthHookRequest {
            method: method.to_string(),
            path_and_query: path_and_query.to_string(),
            headers: included_headers,
        }
    }

    pub async fn execute(
        &self,
        request: &ExternalAuthHookRequest,
    ) -> Result<ExternalAuthHookDecision, ExternalAuthHookError> {
        let result = self
            .policy
            .authorize_http_request_with_fail_open(
                &request.method,
                &request.path_and_query,
                &request.headers,
            )
            .await;
        match result {
            Ok(entry) if !entry.allowed => Err(ExternalAuthHookError::Denied),
            Ok(entry) => Ok(ExternalAuthHookDecision {
                context: entry.context,
                fail_open_applied: entry.fail_open_applied,
            }),
            Err(crate::ExternalAuthVerificationError::ServiceUnavailable) => {
                Err(ExternalAuthHookError::ServiceUnavailable)
            }
            Err(crate::ExternalAuthVerificationError::InvalidResponse) => {
                Err(ExternalAuthHookError::InvalidResponse)
            }
            Err(_) => Err(ExternalAuthHookError::Denied),
        }
    }

    pub fn resolve_context_headers(
        &self,
        decision: &ExternalAuthHookDecision,
    ) -> Result<Vec<(String, String)>, ExternalAuthHookError> {
        let mut resolved = Vec::new();
        for mapping in self.policy.context_mappings() {
            let value = match decision.context.get(&mapping.source) {
                Some(value) => value,
                None if mapping.required => return Err(ExternalAuthHookError::Denied),
                None => continue,
            };
            resolved.push((mapping.target_header.clone(), value.clone()));
        }
        Ok(resolved)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionRegistryError {
    DuplicateExtensionName { name: String },
    IncompatibleApiVersion {
        extension_name: String,
        api_version: String,
    },
    UnknownExtension { name: String },
    InvalidStateTransition {
        name: String,
        from: ExtensionLifecycleState,
        to: ExtensionLifecycleState,
    },
}

/// In-memory extension registry with deterministic lifecycle and hook ordering.
#[derive(Debug, Clone)]
pub struct ExtensionRegistry {
    compatibility_policy: ExtensionCompatibilityPolicy,
    extensions: Vec<RegisteredExtension>,
}

impl ExtensionRegistry {
    #[must_use]
    pub fn new(compatibility_policy: ExtensionCompatibilityPolicy) -> Self {
        Self {
            compatibility_policy,
            extensions: Vec::new(),
        }
    }

    #[must_use]
    pub fn compatibility_policy(&self) -> &ExtensionCompatibilityPolicy {
        &self.compatibility_policy
    }

    #[must_use]
    pub fn extensions(&self) -> &[RegisteredExtension] {
        &self.extensions
    }

    pub fn register(
        &mut self,
        descriptor: ExtensionDescriptor,
        hooks: Vec<ExtensionHookBinding>,
    ) -> Result<(), ExtensionRegistryError> {
        if self
            .extensions
            .iter()
            .any(|extension| extension.descriptor.name == descriptor.name)
        {
            return Err(ExtensionRegistryError::DuplicateExtensionName {
                name: descriptor.name,
            });
        }

        if !self.compatibility_policy.supports(&descriptor.api_version) {
            return Err(ExtensionRegistryError::IncompatibleApiVersion {
                extension_name: descriptor.name,
                api_version: descriptor.api_version,
            });
        }

        self.extensions.push(RegisteredExtension {
            descriptor,
            hooks,
            state: ExtensionLifecycleState::Registered,
            failure_reason: None,
        });
        Ok(())
    }

    pub fn activate(&mut self, name: &str) -> Result<(), ExtensionRegistryError> {
        let extension = self.find_mut(name)?;
        match extension.state {
            ExtensionLifecycleState::Registered | ExtensionLifecycleState::Stopped => {
                extension.state = ExtensionLifecycleState::Active;
                extension.failure_reason = None;
                Ok(())
            }
            ExtensionLifecycleState::Failed => Err(ExtensionRegistryError::InvalidStateTransition {
                name: name.to_string(),
                from: extension.state,
                to: ExtensionLifecycleState::Active,
            }),
            ExtensionLifecycleState::Active | ExtensionLifecycleState::Draining => Ok(()),
        }
    }

    pub fn begin_drain(&mut self, name: &str) -> Result<(), ExtensionRegistryError> {
        let extension = self.find_mut(name)?;
        match extension.state {
            ExtensionLifecycleState::Active => {
                extension.state = ExtensionLifecycleState::Draining;
                Ok(())
            }
            ExtensionLifecycleState::Registered
            | ExtensionLifecycleState::Stopped
            | ExtensionLifecycleState::Failed => Err(ExtensionRegistryError::InvalidStateTransition {
                name: name.to_string(),
                from: extension.state,
                to: ExtensionLifecycleState::Draining,
            }),
            ExtensionLifecycleState::Draining => Ok(()),
        }
    }

    pub fn stop(&mut self, name: &str) -> Result<(), ExtensionRegistryError> {
        let extension = self.find_mut(name)?;
        match extension.state {
            ExtensionLifecycleState::Registered
            | ExtensionLifecycleState::Active
            | ExtensionLifecycleState::Draining => {
                extension.state = ExtensionLifecycleState::Stopped;
                extension.failure_reason = None;
                Ok(())
            }
            ExtensionLifecycleState::Stopped => Ok(()),
            ExtensionLifecycleState::Failed => Err(ExtensionRegistryError::InvalidStateTransition {
                name: name.to_string(),
                from: extension.state,
                to: ExtensionLifecycleState::Stopped,
            }),
        }
    }

    pub fn fail(&mut self, name: &str, reason: impl Into<String>) -> Result<(), ExtensionRegistryError> {
        let extension = self.find_mut(name)?;
        extension.state = ExtensionLifecycleState::Failed;
        extension.failure_reason = Some(reason.into());
        Ok(())
    }

    #[must_use]
    pub fn hook_execution_plan(&self, phase: ExtensionHookPhase) -> Vec<HookExecutionPlanEntry> {
        let mut plan = self
            .extensions
            .iter()
            .filter(|extension| extension.state == ExtensionLifecycleState::Active)
            .flat_map(|extension| {
                extension.hooks.iter().filter_map(move |binding| {
                    if binding.phase == phase {
                        Some(HookExecutionPlanEntry {
                            extension_name: extension.descriptor.name.clone(),
                            priority: binding.priority,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>();

        plan.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.extension_name.cmp(&right.extension_name))
        });
        plan
    }

    fn find_mut(&mut self, name: &str) -> Result<&mut RegisteredExtension, ExtensionRegistryError> {
        self.extensions
            .iter_mut()
            .find(|extension| extension.descriptor.name == name)
            .ok_or_else(|| ExtensionRegistryError::UnknownExtension {
                name: name.to_string(),
            })
    }
}

impl Default for ExtensionRegistry {
    fn default() -> Self {
        Self::new(ExtensionCompatibilityPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct StaticDecisionPolicyPlugin {
        descriptor: PolicyPluginDescriptor,
        decision: PolicyPluginDecision,
    }

    impl StaticDecisionPolicyPlugin {
        fn new(name: &str, api_version: &str, decision: PolicyPluginDecision) -> Self {
            Self {
                descriptor: PolicyPluginDescriptor {
                    name: name.to_string(),
                    version: String::from("1.0.0"),
                    api_version: api_version.to_string(),
                },
                decision,
            }
        }
    }

    impl PolicyPlugin for StaticDecisionPolicyPlugin {
        fn descriptor(&self) -> &PolicyPluginDescriptor {
            &self.descriptor
        }

        fn evaluate(
            &self,
            _request: &PolicyPluginRequestContext,
        ) -> Result<PolicyPluginResponse, PolicyPluginError> {
            Ok(PolicyPluginResponse {
                decision: self.decision,
                reason: Some(String::from("static-decision")),
            })
        }
    }

    #[derive(Debug)]
    struct SleepyPolicyPlugin {
        descriptor: PolicyPluginDescriptor,
        sleep_ms: u64,
    }

    impl SleepyPolicyPlugin {
        fn new(name: &str, api_version: &str, sleep_ms: u64) -> Self {
            Self {
                descriptor: PolicyPluginDescriptor {
                    name: name.to_string(),
                    version: String::from("1.0.0"),
                    api_version: api_version.to_string(),
                },
                sleep_ms,
            }
        }
    }

    impl PolicyPlugin for SleepyPolicyPlugin {
        fn descriptor(&self) -> &PolicyPluginDescriptor {
            &self.descriptor
        }

        fn evaluate(
            &self,
            _request: &PolicyPluginRequestContext,
        ) -> Result<PolicyPluginResponse, PolicyPluginError> {
            std::thread::sleep(Duration::from_millis(self.sleep_ms));
            Ok(PolicyPluginResponse {
                decision: PolicyPluginDecision::Allow,
                reason: Some(String::from("sleepy")),
            })
        }
    }

    #[derive(Debug)]
    struct PanicPolicyPlugin {
        descriptor: PolicyPluginDescriptor,
    }

    impl PanicPolicyPlugin {
        fn new(name: &str, api_version: &str) -> Self {
            Self {
                descriptor: PolicyPluginDescriptor {
                    name: name.to_string(),
                    version: String::from("1.0.0"),
                    api_version: api_version.to_string(),
                },
            }
        }
    }

    impl PolicyPlugin for PanicPolicyPlugin {
        fn descriptor(&self) -> &PolicyPluginDescriptor {
            &self.descriptor
        }

        fn evaluate(
            &self,
            _request: &PolicyPluginRequestContext,
        ) -> Result<PolicyPluginResponse, PolicyPluginError> {
            panic!("plugin panic for isolation test")
        }
    }

    fn descriptor(name: &str, api_version: &str) -> ExtensionDescriptor {
        ExtensionDescriptor {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            api_version: api_version.to_string(),
        }
    }

    fn request_headers_hook(priority: u16) -> ExtensionHookBinding {
        ExtensionHookBinding {
            phase: ExtensionHookPhase::RequestHeaders,
            priority,
        }
    }

    fn external_auth_policy() -> crate::ExternalAuthPolicyRuntime {
        let config = lb_config_model::ExternalAuthPolicyConfig {
            endpoint: String::from("http://127.0.0.1:18080/authz"),
            protocol: lb_config_model::ExternalAuthProtocolConfig::Http,
            timeout_ms: 1_000,
            fail_open: true,
            include_headers: vec![String::from("authorization"), String::from("x-device-id")],
            context_mappings: vec![lb_config_model::AuthContextMappingConfig {
                source: String::from("principal"),
                target_header: String::from("x-auth-principal"),
                required: true,
            }],
        };
        crate::ExternalAuthPolicyRuntime::from_config(&config)
            .expect("external auth policy should parse")
    }

    #[test]
    fn rejects_incompatible_extension_api_version() {
        let mut registry = ExtensionRegistry::new(ExtensionCompatibilityPolicy::new(["v1"]));

        let error = registry
            .register(descriptor("authz-plugin", "v2"), vec![request_headers_hook(10)])
            .expect_err("incompatible api version should be rejected");

        assert_eq!(
            error,
            ExtensionRegistryError::IncompatibleApiVersion {
                extension_name: "authz-plugin".to_string(),
                api_version: "v2".to_string(),
            }
        );
    }

    #[test]
    fn hook_execution_plan_is_priority_then_name_stable() {
        let mut registry = ExtensionRegistry::default();

        registry
            .register(descriptor("z-auth", "v1"), vec![request_headers_hook(20)])
            .expect("register z-auth");
        registry
            .register(descriptor("a-auth", "v1"), vec![request_headers_hook(20)])
            .expect("register a-auth");
        registry
            .register(descriptor("rate", "v1"), vec![request_headers_hook(10)])
            .expect("register rate");

        registry.activate("z-auth").expect("activate z-auth");
        registry.activate("a-auth").expect("activate a-auth");
        registry.activate("rate").expect("activate rate");

        let plan = registry.hook_execution_plan(ExtensionHookPhase::RequestHeaders);
        let names = plan
            .iter()
            .map(|entry| entry.extension_name.clone())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["rate", "a-auth", "z-auth"]);
    }

    #[test]
    fn lifecycle_transitions_enforce_safety_boundaries() {
        let mut registry = ExtensionRegistry::default();
        registry
            .register(
                descriptor("external-auth", "v1"),
                vec![request_headers_hook(5)],
            )
            .expect("register extension");

        registry
            .activate("external-auth")
            .expect("activate extension");
        registry
            .begin_drain("external-auth")
            .expect("begin drain");
        registry.stop("external-auth").expect("stop extension");

        let extension = registry
            .extensions()
            .iter()
            .find(|entry| entry.descriptor.name == "external-auth")
            .expect("extension must exist");
        assert_eq!(extension.state, ExtensionLifecycleState::Stopped);

        let error = registry
            .begin_drain("external-auth")
            .expect_err("drain from stopped must fail");
        assert_eq!(
            error,
            ExtensionRegistryError::InvalidStateTransition {
                name: "external-auth".to_string(),
                from: ExtensionLifecycleState::Stopped,
                to: ExtensionLifecycleState::Draining,
            }
        );
    }

    #[test]
    fn runtime_external_auth_hook_request_includes_only_selected_headers() {
        let policy = external_auth_policy();
        let hook = RuntimeExternalAuthHook::new(&policy);

        let request = hook.build_request(
            "GET",
            "/payments",
            [
                ("authorization", "Bearer token"),
                ("x-device-id", "ios"),
                ("x-ignore", "skip"),
            ],
        );

        assert_eq!(request.method, "GET");
        assert_eq!(request.path_and_query, "/payments");
        assert_eq!(request.headers.len(), 2);
        assert_eq!(
            request.headers.get("authorization"),
            Some(&String::from("Bearer token"))
        );
        assert_eq!(
            request.headers.get("x-device-id"),
            Some(&String::from("ios"))
        );
    }

    #[test]
    fn runtime_external_auth_hook_resolves_required_context_mappings() {
        let policy = external_auth_policy();
        let hook = RuntimeExternalAuthHook::new(&policy);

        let decision = ExternalAuthHookDecision {
            context: [(String::from("principal"), String::from("alice"))]
                .into_iter()
                .collect(),
            fail_open_applied: false,
        };

        let headers = hook
            .resolve_context_headers(&decision)
            .expect("required mapping should resolve");
        assert_eq!(
            headers,
            vec![(String::from("x-auth-principal"), String::from("alice"))]
        );

        let missing = ExternalAuthHookDecision {
            context: BTreeMap::new(),
            fail_open_applied: false,
        };
        assert_eq!(
            hook.resolve_context_headers(&missing),
            Err(ExternalAuthHookError::Denied)
        );
    }

    #[test]
    fn policy_plugin_registry_rejects_incompatible_version() {
        let mut registry = PolicyPluginRegistry::new(ExtensionCompatibilityPolicy::new(["v1"]));
        let registration = PolicyPluginRegistration {
            plugin_name: String::from("custom-authz"),
            required: false,
            disabled_fallback: PolicyPluginDisabledFallback::Deny,
        };
        let plugin = Arc::new(StaticDecisionPolicyPlugin::new(
            "custom-authz",
            "v2",
            PolicyPluginDecision::Allow,
        ));

        let error = registry
            .register(registration, plugin)
            .expect_err("incompatible version must be rejected");
        assert_eq!(
            error,
            PolicyPluginRegistryError::IncompatibleApiVersion {
                plugin_name: String::from("custom-authz"),
                api_version: String::from("v2"),
            }
        );
    }

    #[test]
    fn policy_plugin_registry_applies_disabled_fallback_for_optional_plugin() {
        let mut registry = PolicyPluginRegistry::new(ExtensionCompatibilityPolicy::new(["v1"]));
        let registration = PolicyPluginRegistration {
            plugin_name: String::from("custom-authz"),
            required: false,
            disabled_fallback: PolicyPluginDisabledFallback::Deny,
        };
        let plugin = Arc::new(StaticDecisionPolicyPlugin::new(
            "custom-authz",
            "v1",
            PolicyPluginDecision::Allow,
        ));
        registry
            .register(registration, plugin)
            .expect("plugin should register");
        registry
            .set_disabled("custom-authz", true)
            .expect("plugin should disable");

        let outcome = registry
            .evaluate("custom-authz", &PolicyPluginRequestContext::default())
            .expect("fallback should apply");
        assert_eq!(outcome.decision, PolicyPluginDecision::Deny);
        assert!(outcome.fallback_applied);
    }

    #[test]
    fn policy_plugin_registry_errors_when_required_plugin_is_disabled() {
        let mut registry = PolicyPluginRegistry::new(ExtensionCompatibilityPolicy::new(["v1"]));
        let registration = PolicyPluginRegistration {
            plugin_name: String::from("required-authz"),
            required: true,
            disabled_fallback: PolicyPluginDisabledFallback::Allow,
        };
        let plugin = Arc::new(StaticDecisionPolicyPlugin::new(
            "required-authz",
            "v1",
            PolicyPluginDecision::Allow,
        ));
        registry
            .register(registration, plugin)
            .expect("plugin should register");
        registry
            .set_disabled("required-authz", true)
            .expect("plugin should disable");

        let error = registry
            .evaluate("required-authz", &PolicyPluginRequestContext::default())
            .expect_err("required plugin disabled must error");
        assert_eq!(
            error,
            PolicyPluginRegistryError::PluginDisabledRequired {
                name: String::from("required-authz"),
            }
        );
    }

    #[test]
    fn policy_plugin_registry_times_out_and_isolates_optional_plugin() {
        let mut registry = PolicyPluginRegistry::new_with_isolation_policy(
            ExtensionCompatibilityPolicy::new(["v1"]),
            PolicyPluginIsolationPolicy {
                execution_timeout_ms: 5,
                max_consecutive_failures: 1,
                isolation_cooldown_secs: 60,
            },
        );
        registry
            .register(
                PolicyPluginRegistration {
                    plugin_name: String::from("slow-authz"),
                    required: false,
                    disabled_fallback: PolicyPluginDisabledFallback::Abstain,
                },
                Arc::new(SleepyPolicyPlugin::new("slow-authz", "v1", 100)),
            )
            .expect("plugin should register");

        let first = registry.evaluate("slow-authz", &PolicyPluginRequestContext::default());
        assert_eq!(
            first,
            Err(PolicyPluginRegistryError::PluginExecutionTimedOut {
                name: String::from("slow-authz"),
            })
        );

        let second = registry
            .evaluate("slow-authz", &PolicyPluginRequestContext::default())
            .expect("isolated optional plugin should use fallback");
        assert_eq!(second.decision, PolicyPluginDecision::Abstain);
        assert!(second.fallback_applied);
    }

    #[test]
    fn policy_plugin_registry_contains_panics_and_marks_failure() {
        let mut registry = PolicyPluginRegistry::new_with_isolation_policy(
            ExtensionCompatibilityPolicy::new(["v1"]),
            PolicyPluginIsolationPolicy {
                execution_timeout_ms: 50,
                max_consecutive_failures: 2,
                isolation_cooldown_secs: 60,
            },
        );
        registry
            .register(
                PolicyPluginRegistration {
                    plugin_name: String::from("panic-authz"),
                    required: true,
                    disabled_fallback: PolicyPluginDisabledFallback::Deny,
                },
                Arc::new(PanicPolicyPlugin::new("panic-authz", "v1")),
            )
            .expect("plugin should register");

        let error = registry
            .evaluate("panic-authz", &PolicyPluginRequestContext::default())
            .expect_err("panic should be contained and mapped to error");
        assert_eq!(
            error,
            PolicyPluginRegistryError::PluginPanicked {
                name: String::from("panic-authz"),
            }
        );
    }
}