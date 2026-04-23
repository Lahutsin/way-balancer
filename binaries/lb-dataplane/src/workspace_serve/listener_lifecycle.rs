#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerIdentity {
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
}

impl ListenerIdentity {
    fn from_spec(spec: &CompiledServeListener) -> Self {
        Self {
            class: spec.class(),
            protocol: spec.protocol(),
            proxy_protocol: spec.proxy_protocol(),
            configured_bind: spec.bind_address(),
            bind_mode: spec.bind_mode(),
        }
    }

    fn from_listener(listener: &ManagedServeListener) -> Self {
        Self {
            class: listener.class,
            protocol: listener.protocol,
            proxy_protocol: listener.proxy_protocol,
            configured_bind: listener.configured_bind,
            bind_mode: listener.bind_mode,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerLifecycleState {
    Active,
    Draining,
    Retired,
    FailedStart,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenerLifecycleEntry {
    identity: ListenerIdentity,
    state: ListenerLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FailedListenerStart {
    identity: ListenerIdentity,
    detail: String,
}

#[derive(Debug, Clone)]
struct ListenerLifecycleModel {
    desired_identity: ListenerIdentity,
    active_identity: Option<ListenerIdentity>,
    draining_identities: Vec<ListenerIdentity>,
    retired_identities: Vec<ListenerIdentity>,
    drain_timed_out_identities: Vec<ListenerIdentity>,
    failed_start: Option<FailedListenerStart>,
}

impl ListenerLifecycleModel {
    fn new_active(identity: ListenerIdentity) -> Self {
        Self {
            desired_identity: identity,
            active_identity: Some(identity),
            draining_identities: Vec::new(),
            retired_identities: Vec::new(),
            drain_timed_out_identities: Vec::new(),
            failed_start: None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn active_identity(&self) -> Option<ListenerIdentity> {
        self.active_identity
    }

    fn apply_in_place(&mut self, identity: ListenerIdentity) {
        self.desired_identity = identity;
        self.active_identity = Some(identity);
        self.failed_start = None;
    }

    fn activate_replacement(&mut self, identity: ListenerIdentity) -> Option<ListenerIdentity> {
        let previous = self.active_identity.replace(identity);
        if let Some(previous) = previous {
            self.draining_identities.push(previous);
        }
        self.desired_identity = identity;
        self.failed_start = None;
        previous
    }

    fn finish_draining(&mut self, identity: ListenerIdentity, outcome: ListenerDrainOutcome) {
        if let Some(index) =
            self.draining_identities.iter().position(|candidate| *candidate == identity)
        {
            let retired = self.draining_identities.remove(index);
            self.push_retired(retired);
            if matches!(outcome, ListenerDrainOutcome::TimedOut) {
                self.push_drain_timed_out(retired);
            }
        }
    }

    fn retire_active(&mut self) -> Option<ListenerIdentity> {
        let retired = self.active_identity.take()?;
        self.push_retired(retired);
        self.failed_start = None;
        Some(retired)
    }

    fn record_failed_start(&mut self, identity: ListenerIdentity, detail: String) {
        self.failed_start = Some(FailedListenerStart { identity, detail });
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn entries(&self) -> Vec<ListenerLifecycleEntry> {
        let mut entries = Vec::new();
        if let Some(identity) = self.active_identity {
            entries
                .push(ListenerLifecycleEntry { identity, state: ListenerLifecycleState::Active });
        }
        entries.extend(self.draining_identities.iter().copied().map(|identity| {
            ListenerLifecycleEntry { identity, state: ListenerLifecycleState::Draining }
        }));
        entries.extend(self.retired_identities.iter().copied().map(|identity| {
            ListenerLifecycleEntry { identity, state: ListenerLifecycleState::Retired }
        }));
        if let Some(failed_start) = &self.failed_start {
            entries.push(ListenerLifecycleEntry {
                identity: failed_start.identity,
                state: ListenerLifecycleState::FailedStart,
            });
        }
        entries
    }

    fn push_retired(&mut self, identity: ListenerIdentity) {
        const MAX_RETIRED_IDENTITIES: usize = 4;

        if self.retired_identities.len() == MAX_RETIRED_IDENTITIES {
            let _ = self.retired_identities.remove(0);
        }
        self.retired_identities.push(identity);
    }

    fn push_drain_timed_out(&mut self, identity: ListenerIdentity) {
        const MAX_DRAIN_TIMEOUT_IDENTITIES: usize = 4;

        if self.drain_timed_out_identities.len() == MAX_DRAIN_TIMEOUT_IDENTITIES {
            let _ = self.drain_timed_out_identities.remove(0);
        }
        self.drain_timed_out_identities.push(identity);
    }
}

#[derive(Debug)]
struct RetiredManagedListener {
    slot_name: Option<String>,
    identity: ListenerIdentity,
    listener: ManagedServeListener,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CurrentListenerIdentity {
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
    local_addr: SocketAddr,
}

impl CurrentListenerIdentity {
    fn matches_spec(&self, spec: &CompiledServeListener) -> bool {
        self.class == spec.class()
            && self.protocol == spec.protocol()
            && self.proxy_protocol == spec.proxy_protocol()
            && self.configured_bind == spec.bind_address()
            && self.bind_mode == spec.bind_mode()
    }

    fn needs_replacement(&self, spec: &CompiledServeListener) -> bool {
        !self.matches_spec(spec)
    }

    fn can_stage_replacement(&self, spec: &CompiledServeListener) -> bool {
        spec.bind_address() != self.local_addr
    }
}

#[derive(Debug)]
struct ManagedListenerSlot {
    lifecycle: ListenerLifecycleModel,
    active: ManagedServeListener,
}

impl ManagedListenerSlot {
    fn new(listener: ManagedServeListener) -> Self {
        let identity = ListenerIdentity::from_listener(&listener);
        Self { lifecycle: ListenerLifecycleModel::new_active(identity), active: listener }
    }

    fn current_identity(&self) -> CurrentListenerIdentity {
        CurrentListenerIdentity {
            class: self.active.class,
            protocol: self.active.protocol,
            proxy_protocol: self.active.proxy_protocol,
            configured_bind: self.active.configured_bind,
            bind_mode: self.active.bind_mode,
            local_addr: self.active.local_addr,
        }
    }

    fn can_update_in_place(&self, spec: &CompiledServeListener) -> bool {
        self.active.class == spec.class()
            && self.active.protocol == spec.protocol()
            && self.active.proxy_protocol == spec.proxy_protocol()
            && self.active.configured_bind == spec.bind_address()
            && self.active.bind_mode == spec.bind_mode()
    }

    async fn apply_update(&mut self, spec: &CompiledServeListener) -> Result<(), DynError> {
        self.active.apply_update(spec).await?;
        self.lifecycle.apply_in_place(ListenerIdentity::from_spec(spec));
        Ok(())
    }

    fn activate_replacement(
        &mut self,
        slot_name: String,
        replacement: ManagedServeListener,
    ) -> RetiredManagedListener {
        let retired_identity = ListenerIdentity::from_listener(&self.active);
        let replacement_identity = ListenerIdentity::from_listener(&replacement);
        let _ = self.lifecycle.activate_replacement(replacement_identity);
        let listener = std::mem::replace(&mut self.active, replacement);
        RetiredManagedListener { slot_name: Some(slot_name), identity: retired_identity, listener }
    }

    fn into_retired(mut self) -> RetiredManagedListener {
        let identity = self
            .lifecycle
            .retire_active()
            .unwrap_or_else(|| ListenerIdentity::from_listener(&self.active));
        RetiredManagedListener { slot_name: None, identity, listener: self.active }
    }

    fn record_failed_start(&mut self, spec: &CompiledServeListener, detail: String) {
        self.lifecycle.record_failed_start(ListenerIdentity::from_spec(spec), detail);
    }

    fn finish_draining_with_outcome(
        &mut self,
        identity: ListenerIdentity,
        outcome: ListenerDrainOutcome,
    ) {
        self.lifecycle.finish_draining(identity, outcome);
    }
}

#[derive(Debug, Clone)]
enum CompiledServeListener {
    Public {
        class: lb_config_model::ListenerClassConfig,
        protocol: lb_config_model::ListenerProtocolConfig,
        proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
        bind_address: SocketAddr,
        bind_mode: lb_net_core::ListenerBindMode,
        max_connections: usize,
        drain_timeout: Duration,
        overload_policy: Option<CompiledListenerOverloadPolicy>,
        abuse_protection_policy: Option<CompiledListenerAbuseProtectionPolicy>,
        proxy: ManagedProxyConfig,
    },
    Admin {
        protocol: lb_config_model::ListenerProtocolConfig,
        proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
        bind_address: SocketAddr,
        bind_mode: lb_net_core::ListenerBindMode,
        max_connections: usize,
        drain_timeout: Duration,
        overload_policy: Option<CompiledListenerOverloadPolicy>,
        abuse_protection_policy: Option<CompiledListenerAbuseProtectionPolicy>,
        admin_policy: CompiledAdminPolicy,
        tls: Option<ManagedAdminTlsConfig>,
    },
}

impl CompiledServeListener {
    fn class(&self) -> lb_config_model::ListenerClassConfig {
        match self {
            Self::Public { class, .. } => *class,
            Self::Admin { .. } => lb_config_model::ListenerClassConfig::Admin,
        }
    }

    fn protocol(&self) -> lb_config_model::ListenerProtocolConfig {
        match self {
            Self::Public { protocol, .. } => *protocol,
            Self::Admin { protocol, .. } => *protocol,
        }
    }

    fn proxy_protocol(&self) -> lb_config_model::ProxyProtocolModeConfig {
        match self {
            Self::Public { proxy_protocol, .. } => *proxy_protocol,
            Self::Admin { proxy_protocol, .. } => *proxy_protocol,
        }
    }

    fn bind_address(&self) -> SocketAddr {
        match self {
            Self::Public { bind_address, .. } | Self::Admin { bind_address, .. } => *bind_address,
        }
    }

    fn bind_mode(&self) -> lb_net_core::ListenerBindMode {
        match self {
            Self::Public { bind_mode, .. } | Self::Admin { bind_mode, .. } => *bind_mode,
        }
    }

    fn drain_timeout(&self) -> Duration {
        match self {
            Self::Public { drain_timeout, .. } | Self::Admin { drain_timeout, .. } => {
                *drain_timeout
            }
        }
    }

    fn max_connections(&self) -> usize {
        match self {
            Self::Public { max_connections, .. } | Self::Admin { max_connections, .. } => {
                *max_connections
            }
        }
    }

    fn overload_policy(&self) -> Option<&CompiledListenerOverloadPolicy> {
        match self {
            Self::Public { overload_policy, .. } | Self::Admin { overload_policy, .. } => {
                overload_policy.as_ref()
            }
        }
    }

    fn abuse_protection_policy(&self) -> Option<&CompiledListenerAbuseProtectionPolicy> {
        match self {
            Self::Public { abuse_protection_policy, .. }
            | Self::Admin { abuse_protection_policy, .. } => abuse_protection_policy.as_ref(),
        }
    }
}

#[derive(Debug)]
struct CompiledWorkspaceRuntime {
    source_label: String,
    snapshot: lb_config_model::WorkspaceSnapshot,
    listeners: BTreeMap<String, CompiledServeListener>,
    http_cache_scopes: BTreeMap<String, HttpCacheScopeRuntime>,
}
