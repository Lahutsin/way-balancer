use serde::{Deserialize, Serialize};

use crate::{
    rollout::validate_rollout_request, InvalidRolloutRequest, RollbackRequest, RolloutActionKind,
    RolloutRequest, RolloutResponse, SnapshotControlService,
};

const MAX_FLEET_NODES: usize = 128;
const MAX_NODE_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetConsistencyMode {
    BoundedEventual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetRolloutStrategy {
    Immediate,
    Sequential,
    Canary { canary_nodes: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetConvergenceState {
    Converged,
    Progressing,
    Diverged,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetRecommendedAction {
    ObserveOnly,
    WaitForConvergence,
    RetryFailedNodes,
    RollbackFleet,
    InvestigatePartition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetNodeConvergenceState {
    Converged,
    Pending,
    Diverged,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetNodeActionResult {
    Applied,
    Unchanged,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetNodeRuntimeStatus {
    pub node_id: String,
    pub desired_version: Option<String>,
    pub desired_digest_sha256: Option<String>,
    pub active_version: Option<String>,
    pub active_digest_sha256: Option<String>,
    pub last_known_good_version: Option<String>,
    pub readiness: Option<String>,
    pub observed_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetNodeStatus {
    pub node_id: String,
    pub desired_version: Option<String>,
    pub desired_digest_sha256: Option<String>,
    pub active_version: Option<String>,
    pub active_digest_sha256: Option<String>,
    pub last_known_good_version: Option<String>,
    pub readiness: Option<String>,
    pub observed_at_unix_ms: u64,
    pub convergence_state: FleetNodeConvergenceState,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetNodeActionOutcome {
    pub node_id: String,
    pub result: FleetNodeActionResult,
    pub active_version: Option<String>,
    pub active_digest_sha256: Option<String>,
    pub last_known_good_version: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetConvergenceReport {
    pub desired_version: String,
    pub desired_digest_sha256: String,
    pub consistency_mode: FleetConsistencyMode,
    pub state: FleetConvergenceState,
    pub recommended_action: FleetRecommendedAction,
    pub rollout_started_at_unix_ms: u64,
    pub divergence_deadline_unix_ms: u64,
    pub exceeded_divergence_budget: bool,
    pub converged_nodes: usize,
    pub pending_nodes: usize,
    pub diverged_nodes: usize,
    pub unavailable_nodes: usize,
    pub partial_rollout: bool,
    pub nodes: Vec<FleetNodeStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRolloutRequest {
    pub version: String,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
    pub node_ids: Vec<String>,
    pub strategy: FleetRolloutStrategy,
    pub max_allowed_divergence_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRollbackRequest {
    pub target_version: Option<String>,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
    pub node_ids: Vec<String>,
    pub max_allowed_divergence_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRolloutResponse {
    pub action: RolloutActionKind,
    pub strategy: FleetRolloutStrategy,
    pub desired_version: String,
    pub desired_digest_sha256: String,
    pub shared_last_known_good_version: Option<String>,
    pub convergence: FleetConvergenceReport,
    pub node_outcomes: Vec<FleetNodeActionOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FleetRolloutMetrics {
    pub rollout_count: u64,
    pub rollback_count: u64,
    pub converged_fleet_count: u64,
    pub partial_failure_count: u64,
    pub divergence_count: u64,
    pub degraded_count: u64,
    pub audit_event_count: u64,
    pub history_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRolloutHistoryEntry {
    pub action: RolloutActionKind,
    pub strategy: FleetRolloutStrategy,
    pub target_version: String,
    pub desired_digest_sha256: String,
    pub convergence_state: FleetConvergenceState,
    pub converged_nodes: usize,
    pub pending_nodes: usize,
    pub diverged_nodes: usize,
    pub unavailable_nodes: usize,
    pub occurred_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidFleetRequest {
    EmptyNodeIds,
    TooManyNodes,
    EmptyNodeId,
    DuplicateNodeId(String),
    NodeIdTooLong,
    ZeroMaxAllowedDivergenceMs,
    ZeroCanaryNodes,
}

impl std::fmt::Display for InvalidFleetRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyNodeIds => write!(formatter, "fleet request must include at least one node"),
            Self::TooManyNodes => write!(formatter, "fleet request exceeds max node count"),
            Self::EmptyNodeId => write!(formatter, "fleet node_id must not be empty"),
            Self::DuplicateNodeId(node_id) => {
                write!(formatter, "fleet request contains duplicate node_id '{node_id}'")
            }
            Self::NodeIdTooLong => write!(formatter, "fleet node_id exceeds max length"),
            Self::ZeroMaxAllowedDivergenceMs => {
                write!(formatter, "max_allowed_divergence_ms must be greater than zero")
            }
            Self::ZeroCanaryNodes => {
                write!(formatter, "canary rollout requires at least one canary node")
            }
        }
    }
}

impl std::error::Error for InvalidFleetRequest {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetNodeBackendError {
    Unreachable(String),
    Rejected(String),
}

impl std::fmt::Display for FleetNodeBackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(detail) => write!(formatter, "node unreachable: {detail}"),
            Self::Rejected(detail) => write!(formatter, "node rejected operation: {detail}"),
        }
    }
}

impl std::error::Error for FleetNodeBackendError {}

#[derive(Debug)]
pub enum FleetRolloutError {
    InvalidFleetRequest(InvalidFleetRequest),
    InvalidRolloutRequest(InvalidRolloutRequest),
    UnknownPublishedVersion(String),
    NoSharedRollbackCandidate,
    StatusUnavailable { node_id: String, detail: String },
}

impl std::fmt::Display for FleetRolloutError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFleetRequest(error) => {
                write!(formatter, "invalid fleet request: {error}")
            }
            Self::InvalidRolloutRequest(error) => {
                write!(formatter, "invalid rollout request: {error}")
            }
            Self::UnknownPublishedVersion(version) => {
                write!(formatter, "published snapshot version '{version}' was not found")
            }
            Self::NoSharedRollbackCandidate => write!(
                formatter,
                "fleet rollback requires an explicit target_version or a shared last-known-good version"
            ),
            Self::StatusUnavailable { node_id, detail } => {
                write!(formatter, "fleet node '{node_id}' status unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for FleetRolloutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidFleetRequest(error) => Some(error),
            Self::InvalidRolloutRequest(error) => Some(error),
            Self::UnknownPublishedVersion(_)
            | Self::NoSharedRollbackCandidate
            | Self::StatusUnavailable { .. } => None,
        }
    }
}

pub trait FleetNodeBackend {
    fn fetch_status(&self, node_id: &str) -> Result<FleetNodeRuntimeStatus, FleetNodeBackendError>;

    fn rollout_node(
        &mut self,
        node_id: &str,
        request: RolloutRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<RolloutResponse, FleetNodeBackendError>;

    fn rollback_node(
        &mut self,
        node_id: &str,
        request: RollbackRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<RolloutResponse, FleetNodeBackendError>;
}

#[derive(Debug, Default)]
pub struct FleetRolloutCoordinator {
    history: Vec<FleetRolloutHistoryEntry>,
    metrics: FleetRolloutMetrics,
}

impl FleetRolloutCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rollout_at<B>(
        &mut self,
        control: &SnapshotControlService,
        backend: &mut B,
        request: FleetRolloutRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<FleetRolloutResponse, FleetRolloutError>
    where
        B: FleetNodeBackend,
    {
        validate_fleet_request(
            &request.node_ids,
            request.strategy,
            request.max_allowed_divergence_ms,
        )?;
        validate_rollout_request(&request.version, &request.requested_by, &request.reason)
            .map_err(FleetRolloutError::InvalidRolloutRequest)?;

        let published = control
            .get_version(&request.version)
            .map_err(|_| FleetRolloutError::UnknownPublishedVersion(request.version.clone()))?;

        self.execute_action(
            backend,
            RolloutActionKind::Rollout,
            &request.node_ids,
            request.strategy,
            request.max_allowed_divergence_ms,
            request.requested_by,
            request.reason,
            published.version.clone(),
            published.digest_sha256.clone(),
            move |backend, node_id, actor, reason, occurred_at_unix_ms| {
                backend.rollout_node(
                    node_id,
                    RolloutRequest {
                        version: published.version.clone(),
                        requested_by: actor,
                        reason,
                    },
                    occurred_at_unix_ms,
                )
            },
            occurred_at_unix_ms,
        )
    }

    pub fn rollback_at<B>(
        &mut self,
        control: &SnapshotControlService,
        backend: &mut B,
        request: FleetRollbackRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<FleetRolloutResponse, FleetRolloutError>
    where
        B: FleetNodeBackend,
    {
        validate_fleet_request(
            &request.node_ids,
            FleetRolloutStrategy::Sequential,
            request.max_allowed_divergence_ms,
        )?;
        if let Some(version) = &request.target_version {
            validate_rollout_request(version, &request.requested_by, &request.reason)
                .map_err(FleetRolloutError::InvalidRolloutRequest)?;
        }

        let target_version = match request.target_version.clone() {
            Some(version) => version,
            None => self.shared_rollback_candidate(backend, &request.node_ids)?,
        };

        let published = control
            .get_version(&target_version)
            .map_err(|_| FleetRolloutError::UnknownPublishedVersion(target_version.clone()))?;

        self.execute_action(
            backend,
            RolloutActionKind::Rollback,
            &request.node_ids,
            FleetRolloutStrategy::Sequential,
            request.max_allowed_divergence_ms,
            request.requested_by,
            request.reason,
            published.version.clone(),
            published.digest_sha256.clone(),
            move |backend, node_id, actor, reason, occurred_at_unix_ms| {
                backend.rollback_node(
                    node_id,
                    RollbackRequest {
                        target_version: Some(published.version.clone()),
                        requested_by: actor,
                        reason,
                    },
                    occurred_at_unix_ms,
                )
            },
            occurred_at_unix_ms,
        )
    }

    #[must_use]
    pub fn history(&self) -> &[FleetRolloutHistoryEntry] {
        &self.history
    }

    #[must_use]
    pub const fn metrics(&self) -> FleetRolloutMetrics {
        self.metrics
    }

    fn shared_rollback_candidate<B>(
        &self,
        backend: &B,
        node_ids: &[String],
    ) -> Result<String, FleetRolloutError>
    where
        B: FleetNodeBackend,
    {
        let mut candidate: Option<String> = None;
        for node_id in node_ids {
            let status = backend.fetch_status(node_id).map_err(|error| {
                FleetRolloutError::StatusUnavailable {
                    node_id: node_id.clone(),
                    detail: error.to_string(),
                }
            })?;
            let Some(last_known_good) = status.last_known_good_version else {
                return Err(FleetRolloutError::NoSharedRollbackCandidate);
            };
            if let Some(existing) = &candidate {
                if existing != &last_known_good {
                    return Err(FleetRolloutError::NoSharedRollbackCandidate);
                }
            } else {
                candidate = Some(last_known_good);
            }
        }
        candidate.ok_or(FleetRolloutError::NoSharedRollbackCandidate)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_action<B, F>(
        &mut self,
        backend: &mut B,
        action: RolloutActionKind,
        node_ids: &[String],
        strategy: FleetRolloutStrategy,
        max_allowed_divergence_ms: u64,
        requested_by: Option<String>,
        reason: Option<String>,
        desired_version: String,
        desired_digest_sha256: String,
        mut operation: F,
        occurred_at_unix_ms: u64,
    ) -> Result<FleetRolloutResponse, FleetRolloutError>
    where
        B: FleetNodeBackend,
        F: FnMut(
            &mut B,
            &str,
            Option<String>,
            Option<String>,
            u64,
        ) -> Result<RolloutResponse, FleetNodeBackendError>,
    {
        let mut node_outcomes = Vec::with_capacity(node_ids.len());
        let mut halted = false;
        let canary_nodes = match strategy {
            FleetRolloutStrategy::Canary { canary_nodes } => canary_nodes,
            _ => 0,
        };

        for (index, node_id) in node_ids.iter().enumerate() {
            if halted {
                node_outcomes.push(FleetNodeActionOutcome {
                    node_id: node_id.clone(),
                    result: FleetNodeActionResult::Skipped,
                    active_version: None,
                    active_digest_sha256: None,
                    last_known_good_version: None,
                    detail: String::from("rollout halted before this node was updated"),
                });
                continue;
            }

            match operation(
                backend,
                node_id,
                requested_by.clone(),
                reason.clone(),
                occurred_at_unix_ms,
            ) {
                Ok(response) => {
                    node_outcomes.push(FleetNodeActionOutcome {
                        node_id: node_id.clone(),
                        result: match response.result {
                            crate::RolloutResultKind::Applied => FleetNodeActionResult::Applied,
                            crate::RolloutResultKind::Unchanged => FleetNodeActionResult::Unchanged,
                            crate::RolloutResultKind::Rejected => FleetNodeActionResult::Failed,
                        },
                        active_version: Some(response.active_version),
                        active_digest_sha256: Some(response.active_digest_sha256),
                        last_known_good_version: Some(response.last_known_good_version),
                        detail: match action {
                            RolloutActionKind::Rollout => {
                                String::from("node accepted fleet rollout request")
                            }
                            RolloutActionKind::Rollback => {
                                String::from("node accepted fleet rollback request")
                            }
                        },
                    });
                }
                Err(error) => {
                    node_outcomes.push(FleetNodeActionOutcome {
                        node_id: node_id.clone(),
                        result: FleetNodeActionResult::Failed,
                        active_version: None,
                        active_digest_sha256: None,
                        last_known_good_version: None,
                        detail: error.to_string(),
                    });
                    halted = matches!(strategy, FleetRolloutStrategy::Sequential)
                        || matches!(strategy, FleetRolloutStrategy::Canary { .. }
                            if index + 1 <= canary_nodes);
                }
            }
        }

        let convergence = build_convergence_report(
            backend,
            node_ids,
            &node_outcomes,
            desired_version.clone(),
            desired_digest_sha256.clone(),
            occurred_at_unix_ms,
            max_allowed_divergence_ms,
        );
        let shared_last_known_good_version = shared_last_known_good_version(&convergence.nodes);

        self.push_history(FleetRolloutHistoryEntry {
            action,
            strategy,
            target_version: desired_version.clone(),
            desired_digest_sha256: desired_digest_sha256.clone(),
            convergence_state: convergence.state,
            converged_nodes: convergence.converged_nodes,
            pending_nodes: convergence.pending_nodes,
            diverged_nodes: convergence.diverged_nodes,
            unavailable_nodes: convergence.unavailable_nodes,
            occurred_at_unix_ms,
            detail: match convergence.state {
                FleetConvergenceState::Converged => {
                    String::from("fleet converged on desired snapshot")
                }
                FleetConvergenceState::Progressing => {
                    String::from("fleet rollout is within bounded eventual convergence window")
                }
                FleetConvergenceState::Diverged => {
                    String::from("fleet exceeded the configured convergence budget")
                }
                FleetConvergenceState::Degraded => {
                    String::from("fleet rollout completed with partial node failures")
                }
            },
        });

        match action {
            RolloutActionKind::Rollout => {
                self.metrics.rollout_count = self.metrics.rollout_count.saturating_add(1)
            }
            RolloutActionKind::Rollback => {
                self.metrics.rollback_count = self.metrics.rollback_count.saturating_add(1)
            }
        }
        match convergence.state {
            FleetConvergenceState::Converged => {
                self.metrics.converged_fleet_count =
                    self.metrics.converged_fleet_count.saturating_add(1);
            }
            FleetConvergenceState::Diverged => {
                self.metrics.divergence_count = self.metrics.divergence_count.saturating_add(1);
            }
            FleetConvergenceState::Degraded => {
                self.metrics.degraded_count = self.metrics.degraded_count.saturating_add(1);
                self.metrics.partial_failure_count =
                    self.metrics.partial_failure_count.saturating_add(1);
            }
            FleetConvergenceState::Progressing => {}
        }

        Ok(FleetRolloutResponse {
            action,
            strategy,
            desired_version,
            desired_digest_sha256,
            shared_last_known_good_version,
            convergence,
            node_outcomes,
        })
    }

    fn push_history(&mut self, entry: FleetRolloutHistoryEntry) {
        self.history.push(entry);
        self.metrics.audit_event_count = self.metrics.audit_event_count.saturating_add(1);
        self.metrics.history_size = self.history.len();
    }
}

fn build_convergence_report<B>(
    backend: &B,
    node_ids: &[String],
    node_outcomes: &[FleetNodeActionOutcome],
    desired_version: String,
    desired_digest_sha256: String,
    rollout_started_at_unix_ms: u64,
    max_allowed_divergence_ms: u64,
) -> FleetConvergenceReport
where
    B: FleetNodeBackend,
{
    let mut nodes = Vec::with_capacity(node_ids.len());
    let mut converged_nodes = 0;
    let mut pending_nodes = 0;
    let mut diverged_nodes = 0;
    let mut unavailable_nodes = 0;
    let deadline = rollout_started_at_unix_ms.saturating_add(max_allowed_divergence_ms);
    let exceeded_divergence_budget = rollout_started_at_unix_ms >= deadline;

    for node_id in node_ids {
        let outcome = node_outcomes.iter().find(|entry| entry.node_id == *node_id);
        match backend.fetch_status(node_id) {
            Ok(status) => {
                let (convergence_state, detail) = if status.active_version.as_deref()
                    == Some(desired_version.as_str())
                    && status.active_digest_sha256.as_deref()
                        == Some(desired_digest_sha256.as_str())
                {
                    converged_nodes += 1;
                    (FleetNodeConvergenceState::Converged, None)
                } else if status.observed_at_unix_ms <= deadline {
                    pending_nodes += 1;
                    (
                        FleetNodeConvergenceState::Pending,
                        outcome.map(|entry| entry.detail.clone()),
                    )
                } else {
                    diverged_nodes += 1;
                    (
                        FleetNodeConvergenceState::Diverged,
                        outcome.map(|entry| entry.detail.clone()).or_else(|| {
                            Some(String::from(
                                "node did not apply the desired snapshot within the convergence budget",
                            ))
                        }),
                    )
                };
                nodes.push(FleetNodeStatus {
                    node_id: status.node_id,
                    desired_version: status.desired_version,
                    desired_digest_sha256: status.desired_digest_sha256,
                    active_version: status.active_version,
                    active_digest_sha256: status.active_digest_sha256,
                    last_known_good_version: status.last_known_good_version,
                    readiness: status.readiness,
                    observed_at_unix_ms: status.observed_at_unix_ms,
                    convergence_state,
                    detail,
                });
            }
            Err(error) => {
                unavailable_nodes += 1;
                nodes.push(FleetNodeStatus {
                    node_id: node_id.clone(),
                    desired_version: None,
                    desired_digest_sha256: None,
                    active_version: None,
                    active_digest_sha256: None,
                    last_known_good_version: None,
                    readiness: None,
                    observed_at_unix_ms: rollout_started_at_unix_ms,
                    convergence_state: FleetNodeConvergenceState::Unavailable,
                    detail: Some(error.to_string()),
                });
            }
        }
    }

    let partial_rollout = converged_nodes > 0 && converged_nodes < node_ids.len();
    let action_failure = node_outcomes
        .iter()
        .any(|outcome| matches!(outcome.result, FleetNodeActionResult::Failed));
    let state = if converged_nodes == node_ids.len() {
        FleetConvergenceState::Converged
    } else if unavailable_nodes > 0 || action_failure {
        FleetConvergenceState::Degraded
    } else if diverged_nodes > 0 {
        FleetConvergenceState::Diverged
    } else {
        FleetConvergenceState::Progressing
    };
    let recommended_action = match state {
        FleetConvergenceState::Converged => FleetRecommendedAction::ObserveOnly,
        FleetConvergenceState::Progressing => FleetRecommendedAction::WaitForConvergence,
        FleetConvergenceState::Diverged => FleetRecommendedAction::RollbackFleet,
        FleetConvergenceState::Degraded => {
            if unavailable_nodes > 0 {
                FleetRecommendedAction::InvestigatePartition
            } else {
                FleetRecommendedAction::RetryFailedNodes
            }
        }
    };

    FleetConvergenceReport {
        desired_version,
        desired_digest_sha256,
        consistency_mode: FleetConsistencyMode::BoundedEventual,
        state,
        recommended_action,
        rollout_started_at_unix_ms,
        divergence_deadline_unix_ms: deadline,
        exceeded_divergence_budget: exceeded_divergence_budget
            && !matches!(state, FleetConvergenceState::Converged),
        converged_nodes,
        pending_nodes,
        diverged_nodes,
        unavailable_nodes,
        partial_rollout,
        nodes,
    }
}

fn shared_last_known_good_version(nodes: &[FleetNodeStatus]) -> Option<String> {
    let mut shared: Option<&str> = None;
    for node in nodes {
        let candidate = node.last_known_good_version.as_deref()?;
        if let Some(existing) = shared {
            if existing != candidate {
                return None;
            }
        } else {
            shared = Some(candidate);
        }
    }
    shared.map(String::from)
}

fn validate_fleet_request(
    node_ids: &[String],
    strategy: FleetRolloutStrategy,
    max_allowed_divergence_ms: u64,
) -> Result<(), FleetRolloutError> {
    if node_ids.is_empty() {
        return Err(FleetRolloutError::InvalidFleetRequest(
            InvalidFleetRequest::EmptyNodeIds,
        ));
    }
    if node_ids.len() > MAX_FLEET_NODES {
        return Err(FleetRolloutError::InvalidFleetRequest(
            InvalidFleetRequest::TooManyNodes,
        ));
    }
    if max_allowed_divergence_ms == 0 {
        return Err(FleetRolloutError::InvalidFleetRequest(
            InvalidFleetRequest::ZeroMaxAllowedDivergenceMs,
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for node_id in node_ids {
        let node_id = node_id.trim();
        if node_id.is_empty() {
            return Err(FleetRolloutError::InvalidFleetRequest(
                InvalidFleetRequest::EmptyNodeId,
            ));
        }
        if node_id.len() > MAX_NODE_ID_LEN {
            return Err(FleetRolloutError::InvalidFleetRequest(
                InvalidFleetRequest::NodeIdTooLong,
            ));
        }
        if !seen.insert(node_id.to_string()) {
            return Err(FleetRolloutError::InvalidFleetRequest(
                InvalidFleetRequest::DuplicateNodeId(node_id.to_string()),
            ));
        }
    }
    if matches!(strategy, FleetRolloutStrategy::Canary { canary_nodes: 0 }) {
        return Err(FleetRolloutError::InvalidFleetRequest(
            InvalidFleetRequest::ZeroCanaryNodes,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use lb_config_model::WorkspaceConfig;
    use lb_test_support::{configure_test_trusted_signers, test_artifact_attestation};

    use super::{
        FleetConvergenceState, FleetNodeBackend, FleetNodeBackendError, FleetNodeRuntimeStatus,
        FleetRecommendedAction, FleetRollbackRequest, FleetRolloutCoordinator,
        FleetRolloutError, FleetRolloutRequest, FleetRolloutStrategy,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ApplyMode {
        Immediate,
        Pending,
    }

    #[derive(Debug, Clone)]
    struct MockNode {
        status: FleetNodeRuntimeStatus,
        apply_mode: ApplyMode,
        fail_rollout: bool,
        fail_rollback: bool,
    }

    #[derive(Debug, Default)]
    struct MockBackend {
        nodes: BTreeMap<String, MockNode>,
        known_digests: BTreeMap<String, String>,
    }

    impl MockBackend {
        fn with_node(
            mut self,
            node_id: &str,
            active_version: Option<&str>,
            active_digest_sha256: Option<&str>,
            apply_mode: ApplyMode,
        ) -> Self {
            self.nodes.insert(
                String::from(node_id),
                MockNode {
                    status: FleetNodeRuntimeStatus {
                        node_id: String::from(node_id),
                        desired_version: active_version.map(String::from),
                        desired_digest_sha256: active_digest_sha256.map(String::from),
                        active_version: active_version.map(String::from),
                        active_digest_sha256: active_digest_sha256.map(String::from),
                        last_known_good_version: active_version.map(String::from),
                        readiness: Some(String::from("ready")),
                        observed_at_unix_ms: 10,
                    },
                    apply_mode,
                    fail_rollout: false,
                    fail_rollback: false,
                },
            );
            self
        }

        fn with_known_digest(mut self, version: &str, digest_sha256: &str) -> Self {
            self.known_digests.insert(String::from(version), String::from(digest_sha256));
            self
        }

        fn with_rollout_failure(mut self, node_id: &str) -> Self {
            self.nodes.get_mut(node_id).unwrap().fail_rollout = true;
            self
        }

        fn with_rollback_failure(mut self, node_id: &str) -> Self {
            self.nodes.get_mut(node_id).unwrap().fail_rollback = true;
            self
        }
    }

    impl FleetNodeBackend for MockBackend {
        fn fetch_status(&self, node_id: &str) -> Result<FleetNodeRuntimeStatus, FleetNodeBackendError> {
            self.nodes
                .get(node_id)
                .cloned()
                .map(|node| node.status)
                .ok_or_else(|| FleetNodeBackendError::Unreachable(String::from("missing node")))
        }

        fn rollout_node(
            &mut self,
            node_id: &str,
            request: crate::RolloutRequest,
            occurred_at_unix_ms: u64,
        ) -> Result<crate::RolloutResponse, FleetNodeBackendError> {
            let node = self
                .nodes
                .get_mut(node_id)
                .ok_or_else(|| FleetNodeBackendError::Unreachable(String::from("missing node")))?;
            if node.fail_rollout {
                return Err(FleetNodeBackendError::Rejected(String::from(
                    "simulated rollout failure",
                )));
            }
            let digest = self
                .known_digests
                .get(&request.version)
                .cloned()
                .unwrap_or_else(|| digest_for_version(&request.version));
            node.status.desired_version = Some(request.version.clone());
            node.status.desired_digest_sha256 = Some(digest.clone());
            node.status.observed_at_unix_ms = occurred_at_unix_ms;
            if node.apply_mode == ApplyMode::Immediate {
                node.status.active_version = Some(request.version.clone());
                node.status.active_digest_sha256 = Some(digest.clone());
                node.status.last_known_good_version = Some(request.version.clone());
            }
            Ok(crate::RolloutResponse {
                action: crate::RolloutActionKind::Rollout,
                result: crate::RolloutResultKind::Applied,
                active_version: node.status.active_version.clone().unwrap_or_else(|| request.version.clone()),
                active_digest_sha256: node
                    .status
                    .active_digest_sha256
                    .clone()
                    .unwrap_or_else(|| digest.clone()),
                last_known_good_version: node
                    .status
                    .last_known_good_version
                    .clone()
                    .unwrap_or_else(|| String::from("baseline-1")),
            })
        }

        fn rollback_node(
            &mut self,
            node_id: &str,
            request: crate::RollbackRequest,
            occurred_at_unix_ms: u64,
        ) -> Result<crate::RolloutResponse, FleetNodeBackendError> {
            let node = self
                .nodes
                .get_mut(node_id)
                .ok_or_else(|| FleetNodeBackendError::Unreachable(String::from("missing node")))?;
            if node.fail_rollback {
                return Err(FleetNodeBackendError::Rejected(String::from(
                    "simulated rollback failure",
                )));
            }
            let version = request.target_version.unwrap();
            let digest = self
                .known_digests
                .get(&version)
                .cloned()
                .unwrap_or_else(|| digest_for_version(&version));
            node.status.desired_version = Some(version.clone());
            node.status.desired_digest_sha256 = Some(digest.clone());
            node.status.active_version = Some(version.clone());
            node.status.active_digest_sha256 = Some(digest.clone());
            node.status.last_known_good_version = Some(version.clone());
            node.status.observed_at_unix_ms = occurred_at_unix_ms;
            Ok(crate::RolloutResponse {
                action: crate::RolloutActionKind::Rollback,
                result: crate::RolloutResultKind::Applied,
                active_version: version.clone(),
                active_digest_sha256: digest,
                last_known_good_version: version,
            })
        }
    }

    fn publish_snapshot(
        control: &mut crate::SnapshotControlService,
        version: &str,
        workspace_name: &str,
        published_at_unix_ms: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.name = String::from(workspace_name);
        configure_test_trusted_signers(&mut config)?;
        let snapshot = config.compile_snapshot()?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let _ = control.publish_at(
            crate::SnapshotPublishRequest {
                version: String::from(version),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: Some(digest),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("test publish")),
            },
            published_at_unix_ms,
        )?;
        Ok(())
    }

    fn digest_for_version(version: &str) -> String {
        format!("{version:0<64}").chars().take(64).collect()
    }

    #[test]
    fn immediate_rollout_converges_all_nodes() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-2", "stable", 10)?;
        let stable_digest = control.get_version("stable-2")?.digest_sha256.clone();
        let mut backend = MockBackend::default()
            .with_known_digest("stable-2", &stable_digest)
            .with_node("node-a", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate)
            .with_node("node-b", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate);
        let mut coordinator = FleetRolloutCoordinator::new();

        let response = coordinator.rollout_at(
            &control,
            &mut backend,
            FleetRolloutRequest {
                version: String::from("stable-2"),
                requested_by: Some(String::from("operator")),
                reason: Some(String::from("fleet deploy")),
                node_ids: vec![String::from("node-a"), String::from("node-b")],
                strategy: FleetRolloutStrategy::Immediate,
                max_allowed_divergence_ms: 1_000,
            },
            100,
        )?;

        assert_eq!(response.convergence.state, FleetConvergenceState::Converged);
        assert_eq!(response.convergence.converged_nodes, 2);
        assert_eq!(response.convergence.recommended_action, FleetRecommendedAction::ObserveOnly);
        assert_eq!(coordinator.metrics().converged_fleet_count, 1);
        Ok(())
    }

    #[test]
    fn sequential_rollout_stops_after_failure_and_surfaces_partial_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-2", "stable", 10)?;
        let stable_digest = control.get_version("stable-2")?.digest_sha256.clone();
        let mut backend = MockBackend::default()
            .with_known_digest("stable-2", &stable_digest)
            .with_node("node-a", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate)
            .with_node("node-b", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate)
            .with_node("node-c", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate)
            .with_rollout_failure("node-b");
        let mut coordinator = FleetRolloutCoordinator::new();

        let response = coordinator.rollout_at(
            &control,
            &mut backend,
            FleetRolloutRequest {
                version: String::from("stable-2"),
                requested_by: Some(String::from("operator")),
                reason: Some(String::from("fleet deploy")),
                node_ids: vec![
                    String::from("node-a"),
                    String::from("node-b"),
                    String::from("node-c"),
                ],
                strategy: FleetRolloutStrategy::Sequential,
                max_allowed_divergence_ms: 1_000,
            },
            100,
        )?;

        assert_eq!(response.convergence.state, FleetConvergenceState::Degraded);
        assert!(response.convergence.partial_rollout);
        assert_eq!(response.node_outcomes[2].result, super::FleetNodeActionResult::Skipped);
        assert_eq!(coordinator.metrics().partial_failure_count, 1);
        Ok(())
    }

    #[test]
    fn canary_failure_gates_remaining_nodes() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-2", "stable", 10)?;
        let stable_digest = control.get_version("stable-2")?.digest_sha256.clone();
        let mut backend = MockBackend::default()
            .with_known_digest("stable-2", &stable_digest)
            .with_node("node-a", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate)
            .with_node("node-b", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate)
            .with_node("node-c", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Immediate)
            .with_rollout_failure("node-a");
        let mut coordinator = FleetRolloutCoordinator::new();

        let response = coordinator.rollout_at(
            &control,
            &mut backend,
            FleetRolloutRequest {
                version: String::from("stable-2"),
                requested_by: Some(String::from("operator")),
                reason: Some(String::from("fleet deploy")),
                node_ids: vec![
                    String::from("node-a"),
                    String::from("node-b"),
                    String::from("node-c"),
                ],
                strategy: FleetRolloutStrategy::Canary { canary_nodes: 1 },
                max_allowed_divergence_ms: 1_000,
            },
            100,
        )?;

        assert_eq!(response.convergence.state, FleetConvergenceState::Degraded);
        assert_eq!(response.node_outcomes[1].result, super::FleetNodeActionResult::Skipped);
        assert_eq!(response.node_outcomes[2].result, super::FleetNodeActionResult::Skipped);
        Ok(())
    }

    #[test]
    fn pending_nodes_within_budget_report_progressing() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-2", "stable", 10)?;
        let stable_digest = control.get_version("stable-2")?.digest_sha256.clone();
        let mut backend = MockBackend::default()
            .with_known_digest("stable-2", &stable_digest)
            .with_node("node-a", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Pending)
            .with_node("node-b", Some("baseline-1"), Some(&digest_for_version("baseline-1")), ApplyMode::Pending);
        let mut coordinator = FleetRolloutCoordinator::new();

        let response = coordinator.rollout_at(
            &control,
            &mut backend,
            FleetRolloutRequest {
                version: String::from("stable-2"),
                requested_by: Some(String::from("operator")),
                reason: Some(String::from("fleet deploy")),
                node_ids: vec![String::from("node-a"), String::from("node-b")],
                strategy: FleetRolloutStrategy::Immediate,
                max_allowed_divergence_ms: 1_000,
            },
            100,
        )?;

        assert_eq!(response.convergence.state, FleetConvergenceState::Progressing);
        assert_eq!(response.convergence.recommended_action, FleetRecommendedAction::WaitForConvergence);
        Ok(())
    }

    #[test]
    fn rollback_requires_shared_known_good_when_target_missing() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-1", "stable", 10)?;
        let mut backend = MockBackend::default()
            .with_node("node-a", Some("canary-2"), Some(&digest_for_version("canary-2")), ApplyMode::Immediate)
            .with_node("node-b", Some("canary-2"), Some(&digest_for_version("canary-2")), ApplyMode::Immediate);
        backend.nodes.get_mut("node-a").unwrap().status.last_known_good_version = Some(String::from("stable-1"));
        backend.nodes.get_mut("node-b").unwrap().status.last_known_good_version = Some(String::from("older-0"));
        let mut coordinator = FleetRolloutCoordinator::new();

        let error = coordinator.rollback_at(
            &control,
            &mut backend,
            FleetRollbackRequest {
                target_version: None,
                requested_by: Some(String::from("operator")),
                reason: Some(String::from("rollback")),
                node_ids: vec![String::from("node-a"), String::from("node-b")],
                max_allowed_divergence_ms: 1_000,
            },
            100,
        )
        .expect_err("rollback should reject without shared candidate");

        assert!(matches!(error, FleetRolloutError::NoSharedRollbackCandidate));
        Ok(())
    }

    #[test]
    fn rollback_surfaces_partial_failure_when_one_node_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-1", "stable", 10)?;
        let stable_digest = control.get_version("stable-1")?.digest_sha256.clone();
        let mut backend = MockBackend::default()
            .with_known_digest("stable-1", &stable_digest)
            .with_node(
                "node-a",
                Some("canary-2"),
                Some(&digest_for_version("canary-2")),
                ApplyMode::Immediate,
            )
            .with_node(
                "node-b",
                Some("canary-2"),
                Some(&digest_for_version("canary-2")),
                ApplyMode::Immediate,
            )
            .with_rollback_failure("node-b");
        backend.nodes.get_mut("node-a").unwrap().status.last_known_good_version =
            Some(String::from("stable-1"));
        backend.nodes.get_mut("node-b").unwrap().status.last_known_good_version =
            Some(String::from("stable-1"));
        let mut coordinator = FleetRolloutCoordinator::new();

        let response = coordinator.rollback_at(
            &control,
            &mut backend,
            FleetRollbackRequest {
                target_version: None,
                requested_by: Some(String::from("operator")),
                reason: Some(String::from("fleet rollback")),
                node_ids: vec![String::from("node-a"), String::from("node-b")],
                max_allowed_divergence_ms: 1_000,
            },
            100,
        )?;

        assert_eq!(response.action, crate::RolloutActionKind::Rollback);
        assert_eq!(response.convergence.state, FleetConvergenceState::Degraded);
        assert!(response.convergence.partial_rollout);
        assert_eq!(response.node_outcomes[1].result, super::FleetNodeActionResult::Failed);
        Ok(())
    }
}