use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::FleetRolloutRequest;

const MAX_WAVE_ID_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetHealthGateMode {
    Required,
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHealthGatePolicy {
    pub mode: FleetHealthGateMode,
    pub min_ready_percent: u8,
    pub max_error_percent: u8,
    pub evaluation_window_ms: u64,
    pub timeout_ms: u64,
}

impl Default for FleetHealthGatePolicy {
    fn default() -> Self {
        Self {
            mode: FleetHealthGateMode::Required,
            min_ready_percent: 95,
            max_error_percent: 5,
            evaluation_window_ms: 30_000,
            timeout_ms: 120_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRolloutWaveDefinition {
    pub wave_id: String,
    pub node_ids: Vec<String>,
    pub max_parallel: usize,
    pub gate_policy: FleetHealthGatePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetStagedRolloutRequest {
    pub rollout: FleetRolloutRequest,
    pub waves: Vec<FleetRolloutWaveDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetStagedRolloutPlan {
    pub rollout: FleetRolloutRequest,
    pub waves: Vec<FleetRolloutWaveDefinition>,
    pub node_to_wave: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidFleetStagedRolloutRequest {
    EmptyWaves,
    EmptyWaveId,
    WaveIdTooLong,
    DuplicateWaveId(String),
    EmptyWaveNodes(String),
    ZeroMaxParallel(String),
    MaxParallelExceedsWaveSize(String),
    DuplicateNodeAcrossWaves(String),
    UnassignedNode(String),
    UnknownNodeInWave(String),
    ZeroGateEvaluationWindow(String),
    ZeroGateTimeout(String),
    InvalidGateReadyPercent(String),
    InvalidGateErrorPercent(String),
}

impl std::fmt::Display for InvalidFleetStagedRolloutRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyWaves => write!(formatter, "staged rollout must declare at least one wave"),
            Self::EmptyWaveId => write!(formatter, "wave_id must not be empty"),
            Self::WaveIdTooLong => write!(formatter, "wave_id exceeds max length"),
            Self::DuplicateWaveId(wave_id) => {
                write!(formatter, "duplicate wave_id '{wave_id}'")
            }
            Self::EmptyWaveNodes(wave_id) => {
                write!(formatter, "wave '{wave_id}' must include at least one node")
            }
            Self::ZeroMaxParallel(wave_id) => {
                write!(formatter, "wave '{wave_id}' max_parallel must be greater than zero")
            }
            Self::MaxParallelExceedsWaveSize(wave_id) => write!(
                formatter,
                "wave '{wave_id}' max_parallel exceeds number of nodes in the wave"
            ),
            Self::DuplicateNodeAcrossWaves(node_id) => {
                write!(formatter, "node '{node_id}' appears in more than one wave")
            }
            Self::UnassignedNode(node_id) => {
                write!(formatter, "requested node '{node_id}' is not assigned to any wave")
            }
            Self::UnknownNodeInWave(node_id) => {
                write!(formatter, "wave references unknown node '{node_id}'")
            }
            Self::ZeroGateEvaluationWindow(wave_id) => write!(
                formatter,
                "wave '{wave_id}' gate policy evaluation_window_ms must be greater than zero"
            ),
            Self::ZeroGateTimeout(wave_id) => write!(
                formatter,
                "wave '{wave_id}' gate policy timeout_ms must be greater than zero"
            ),
            Self::InvalidGateReadyPercent(wave_id) => write!(
                formatter,
                "wave '{wave_id}' gate policy min_ready_percent must be in 1..=100"
            ),
            Self::InvalidGateErrorPercent(wave_id) => write!(
                formatter,
                "wave '{wave_id}' gate policy max_error_percent must be in 0..=100"
            ),
        }
    }
}

impl std::error::Error for InvalidFleetStagedRolloutRequest {}

pub fn plan_staged_rollout(
    request: FleetStagedRolloutRequest,
) -> Result<FleetStagedRolloutPlan, InvalidFleetStagedRolloutRequest> {
    if request.waves.is_empty() {
        return Err(InvalidFleetStagedRolloutRequest::EmptyWaves);
    }

    let expected_nodes = request
        .rollout
        .node_ids
        .iter()
        .map(|node_id| node_id.trim().to_string())
        .collect::<BTreeSet<_>>();

    let mut wave_ids = BTreeSet::new();
    let mut assigned_nodes = BTreeSet::new();
    let mut node_to_wave = BTreeMap::new();

    for wave in &request.waves {
        let wave_id = wave.wave_id.trim();
        if wave_id.is_empty() {
            return Err(InvalidFleetStagedRolloutRequest::EmptyWaveId);
        }
        if wave_id.len() > MAX_WAVE_ID_LEN {
            return Err(InvalidFleetStagedRolloutRequest::WaveIdTooLong);
        }
        if !wave_ids.insert(wave_id.to_string()) {
            return Err(InvalidFleetStagedRolloutRequest::DuplicateWaveId(
                wave_id.to_string(),
            ));
        }
        if wave.node_ids.is_empty() {
            return Err(InvalidFleetStagedRolloutRequest::EmptyWaveNodes(
                wave_id.to_string(),
            ));
        }
        if wave.max_parallel == 0 {
            return Err(InvalidFleetStagedRolloutRequest::ZeroMaxParallel(
                wave_id.to_string(),
            ));
        }
        if wave.max_parallel > wave.node_ids.len() {
            return Err(InvalidFleetStagedRolloutRequest::MaxParallelExceedsWaveSize(
                wave_id.to_string(),
            ));
        }
        if wave.gate_policy.evaluation_window_ms == 0 {
            return Err(InvalidFleetStagedRolloutRequest::ZeroGateEvaluationWindow(
                wave_id.to_string(),
            ));
        }
        if wave.gate_policy.timeout_ms == 0 {
            return Err(InvalidFleetStagedRolloutRequest::ZeroGateTimeout(
                wave_id.to_string(),
            ));
        }
        if wave.gate_policy.min_ready_percent == 0 || wave.gate_policy.min_ready_percent > 100 {
            return Err(InvalidFleetStagedRolloutRequest::InvalidGateReadyPercent(
                wave_id.to_string(),
            ));
        }
        if wave.gate_policy.max_error_percent > 100 {
            return Err(InvalidFleetStagedRolloutRequest::InvalidGateErrorPercent(
                wave_id.to_string(),
            ));
        }

        for node_id in &wave.node_ids {
            let node_id = node_id.trim();
            if !expected_nodes.contains(node_id) {
                return Err(InvalidFleetStagedRolloutRequest::UnknownNodeInWave(
                    node_id.to_string(),
                ));
            }
            if !assigned_nodes.insert(node_id.to_string()) {
                return Err(InvalidFleetStagedRolloutRequest::DuplicateNodeAcrossWaves(
                    node_id.to_string(),
                ));
            }
            node_to_wave.insert(node_id.to_string(), wave_id.to_string());
        }
    }

    for node_id in &expected_nodes {
        if !assigned_nodes.contains(node_id) {
            return Err(InvalidFleetStagedRolloutRequest::UnassignedNode(
                node_id.to_string(),
            ));
        }
    }

    Ok(FleetStagedRolloutPlan {
        rollout: request.rollout,
        waves: request.waves,
        node_to_wave,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        plan_staged_rollout, FleetHealthGateMode, FleetHealthGatePolicy,
        FleetRolloutWaveDefinition, FleetStagedRolloutRequest,
    };

    fn wave(id: &str, nodes: &[&str]) -> FleetRolloutWaveDefinition {
        FleetRolloutWaveDefinition {
            wave_id: id.to_string(),
            node_ids: nodes.iter().map(|value| (*value).to_string()).collect(),
            max_parallel: 1,
            gate_policy: FleetHealthGatePolicy {
                mode: FleetHealthGateMode::Required,
                min_ready_percent: 95,
                max_error_percent: 5,
                evaluation_window_ms: 10_000,
                timeout_ms: 30_000,
            },
        }
    }

    fn request() -> FleetStagedRolloutRequest {
        FleetStagedRolloutRequest {
            rollout: crate::FleetRolloutRequest {
                version: String::from("v2"),
                requested_by: Some(String::from("ops")),
                reason: Some(String::from("canary")),
                node_ids: vec![
                    String::from("node-a"),
                    String::from("node-b"),
                    String::from("node-c"),
                ],
                strategy: crate::FleetRolloutStrategy::Sequential,
                max_allowed_divergence_ms: 60_000,
            },
            waves: vec![wave("wave-1", &["node-a"]), wave("wave-2", &["node-b", "node-c"])],
        }
    }

    #[test]
    fn staged_plan_accepts_valid_wave_layout() -> Result<(), Box<dyn std::error::Error>> {
        let plan = plan_staged_rollout(request())?;
        assert_eq!(plan.waves.len(), 2);
        assert_eq!(plan.node_to_wave.get("node-a"), Some(&String::from("wave-1")));
        assert_eq!(plan.node_to_wave.get("node-c"), Some(&String::from("wave-2")));
        Ok(())
    }

    #[test]
    fn staged_plan_rejects_duplicate_nodes_across_waves() {
        let mut request = request();
        request.waves[1].node_ids.push(String::from("node-a"));

        let error = plan_staged_rollout(request).expect_err("duplicate node must fail");
        assert!(error.to_string().contains("appears in more than one wave"));
    }

    #[test]
    fn staged_plan_rejects_missing_node_assignment() {
        let mut request = request();
        request.waves[1].node_ids.pop();

        let error = plan_staged_rollout(request).expect_err("missing assignment must fail");
        assert!(error.to_string().contains("is not assigned to any wave"));
    }

    #[test]
    fn staged_plan_rejects_zero_gate_timeout() {
        let mut request = request();
        request.waves[0].gate_policy.timeout_ms = 0;

        let error = plan_staged_rollout(request).expect_err("zero timeout must fail");
        assert!(error.to_string().contains("timeout_ms must be greater than zero"));
    }
}
