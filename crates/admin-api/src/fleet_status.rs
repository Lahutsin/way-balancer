use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    FleetAbortRollbackDecision, FleetAutoRollbackOutcome, FleetConvergenceReport,
    FleetConvergenceState, FleetNodeConvergenceState, FleetNodeHealthSignal,
    FleetRecommendedAction, FleetRolloutWaveDefinition, FleetStagedRolloutPlan,
    FleetWaveGateEvaluation, FleetWaveGateVerdict,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetWaveStatusState {
    Pending,
    InProgress,
    Passed,
    Failed,
    Aborted,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetStagedRolloutState {
    Progressing,
    Aborted,
    RolledBack,
    Converged,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetWaveStatusSurface {
    pub wave_id: String,
    pub node_count: usize,
    pub max_parallel: usize,
    pub state: FleetWaveStatusState,
    pub gate_verdict: Option<FleetWaveGateVerdict>,
    pub degraded: bool,
    pub timed_out: bool,
    pub evaluated_nodes: usize,
    pub failing_nodes: usize,
    pub missing_nodes: usize,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetNodeStatusSurface {
    pub node_id: String,
    pub wave_id: String,
    pub convergence_state: FleetNodeConvergenceState,
    pub readiness: Option<String>,
    pub active_version: Option<String>,
    pub active_digest_sha256: Option<String>,
    pub gate_signal: Option<FleetNodeHealthSignal>,
    pub gate_failed: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStagedStatusSurface {
    pub state: FleetStagedRolloutState,
    pub desired_version: String,
    pub desired_digest_sha256: String,
    pub recommended_action: FleetRecommendedAction,
    pub aborted: bool,
    pub rolled_back: bool,
    pub rollback_target_version: Option<String>,
    pub rollback_succeeded: Option<bool>,
    pub waves: Vec<FleetWaveStatusSurface>,
    pub nodes: Vec<FleetNodeStatusSurface>,
}

#[must_use]
pub fn render_staged_status_surface(
    plan: &FleetStagedRolloutPlan,
    convergence: &FleetConvergenceReport,
    wave_gates: &BTreeMap<String, FleetWaveGateEvaluation>,
    abort_decision: Option<&FleetAbortRollbackDecision>,
    auto_rollback: Option<&FleetAutoRollbackOutcome>,
) -> FleetStagedStatusSurface {
    let abort_wave_id = abort_decision
        .filter(|decision| decision.should_abort)
        .map(|decision| decision.wave_id.as_str());

    let mut waves = Vec::with_capacity(plan.waves.len());
    let mut blocked = false;
    for wave in &plan.waves {
        let surface = render_wave_surface(wave, wave_gates.get(&wave.wave_id), abort_wave_id, blocked);
        blocked = blocked || matches!(surface.state, FleetWaveStatusState::Failed | FleetWaveStatusState::Aborted);
        waves.push(surface);
    }

    let gate_signals = flatten_gate_signals(wave_gates);
    let gate_failures = gate_failure_nodes(wave_gates);
    let mut nodes = Vec::with_capacity(convergence.nodes.len());
    for node in &convergence.nodes {
        let wave_id = plan
            .node_to_wave
            .get(&node.node_id)
            .cloned()
            .unwrap_or_else(|| String::from("unassigned"));
        nodes.push(FleetNodeStatusSurface {
            node_id: node.node_id.clone(),
            wave_id,
            convergence_state: node.convergence_state,
            readiness: node.readiness.clone(),
            active_version: node.active_version.clone(),
            active_digest_sha256: node.active_digest_sha256.clone(),
            gate_signal: gate_signals.get(&node.node_id).cloned(),
            gate_failed: gate_failures.contains_key(&node.node_id),
            detail: node.detail.clone(),
        });
    }

    let aborted = abort_decision.is_some_and(|decision| decision.should_abort);
    let rolled_back = auto_rollback.is_some_and(|outcome| outcome.attempted);
    let state = if rolled_back {
        FleetStagedRolloutState::RolledBack
    } else if aborted {
        FleetStagedRolloutState::Aborted
    } else {
        match convergence.state {
            FleetConvergenceState::Converged => FleetStagedRolloutState::Converged,
            FleetConvergenceState::Degraded => FleetStagedRolloutState::Degraded,
            FleetConvergenceState::Progressing | FleetConvergenceState::Diverged => {
                FleetStagedRolloutState::Progressing
            }
        }
    };

    FleetStagedStatusSurface {
        state,
        desired_version: convergence.desired_version.clone(),
        desired_digest_sha256: convergence.desired_digest_sha256.clone(),
        recommended_action: convergence.recommended_action,
        aborted,
        rolled_back,
        rollback_target_version: auto_rollback.and_then(|outcome| outcome.target_version.clone()),
        rollback_succeeded: auto_rollback.map(|outcome| outcome.succeeded),
        waves,
        nodes,
    }
}

fn render_wave_surface(
    wave: &FleetRolloutWaveDefinition,
    gate: Option<&FleetWaveGateEvaluation>,
    abort_wave_id: Option<&str>,
    blocked: bool,
) -> FleetWaveStatusSurface {
    if blocked && gate.is_none() {
        return FleetWaveStatusSurface {
            wave_id: wave.wave_id.clone(),
            node_count: wave.node_ids.len(),
            max_parallel: wave.max_parallel,
            state: FleetWaveStatusState::Blocked,
            gate_verdict: None,
            degraded: false,
            timed_out: false,
            evaluated_nodes: 0,
            failing_nodes: 0,
            missing_nodes: 0,
            detail: String::from("wave blocked by failure in previous wave"),
        };
    }

    let (state, verdict, degraded, timed_out, evaluated_nodes, failing_nodes, missing_nodes, detail) =
        if abort_wave_id == Some(wave.wave_id.as_str()) {
            (
                FleetWaveStatusState::Aborted,
                gate.map(|entry| entry.verdict),
                gate.is_some_and(|entry| entry.degraded),
                gate.is_some_and(|entry| entry.timed_out),
                gate.map_or(0, |entry| entry.evaluated_nodes),
                gate.map_or(0, |entry| entry.failing_nodes),
                gate.map_or(0, |entry| entry.missing_nodes),
                String::from("wave aborted by rollout decision policy"),
            )
        } else if let Some(gate) = gate {
            (
                match gate.verdict {
                    FleetWaveGateVerdict::Passed => FleetWaveStatusState::Passed,
                    FleetWaveGateVerdict::Failed => FleetWaveStatusState::Failed,
                    FleetWaveGateVerdict::Pending => FleetWaveStatusState::InProgress,
                },
                Some(gate.verdict),
                gate.degraded,
                gate.timed_out,
                gate.evaluated_nodes,
                gate.failing_nodes,
                gate.missing_nodes,
                gate.detail.clone(),
            )
        } else {
            (
                FleetWaveStatusState::Pending,
                None,
                false,
                false,
                0,
                0,
                0,
                String::from("wave has not started gate evaluation yet"),
            )
        };

    FleetWaveStatusSurface {
        wave_id: wave.wave_id.clone(),
        node_count: wave.node_ids.len(),
        max_parallel: wave.max_parallel,
        state,
        gate_verdict: verdict,
        degraded,
        timed_out,
        evaluated_nodes,
        failing_nodes,
        missing_nodes,
        detail,
    }
}

fn flatten_gate_signals(
    wave_gates: &BTreeMap<String, FleetWaveGateEvaluation>,
) -> BTreeMap<String, FleetNodeHealthSignal> {
    let mut signals = BTreeMap::new();
    for gate in wave_gates.values() {
        for signal in &gate.signals {
            signals.insert(signal.node_id.clone(), signal.clone());
        }
    }
    signals
}

fn gate_failure_nodes(
    wave_gates: &BTreeMap<String, FleetWaveGateEvaluation>,
) -> BTreeMap<String, bool> {
    let mut failures = BTreeMap::new();
    for gate in wave_gates.values() {
        for signal in &gate.signals {
            if signal.ready_percent < 95 || signal.error_percent > 5 {
                failures.insert(signal.node_id.clone(), true);
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        fleet_staged::{FleetHealthGateMode, FleetHealthGatePolicy},
        FleetAbortReason, FleetNodeConvergenceState, FleetNodeStatus,
    };

    use super::{
        render_staged_status_surface, FleetStagedRolloutState, FleetWaveStatusState,
    };

    fn wave(id: &str, nodes: &[&str]) -> crate::FleetRolloutWaveDefinition {
        crate::FleetRolloutWaveDefinition {
            wave_id: id.to_string(),
            node_ids: nodes.iter().map(|entry| (*entry).to_string()).collect(),
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

    fn sample_plan() -> crate::FleetStagedRolloutPlan {
        crate::FleetStagedRolloutPlan {
            rollout: crate::FleetRolloutRequest {
                version: String::from("stable-2"),
                requested_by: Some(String::from("operator")),
                reason: Some(String::from("deploy")),
                node_ids: vec![
                    String::from("node-a"),
                    String::from("node-b"),
                    String::from("node-c"),
                ],
                strategy: crate::FleetRolloutStrategy::Sequential,
                max_allowed_divergence_ms: 30_000,
            },
            waves: vec![wave("wave-1", &["node-a"]), wave("wave-2", &["node-b", "node-c"])],
            node_to_wave: BTreeMap::from([
                (String::from("node-a"), String::from("wave-1")),
                (String::from("node-b"), String::from("wave-2")),
                (String::from("node-c"), String::from("wave-2")),
            ]),
        }
    }

    fn sample_convergence(state: crate::FleetConvergenceState) -> crate::FleetConvergenceReport {
        crate::FleetConvergenceReport {
            desired_version: String::from("stable-2"),
            desired_digest_sha256: String::from("a").repeat(64),
            consistency_mode: crate::FleetConsistencyMode::BoundedEventual,
            state,
            recommended_action: crate::FleetRecommendedAction::ObserveOnly,
            rollout_started_at_unix_ms: 10,
            divergence_deadline_unix_ms: 1_000,
            exceeded_divergence_budget: false,
            converged_nodes: 3,
            pending_nodes: 0,
            diverged_nodes: 0,
            unavailable_nodes: 0,
            partial_rollout: false,
            nodes: vec![
                FleetNodeStatus {
                    node_id: String::from("node-a"),
                    desired_version: Some(String::from("stable-2")),
                    desired_digest_sha256: Some(String::from("a").repeat(64)),
                    active_version: Some(String::from("stable-2")),
                    active_digest_sha256: Some(String::from("a").repeat(64)),
                    last_known_good_version: Some(String::from("stable-1")),
                    readiness: Some(String::from("ready")),
                    observed_at_unix_ms: 100,
                    convergence_state: FleetNodeConvergenceState::Converged,
                    detail: None,
                },
                FleetNodeStatus {
                    node_id: String::from("node-b"),
                    desired_version: Some(String::from("stable-2")),
                    desired_digest_sha256: Some(String::from("a").repeat(64)),
                    active_version: Some(String::from("stable-2")),
                    active_digest_sha256: Some(String::from("a").repeat(64)),
                    last_known_good_version: Some(String::from("stable-1")),
                    readiness: Some(String::from("ready")),
                    observed_at_unix_ms: 100,
                    convergence_state: FleetNodeConvergenceState::Converged,
                    detail: None,
                },
                FleetNodeStatus {
                    node_id: String::from("node-c"),
                    desired_version: Some(String::from("stable-2")),
                    desired_digest_sha256: Some(String::from("a").repeat(64)),
                    active_version: Some(String::from("stable-2")),
                    active_digest_sha256: Some(String::from("a").repeat(64)),
                    last_known_good_version: Some(String::from("stable-1")),
                    readiness: Some(String::from("ready")),
                    observed_at_unix_ms: 100,
                    convergence_state: FleetNodeConvergenceState::Converged,
                    detail: None,
                },
            ],
        }
    }

    fn gate(wave_id: &str, verdict: crate::FleetWaveGateVerdict) -> crate::FleetWaveGateEvaluation {
        crate::FleetWaveGateEvaluation {
            wave_id: wave_id.to_string(),
            verdict,
            degraded: !matches!(verdict, crate::FleetWaveGateVerdict::Passed),
            mode: crate::FleetHealthGateMode::Required,
            evaluated_nodes: 1,
            missing_nodes: 0,
            failing_nodes: if matches!(verdict, crate::FleetWaveGateVerdict::Passed) {
                0
            } else {
                1
            },
            timed_out: false,
            detail: String::from("gate"),
            signals: vec![crate::FleetNodeHealthSignal {
                node_id: String::from("node-a"),
                window_ms: 10_000,
                observed_at_unix_ms: 100,
                ready_percent: if matches!(verdict, crate::FleetWaveGateVerdict::Passed) {
                    99
                } else {
                    70
                },
                error_percent: if matches!(verdict, crate::FleetWaveGateVerdict::Passed) {
                    1
                } else {
                    20
                },
                request_count: 10,
            }],
        }
    }

    #[test]
    fn status_surface_marks_blocked_waves_after_failure() {
        let plan = sample_plan();
        let convergence = sample_convergence(crate::FleetConvergenceState::Progressing);
        let gates = BTreeMap::from([(String::from("wave-1"), gate("wave-1", crate::FleetWaveGateVerdict::Failed))]);

        let surface = render_staged_status_surface(&plan, &convergence, &gates, None, None);

        assert_eq!(surface.state, FleetStagedRolloutState::Progressing);
        assert_eq!(surface.waves[0].state, FleetWaveStatusState::Failed);
        assert_eq!(surface.waves[1].state, FleetWaveStatusState::Blocked);
    }

    #[test]
    fn status_surface_marks_aborted_and_rolled_back() {
        let plan = sample_plan();
        let convergence = sample_convergence(crate::FleetConvergenceState::Degraded);
        let gates = BTreeMap::from([(String::from("wave-1"), gate("wave-1", crate::FleetWaveGateVerdict::Failed))]);
        let decision = crate::FleetAbortRollbackDecision {
            wave_id: String::from("wave-1"),
            should_abort: true,
            should_auto_rollback: true,
            reason: Some(FleetAbortReason::WaveGateFailed),
            detail: String::from("abort"),
        };
        let rollback = crate::FleetAutoRollbackOutcome {
            attempted: true,
            succeeded: true,
            target_version: Some(String::from("stable-1")),
            convergence_state: Some(crate::FleetConvergenceState::Converged),
            detail: String::from("rolled back"),
        };

        let surface = render_staged_status_surface(
            &plan,
            &convergence,
            &gates,
            Some(&decision),
            Some(&rollback),
        );

        assert_eq!(surface.state, FleetStagedRolloutState::RolledBack);
        assert!(surface.aborted);
        assert!(surface.rolled_back);
        assert_eq!(surface.rollback_target_version.as_deref(), Some("stable-1"));
        assert_eq!(surface.waves[0].state, FleetWaveStatusState::Aborted);
    }

    #[test]
    fn status_surface_maps_nodes_to_waves_and_keeps_gate_signal() {
        let plan = sample_plan();
        let convergence = sample_convergence(crate::FleetConvergenceState::Converged);
        let gates = BTreeMap::from([(String::from("wave-1"), gate("wave-1", crate::FleetWaveGateVerdict::Passed))]);

        let surface = render_staged_status_surface(&plan, &convergence, &gates, None, None);

        let node_a = surface
            .nodes
            .iter()
            .find(|entry| entry.node_id == "node-a")
            .expect("node-a should exist");
        let node_b = surface
            .nodes
            .iter()
            .find(|entry| entry.node_id == "node-b")
            .expect("node-b should exist");

        assert_eq!(surface.state, FleetStagedRolloutState::Converged);
        assert_eq!(node_a.wave_id, "wave-1");
        assert_eq!(node_b.wave_id, "wave-2");
        assert!(node_a.gate_signal.is_some());
        assert!(!node_a.gate_failed);
    }
}
