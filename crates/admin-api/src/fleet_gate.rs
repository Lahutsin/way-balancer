use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    fleet_staged::{FleetHealthGateMode, FleetHealthGatePolicy, FleetRolloutWaveDefinition},
    FleetNodeBackend,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetNodeHealthSignal {
    pub node_id: String,
    pub window_ms: u64,
    pub observed_at_unix_ms: u64,
    pub ready_percent: u8,
    pub error_percent: u8,
    pub request_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetWaveGateVerdict {
    Passed,
    Failed,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetWaveGateEvaluation {
    pub wave_id: String,
    pub verdict: FleetWaveGateVerdict,
    pub degraded: bool,
    pub mode: FleetHealthGateMode,
    pub evaluated_nodes: usize,
    pub missing_nodes: usize,
    pub failing_nodes: usize,
    pub timed_out: bool,
    pub detail: String,
    pub signals: Vec<FleetNodeHealthSignal>,
}

pub fn collect_wave_health_signals<B>(
    backend: &B,
    wave: &FleetRolloutWaveDefinition,
) -> BTreeMap<String, FleetNodeHealthSignal>
where
    B: FleetNodeBackend,
{
    let mut signals = BTreeMap::new();
    for node_id in &wave.node_ids {
        if let Ok(Some(signal)) = backend.fetch_health_signals(node_id, wave.gate_policy.evaluation_window_ms) {
            signals.insert(node_id.clone(), signal);
        }
    }
    signals
}

pub fn evaluate_wave_gate(
    wave: &FleetRolloutWaveDefinition,
    signals: &BTreeMap<String, FleetNodeHealthSignal>,
    wave_started_at_unix_ms: u64,
    evaluated_at_unix_ms: u64,
) -> FleetWaveGateEvaluation {
    evaluate_wave_gate_with_policy(
        &wave.wave_id,
        &wave.node_ids,
        &wave.gate_policy,
        signals,
        wave_started_at_unix_ms,
        evaluated_at_unix_ms,
    )
}

pub fn evaluate_wave_gate_with_policy(
    wave_id: &str,
    node_ids: &[String],
    policy: &FleetHealthGatePolicy,
    signals: &BTreeMap<String, FleetNodeHealthSignal>,
    wave_started_at_unix_ms: u64,
    evaluated_at_unix_ms: u64,
) -> FleetWaveGateEvaluation {
    let deadline = wave_started_at_unix_ms.saturating_add(policy.timeout_ms);
    let timed_out = evaluated_at_unix_ms >= deadline;

    let mut missing_nodes = 0_usize;
    let mut failing_nodes = 0_usize;
    let mut ingested = Vec::new();

    for node_id in node_ids {
        if let Some(signal) = signals.get(node_id) {
            if signal.ready_percent < policy.min_ready_percent
                || signal.error_percent > policy.max_error_percent
            {
                failing_nodes += 1;
            }
            ingested.push(signal.clone());
        } else {
            missing_nodes += 1;
        }
    }

    let evaluated_nodes = ingested.len();

    let (verdict, degraded, detail) = match policy.mode {
        FleetHealthGateMode::Required => {
            if failing_nodes == 0 && missing_nodes == 0 {
                (
                    FleetWaveGateVerdict::Passed,
                    false,
                    String::from("all nodes satisfy required wave gate thresholds"),
                )
            } else if timed_out {
                (
                    FleetWaveGateVerdict::Failed,
                    true,
                    format!(
                        "required wave gate timed out with {} failing and {} missing nodes",
                        failing_nodes, missing_nodes
                    ),
                )
            } else {
                (
                    FleetWaveGateVerdict::Pending,
                    failing_nodes > 0,
                    format!(
                        "required wave gate pending: {} failing and {} missing nodes",
                        failing_nodes, missing_nodes
                    ),
                )
            }
        }
        FleetHealthGateMode::BestEffort => {
            let degraded = failing_nodes > 0 || missing_nodes > 0;
            (
                FleetWaveGateVerdict::Passed,
                degraded,
                if degraded {
                    format!(
                        "best-effort wave gate accepted with {} failing and {} missing nodes",
                        failing_nodes, missing_nodes
                    )
                } else {
                    String::from("all nodes satisfy best-effort wave gate thresholds")
                },
            )
        }
    };

    FleetWaveGateEvaluation {
        wave_id: wave_id.to_string(),
        verdict,
        degraded,
        mode: policy.mode,
        evaluated_nodes,
        missing_nodes,
        failing_nodes,
        timed_out,
        detail,
        signals: ingested,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        fleet_staged::{FleetHealthGateMode, FleetHealthGatePolicy, FleetRolloutWaveDefinition},
        FleetNodeBackend, FleetNodeBackendError, FleetNodeRuntimeStatus,
    };

    use super::{evaluate_wave_gate, FleetNodeHealthSignal, FleetWaveGateVerdict};

    #[derive(Default)]
    struct MockBackend {
        signals: BTreeMap<String, FleetNodeHealthSignal>,
    }

    impl FleetNodeBackend for MockBackend {
        fn fetch_status(
            &self,
            _node_id: &str,
        ) -> Result<FleetNodeRuntimeStatus, FleetNodeBackendError> {
            Err(FleetNodeBackendError::Unreachable(String::from("unused in this test")))
        }

        fn rollout_node(
            &mut self,
            _node_id: &str,
            _request: crate::RolloutRequest,
            _occurred_at_unix_ms: u64,
        ) -> Result<crate::RolloutResponse, FleetNodeBackendError> {
            Err(FleetNodeBackendError::Rejected(String::from("unused in this test")))
        }

        fn rollback_node(
            &mut self,
            _node_id: &str,
            _request: crate::RollbackRequest,
            _occurred_at_unix_ms: u64,
        ) -> Result<crate::RolloutResponse, FleetNodeBackendError> {
            Err(FleetNodeBackendError::Rejected(String::from("unused in this test")))
        }

        fn fetch_health_signals(
            &self,
            node_id: &str,
            _window_ms: u64,
        ) -> Result<Option<FleetNodeHealthSignal>, FleetNodeBackendError> {
            Ok(self.signals.get(node_id).cloned())
        }
    }

    fn wave(mode: FleetHealthGateMode) -> FleetRolloutWaveDefinition {
        FleetRolloutWaveDefinition {
            wave_id: String::from("wave-a"),
            node_ids: vec![String::from("node-a"), String::from("node-b")],
            max_parallel: 1,
            gate_policy: FleetHealthGatePolicy {
                mode,
                min_ready_percent: 95,
                max_error_percent: 5,
                evaluation_window_ms: 10_000,
                timeout_ms: 30_000,
            },
        }
    }

    fn signal(node_id: &str, ready_percent: u8, error_percent: u8) -> FleetNodeHealthSignal {
        FleetNodeHealthSignal {
            node_id: node_id.to_string(),
            window_ms: 10_000,
            observed_at_unix_ms: 1_000,
            ready_percent,
            error_percent,
            request_count: 100,
        }
    }

    #[test]
    fn required_gate_passes_when_all_nodes_are_healthy() {
        let wave = wave(FleetHealthGateMode::Required);
        let mut signals = BTreeMap::new();
        signals.insert(String::from("node-a"), signal("node-a", 99, 1));
        signals.insert(String::from("node-b"), signal("node-b", 98, 1));

        let evaluation = evaluate_wave_gate(&wave, &signals, 1_000, 10_000);

        assert_eq!(evaluation.verdict, FleetWaveGateVerdict::Passed);
        assert!(!evaluation.degraded);
        assert_eq!(evaluation.failing_nodes, 0);
        assert_eq!(evaluation.missing_nodes, 0);
    }

    #[test]
    fn required_gate_is_pending_before_timeout_with_missing_or_failing_nodes() {
        let wave = wave(FleetHealthGateMode::Required);
        let mut signals = BTreeMap::new();
        signals.insert(String::from("node-a"), signal("node-a", 85, 12));

        let evaluation = evaluate_wave_gate(&wave, &signals, 1_000, 20_000);

        assert_eq!(evaluation.verdict, FleetWaveGateVerdict::Pending);
        assert!(evaluation.degraded);
        assert_eq!(evaluation.failing_nodes, 1);
        assert_eq!(evaluation.missing_nodes, 1);
    }

    #[test]
    fn required_gate_fails_after_timeout_if_nodes_not_healthy() {
        let wave = wave(FleetHealthGateMode::Required);
        let signals = BTreeMap::new();

        let evaluation = evaluate_wave_gate(&wave, &signals, 1_000, 31_000);

        assert_eq!(evaluation.verdict, FleetWaveGateVerdict::Failed);
        assert!(evaluation.degraded);
        assert!(evaluation.timed_out);
    }

    #[test]
    fn best_effort_gate_passes_but_marks_degraded_when_signals_are_bad() {
        let wave = wave(FleetHealthGateMode::BestEffort);
        let mut signals = BTreeMap::new();
        signals.insert(String::from("node-a"), signal("node-a", 80, 15));

        let evaluation = evaluate_wave_gate(&wave, &signals, 1_000, 60_000);

        assert_eq!(evaluation.verdict, FleetWaveGateVerdict::Passed);
        assert!(evaluation.degraded);
    }

    #[test]
    fn backend_can_ingest_signals_for_wave_nodes() -> Result<(), Box<dyn std::error::Error>> {
        let mut backend = MockBackend::default();
        backend
            .signals
            .insert(String::from("node-a"), signal("node-a", 97, 2));
        backend
            .signals
            .insert(String::from("node-b"), signal("node-b", 99, 1));
        let wave = wave(FleetHealthGateMode::Required);

        let signals = super::collect_wave_health_signals(&backend, &wave);

        assert_eq!(signals.len(), 2);
        assert_eq!(signals.get("node-a").map(|entry| entry.ready_percent), Some(97));
        Ok(())
    }
}
