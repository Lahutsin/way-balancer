#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeProbeInput {
    pub startup_complete: bool,
    pub active_config_loaded: bool,
    pub has_ready_listeners: bool,
    pub has_ready_upstreams: bool,
    pub degraded: bool,
    pub fatal_error: bool,
    pub control_plane_stalled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupProbeState {
    Starting,
    Succeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessProbeState {
    Live,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessProbeState {
    Ready,
    NotReady,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeEvaluation {
    pub startup: StartupProbeState,
    pub liveness: LivenessProbeState,
    pub readiness: ReadinessProbeState,
    pub readiness_reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeMetrics {
    pub readiness_ready_count: u64,
    pub readiness_not_ready_count: u64,
    pub liveness_live_count: u64,
    pub liveness_failed_count: u64,
    pub startup_pending_count: u64,
    pub startup_success_count: u64,
}

#[derive(Debug, Default)]
pub struct ProbeSemanticsEvaluator {
    metrics: ProbeMetrics,
}

impl ProbeSemanticsEvaluator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate(&mut self, input: RuntimeProbeInput) -> ProbeEvaluation {
        let startup = if input.startup_complete && input.active_config_loaded {
            self.metrics.startup_success_count =
                self.metrics.startup_success_count.saturating_add(1);
            StartupProbeState::Succeeded
        } else {
            self.metrics.startup_pending_count =
                self.metrics.startup_pending_count.saturating_add(1);
            StartupProbeState::Starting
        };

        let liveness = if input.fatal_error || input.control_plane_stalled {
            self.metrics.liveness_failed_count =
                self.metrics.liveness_failed_count.saturating_add(1);
            LivenessProbeState::Failed
        } else {
            self.metrics.liveness_live_count = self.metrics.liveness_live_count.saturating_add(1);
            LivenessProbeState::Live
        };

        let (readiness, readiness_reason) =
            if !input.startup_complete || !input.active_config_loaded {
                (ReadinessProbeState::NotReady, String::from("startup_incomplete"))
            } else if !input.has_ready_listeners {
                (ReadinessProbeState::NotReady, String::from("no_ready_listeners"))
            } else if !input.has_ready_upstreams {
                (ReadinessProbeState::NotReady, String::from("no_ready_upstreams"))
            } else if input.degraded {
                (ReadinessProbeState::NotReady, String::from("runtime_degraded"))
            } else if input.fatal_error {
                (ReadinessProbeState::NotReady, String::from("fatal_error"))
            } else {
                (ReadinessProbeState::Ready, String::from("ready"))
            };

        match readiness {
            ReadinessProbeState::Ready => {
                self.metrics.readiness_ready_count =
                    self.metrics.readiness_ready_count.saturating_add(1);
            }
            ReadinessProbeState::NotReady => {
                self.metrics.readiness_not_ready_count =
                    self.metrics.readiness_not_ready_count.saturating_add(1);
            }
        }

        ProbeEvaluation { startup, liveness, readiness, readiness_reason }
    }

    #[must_use]
    pub const fn metrics(&self) -> ProbeMetrics {
        self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LivenessProbeState, ProbeSemanticsEvaluator, ReadinessProbeState, RuntimeProbeInput,
        StartupProbeState,
    };

    #[test]
    fn startup_liveness_and_readiness_are_distinguishable() {
        let mut evaluator = ProbeSemanticsEvaluator::new();

        let evaluation = evaluator.evaluate(RuntimeProbeInput {
            startup_complete: false,
            active_config_loaded: false,
            has_ready_listeners: false,
            has_ready_upstreams: false,
            degraded: false,
            fatal_error: false,
            control_plane_stalled: false,
        });

        assert_eq!(evaluation.startup, StartupProbeState::Starting);
        assert_eq!(evaluation.liveness, LivenessProbeState::Live);
        assert_eq!(evaluation.readiness, ReadinessProbeState::NotReady);
        assert_eq!(evaluation.readiness_reason, "startup_incomplete");
    }

    #[test]
    fn degraded_runtime_can_fail_readiness_without_failing_liveness() {
        let mut evaluator = ProbeSemanticsEvaluator::new();

        let evaluation = evaluator.evaluate(RuntimeProbeInput {
            startup_complete: true,
            active_config_loaded: true,
            has_ready_listeners: true,
            has_ready_upstreams: true,
            degraded: true,
            fatal_error: false,
            control_plane_stalled: false,
        });

        assert_eq!(evaluation.liveness, LivenessProbeState::Live);
        assert_eq!(evaluation.readiness, ReadinessProbeState::NotReady);
        assert_eq!(evaluation.readiness_reason, "runtime_degraded");
    }

    #[test]
    fn fatal_or_stalled_runtime_fails_liveness() {
        let mut evaluator = ProbeSemanticsEvaluator::new();

        let evaluation = evaluator.evaluate(RuntimeProbeInput {
            startup_complete: true,
            active_config_loaded: true,
            has_ready_listeners: true,
            has_ready_upstreams: true,
            degraded: false,
            fatal_error: false,
            control_plane_stalled: true,
        });

        assert_eq!(evaluation.liveness, LivenessProbeState::Failed);
        assert_eq!(evaluation.readiness, ReadinessProbeState::Ready);
    }

    #[test]
    fn healthy_runtime_reports_all_probes_ready() {
        let mut evaluator = ProbeSemanticsEvaluator::new();

        let evaluation = evaluator.evaluate(RuntimeProbeInput {
            startup_complete: true,
            active_config_loaded: true,
            has_ready_listeners: true,
            has_ready_upstreams: true,
            degraded: false,
            fatal_error: false,
            control_plane_stalled: false,
        });

        assert_eq!(evaluation.startup, StartupProbeState::Succeeded);
        assert_eq!(evaluation.liveness, LivenessProbeState::Live);
        assert_eq!(evaluation.readiness, ReadinessProbeState::Ready);
        assert_eq!(evaluator.metrics().readiness_ready_count, 1);
    }
}
