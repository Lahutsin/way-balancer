#[path = "../dev-support/performance_harness.rs"]
mod performance_harness;

use performance_harness::{
    build_performance_envelope_artifact, capture_control_plane_timing_evidence, run_or_exit,
    ControlPlaneTimingEvidence, DeploymentProfile, EnvelopeMode,
};

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mode = parse_mode(arguments.clone());
    let profile = parse_profile(arguments.clone());
    let baseline = parse_string_flag(arguments.clone(), "--baseline");
    let capture_control_plane_timing = has_flag(arguments.clone(), "--capture-control-plane-timing");
    let timing_evidence_source = parse_string_flag(arguments.clone(), "--timing-evidence-source");
    let mut timing = ControlPlaneTimingEvidence {
        reload_success_ms: parse_u64_flag(arguments.clone(), "--observed-reload-success-ms"),
        reload_degraded_success_ms: parse_u64_flag(
            arguments.clone(),
            "--observed-reload-degraded-success-ms",
        ),
        failover_ms: parse_u64_flag(arguments.clone(), "--observed-failover-ms"),
        evidence_source: timing_evidence_source,
    };

    let runtime = run_or_exit(tokio::runtime::Runtime::new().map_err(Into::into));
    if capture_control_plane_timing {
        let captured = run_or_exit(runtime.block_on(capture_control_plane_timing_evidence()));
        timing = merge_control_plane_timing(captured, timing);
    }

    let report = run_or_exit(
        runtime.block_on(build_performance_envelope_artifact(
            mode,
            profile,
            timing,
            baseline.as_deref(),
        )),
    );

    let json = run_or_exit(serde_json::to_string_pretty(&report).map_err(Into::into));
    println!("{json}");
}

fn parse_mode(arguments: Vec<String>) -> EnvelopeMode {
    let mut next_is_mode = false;
    for argument in arguments {
        if next_is_mode {
            if let Some(mode) = EnvelopeMode::parse(argument.as_str()) {
                return mode;
            }
            eprintln!("unsupported --mode value: {argument}");
            std::process::exit(2);
        }
        if argument == "--mode" {
            next_is_mode = true;
            continue;
        }
        if argument == "--smoke" {
            return EnvelopeMode::Smoke;
        }
        if argument == "--full" {
            return EnvelopeMode::Full;
        }
    }

    if next_is_mode {
        eprintln!("missing value after --mode");
        std::process::exit(2);
    }

    EnvelopeMode::Smoke
}

fn parse_profile(arguments: Vec<String>) -> DeploymentProfile {
    parse_string_flag(arguments, "--profile")
        .as_deref()
        .and_then(DeploymentProfile::parse)
        .unwrap_or(DeploymentProfile::LoopbackRegressionV1)
}

fn parse_string_flag(arguments: Vec<String>, flag: &str) -> Option<String> {
    let mut next_is_value = false;
    for argument in arguments {
        if next_is_value {
            return Some(argument);
        }
        if argument == flag {
            next_is_value = true;
        }
    }
    None
}

fn parse_u64_flag(arguments: Vec<String>, flag: &str) -> Option<u64> {
    parse_string_flag(arguments, flag).map(|value| {
        value.parse::<u64>().unwrap_or_else(|_error| {
            eprintln!("invalid {flag} value: {value}");
            std::process::exit(2);
        })
    })
}

fn has_flag(arguments: Vec<String>, flag: &str) -> bool {
    arguments.iter().any(|argument| argument == flag)
}

fn merge_control_plane_timing(
    captured: ControlPlaneTimingEvidence,
    explicit: ControlPlaneTimingEvidence,
) -> ControlPlaneTimingEvidence {
    ControlPlaneTimingEvidence {
        reload_success_ms: explicit.reload_success_ms.or(captured.reload_success_ms),
        reload_degraded_success_ms: explicit
            .reload_degraded_success_ms
            .or(captured.reload_degraded_success_ms),
        failover_ms: explicit.failover_ms.or(captured.failover_ms),
        evidence_source: explicit.evidence_source.or(captured.evidence_source),
    }
}
