#[path = "../dev-support/performance_harness.rs"]
mod performance_harness;

use performance_harness::{run_or_exit, run_performance_envelope, EnvelopeMode};

fn main() {
    let mode = parse_mode(std::env::args().skip(1).collect());
    let report = run_or_exit(
        tokio::runtime::Runtime::new()
            .map_err(Into::into)
            .and_then(|runtime| runtime.block_on(run_performance_envelope(mode))),
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