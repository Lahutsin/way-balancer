use std::time::Duration;

use lb_runtime::{
    BrownoutFeature, BrownoutHookRegistry, OverloadManager, OverloadPolicy, OverloadSignal,
    OverloadState, SheddingAction, TrafficClass,
};

fn overload_manager() -> Result<OverloadManager, Box<dyn std::error::Error>> {
    Ok(OverloadManager::new(
        OverloadPolicy {
            signal_window: Duration::from_secs(10),
            constrained_signal_threshold: 2,
            shedding_signal_threshold: 4,
            brownout_signal_threshold: 6,
        },
        BrownoutHookRegistry::new(vec![
            BrownoutFeature {
                name: String::from("expensive_search"),
                priority: TrafficClass::BestEffort,
            },
            BrownoutFeature {
                name: String::from("decorated_responses"),
                priority: TrafficClass::Default,
            },
        ])?,
    )?)
}

#[test]
fn overload_signal_window_prevents_false_positives() -> Result<(), Box<dyn std::error::Error>> {
    let manager = overload_manager()?;

    let _ = manager.record_signal(
        Duration::ZERO,
        OverloadSignal { rate_limited: true, ..OverloadSignal::default() },
    );
    let snapshot = manager.snapshot(Duration::from_secs(11));
    assert_eq!(snapshot.state, OverloadState::Normal);
    assert_eq!(snapshot.active_signal_count, 0);
    Ok(())
}

#[test]
fn shedding_integration_is_predictable() -> Result<(), Box<dyn std::error::Error>> {
    let manager = overload_manager()?;

    let _ = manager.record_signal(
        Duration::ZERO,
        OverloadSignal {
            rate_limited: true,
            concurrency_limited: true,
            breaker_open: true,
            retry_budget_exhausted: true,
        },
    );

    assert_eq!(manager.decide(TrafficClass::Critical).action, SheddingAction::Allow);
    assert_eq!(manager.decide(TrafficClass::Default).action, SheddingAction::Shed);
    assert_eq!(manager.metrics(Duration::ZERO).shed_request_count, 1);
    Ok(())
}

#[test]
fn sustained_stress_degrades_without_collapse() -> Result<(), Box<dyn std::error::Error>> {
    let manager = overload_manager()?;

    for second in 0..8 {
        let _ = manager.record_signal(
            Duration::from_secs(second),
            OverloadSignal {
                rate_limited: true,
                concurrency_limited: true,
                breaker_open: second % 2 == 0,
                retry_budget_exhausted: true,
            },
        );
    }

    let snapshot = manager.snapshot(Duration::from_secs(8));
    assert_eq!(snapshot.state, OverloadState::Brownout);
    assert!(manager.disabled_features().contains("expensive_search"));
    assert!(manager.disabled_features().contains("decorated_responses"));
    assert!(manager.recent_events().len() >= 2);
    Ok(())
}
