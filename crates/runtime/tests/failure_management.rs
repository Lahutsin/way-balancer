use std::time::Duration;

use lb_runtime::{
    CircuitBreakerPolicy, CircuitBreakerState, FailureManager, RetryBudgetPolicy, TimeoutCategory,
    TimeoutHierarchy, UpstreamFailureClass,
};

fn failure_manager() -> Result<FailureManager, Box<dyn std::error::Error>> {
    Ok(FailureManager::new(
        RetryBudgetPolicy {
            min_retry_tokens: 1,
            retry_percent: 50,
            window: Duration::from_secs(10),
        },
        TimeoutHierarchy {
            request_timeout: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(5),
        },
        CircuitBreakerPolicy {
            open_failure_threshold: 2,
            open_duration: Duration::from_secs(20),
            half_open_success_threshold: 2,
        },
    )?)
}

#[test]
fn retry_budget_exhaustion_is_observable() -> Result<(), Box<dyn std::error::Error>> {
    let manager = failure_manager()?;
    manager.record_base_request(Duration::ZERO);
    manager.record_base_request(Duration::ZERO);

    assert!(manager.allow_retry(Duration::ZERO, UpstreamFailureClass::Timeout).allowed);
    assert!(manager.allow_retry(Duration::ZERO, UpstreamFailureClass::Connect).allowed);
    assert!(!manager.allow_retry(Duration::ZERO, UpstreamFailureClass::Overloaded).allowed);

    let metrics = manager.metrics();
    assert_eq!(metrics.retry_budget_exhausted_count, 1);
    Ok(())
}

#[test]
fn timeout_precedence_is_enforced_predictably() -> Result<(), Box<dyn std::error::Error>> {
    let manager = failure_manager()?;

    assert_eq!(manager.effective_timeout(TimeoutCategory::Request), Duration::from_secs(30));
    assert_eq!(manager.effective_timeout(TimeoutCategory::Attempt), Duration::from_secs(10));
    assert_eq!(manager.effective_timeout(TimeoutCategory::Connect), Duration::from_secs(2));
    assert_eq!(manager.effective_timeout(TimeoutCategory::Idle), Duration::from_secs(5));

    manager.record_timeout(TimeoutCategory::Connect);
    manager.record_timeout(TimeoutCategory::Connect);
    manager.record_timeout(TimeoutCategory::Idle);

    let metrics = manager.metrics();
    assert_eq!(metrics.timeout_category_counts.get(&TimeoutCategory::Connect), Some(&2));
    assert_eq!(metrics.timeout_category_counts.get(&TimeoutCategory::Idle), Some(&1));
    Ok(())
}

#[test]
fn breaker_opens_and_recovers_by_policy() -> Result<(), Box<dyn std::error::Error>> {
    let manager = failure_manager()?;

    assert!(manager.allow_request(Duration::ZERO));
    manager.record_failure(Duration::ZERO, UpstreamFailureClass::Connect);
    manager.record_failure(Duration::ZERO, UpstreamFailureClass::Timeout);

    assert_eq!(manager.breaker_snapshot(Duration::ZERO).state, CircuitBreakerState::Open);
    assert!(!manager.allow_request(Duration::from_secs(5)));
    assert_eq!(manager.metrics().breaker_open_rejection_count, 1);

    assert!(manager.allow_request(Duration::from_secs(20)));
    assert_eq!(
        manager.breaker_snapshot(Duration::from_secs(20)).state,
        CircuitBreakerState::HalfOpen
    );

    manager.record_success();
    manager.record_success();
    assert_eq!(
        manager.breaker_snapshot(Duration::from_secs(20)).state,
        CircuitBreakerState::Closed
    );

    assert_eq!(manager.recent_events().len(), 3);
    Ok(())
}

#[test]
fn repeated_failure_handling_stays_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let manager = failure_manager()?;

    manager.record_base_request(Duration::ZERO);
    manager.record_failure(Duration::ZERO, UpstreamFailureClass::Temporary);
    assert!(manager.allow_retry(Duration::ZERO, UpstreamFailureClass::Temporary).allowed);
    manager.record_failure(Duration::from_secs(1), UpstreamFailureClass::Temporary);

    assert_eq!(manager.breaker_snapshot(Duration::from_secs(1)).state, CircuitBreakerState::Open);
    assert!(!manager.allow_request(Duration::from_secs(2)));
    assert!(!manager.allow_retry(Duration::from_secs(2), UpstreamFailureClass::Permanent).allowed);
    Ok(())
}
