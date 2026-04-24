use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

/// Runtime hedging policy used by forwarding orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHedgingPolicy {
    /// Delay before launching the hedge attempt.
    pub hedge_delay: Duration,
    /// Maximum attempts including the primary request.
    pub max_attempts: u8,
}

impl Default for RequestHedgingPolicy {
    fn default() -> Self {
        Self {
            hedge_delay: Duration::from_millis(20),
            max_attempts: 2,
        }
    }
}

impl RequestHedgingPolicy {
    #[must_use]
    pub fn enabled(self) -> bool {
        self.max_attempts >= 2
    }
}

/// Outcome metadata for a hedged execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HedgeOutcome {
    pub hedge_launched: bool,
    pub winner_attempt: u8,
}

/// Executes a primary attempt and an optional delayed hedge attempt.
///
/// Winner semantics:
/// - first successful attempt wins and cancels the other attempt
/// - if one attempt fails, waits for the other attempt
/// - if both fail, returns the first failure
pub async fn execute_with_hedge<T, E, A, B, AFut, BFut, AllowHedge>(
    policy: RequestHedgingPolicy,
    allow_hedge: AllowHedge,
    primary_attempt: A,
    hedge_attempt: B,
) -> Result<(T, HedgeOutcome), E>
where
    T: Send + 'static,
    E: Send + 'static,
    A: FnOnce() -> AFut,
    B: FnOnce() -> BFut,
    AFut: Future<Output = Result<T, E>> + Send + 'static,
    BFut: Future<Output = Result<T, E>> + Send + 'static,
    AllowHedge: FnOnce() -> bool,
{
    let mut primary_handle = tokio::spawn(primary_attempt());

    if !policy.enabled() || !allow_hedge() {
        let value = primary_handle
            .await
            .expect("primary hedged task must not panic")?;
        return Ok((
            value,
            HedgeOutcome {
                hedge_launched: false,
                winner_attempt: 1,
            },
        ));
    }

    tokio::time::sleep(policy.hedge_delay).await;

    if primary_handle.is_finished() {
        let value = primary_handle
            .await
            .expect("primary hedged task must not panic")?;
        return Ok((
            value,
            HedgeOutcome {
                hedge_launched: false,
                winner_attempt: 1,
            },
        ));
    }

    let mut hedge_handle = tokio::spawn(hedge_attempt());

    let (winner, first_error) = tokio::select! {
        primary = &mut primary_handle => {
            match primary.expect("primary hedged task must not panic") {
                Ok(value) => {
                    abort_if_running(&mut hedge_handle);
                    return Ok((
                        value,
                        HedgeOutcome { hedge_launched: true, winner_attempt: 1 },
                    ));
                }
                Err(error) => (2, Some(error)),
            }
        }
        hedge = &mut hedge_handle => {
            match hedge.expect("hedge task must not panic") {
                Ok(value) => {
                    abort_if_running(&mut primary_handle);
                    return Ok((
                        value,
                        HedgeOutcome { hedge_launched: true, winner_attempt: 2 },
                    ));
                }
                Err(error) => (1, Some(error)),
            }
        }
    };

    // One attempt already failed. Await the other one for a possible recovery success.
    if winner == 1 {
        match primary_handle
            .await
            .expect("primary hedged task must not panic")
        {
            Ok(value) => {
                return Ok((
                    value,
                    HedgeOutcome {
                        hedge_launched: true,
                        winner_attempt: 1,
                    },
                ));
            }
            Err(error) => return Err(first_error.unwrap_or(error)),
        }
    }

    match hedge_handle.await.expect("hedge task must not panic") {
        Ok(value) => Ok((
            value,
            HedgeOutcome {
                hedge_launched: true,
                winner_attempt: 2,
            },
        )),
        Err(error) => Err(first_error.unwrap_or(error)),
    }
}

fn abort_if_running<T>(handle: &mut JoinHandle<T>) {
    if !handle.is_finished() {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::oneshot;
    use tokio::time;

    use super::{execute_with_hedge, RequestHedgingPolicy};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hedge_selects_faster_second_attempt() -> Result<(), Box<dyn std::error::Error>> {
        let policy = RequestHedgingPolicy {
            hedge_delay: Duration::from_millis(5),
            max_attempts: 2,
        };

        let result = execute_with_hedge(
            policy,
            || true,
            || async {
                time::sleep(Duration::from_millis(40)).await;
                Ok::<_, &'static str>("primary")
            },
            || async {
                time::sleep(Duration::from_millis(10)).await;
                Ok::<_, &'static str>("hedge")
            },
        )
        .await?;

        assert_eq!(result.0, "hedge");
        assert!(result.1.hedge_launched);
        assert_eq!(result.1.winner_attempt, 2);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hedge_is_not_launched_when_budget_denies() -> Result<(), Box<dyn std::error::Error>> {
        let attempts = Arc::new(AtomicU8::new(0));
        let policy = RequestHedgingPolicy {
            hedge_delay: Duration::from_millis(5),
            max_attempts: 2,
        };
        let attempts_for_primary = Arc::clone(&attempts);

        let result = execute_with_hedge(
            policy,
            || false,
            move || {
                let attempts = Arc::clone(&attempts_for_primary);
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &'static str>("primary")
                }
            },
            || async {
                Ok::<_, &'static str>("hedge")
            },
        )
        .await?;

        assert_eq!(result.0, "primary");
        assert!(!result.1.hedge_launched);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loser_attempt_is_cancelled_after_winner() -> Result<(), Box<dyn std::error::Error>> {
        let policy = RequestHedgingPolicy {
            hedge_delay: Duration::from_millis(1),
            max_attempts: 2,
        };
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        let result = execute_with_hedge(
            policy,
            || true,
            move || async move {
                let _guard = CancelSignal(Some(cancel_tx));
                time::sleep(Duration::from_secs(5)).await;
                Ok::<_, &'static str>("primary")
            },
            || async {
                time::sleep(Duration::from_millis(5)).await;
                Ok::<_, &'static str>("hedge")
            },
        )
        .await?;

        assert_eq!(result.0, "hedge");
        let _ = time::timeout(Duration::from_millis(100), cancel_rx).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn helper_obeys_external_timeout_bound() -> Result<(), Box<dyn std::error::Error>> {
        let policy = RequestHedgingPolicy {
            hedge_delay: Duration::from_millis(1),
            max_attempts: 2,
        };

        let bounded = tokio::time::timeout(
            Duration::from_millis(50),
            execute_with_hedge(
                policy,
                || true,
                || async {
                    time::sleep(Duration::from_secs(5)).await;
                    Ok::<_, &'static str>("primary")
                },
                || async {
                    time::sleep(Duration::from_secs(5)).await;
                    Ok::<_, &'static str>("hedge")
                },
            ),
        )
        .await;

        assert!(bounded.is_err());
        Ok(())
    }

    struct CancelSignal(Option<oneshot::Sender<()>>);

    impl Drop for CancelSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
}
