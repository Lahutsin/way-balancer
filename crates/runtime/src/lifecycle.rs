use std::fmt;

/// Canonical lifecycle states for runtime-managed resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleState {
    Warming,
    Active,
    Draining,
    Drained,
    Removed,
}

impl LifecycleState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warming => "warming",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Drained => "drained",
            Self::Removed => "removed",
        }
    }
}

/// Error returned when a lifecycle transition is not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleTransitionError {
    pub from: LifecycleState,
    pub action: &'static str,
}

impl fmt::Display for LifecycleTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid lifecycle transition: action {} is not allowed from {}",
            self.action,
            self.from.as_str()
        )
    }
}

impl std::error::Error for LifecycleTransitionError {}

/// Small deterministic state machine used by endpoint and client lifecycle orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleStateMachine {
    state: LifecycleState,
}

impl LifecycleStateMachine {
    #[must_use]
    pub const fn new_warming() -> Self {
        Self {
            state: LifecycleState::Warming,
        }
    }

    #[must_use]
    pub const fn new_active() -> Self {
        Self {
            state: LifecycleState::Active,
        }
    }

    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn activate(&mut self) -> Result<(), LifecycleTransitionError> {
        match self.state {
            LifecycleState::Warming => {
                self.state = LifecycleState::Active;
                Ok(())
            }
            LifecycleState::Active => Ok(()),
            state => Err(LifecycleTransitionError {
                from: state,
                action: "activate",
            }),
        }
    }

    pub fn start_draining(&mut self) -> Result<(), LifecycleTransitionError> {
        match self.state {
            LifecycleState::Warming | LifecycleState::Active => {
                self.state = LifecycleState::Draining;
                Ok(())
            }
            LifecycleState::Draining => Ok(()),
            state => Err(LifecycleTransitionError {
                from: state,
                action: "start_draining",
            }),
        }
    }

    pub fn mark_drained(&mut self) -> Result<(), LifecycleTransitionError> {
        match self.state {
            LifecycleState::Draining => {
                self.state = LifecycleState::Drained;
                Ok(())
            }
            LifecycleState::Drained => Ok(()),
            state => Err(LifecycleTransitionError {
                from: state,
                action: "mark_drained",
            }),
        }
    }

    pub fn mark_removed(&mut self) -> Result<(), LifecycleTransitionError> {
        match self.state {
            LifecycleState::Drained => {
                self.state = LifecycleState::Removed;
                Ok(())
            }
            LifecycleState::Removed => Ok(()),
            state => Err(LifecycleTransitionError {
                from: state,
                action: "mark_removed",
            }),
        }
    }

    pub fn force_remove(&mut self) {
        self.state = LifecycleState::Removed;
    }
}

#[cfg(test)]
mod tests {
    use super::{LifecycleState, LifecycleStateMachine};

    #[test]
    fn machine_follows_expected_happy_path() -> Result<(), Box<dyn std::error::Error>> {
        let mut machine = LifecycleStateMachine::new_warming();
        assert_eq!(machine.state(), LifecycleState::Warming);

        machine.activate()?;
        assert_eq!(machine.state(), LifecycleState::Active);

        machine.start_draining()?;
        assert_eq!(machine.state(), LifecycleState::Draining);

        machine.mark_drained()?;
        assert_eq!(machine.state(), LifecycleState::Drained);

        machine.mark_removed()?;
        assert_eq!(machine.state(), LifecycleState::Removed);
        Ok(())
    }

    #[test]
    fn machine_rejects_invalid_transitions() {
        let mut machine = LifecycleStateMachine::new_active();
        assert!(machine.mark_drained().is_err());
        assert!(machine.mark_removed().is_err());

        let mut machine = LifecycleStateMachine::new_warming();
        assert!(machine.mark_drained().is_err());
    }

    #[test]
    fn force_remove_short_circuits_state() {
        let mut machine = LifecycleStateMachine::new_active();
        machine.force_remove();
        assert_eq!(machine.state(), LifecycleState::Removed);
        assert!(machine.activate().is_err());
    }
}
