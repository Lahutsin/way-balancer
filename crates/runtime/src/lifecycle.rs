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
        Self { state: LifecycleState::Warming }
    }

    #[must_use]
    pub const fn new_active() -> Self {
        Self { state: LifecycleState::Active }
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
            state => Err(LifecycleTransitionError { from: state, action: "activate" }),
        }
    }

    pub fn start_draining(&mut self) -> Result<(), LifecycleTransitionError> {
        match self.state {
            LifecycleState::Warming | LifecycleState::Active => {
                self.state = LifecycleState::Draining;
                Ok(())
            }
            LifecycleState::Draining => Ok(()),
            state => Err(LifecycleTransitionError { from: state, action: "start_draining" }),
        }
    }

    pub fn mark_drained(&mut self) -> Result<(), LifecycleTransitionError> {
        match self.state {
            LifecycleState::Draining => {
                self.state = LifecycleState::Drained;
                Ok(())
            }
            LifecycleState::Drained => Ok(()),
            state => Err(LifecycleTransitionError { from: state, action: "mark_drained" }),
        }
    }

    pub fn mark_removed(&mut self) -> Result<(), LifecycleTransitionError> {
        match self.state {
            LifecycleState::Drained => {
                self.state = LifecycleState::Removed;
                Ok(())
            }
            LifecycleState::Removed => Ok(()),
            state => Err(LifecycleTransitionError { from: state, action: "mark_removed" }),
        }
    }

    pub fn force_remove(&mut self) {
        self.state = LifecycleState::Removed;
    }
}

#[cfg(test)]
mod tests {
    use super::{LifecycleState, LifecycleStateMachine, LifecycleTransitionError};

    #[test]
    fn state_names_and_transition_errors_are_stable() {
        let states = [
            (LifecycleState::Warming, "warming"),
            (LifecycleState::Active, "active"),
            (LifecycleState::Draining, "draining"),
            (LifecycleState::Drained, "drained"),
            (LifecycleState::Removed, "removed"),
        ];
        for (state, name) in states {
            assert_eq!(state.as_str(), name);
        }

        let error = LifecycleTransitionError { from: LifecycleState::Drained, action: "activate" };
        assert_eq!(
            error.to_string(),
            "invalid lifecycle transition: action activate is not allowed from drained"
        );
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn transitions_are_idempotent_only_after_their_target_state() {
        let mut active = LifecycleStateMachine::new_active();
        active.activate().expect("activating active resource is idempotent");
        let mut draining = LifecycleStateMachine::new_active();
        draining.start_draining().expect("start draining");
        draining.start_draining().expect("starting draining twice is idempotent");
        let mut drained = LifecycleStateMachine::new_active();
        drained.start_draining().expect("start draining");
        drained.mark_drained().expect("mark drained");
        drained.mark_drained().expect("marking drained twice is idempotent");
        let mut removed = LifecycleStateMachine::new_active();
        removed.start_draining().expect("start draining");
        removed.mark_drained().expect("mark drained");
        removed.mark_removed().expect("mark removed");
        removed.mark_removed().expect("marking removed twice is idempotent");
        assert_eq!(removed.state(), LifecycleState::Removed);
    }

    #[test]
    fn invalid_transitions_preserve_the_state_and_name_the_action() {
        let cases = [
            (LifecycleState::Draining, "activate"),
            (LifecycleState::Drained, "activate"),
            (LifecycleState::Removed, "activate"),
            (LifecycleState::Drained, "start_draining"),
            (LifecycleState::Removed, "start_draining"),
            (LifecycleState::Warming, "mark_drained"),
            (LifecycleState::Active, "mark_drained"),
            (LifecycleState::Removed, "mark_drained"),
            (LifecycleState::Warming, "mark_removed"),
            (LifecycleState::Active, "mark_removed"),
            (LifecycleState::Draining, "mark_removed"),
        ];
        for (state, action) in cases {
            let mut machine = LifecycleStateMachine { state };
            let error = match action {
                "activate" => machine.activate().expect_err("transition is invalid"),
                "start_draining" => machine.start_draining().expect_err("transition is invalid"),
                "mark_drained" => machine.mark_drained().expect_err("transition is invalid"),
                "mark_removed" => machine.mark_removed().expect_err("transition is invalid"),
                _ => unreachable!(),
            };
            assert_eq!(machine.state(), state);
            assert_eq!(error.from, state);
            assert_eq!(error.action, action);
        }
    }

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
