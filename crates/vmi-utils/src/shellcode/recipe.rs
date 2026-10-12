use std::num::NonZeroU32;

use vmi_core::{Architecture, VmiError};

/// Retry policy applied to a shellcode recipe.
///
/// A recipe can fail before the shellcode runs, for example when the
/// allocation fails. The policy decides whether the recipe tries again.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicy {
    /// Does not retry.
    Never,

    /// Makes at most this many attempts.
    Attempts(NonZeroU32),

    /// Retries until an attempt succeeds.
    #[default]
    Unlimited,
}

/// State retained while a shellcode recipe is retried.
#[derive(Debug)]
pub struct RetryState<Arch>
where
    Arch: Architecture,
{
    /// Number of attempts started.
    attempt: u64,

    /// Registers captured before the first attempt.
    original_registers: Option<Arch::Registers>,

    /// Retry policy applied to the recipe.
    policy: RetryPolicy,

    /// Whether the current attempt was aborted.
    aborted: bool,
}

impl<Arch> RetryState<Arch>
where
    Arch: Architecture,
{
    /// Creates a new retry state with the given policy.
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            attempt: 0,
            original_registers: None,
            policy,
            aborted: false,
        }
    }

    /// Returns the number of attempts started.
    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    /// Starts an attempt and returns its number, starting at one.
    ///
    /// The first attempt captures the registers. Later attempts restore them
    /// before continuing.
    ///
    /// # Errors
    ///
    /// Returns an error if the last attempt was aborted and the policy allows
    /// no more attempts.
    pub fn begin_attempt(&mut self, registers: &mut Arch::Registers) -> Result<u64, VmiError> {
        if std::mem::take(&mut self.aborted) && !self.should_retry() {
            return Err(VmiError::Other("shellcode failed"));
        }

        match self.original_registers {
            Some(original_registers) => *registers = original_registers,
            None => self.original_registers = Some(*registers),
        }

        self.attempt += 1;
        Ok(self.attempt)
    }

    /// Aborts the current attempt.
    ///
    /// The next [`begin_attempt`](Self::begin_attempt) either starts another
    /// attempt or returns an error, as the policy decides.
    pub fn abort_attempt(&mut self) {
        self.aborted = true;
    }

    /// Returns whether the policy allows another attempt.
    fn should_retry(&self) -> bool {
        match self.policy {
            RetryPolicy::Never => false,
            RetryPolicy::Attempts(attempts) => self.attempt < u64::from(attempts.get()),
            RetryPolicy::Unlimited => true,
        }
    }
}

impl<Arch> Default for RetryState<Arch>
where
    Arch: Architecture,
{
    fn default() -> Self {
        Self::new(RetryPolicy::default())
    }
}

#[cfg(all(test, feature = "arch-amd64"))]
mod tests {
    use std::num::NonZeroU32;

    use vmi_arch_amd64::{Amd64, Registers};
    use vmi_core::VmiError;

    use super::{RetryPolicy, RetryState};

    /// Aborts every attempt until `policy` ends the recipe. Returns the number
    /// of attempts started, or `None` if the recipe still retried after
    /// `limit` attempts.
    fn attempts_until_error(policy: RetryPolicy, limit: u64) -> Option<u64> {
        let mut state = RetryState::<Amd64>::new(policy);
        let mut registers = Registers::default();

        loop {
            match state.begin_attempt(&mut registers) {
                Ok(attempt) if attempt > limit => return None,
                Ok(_) => state.abort_attempt(),
                Err(VmiError::Other(_)) => return Some(state.attempt()),
                Err(err) => panic!("unexpected error: {err}"),
            }
        }
    }

    #[test]
    fn never_stops_after_the_first_attempt() {
        assert_eq!(attempts_until_error(RetryPolicy::Never, 10), Some(1));
    }

    #[test]
    fn attempts_bounds_the_number_of_attempts() {
        let policy = RetryPolicy::Attempts(NonZeroU32::new(3).expect("nonzero"));
        assert_eq!(attempts_until_error(policy, 10), Some(3));
    }

    #[test]
    fn unlimited_keeps_retrying() {
        assert_eq!(attempts_until_error(RetryPolicy::Unlimited, 100), None);
    }
}
