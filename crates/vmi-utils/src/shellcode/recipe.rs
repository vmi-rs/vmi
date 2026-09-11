#![allow(dead_code, reason = "used by OS adapters")]

use vmi_core::Architecture;

/// Original register state retained across recoverable recipe failures.
#[derive(Debug)]
pub struct ShellcodeRetryState<Arch>
where
    Arch: Architecture,
{
    /// Number of attempts started from this checkpoint.
    pub attempt: u64,

    /// Registers captured before the first attempt.
    pub original_registers: Option<Arch::Registers>,
}

impl<Arch> ShellcodeRetryState<Arch>
where
    Arch: Architecture,
{
    /// Prepares the registers for an attempt and returns its one-based number.
    ///
    /// The first attempt captures the registers. Later attempts restore the
    /// captured registers before proceeding.
    pub fn begin_attempt(&mut self, registers: &mut Arch::Registers) -> u64 {
        match self.original_registers {
            Some(original_registers) => *registers = original_registers,
            None => self.original_registers = Some(*registers),
        }

        self.attempt += 1;
        self.attempt
    }
}

impl<Arch> Default for ShellcodeRetryState<Arch>
where
    Arch: Architecture,
{
    fn default() -> Self {
        Self {
            attempt: 0,
            original_registers: None,
        }
    }
}

#[cfg(all(test, feature = "arch-amd64"))]
mod tests {
    use vmi_arch_amd64::{Amd64, Registers};

    use super::*;

    #[test]
    fn retry_state_captures_then_restores_registers() {
        let mut retry = ShellcodeRetryState::<Amd64>::default();
        let original = Registers {
            rax: 1,
            rsp: 2,
            rip: 3,
            ..Registers::default()
        };
        let mut registers = original;

        assert_eq!(retry.begin_attempt(&mut registers), 1);
        assert_eq!(retry.original_registers, Some(original));

        registers.rax = 10;
        registers.rsp = 20;
        registers.rip = 30;

        assert_eq!(retry.begin_attempt(&mut registers), 2);
        assert_eq!(registers, original);
    }
}
