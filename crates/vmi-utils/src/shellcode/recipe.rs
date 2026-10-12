use vmi_core::Architecture;

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
}

impl<Arch> RetryState<Arch>
where
    Arch: Architecture,
{
    /// Returns the number of attempts started.
    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    /// Starts an attempt and returns its number, starting at one.
    ///
    /// The first attempt captures the registers. Later attempts restore them
    /// before continuing.
    pub fn begin_attempt(&mut self, registers: &mut Arch::Registers) -> u64 {
        match self.original_registers {
            Some(original_registers) => *registers = original_registers,
            None => self.original_registers = Some(*registers),
        }

        self.attempt += 1;
        self.attempt
    }
}

impl<Arch> Default for RetryState<Arch>
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
