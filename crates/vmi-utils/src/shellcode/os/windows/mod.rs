mod kernel_mode;
mod user_mode;

use vmi_arch_amd64::{Amd64, Registers};
use vmi_core::driver::VmiMemory;
use vmi_os_windows::WindowsOs;

use super::{super::ShellcodeParameterSource, OsAdapter};
use crate::injector::Recipe;

impl<Driver> OsAdapter for WindowsOs<Driver>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    type KernelRecipeData = kernel_mode::KernelShellcodeRecipeData;
    type UserRecipeData = user_mode::UserShellcodeRecipeData;

    fn kernel_shellcode_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::KernelRecipeData> {
        kernel_mode::kernel_shellcode_recipe(shellcode, parameter)
    }

    fn user_shellcode_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::UserRecipeData> {
        user_mode::user_shellcode_recipe(shellcode, parameter)
    }
}

/// Original register state retained across recoverable recipe failures.
#[derive(Debug, Default)]
struct ShellcodeRetryState {
    attempt: u64,
    original_registers: Option<Registers>,
}

impl ShellcodeRetryState {
    fn begin_attempt(&mut self, registers: &mut Registers) -> u64 {
        match self.original_registers {
            Some(original_registers) => *registers = original_registers,
            None => self.original_registers = Some(*registers),
        }

        self.attempt += 1;
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_state_captures_then_restores_registers() {
        let mut retry = ShellcodeRetryState::default();
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
