mod user_mode;

use vmi_arch_arm64::{Arm64, Granule16KVa47, Registers};
use vmi_core::{
    Registers as _, Va, VmiCore, VmiError,
    driver::{
        VmiDriver, VmiEventControl, VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl,
        VmiWrite,
    },
    trace::Hex,
};
use vmi_os_macos::MacOs;

use self::user_mode::UserInjectorHandler;
use super::{
    super::{CallBuilder, InjectorExecutionAdapter, UserMode, arch::ArchAdapter as _},
    OsAdapter,
};

/// Number of arguments passed in the registers `x0` to `x7`.
const REGISTER_ARGUMENTS: usize = 8;

/// Index of the link register, `x30`, which holds the return address.
const LINK_REGISTER: usize = 30;

impl<Driver, T> InjectorExecutionAdapter<UserMode, T, ()> for MacOs<Driver>
where
    Driver: VmiDriver<Architecture = Arm64<Granule16KVa47>>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
{
    type Handler = UserInjectorHandler<Driver, T>;
}

impl<Driver> OsAdapter for MacOs<Driver>
where
    Driver: VmiDriver<Architecture = Arm64<Granule16KVa47>> + VmiRead + VmiWrite,
{
    /// Prepares a call as the arm64 procedure call standard of Apple
    /// platforms lays it out.
    ///
    /// The first eight arguments go in `x0` to `x7`, the rest in 8-byte slots
    /// on the stack. The link register holds the current instruction pointer,
    /// so the call returns to the instruction it interrupted.
    ///
    /// # Notes
    ///
    /// Apple platforms pass every variadic argument on the stack, and pack
    /// stack arguments smaller than 8 bytes. Calls that need either are laid
    /// out wrong. See "Pass arguments to functions correctly" in [Writing
    /// ARM64 code for Apple platforms](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms).
    fn prepare_function_call(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &mut Registers<Granule16KVa47>,
        builder: CallBuilder,
    ) -> Result<(), VmiError> {
        tracing::trace!(
            sp = %Hex(registers.stack_pointer()),
            pc = %Hex(registers.pc),
            "preparing function call"
        );

        let arguments =
            Arm64::<Granule16KVa47>::push_arguments(vmi, registers, &builder.arguments)?;

        tracing::trace!(
            sp = %Hex(registers.stack_pointer()),
            "pushed arguments"
        );

        let (register_arguments, stack_arguments) =
            arguments.split_at(arguments.len().min(REGISTER_ARGUMENTS));

        // The stack pointer is 16-byte aligned at a call.
        let sp = (registers.stack_pointer() - stack_arguments.len() as u64 * 8) & !0xf;

        for (index, value) in stack_arguments.iter().enumerate() {
            let va = Va(sp + index as u64 * 8);
            vmi.write_u64((va, registers.translation_root(va)), *value)?;

            tracing::trace!(
                index = REGISTER_ARGUMENTS + index,
                value = %Hex(*value),
                %va,
                "argument (stack)"
            );
        }

        for (index, value) in register_arguments.iter().enumerate() {
            registers.regs[index] = *value;

            tracing::trace!(
                index,
                value = %Hex(*value),
                "argument"
            );
        }

        registers.regs[LINK_REGISTER] = registers.pc;
        registers.set_stack_pointer(sp);
        registers.pc = builder.function_address.0;

        tracing::trace!(
            sp = %Hex(sp),
            pc = %Hex(registers.pc),
            "finished preparing function call"
        );

        Ok(())
    }
}
