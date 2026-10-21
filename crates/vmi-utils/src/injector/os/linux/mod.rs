mod kernel_mode;
mod user_mode;

use vmi_arch_amd64::{Amd64, Registers};
use vmi_core::{
    Architecture as _, Pa, Va, VmiCore, VmiError, VmiState,
    driver::{
        VmiDriver, VmiEventControl, VmiQueryProtection, VmiQueryRegisters, VmiRead,
        VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
    },
    os::{VmiOsProcessExt as _, VmiOsUserModule as _},
    trace::Hex,
};
use vmi_os_linux::{LinuxOs, LinuxUserModule};
use zerocopy::IntoBytes as _;

use self::{kernel_mode::KernelInjectorHandler, user_mode::UserInjectorHandler};
use super::{
    super::{
        ArgumentData, BridgeDispatch, CallBuilder, InjectorExecutionAdapter, KernelMode, UserMode,
    },
    OsAdapter,
};

/// The name that `inject!` gives the kernel image, as in `kernel!filp_open`.
const KERNEL_IMAGE_NAME: &str = "kernel";

/// The number of arguments that a call passes in registers, in `rdi`, `rsi`,
/// `rdx`, `rcx`, `r8` and `r9` (System V ABI).
const ARGUMENT_REGISTERS: usize = 6;

/// The alignment of the stack pointer before a call pushes its return
/// address (System V ABI).
const STACK_ALIGNMENT: u64 = 16;

/// The size of the red zone below the stack pointer in user mode (System V
/// ABI). The kernel builds without one.
const RED_ZONE_SIZE: u64 = 128;

impl<Driver, T, Bridge> InjectorExecutionAdapter<KernelMode, T, Bridge> for LinuxOs<Driver>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiQueryRegisters
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<Self>,
{
    type Handler = KernelInjectorHandler<Driver, T, Bridge>;
}

impl<Driver, T, Bridge> InjectorExecutionAdapter<UserMode, T, Bridge> for LinuxOs<Driver>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiQueryRegisters
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<Self>,
{
    type Handler = UserInjectorHandler<Driver, T, Bridge>;
}

impl<Driver> OsAdapter for LinuxOs<Driver>
where
    Driver: VmiDriver<Architecture = Amd64> + VmiRead + VmiWrite,
{
    fn prepare_function_call(
        &self,
        vmi: &VmiCore<Self::Driver>,
        registers: &mut Registers,
        builder: CallBuilder,
    ) -> Result<(), VmiError> {
        prepare_call(vmi, registers, builder)
    }

    /// Finds an image for `inject!`.
    ///
    /// `kernel` names the kernel image. A name with a dot names a user
    /// module by its file name, such as `"ld-linux-x86-64.so.2"`. Another
    /// name, such as `libc`, names the user module `libc.so` or
    /// `libc.so.<version>`. The search compares the file name of each module
    /// in the current process, then its `DT_SONAME`, which finds `libc.so.6`
    /// in a file named `libc-2.31.so`.
    fn find_image(vmi: &VmiState<'_, Self>, name: &str) -> Result<Option<Va>, VmiError> {
        if name == KERNEL_IMAGE_NAME {
            return Ok(Some(vmi.os().kernel_image_base()?));
        }

        let current_process = vmi.os().current_process()?;

        let module = if name.contains('.') {
            current_process.find_user_module(name)?
        }
        else {
            let by_file_name = |module: &LinuxUserModule<'_, Driver>| -> Result<bool, VmiError> {
                Ok(is_library(&module.name()?, name))
            };

            let by_soname = |module: &LinuxUserModule<'_, Driver>| -> Result<bool, VmiError> {
                Ok(module
                    .soname()?
                    .is_some_and(|soname| is_library(&soname, name)))
            };

            match current_process.find_user_module(by_file_name)? {
                Some(module) => Some(module),
                None => current_process.find_user_module(by_soname)?,
            }
        };

        match module {
            Some(module) => Ok(Some(module.base_address()?)),
            None => Ok(None),
        }
    }

    fn red_zone(&self, registers: &Registers) -> u64 {
        red_zone(registers)
    }

    fn copy_to_stack(
        &self,
        vmi: &VmiCore<Self::Driver>,
        registers: &mut Registers,
        data: &[u8],
        alignment: usize,
    ) -> Result<Va, VmiError> {
        copy_to_stack(vmi, registers, data, alignment)
    }
}

/// Prepares a call with the System V calling convention.
///
/// Reference arguments go to the stack first. The first six arguments go to
/// `rdi`, `rsi`, `rdx`, `rcx`, `r8` and `r9`, and the rest to the stack,
/// aligned to 16 bytes before the return address. `rax` is 0, the number of
/// vector registers that a variadic function reads from `al`. The return
/// address is the current `rip`. Every write respects the guest's page
/// tables.
fn prepare_call<Driver>(
    vmi: &VmiCore<Driver>,
    registers: &mut Registers,
    builder: CallBuilder,
) -> Result<(), VmiError>
where
    Driver: VmiDriver<Architecture = Amd64> + VmiRead + VmiWrite,
{
    tracing::trace!(
        rsp = %Hex(registers.rsp),
        rip = %Hex(registers.rip),
        "preparing function call"
    );

    let mut arguments = Vec::with_capacity(builder.arguments.len());
    for argument in &builder.arguments {
        let value = match &argument.data {
            ArgumentData::Value(value) => *value,
            ArgumentData::Reference(data) => {
                copy_to_stack(vmi, registers, data, argument.alignment as usize)?.0
            }
        };

        arguments.push(value);
    }

    let (in_registers, on_stack) = arguments.split_at(arguments.len().min(ARGUMENT_REGISTERS));
    let root = Pa::from(registers.cr3);

    // The arguments on the stack lie right above the return address, the
    // seventh argument first.
    let mut address = registers.rsp - size_of_val(on_stack) as u64;
    address &= !(STACK_ALIGNMENT - 1);
    vmi.write_checked((Va(address), root), on_stack.as_bytes())?;

    for (index, value) in on_stack.iter().enumerate() {
        tracing::trace!(
            index = ARGUMENT_REGISTERS + index,
            value = %Hex(*value),
            "argument (stack)"
        );
    }

    address -= size_of::<u64>() as u64;
    vmi.write_checked((Va(address), root), &registers.rip.to_le_bytes())?;

    let targets = [
        &mut registers.rdi,
        &mut registers.rsi,
        &mut registers.rdx,
        &mut registers.rcx,
        &mut registers.r8,
        &mut registers.r9,
    ];

    for (index, (target, value)) in targets.into_iter().zip(in_registers).enumerate() {
        *target = *value;

        tracing::trace!(
            index,
            value = %Hex(*value),
            "argument"
        );
    }

    registers.rax = 0;
    registers.rsp = address;
    registers.rip = builder.function_address.into();

    tracing::trace!(
        rsp = %Hex(registers.rsp),
        rip = %Hex(registers.rip),
        "finished preparing function call"
    );

    Ok(())
}

/// Returns the red zone of user mode, 128 bytes, or 0 in the kernel.
fn red_zone(registers: &Registers) -> u64 {
    if Amd64::is_kernel_address(Va(registers.rip)) {
        0
    }
    else {
        RED_ZONE_SIZE
    }
}

/// Copies bytes below the stack pointer with a write that respects the
/// guest's page tables.
fn copy_to_stack<Driver>(
    vmi: &VmiCore<Driver>,
    registers: &mut Registers,
    data: &[u8],
    alignment: usize,
) -> Result<Va, VmiError>
where
    Driver: VmiDriver<Architecture = Amd64> + VmiRead + VmiWrite,
{
    let mut address = registers.rsp - data.len() as u64;
    address &= !(alignment as u64 - 1);

    vmi.write_checked((Va(address), Pa::from(registers.cr3)), data)?;

    registers.rsp = address;
    Ok(Va(address))
}

/// Checks if a file name or a soname names the library `name`, as
/// `libc.so` or `libc.so.6` name `libc`.
fn is_library(file_name: &str, name: &str) -> bool {
    file_name
        .strip_prefix(name)
        .and_then(|suffix| suffix.strip_prefix(".so"))
        .is_some_and(|version| version.is_empty() || version.starts_with('.'))
}

#[cfg(test)]
mod tests;
