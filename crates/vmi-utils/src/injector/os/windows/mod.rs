mod user_mode;

use vmi_arch_amd64::{Amd64, Registers};
use vmi_core::{
    Hex, VmiCore, VmiError,
    driver::{VmiEventControl, VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite},
};
use vmi_os_windows::WindowsOs;

use self::user_mode::UserInjectorHandler;
use super::{
    super::{
        BridgeHandler, CallBuilder, InjectorExecutionAdapter, InjectorResultCode, UserMode,
        arch::ArchAdapter as _,
    },
    OsAdapter,
};

impl<Driver> OsAdapter<Driver> for WindowsOs<Driver>
where
    Driver: VmiRead<Architecture = Amd64> + VmiWrite<Architecture = Amd64>,
{
    fn prepare_function_call(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &mut Registers,
        builder: CallBuilder,
    ) -> Result<(), VmiError> {
        tracing::trace!(
            rsp = %Hex(registers.rsp),
            rip = %Hex(registers.rip),
            "preparing function call"
        );

        let arguments = Amd64::push_arguments(vmi, registers, &builder.arguments)?;

        tracing::trace!(
            rsp = %Hex(registers.rsp),
            "pushed arguments"
        );

        let mut addr = registers.rsp;

        let nb_args = arguments.len();

        // According to Microsoft Doc "Building C/C++ Programs":
        // > The stack will always be maintained 16-byte aligned, except within the
        // > prolog
        // > (for example, after the return address is pushed), and except where
        // > indicated
        // > in Function Types for a certain class of frame functions.
        //
        // Add padding to be aligned to "16+8" boundary.
        //
        // https://www.gamasutra.com/view/news/178446/Indepth_Windows_x64_ABI_Stack_frames.php
        //
        // This padding on the stack only exists if the maximum number of parameters
        // passed to functions is greater than 4 and is an odd number.
        let effective_nb_args = nb_args.max(4) as u64;
        if (addr - effective_nb_args * 0x8 - 0x8) & 0xf != 8 {
            addr -= 0x8;

            tracing::trace!(
                addr = %Hex(addr),
                "aligning stack"
            );
        }

        // http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
        //
        // First 4 parameters to functions are always passed in registers
        // P1=rcx, P2=rdx, P3=r8, P4=r9
        // 5th parameter onwards (if any) passed via the stack

        // write parameters (5th onwards) into guest's stack
        for index in (4..nb_args).rev() {
            addr -= 0x8;
            vmi.write_u64((addr.into(), registers.cr3.into()), arguments[index])?;

            tracing::trace!(
                index,
                value = %Hex(arguments[index]),
                addr = %Hex(addr),
                "argument (stack)"
            );
        }

        // write the first 4 parameters into registers
        if nb_args > 3 {
            registers.r9 = arguments[3];

            tracing::trace!(
                index = 3,
                value = %Hex(arguments[3]),
                "argument"
            );
        }

        if nb_args > 2 {
            registers.r8 = arguments[2];

            tracing::trace!(
                index = 2,
                value = %Hex(arguments[2]),
                "argument"
            );
        }

        if nb_args > 1 {
            registers.rdx = arguments[1];

            tracing::trace!(
                index = 1,
                value = %Hex(arguments[1]),
                "argument"
            );
        }

        if nb_args > 0 {
            registers.rcx = arguments[0];

            tracing::trace!(
                index = 0,
                value = %Hex(arguments[0]),
                "argument"
            );
        }

        // allocate 0x20 "homing space"
        addr -= 0x20;

        // save the return address
        addr -= 0x8;
        vmi.write_u64((addr.into(), registers.cr3.into()), registers.rip)?;

        // grow the stack
        registers.rsp = addr;

        // set the new instruction pointer
        registers.rip = builder.function_address.into();

        tracing::trace!(
            rsp = %Hex(registers.rsp),
            rip = %Hex(registers.rip),
            "finished preparing function call"
        );

        Ok(())
    }
}

impl<Driver, T, Bridge> InjectorExecutionAdapter<Driver, UserMode, T, Bridge> for WindowsOs<Driver>
where
    Driver: VmiRead<Architecture = Amd64>
        + VmiWrite<Architecture = Amd64>
        + VmiSetProtection<Architecture = Amd64>
        + VmiEventControl<Architecture = Amd64>
        + VmiViewControl<Architecture = Amd64>
        + VmiVmControl<Architecture = Amd64>,
    Bridge: BridgeHandler<Driver, Self, InjectorResultCode>,
{
    type Handler = UserInjectorHandler<Driver, T, Bridge>;
}
