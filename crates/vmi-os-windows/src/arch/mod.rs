mod amd64;
mod context;

use vmi_core::{AccessContext, Architecture, Va, VmiCore, VmiError, VmiState, driver::VmiRead};

pub use self::{
    amd64::{WindowsExceptionVector, WindowsInterrupt, WindowsPageTableEntry},
    context::{
        CONTEXT_AMD64, CONTEXT_X86, FLOATING_SAVE_AREA, KDESCRIPTOR_AMD64, KDESCRIPTOR_X86,
        KSPECIAL_REGISTERS_AMD64, KSPECIAL_REGISTERS_X86, M128A, MAXIMUM_SUPPORTED_EXTENSION,
        SIZE_OF_80387_REGISTERS, WindowsContext, WindowsRegistersAdapter, WindowsSpecialRegisters,
        XSAVE_FORMAT,
    },
};
use crate::{WindowsKernelInformation, WindowsOs, WindowsOsExt};

/// Architecture-specific Windows functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiRead<Architecture = Self>,
{
    /// Reads a syscall argument by index from the current register state.
    ///
    /// Index 0 is the first argument.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: Arguments 0-3 come from registers (`R10`, `RDX`, `R8`,
    ///   `R9`); subsequent arguments are read from the stack.
    fn syscall_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    /// Reads a function-call argument by index from the current register state.
    ///
    /// Unlike [`syscall_argument`](Self::syscall_argument), this follows the
    /// standard calling convention.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: Microsoft x64 calling convention (`RCX`, `RDX`, `R8`,
    ///   `R9`) in long mode, stdcall (stack-based) in compatibility mode.
    fn function_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    /// Reads the return value of the most recent function call.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RAX`
    fn function_return_value(vmi: VmiState<WindowsOs<Driver>>) -> Result<u64, VmiError>;

    /// Locates the Windows kernel image by scanning backward from the
    /// syscall entry point.
    ///
    /// Returns the kernel's base address, OS version, and CodeView debug
    /// information if found.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: Scans backward from `MSR_LSTAR` (up to 32 MB)
    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError>;

    /// Returns the kernel image base address, caching the result for
    /// subsequent calls.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `MSR_LSTAR - KiSystemCall64`
    fn kernel_image_base(vmi: VmiState<WindowsOs<Driver>>) -> Result<Va, VmiError>;

    /// Checks whether a virtual address maps to a page that is either
    /// present or in the Windows transition state (soft fault, still
    /// resident in physical memory).
    fn is_page_present_or_transition(
        vmi: VmiState<WindowsOs<Driver>>,
        address: Va,
    ) -> Result<bool, VmiError>;

    /// Returns the virtual address of the Kernel Processor Control Region
    /// (KPCR) for the current CPU.
    fn current_kpcr(vmi: VmiState<WindowsOs<Driver>>) -> Va;
}

/// Pointer-width-dependent operations for reading Windows structures.
///
/// Windows structures contain pointer-sized fields (`PVOID`, `UNICODE_STRING`,
/// `LIST_ENTRY`, ...) whose layout differs between 32-bit and 64-bit processes.
/// This trait abstracts over the pointer width so that structure accessors can
/// be generic over both layouts.
pub trait StructLayout {
    /// The address width (i.e. pointer size) in bytes.
    const ADDRESS_WIDTH: u64;

    /// Reads a pointer-sized virtual address from guest memory.
    fn read_va<Driver>(
        vmi: VmiState<WindowsOs<Driver>>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Va, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>;

    /// Reads a `UNICODE_STRING` from guest memory.
    fn read_unicode_string<Driver>(
        vmi: VmiState<WindowsOs<Driver>>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>;
}

/// 32-bit structure layout.
pub struct StructLayout32;

impl StructLayout for StructLayout32 {
    const ADDRESS_WIDTH: u64 = 4;

    fn read_va<Driver>(
        vmi: VmiState<WindowsOs<Driver>>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Va, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        vmi.core().read_va32(ctx)
    }

    fn read_unicode_string<Driver>(
        vmi: VmiState<WindowsOs<Driver>>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        vmi.os().read_unicode_string32_in(ctx)
    }
}

/// 64-bit structure layout.
pub struct StructLayout64;

impl StructLayout for StructLayout64 {
    const ADDRESS_WIDTH: u64 = 8;

    fn read_va<Driver>(
        vmi: VmiState<WindowsOs<Driver>>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Va, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        vmi.core().read_va64(ctx)
    }

    fn read_unicode_string<Driver>(
        vmi: VmiState<WindowsOs<Driver>>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        vmi.os().read_unicode_string64_in(ctx)
    }
}
