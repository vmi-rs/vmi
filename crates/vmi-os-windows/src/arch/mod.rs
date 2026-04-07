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
    fn syscall_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    fn function_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    fn function_return_value(vmi: VmiState<WindowsOs<Driver>>) -> Result<u64, VmiError>;

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError>;

    fn kernel_image_base(vmi: VmiState<WindowsOs<Driver>>) -> Result<Va, VmiError>;

    fn is_page_present_or_transition(
        vmi: VmiState<WindowsOs<Driver>>,
        address: Va,
    ) -> Result<bool, VmiError>;

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
