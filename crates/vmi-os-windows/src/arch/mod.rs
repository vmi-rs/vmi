mod amd64;

use vmi_core::{AccessContext, Architecture, Va, VmiCore, VmiError, VmiState, driver::VmiRead};

pub use self::amd64::{WindowsExceptionVector, WindowsInterrupt, WindowsPageTableEntry};
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
