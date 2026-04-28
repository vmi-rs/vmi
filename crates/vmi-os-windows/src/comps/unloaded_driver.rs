use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _};

//
// The `_UNLOADED_DRIVER` structure is not present in the PDB symbols.
// However, its layout is hardcoded in the dbgeng.dll, so... we'll hardcode
// it too.
//

struct Field {
    offset: u64,
}

impl Field {
    const fn offset(&self) -> u64 {
        self.offset
    }
}

#[expect(non_camel_case_types)]
struct _UNLOADED_DRIVERS {
    Name: Field,         // _UNICODE_STRING
    StartAddress: Field, // PVOID
    EndAddress: Field,   // PVOID
    CurrentTime: Field,  // LARGE_INTEGER
}

const UNLOADED_DRIVERS: _UNLOADED_DRIVERS = _UNLOADED_DRIVERS {
    Name: Field { offset: 0x0000 },         // 32-bit: 0x0000
    StartAddress: Field { offset: 0x0010 }, // 32-bit: 0x0008
    EndAddress: Field { offset: 0x0018 },   // 32-bit: 0x000c
    CurrentTime: Field { offset: 0x0020 },  // 32-bit: 0x0010
};

/// A record of a driver that has been unloaded from the kernel.
///
/// Windows keeps a fixed-size circular buffer of these records so that
/// crash-time stack frames pointing into freed driver code can still be
/// attributed to a name and address range.
///
/// # Implementation Details
///
/// Corresponds to `_UNLOADED_DRIVERS`.
///
/// The struct is not present in the PDB, so the field offsets are hardcoded
/// against the layout that `dbgeng.dll` assumes.
pub struct WindowsUnloadedDriver<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_UNLOADED_DRIVERS` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsUnloadedDriver<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsUnloadedDriver<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows unloaded driver record.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the unloaded driver's name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_UNLOADED_DRIVERS.Name`.
    pub fn name(&self) -> Result<String, VmiError> {
        self.vmi
            .os()
            .read_unicode_string(self.va + UNLOADED_DRIVERS.Name.offset())
    }

    /// Returns the start address of the driver's image.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_UNLOADED_DRIVERS.StartAddress`.
    pub fn start_address(&self) -> Result<Va, VmiError> {
        self.vmi
            .read_va_native(self.va + UNLOADED_DRIVERS.StartAddress.offset())
    }

    /// Returns the end address of the driver's image.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_UNLOADED_DRIVERS.EndAddress`.
    pub fn end_address(&self) -> Result<Va, VmiError> {
        self.vmi
            .read_va_native(self.va + UNLOADED_DRIVERS.EndAddress.offset())
    }

    /// Returns the time the driver was unloaded.
    ///
    /// The value is Windows NT system time.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_UNLOADED_DRIVERS.CurrentTime`.
    pub fn current_time(&self) -> Result<u64, VmiError> {
        self.vmi
            .read_u64(self.va + UNLOADED_DRIVERS.CurrentTime.offset())
    }
}
