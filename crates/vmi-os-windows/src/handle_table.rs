use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{arch::ArchAdapter, handle_table_entry::WindowsOsHandleTableEntry, WindowsOs};

/// A Windows OS module.
pub struct WindowsOsHandleTable<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    table_code: u64,
}

impl<'a, Driver> WindowsOsHandleTable<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new Windows module object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, table_code: u64) -> Self {
        Self { vmi, table_code }
    }

    /// Performs a lookup in the handle table to find the address of a handle
    /// table entry.
    ///
    /// Implements the multi-level handle table lookup algorithm used by
    /// Windows. Returns the virtual address of the handle table entry.
    pub fn lookup(&self, handle: u64) -> Result<WindowsOsHandleTableEntry<Driver>, VmiError> {
        const SIZEOF_POINTER: u64 = 8;
        const SIZEOF_HANDLE_TABLE_ENTRY: u64 = 16;

        const LOWLEVEL_COUNT: u64 = 256; // (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
        const MIDLEVEL_COUNT: u64 = 512; // (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))

        const LEVEL_CODE_MASK: u64 = 3;
        const HANDLE_VALUE_INC: u64 = 4;

        let level = self.table_code & LEVEL_CODE_MASK;
        let table = Va(self.table_code - level);

        //
        // The 2 least significant bits of a handle are available to the
        // application and are ignored by the system.
        //

        let mut index = handle & !0b11;

        let entry = match level {
            0 => table + index * (SIZEOF_HANDLE_TABLE_ENTRY / HANDLE_VALUE_INC),

            1 => {
                let table2 = table;
                let i = index % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                index -= i;
                let j = index / (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                let table1 = self.vmi.read_va_native(table2 + j * SIZEOF_POINTER)?;

                table1 + i * (SIZEOF_HANDLE_TABLE_ENTRY / HANDLE_VALUE_INC)
            }

            2 => {
                let table3 = table;
                let i = index % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                index -= i;
                let mut k = index / (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                let j = k % MIDLEVEL_COUNT;
                k -= j;
                k /= MIDLEVEL_COUNT;

                let table2 = self.vmi.read_va_native(table3 + k * SIZEOF_POINTER)?;
                let table1 = self.vmi.read_va_native(table2 + j * SIZEOF_POINTER)?;

                table1 + i * (SIZEOF_HANDLE_TABLE_ENTRY / HANDLE_VALUE_INC)
            }

            _ => unreachable!(),
        };

        Ok(WindowsOsHandleTableEntry::new(self.vmi, entry))
    }
}
