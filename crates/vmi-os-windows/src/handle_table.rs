use once_cell::unsync::OnceCell;
use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{
    arch::ArchAdapter, handle_table_entry::WindowsHandleTableEntry, macros::impl_offsets,
    WindowsOs,
};

/// A Windows OS module.
pub struct WindowsHandleTable<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
    table_code: OnceCell<u64>,
    next_handle_needing_pool: OnceCell<u64>,
}

impl<Driver> From<WindowsHandleTable<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsHandleTable<Driver>) -> Self {
        value.va
    }
}

impl<'a, Driver> WindowsHandleTable<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows module object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            table_code: OnceCell::new(),
            next_handle_needing_pool: OnceCell::new(),
        }
    }

    /// Returns the table code of the handle table.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HANDLE_TABLE.TableCode`.
    pub fn table_code(&self) -> Result<u64, VmiError> {
        Ok(self
            .table_code
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let HANDLE_TABLE = &offsets._HANDLE_TABLE;

                self.vmi.read_field(self.va, &HANDLE_TABLE.TableCode)
            })
            .copied()?)
    }

    /// Returns the next handle needing pool.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HANDLE_TABLE.NextHandleNeedingPool`.
    pub fn next_handle_needing_pool(&self) -> Result<u64, VmiError> {
        Ok(self
            .next_handle_needing_pool
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let HANDLE_TABLE = &offsets._HANDLE_TABLE;

                self.vmi
                    .read_field(self.va, &HANDLE_TABLE.NextHandleNeedingPool)
            })
            .copied()?)
    }

    /// Performs a lookup in the handle table to find the address of a handle
    /// table entry.
    ///
    /// Implements the multi-level handle table lookup algorithm used by
    /// Windows. Returns the virtual address of the handle table entry.
    pub fn lookup(
        &self,
        handle: u64,
    ) -> Result<Option<WindowsHandleTableEntry<'a, Driver>>, VmiError> {
        const SIZEOF_POINTER: u64 = 8;
        const SIZEOF_HANDLE_TABLE_ENTRY: u64 = 16;

        const LOWLEVEL_COUNT: u64 = 256; // (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
        const MIDLEVEL_COUNT: u64 = 512; // (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))

        const LEVEL_CODE_MASK: u64 = 3;
        const HANDLE_VALUE_INC: u64 = 4;

        //
        // The 2 least significant bits of a handle are available to the
        // application and are ignored by the system.
        //

        let mut index = handle & !0b11;

        if index >= self.next_handle_needing_pool()? {
            return Ok(None);
        }

        let table_code = self.table_code()?;
        let level = table_code & LEVEL_CODE_MASK;
        let table = Va(table_code - level);

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

        Ok(Some(WindowsHandleTableEntry::new(self.vmi, entry)))
    }
}
