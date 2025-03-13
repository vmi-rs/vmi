use once_cell::unsync::OnceCell;
use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{WindowsObject, macros::impl_offsets};
use crate::{ArchAdapter, WindowsError, WindowsOs};

/// A Windows registry key control block.
///
/// A registry key in the kernel mode registry cache. It helps the Configuration
/// Manager manage registry keys efficiently by avoiding redundant registry
/// lookups.
///
/// # Implementation Details
///
/// Corresponds to `_CM_KEY_CONTROL_BLOCK`.
pub struct WindowsKeyControlBlock<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_CM_KEY_CONTROL_BLOCK` structure.
    va: Va,

    /// Cached virtual address of the `_CM_NAME_CONTROL_BLOCK` structure.
    name_block: OnceCell<Va>,
}

impl<'a, Driver> From<WindowsKeyControlBlock<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsKeyControlBlock<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsKeyControlBlock<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsKeyControlBlock<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows key control block.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            name_block: OnceCell::new(),
        }
    }

    /// Returns the parent key control block.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_CONTROL_BLOCK.ParentKcb`.
    pub fn parent(&self) -> Result<Option<WindowsKeyControlBlock<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let CM_KEY_CONTROL_BLOCK = &offsets._CM_KEY_CONTROL_BLOCK;

        let parent_kcb = self
            .vmi
            .read_va_native(self.va + CM_KEY_CONTROL_BLOCK.ParentKcb.offset())?;

        if parent_kcb.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsKeyControlBlock::new(self.vmi, parent_kcb)))
    }

    /// Returns the name of the key.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_CONTROL_BLOCK.NameBlock`.
    /// If the `_CM_NAME_CONTROL_BLOCK.Compressed` field is set, the name is
    /// read as a multibyte string. Otherwise, the name is read as a UTF-16
    /// string.
    pub fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let CM_NAME_CONTROL_BLOCK = &offsets._CM_NAME_CONTROL_BLOCK;

        let name_block = self.name_block()?;

        let compressed = self
            .vmi
            .read_field(name_block, &CM_NAME_CONTROL_BLOCK.Compressed)?;

        let compressed = CM_NAME_CONTROL_BLOCK.Compressed.extract(compressed) != 0;

        let name_length = self
            .vmi
            .read_field(name_block, &CM_NAME_CONTROL_BLOCK.NameLength)?;

        if compressed {
            self.vmi.read_string_limited(
                name_block + CM_NAME_CONTROL_BLOCK.Name.offset(),
                name_length as usize,
            )
        }
        else {
            self.vmi.read_wstring_limited(
                name_block + CM_NAME_CONTROL_BLOCK.Name.offset(),
                name_length as usize,
            )
        }
    }

    /// Returns the name control block associated with the key control block.
    fn name_block(&self) -> Result<Va, VmiError> {
        self.name_block
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let CM_KEY_CONTROL_BLOCK = &offsets._CM_KEY_CONTROL_BLOCK;

                let name_block = self
                    .vmi
                    .read_va_native(self.va + CM_KEY_CONTROL_BLOCK.NameBlock.offset())?;

                if name_block.is_null() {
                    return Err(
                        WindowsError::CorruptedStruct("CM_KEY_CONTROL_BLOCK.NameBlock").into(),
                    );
                }

                Ok(name_block)
            })
            .copied()
    }
}
