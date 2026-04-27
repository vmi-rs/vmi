use once_cell::unsync::OnceCell;
use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{WindowsHive, WindowsHiveCellIndex, WindowsKeyNode};
use crate::{ArchAdapter, WindowsError, WindowsOs, offset};

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
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_CM_KEY_CONTROL_BLOCK` structure.
    va: Va,

    /// Cached address of the `_CM_NAME_CONTROL_BLOCK` structure.
    name_block: OnceCell<Va>,
}

impl<Driver> VmiVa for WindowsKeyControlBlock<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsKeyControlBlock<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows key control block.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            name_block: OnceCell::new(),
        }
    }

    /// Returns the reference count of the key control block.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_CONTROL_BLOCK.RefCount`.
    pub fn refcount(&self) -> Result<u64, VmiError> {
        let CM_KEY_CONTROL_BLOCK = offset!(self.vmi, _CM_KEY_CONTROL_BLOCK);

        let refcount = self
            .vmi
            .read_field(self.va, &CM_KEY_CONTROL_BLOCK.RefCount)?;

        Ok(refcount)
    }

    /// Returns whether the key control block has been marked as discarded.
    ///
    /// A discarded KCB no longer backs a live key node. The cache slot is
    /// kept alive only until its reference count drops to zero.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_CONTROL_BLOCK.Discarded` or
    /// `_CM_KEY_CONTROL_BLOCK.Delete`.
    pub fn discarded(&self) -> Result<bool, VmiError> {
        let CM_KEY_CONTROL_BLOCK = offset!(self.vmi, _CM_KEY_CONTROL_BLOCK);

        let discarded = self
            .vmi
            .read_field(self.va, &CM_KEY_CONTROL_BLOCK.Discarded)?;

        Ok(CM_KEY_CONTROL_BLOCK.Discarded.extract(discarded) != 0)
    }

    /// Returns the parent key control block.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_CONTROL_BLOCK.ParentKcb`.
    pub fn parent(&self) -> Result<Option<WindowsKeyControlBlock<'a, Driver>>, VmiError> {
        let CM_KEY_CONTROL_BLOCK = offset!(self.vmi, _CM_KEY_CONTROL_BLOCK);

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
    /// read as an ASCII string. Otherwise, the name is read as a UTF-16
    /// string.
    pub fn name(&self) -> Result<String, VmiError> {
        let CM_NAME_CONTROL_BLOCK = offset!(self.vmi, _CM_NAME_CONTROL_BLOCK);

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
            self.vmi.read_string_utf16_limited(
                name_block + CM_NAME_CONTROL_BLOCK.Name.offset(),
                name_length as usize,
            )
        }
    }

    /// Returns the name control block associated with the key control block.
    fn name_block(&self) -> Result<Va, VmiError> {
        self.name_block
            .get_or_try_init(|| {
                let CM_KEY_CONTROL_BLOCK = offset!(self.vmi, _CM_KEY_CONTROL_BLOCK);

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

    /// Returns the hive that owns this key control block.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_CONTROL_BLOCK.KeyHive`.
    pub fn hive(&self) -> Result<Option<WindowsHive<'a, Driver>>, VmiError> {
        let CM_KEY_CONTROL_BLOCK = offset!(self.vmi, _CM_KEY_CONTROL_BLOCK);

        let key_hive = self
            .vmi
            .read_va_native(self.va + CM_KEY_CONTROL_BLOCK.KeyHive.offset())?;

        if key_hive.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsHive::new(self.vmi, key_hive)))
    }

    /// Returns the key node backing this key control block.
    ///
    /// # Implementation Details
    ///
    /// Resolves `_CM_KEY_CONTROL_BLOCK.KeyCell` against
    /// `_CM_KEY_CONTROL_BLOCK.KeyHive`.
    pub fn key_node(&self) -> Result<Option<WindowsKeyNode<'a, Driver>>, VmiError> {
        let CM_KEY_CONTROL_BLOCK = offset!(self.vmi, _CM_KEY_CONTROL_BLOCK);

        let hive = match self.hive()? {
            Some(hive) => hive,
            None => return Ok(None),
        };

        let key_cell = self
            .vmi
            .read_u32(self.va + CM_KEY_CONTROL_BLOCK.KeyCell.offset())?;

        if key_cell == 0 {
            return Ok(None);
        }

        Ok(hive
            .cell(WindowsHiveCellIndex::new(key_cell))?
            .map(|va| WindowsKeyNode::new(self.vmi, hive.va, va)))
    }
}
