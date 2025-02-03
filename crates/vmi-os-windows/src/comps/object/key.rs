use once_cell::unsync::OnceCell;
use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{
    super::{macros::impl_offsets, WindowsKeyControlBlock},
    WindowsObject,
};
use crate::{ArchAdapter, WindowsError, WindowsOs};

/// A Windows registry key.
///
/// An open handle to a registry key in kernel mode.
///
/// # Notes
///
/// Multiple `_CM_KEY_BODY` structures can reference a single
/// `_CM_KEY_CONTROL_BLOCK`.
///
/// # Implementation Details
///
/// Corresponds to `_CM_KEY_BODY`.
pub struct WindowsKey<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_CM_KEY_BODY` structure.
    va: Va,

    /// Cached virtual address of the `_CM_KEY_CONTROL_BLOCK` structure.
    key_control_block: OnceCell<Va>,
}

impl<'a, Driver> From<WindowsKey<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsKey<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsKey<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsKey<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows registry key.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            key_control_block: OnceCell::new(),
        }
    }

    /// Returns the name of the key.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_BODY.KeyControlBlock.NameBlock`.
    pub fn name(&self) -> Result<String, VmiError> {
        let kcb = WindowsKeyControlBlock::new(self.vmi, self.key_control_block()?);
        kcb.name()
    }

    /// Constructs the full path of the key.
    ///
    /// # Implementation Details
    ///
    /// This method recursively traverses the parent keys to construct the full path.
    pub fn full_path(&self) -> Result<String, VmiError> {
        let mut kcb = WindowsKeyControlBlock::new(self.vmi, self.key_control_block()?);
        let mut result = kcb.name()?;

        while let Some(parent) = kcb.parent()? {
            let parent_name = parent.name()?;

            result.insert_str(0, "\\");
            result.insert_str(0, &parent_name);
            kcb = parent;
        }

        result.insert(0, '\\');

        Ok(result)
    }

    /// Returns the key control block associated with the key.
    fn key_control_block(&self) -> Result<Va, VmiError> {
        self.key_control_block
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let CM_KEY_BODY = &offsets._CM_KEY_BODY;

                let key_control_block = self
                    .vmi
                    .read_va_native(self.va + CM_KEY_BODY.KeyControlBlock.offset())?;

                if key_control_block.is_null() {
                    return Err(WindowsError::CorruptedStruct("CM_KEY_BODY.KeyControlBlock").into());
                }

                Ok(key_control_block)
            })
            .copied()
    }
}
