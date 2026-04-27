use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, WindowsError, WindowsOs, offset};

/// A subkey index cell of a registry key.
///
/// The Configuration Manager walks `_CM_KEY_INDEX` cells to enumerate a
/// `_CM_KEY_NODE`'s children. Four variants share the same shape and are
/// distinguished by the signature. `il`, `fl`, and `hl` are leaf lists.
/// `ir` is a root index list whose entries point at leaf lists.
///
/// # Implementation Details
///
/// Corresponds to `_CM_KEY_INDEX`.
pub struct WindowsKeyIndex<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_CM_KEY_INDEX` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsKeyIndex<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsKeyIndex<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Signature of a plain leaf list (`il`).
    ///
    /// Each entry is a single `HCELL_INDEX`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `CM_KEY_INDEX_LEAF`.
    pub const INDEX_LEAF_SIGNATURE: u16 = 0x696c;

    /// Signature of a fast leaf list (`fl`).
    ///
    /// Each entry pairs an `HCELL_INDEX` with a 4-byte name hint.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `CM_KEY_FAST_LEAF`.
    pub const FAST_LEAF_SIGNATURE: u16 = 0x666c;

    /// Signature of a hash leaf list (`hl`).
    ///
    /// Each entry pairs an `HCELL_INDEX` with an NT name hash.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `CM_KEY_HASH_LEAF`.
    pub const HASH_LEAF_SIGNATURE: u16 = 0x686c;

    /// Signature of a root index list (`ir`).
    ///
    /// Each entry is an `HCELL_INDEX` pointing to a leaf list.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `CM_KEY_INDEX_ROOT`.
    pub const INDEX_ROOT_SIGNATURE: u16 = 0x6972;

    /// Creates a new key index.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the signature of the index.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_INDEX.Signature`.
    pub fn signature(&self) -> Result<u16, VmiError> {
        let CM_KEY_INDEX = offset!(self.vmi, _CM_KEY_INDEX);

        self.vmi.read_u16(self.va + CM_KEY_INDEX.Signature.offset())
    }

    /// Returns the number of entries in the list.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_INDEX.Count`.
    pub fn count(&self) -> Result<u16, VmiError> {
        let CM_KEY_INDEX = offset!(self.vmi, _CM_KEY_INDEX);

        self.vmi.read_u16(self.va + CM_KEY_INDEX.Count.offset())
    }

    /// Returns the address of the first entry in the index.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_INDEX.List`.
    pub fn list(&self) -> Result<Va, VmiError> {
        let CM_KEY_INDEX = offset!(self.vmi, _CM_KEY_INDEX);

        Ok(self.va + CM_KEY_INDEX.List.offset())
    }

    /// Returns the byte size of one entry.
    ///
    /// 4 bytes for `il` and `ir`. 8 bytes for `fl` and `hl`, which pair
    /// each `HCELL_INDEX` with a 4-byte name hint or hash.
    ///
    /// Reads the signature. Prefer [`entry_size_for`] when the signature is
    /// already in scope.
    ///
    /// [`entry_size_for`]: Self::entry_size_for
    pub fn entry_size(&self) -> Result<u64, VmiError> {
        Self::entry_size_for(self.signature()?)
    }

    /// Returns the byte size of one entry for a given index signature.
    ///
    /// Variant of [`entry_size`] that takes the signature directly, avoiding
    /// the read.
    ///
    /// [`entry_size`]: Self::entry_size
    pub fn entry_size_for(signature: u16) -> Result<u64, VmiError> {
        match signature {
            // `_CM_KEY_INDEX.List` is `HCELL_INDEX[]`, sizeof(HCELL_INDEX) == 4.
            Self::INDEX_LEAF_SIGNATURE | Self::INDEX_ROOT_SIGNATURE => Ok(4),
            // `_CM_KEY_FAST_INDEX.List` is `CM_INDEX[]`, sizeof(CM_INDEX) == 8.
            Self::FAST_LEAF_SIGNATURE | Self::HASH_LEAF_SIGNATURE => Ok(8),
            _ => Err(WindowsError::CorruptedStruct("CM_KEY_INDEX.Signature").into()),
        }
    }
}
