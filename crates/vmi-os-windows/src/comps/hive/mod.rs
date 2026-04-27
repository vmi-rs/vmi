mod key_control_block;
mod key_index;
mod key_node;
mod key_value;

use once_cell::unsync::OnceCell;
use vmi_core::{Registers as _, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

pub use self::{
    key_control_block::WindowsKeyControlBlock,
    key_index::WindowsKeyIndex,
    key_node::WindowsKeyNode,
    key_value::{WindowsKeyValue, WindowsKeyValueData, WindowsKeyValueFlags, WindowsKeyValueType},
};
use crate::{
    ArchAdapter, KeyControlBlockIterator, WindowsError, WindowsOs, WindowsOsExt as _, offset,
};

/// Size of the `_HCELL.Size` field (LONG) that prefixes every hive cell.
pub const HCELL_HEADER_SIZE: u64 = 4;

/// Size of a single `HCELL_INDEX`.
///
/// # Implementation Details
///
/// Corresponds to `sizeof(HCELL_INDEX)`.
///
/// # Notes
///
/// `HCELL_INDEX` is defined as `typedef ULONG HCELL_INDEX`.
pub const HCELL_INDEX_SIZE: u64 = 4;

/// Storage class of a hive cell.
///
/// # Implementation Details
///
/// Corresponds to `HSTORAGE_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsHiveStorageType {
    /// Persisted in the hive's backing file.
    Stable,

    /// Held in memory only.
    Volatile,
}

/// Address of a cell within a hive.
///
/// All references inside a hive go through cell indexes. The hive's
/// storage map resolves them to actual addresses.
///
/// # Implementation Details
///
/// Corresponds to `HCELL_INDEX`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WindowsHiveCellIndex(u32);

impl WindowsHiveCellIndex {
    const HCELL_TYPE_MASK: u32 = 0x80000000;
    const HCELL_TYPE_SHIFT: u32 = 31;

    const HCELL_TABLE_MASK: u32 = 0x7fe00000;
    const HCELL_TABLE_SHIFT: u32 = 21;

    const HCELL_BLOCK_MASK: u32 = 0x001ff000;
    const HCELL_BLOCK_SHIFT: u32 = 12;

    const HCELL_OFFSET_MASK: u32 = 0x00000fff;

    /// Sentinel value meaning "no cell".
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `HCELL_NIL`.
    pub const NIL: Self = Self(0xFFFFFFFF);

    /// Wraps a raw `HCELL_INDEX` value.
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns `true` if this index is `HCELL_NIL`.
    pub fn is_nil(&self) -> bool {
        self == &Self::NIL
    }

    /// Returns the raw `HCELL_INDEX` value.
    pub fn raw(&self) -> u32 {
        self.0
    }

    /// Returns the storage class encoded in the index.
    ///
    /// # Implementation Details
    ///
    /// Decoded from bit 31 of `HCELL_INDEX`.
    pub fn storage(&self) -> WindowsHiveStorageType {
        match (self.0 & Self::HCELL_TYPE_MASK) >> Self::HCELL_TYPE_SHIFT {
            0 => WindowsHiveStorageType::Stable,
            1 => WindowsHiveStorageType::Volatile,
            _ => unreachable!(),
        }
    }

    /// Returns the directory index that selects an `_HMAP_TABLE`.
    ///
    /// # Implementation Details
    ///
    /// Decoded from bits 21-30 of `HCELL_INDEX`.
    pub fn table(&self) -> u32 {
        (self.0 & Self::HCELL_TABLE_MASK) >> Self::HCELL_TABLE_SHIFT
    }

    /// Returns the table index that selects an `_HMAP_ENTRY`.
    ///
    /// # Implementation Details
    ///
    /// Decoded from bits 12-20 of `HCELL_INDEX`.
    pub fn block(&self) -> u32 {
        (self.0 & Self::HCELL_BLOCK_MASK) >> Self::HCELL_BLOCK_SHIFT
    }

    /// Returns the cell's byte offset within the resolved block.
    ///
    /// # Implementation Details
    ///
    /// Decoded from bits 0-11 of `HCELL_INDEX`.
    pub fn offset(&self) -> u32 {
        self.0 & Self::HCELL_OFFSET_MASK
    }
}

impl std::fmt::Debug for WindowsHiveCellIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsHiveCellIndex")
            .field("storage", &self.storage())
            .field("table", &self.table())
            .field("block", &self.block())
            .field("offset", &self.offset())
            .finish()
    }
}

/// Top level of a hive's storage map.
///
/// Indexed by [`WindowsHiveCellIndex::table`] to select a
/// [`WindowsHiveMapTable`] during cell resolution.
///
/// # Implementation Details
///
/// Corresponds to `_HMAP_DIRECTORY`.
pub struct WindowsHiveMapDirectory<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_HMAP_DIRECTORY` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsHiveMapDirectory<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsHiveMapDirectory<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows hive map directory.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the table at the given directory slot.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HMAP_DIRECTORY.Directory[index]`.
    pub fn table(&self, index: u32) -> Result<Option<WindowsHiveMapTable<'a, Driver>>, VmiError> {
        let HMAP_DIRECTORY = offset!(self.vmi, _HMAP_DIRECTORY);

        let table = self.vmi.read_va_native(
            self.va
                + HMAP_DIRECTORY.Directory.offset()
                + (index as u64) * self.vmi.registers().address_width() as u64,
        )?;

        if table.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsHiveMapTable::new(self.vmi, table)))
    }
}

/// Second level of a hive's storage map.
///
/// Indexed by [`WindowsHiveCellIndex::block`] to select a
/// [`WindowsHiveMapEntry`] during cell resolution.
///
/// # Implementation Details
///
/// Corresponds to `_HMAP_TABLE`.
pub struct WindowsHiveMapTable<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_HMAP_TABLE` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsHiveMapTable<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsHiveMapTable<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows hive map table.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the entry at the given table slot.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `&_HMAP_TABLE.Table[index]`.
    pub fn entry(&self, index: u32) -> Result<WindowsHiveMapEntry<'a, Driver>, VmiError> {
        let HMAP_TABLE = offset!(self.vmi, _HMAP_TABLE);
        let HMAP_ENTRY = offset!(self.vmi, _HMAP_ENTRY);

        let entry = self.va + HMAP_TABLE.Table.offset() + (index as u64) * HMAP_ENTRY.len() as u64;

        Ok(WindowsHiveMapEntry::new(self.vmi, entry))
    }
}

/// Leaf of a hive's storage map.
///
/// Holds the address of the block that backs a cell.
///
/// # Implementation Details
///
/// Corresponds to `_HMAP_ENTRY`.
pub struct WindowsHiveMapEntry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_HMAP_ENTRY` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsHiveMapEntry<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsHiveMapEntry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows hive map entry.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the address of the block backing this entry.
    //
    // TODO: # Implementation Details, since HMAP_ENTRY can have various
    // formats.
    pub fn block_address(&self) -> Result<Va, VmiError> {
        let HMAP_ENTRY = offset!(self.vmi, _HMAP_ENTRY);

        match (
            &HMAP_ENTRY.BlockAddress,
            &HMAP_ENTRY.BlockOffset,
            &HMAP_ENTRY.PermanentBinAddress,
        ) {
            (Some(BlockAddress), _, _) => self.vmi.read_va_native(self.va + BlockAddress.offset()),
            (None, Some(BlockOffset), Some(PermanentBinAddress)) => {
                let block_offset = self
                    .vmi
                    .read_address_native(self.va + BlockOffset.offset())?;

                let permanent_bin_address = self
                    .vmi
                    .read_address_native(self.va + PermanentBinAddress.offset())?;

                Ok(Va((permanent_bin_address & !0xf) + block_offset))
            }
            _ => Err(WindowsError::CorruptedStruct("_HMAP_ENTRY").into()),
        }

        /*
        let block_offset = self
            .vmi
            .read_address_native(self.va + HMAP_ENTRY.BlockOffset.offset())?;

        let permanent_bin_address = self
            .vmi
            .read_address_native(self.va + HMAP_ENTRY.PermanentBinAddress.offset())?;

        Ok(Va((permanent_bin_address & !0xf) + block_offset))
        */
    }
}

/// The header block of a registry hive.
///
/// Sits at the start of every hive file image, reachable in memory via
/// `_CMHIVE.BaseBlock`. The Configuration Manager validates its `"regf"`
/// magic at hive load before trusting the rest of the hive.
///
/// # Implementation Details
///
/// Corresponds to `_HBASE_BLOCK`.
pub struct WindowsHiveBaseBlock<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_HBASE_BLOCK` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsHiveBaseBlock<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsHiveBaseBlock<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Signature of an `_HBASE_BLOCK` (`"regf"`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `HBASE_BLOCK_SIGNATURE`.
    pub const SIGNATURE: u32 = 0x6667_6572;

    /// Creates a new hive base block.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the signature of the base block.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HBASE_BLOCK.Signature`.
    pub fn signature(&self) -> Result<u32, VmiError> {
        let HBASE_BLOCK = offset!(self.vmi, _HBASE_BLOCK);

        self.vmi.read_u32(self.va + HBASE_BLOCK.Signature.offset())
    }

    /// Returns the cell index of the hive's root key.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HBASE_BLOCK.RootCell`.
    pub fn root_cell_index(&self) -> Result<WindowsHiveCellIndex, VmiError> {
        let HBASE_BLOCK = offset!(self.vmi, _HBASE_BLOCK);

        self.vmi
            .read_u32(self.va + HBASE_BLOCK.RootCell.offset())
            .map(WindowsHiveCellIndex)
    }
}

/// A Windows registry hive.
///
/// A tree of registry keys mounted under the `\REGISTRY` namespace.
///
/// # Implementation Details
///
/// Corresponds to `_CMHIVE`.
pub struct WindowsHive<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_CMHIVE` structure.
    va: Va,

    /// Cached address of the `_HBASE_BLOCK` structure.
    base_block: OnceCell<Va>,
}

impl<Driver> VmiVa for WindowsHive<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsHive<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Signature of an `_HHIVE`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `HHIVE_SIGNATURE`.
    pub const SIGNATURE: u32 = 0xBEE0_BEE0;

    /// Creates a new Windows hive.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            base_block: OnceCell::new(),
        }
    }

    /// Returns the signature of the hive.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HHIVE.Signature`.
    pub fn signature(&self) -> Result<u32, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);

        self.vmi.read_u32(self.va + CMHIVE.Signature.offset())
    }

    /// Returns the hive's base block.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CMHIVE.BaseBlock`.
    pub fn base_block(&self) -> Result<WindowsHiveBaseBlock<'a, Driver>, VmiError> {
        self.base_block
            .get_or_try_init(|| {
                let CMHIVE = offset!(self.vmi, _CMHIVE);

                let base_block = self
                    .vmi
                    .read_va_native(self.va + CMHIVE.BaseBlock.offset())?;

                if base_block.is_null() {
                    return Err(WindowsError::CorruptedStruct("CMHIVE.BaseBlock").into());
                }

                Ok(base_block)
            })
            .copied()
            .map(|va| WindowsHiveBaseBlock::new(self.vmi, va))
    }

    /// Returns the fully-resolved NT path to the on-disk file that backs
    /// this hive.
    ///
    /// Empty for hives that have no backing file, such as the Volatile hive
    /// (`\REGISTRY\MACHINE\HARDWARE`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CMHIVE.FileFullPath`.
    ///
    /// # Examples
    ///
    /// - `\SystemRoot\System32\Config\SOFTWARE`
    /// - `\Device\HarddiskVolume4\Users\alice\NTUSER.DAT`
    /// - `\Device\HarddiskVolume4\ProgramData\Microsoft\...\ActivationStore.dat`
    ///
    /// # Notes
    ///
    /// This operation might fail as the string is allocated from paged pool.
    pub fn file_full_path(&self) -> Result<String, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);

        self.vmi
            .os()
            .read_unicode_string(self.va + CMHIVE.FileFullPath.offset())
    }

    /// Returns the path exactly as the caller supplied it to `NtLoadKey*`.
    ///
    /// Unlike `CMHIVE.FileFullPath`, this string is **not** canonicalized.
    /// It may still contain `\??\`, drive-letter prefixes (`\??\C:\Users\...`),
    /// per-session device namespaces, or relative-to-`RootDirectory` fragments.
    ///
    /// Empty for hives that were never loaded via `NtLoadKey*`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CMHIVE.FileUserName`.
    ///
    /// # Examples
    ///
    /// - `\SystemRoot\System32\Config\DEFAULT`
    /// - `\??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT`
    /// - `\??\C:\Users\...\ntuser.dat`
    ///
    /// # Notes
    ///
    /// This operation might fail as the string is allocated from paged pool.
    pub fn file_user_name(&self) -> Result<String, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);

        self.vmi
            .os()
            .read_unicode_string(self.va + CMHIVE.FileUserName.offset())
    }

    /// Returns the path at which this hive is mounted inside the `\REGISTRY`
    /// object namespace.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CMHIVE.HiveRootPath`.
    ///
    /// # Examples
    /// - `\REGISTRY\MACHINE\SYSTEM`
    /// - `\REGISTRY\MACHINE\HARDWARE`
    /// - `\REGISTRY\USER\S-1-5-21-...`
    ///
    /// # Notes
    ///
    /// This operation might fail as the string is allocated from paged pool.
    pub fn hive_root_path(&self) -> Result<String, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);

        self.vmi
            .os()
            .read_unicode_string(self.va + CMHIVE.HiveRootPath.offset())
    }

    /// Returns the storage directory for the given storage class.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CMHIVE.Storage[ty].Map`.
    pub fn storage_directory(
        &self,
        ty: WindowsHiveStorageType,
    ) -> Result<Option<WindowsHiveMapDirectory<'a, Driver>>, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);
        let DUAL = offset!(self.vmi, _DUAL);

        let storage = self.va + CMHIVE.Storage.offset() + (ty as u64) * DUAL.len() as u64;
        let map = self.vmi.read_va_native(storage + DUAL.Map.offset())?;

        if map.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsHiveMapDirectory::new(self.vmi, map)))
    }

    /// Returns the hive format version from `_HHIVE.Version`.
    ///
    /// The kernel uses this as part of its big-data discriminator.
    ///
    /// In-memory hives created via `HINIT_CREATE` (the volatile
    /// `\REGISTRY\MACHINE\HARDWARE` hive being the canonical case) are pinned
    /// at version 3, which is below the big-data threshold. So all of their
    /// values are read from a single cell regardless of size.
    pub fn version(&self) -> Result<u32, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);

        self.vmi.read_u32(self.va + CMHIVE.Version.offset())
    }

    /// Returns the cell index of the hive's root key.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CMHIVE.BaseBlock->RootCell`.
    pub fn root_cell_index(&self) -> Result<WindowsHiveCellIndex, VmiError> {
        self.base_block()?.root_cell_index()
    }

    /// Resolves a cell index to the address of its payload.
    ///
    /// The payload can be a `_CM_KEY_NODE`, `_CM_KEY_VALUE`, `_CM_KEY_INDEX`,
    /// `_CM_KEY_SECURITY`, `_CM_BIG_DATA`, a value list, or a raw blob such
    /// as a name string or value data.
    ///
    /// The index does not carry the type, so the caller must already know
    /// which kind of cell it requested.
    ///
    /// # Implementation Details
    ///
    /// Flat hives index directly into the `CMHIVE.BaseBlock`.
    /// Otherwise walks `_CMHIVE.Storage[type].Map` through directory, table,
    /// and entry.
    ///
    /// The returned address points past the cell's `_HCELL.Size` header.
    pub fn cell(&self, index: WindowsHiveCellIndex) -> Result<Option<Va>, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);
        let HBASE_BLOCK = offset!(self.vmi, _HBASE_BLOCK);

        let flat = self.vmi.read_field(self.va, &CMHIVE.Flat)?;
        let flat = CMHIVE.Flat.extract(flat) != 0;

        // Flat hive
        // Cell index is a byte offset into the hive image, past the base block.
        if flat {
            let base = self
                .vmi
                .read_va_native(self.va + CMHIVE.BaseBlock.offset())?;

            return Ok(Some(
                base + HBASE_BLOCK.len() as u64 + (index.0 as u64) + HCELL_HEADER_SIZE,
            ));
        }

        let directory = match self.storage_directory(index.storage())? {
            Some(directory) => directory,
            None => return Ok(None),
        };

        let table = match directory.table(index.table())? {
            Some(table) => table,
            None => return Ok(None),
        };

        let entry = table.entry(index.block())?;

        Ok(Some(
            entry.block_address()? + (index.offset() as u64) + HCELL_HEADER_SIZE,
        ))
    }

    /// Returns the root key of this hive.
    pub fn root_key(&self) -> Result<WindowsKeyNode<'a, Driver>, VmiError> {
        // A mounted hive always has a valid `_HBASE_BLOCK.RootCell`. The
        // sentinel value `HCELL_NIL` only appears at hive creation.
        let index = self.root_cell_index()?;
        match self.cell(index)? {
            Some(va) => Ok(WindowsKeyNode::new(self.vmi, self.va, va)),
            None => Err(WindowsError::CorruptedStruct("CMHIVE.BaseBlock.RootCell").into()),
        }
    }

    /// Resolves a path relative to the hive's root key.
    ///
    /// Convenience for `self.root_key()?.lookup(path)`. The path is treated
    /// as relative regardless of leading `\\`, so absolute strings such as
    /// `\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft` are not stripped of their
    /// hive-root prefix.
    pub fn lookup(
        &self,
        path: impl AsRef<str>,
    ) -> Result<Option<WindowsKeyNode<'a, Driver>>, VmiError> {
        self.root_key()?.lookup(path)
    }

    /// Returns an iterator over the key control blocks cached in this
    /// hive's `KcbCacheTable`.
    ///
    /// The kernel maintains the cache opportunistically. The set of cached
    /// keys reflects what has been opened recently, not the hive's contents.
    /// Discarded entries are still yielded.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CMHIVE.KcbCacheTable`.
    pub fn kcbs(&self) -> Result<KeyControlBlockIterator<'a, Driver>, VmiError> {
        let CMHIVE = offset!(self.vmi, _CMHIVE);

        let cache_va = self
            .vmi
            .read_va_native(self.va + CMHIVE.KcbCacheTable.offset())?;

        if cache_va.is_null() {
            return Ok(KeyControlBlockIterator::empty(self.vmi));
        }

        let bucket_count = self
            .vmi
            .read_u32(self.va + CMHIVE.KcbCacheTableSize.offset())?;

        Ok(KeyControlBlockIterator::new(
            self.vmi,
            cache_va,
            bucket_count,
        ))
    }
}
