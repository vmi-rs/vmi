use vmi_core::{Hex, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{HCELL_INDEX_SIZE, WindowsHive, WindowsHiveCellIndex};
use crate::{ArchAdapter, KeyValueIterator, WindowsError, WindowsOs, offset};

/// Marker in `_CM_KEY_VALUE.DataLength` indicating that the data is stored
/// inline in the `Data` field itself.
const CM_KEY_VALUE_SPECIAL_SIZE: u32 = 0x8000_0000;

/// Threshold above which a value may be stored as `_CM_BIG_DATA`.
///
/// Whether it actually is depends on the hive's minor version.
/// See [`data_bytes`] for the full discriminator.
///
/// [`data_bytes`]: WindowsKeyValue::data_bytes
const CM_KEY_VALUE_BIG: u32 = 0x3FD8;

/// First hive version that supports `_CM_BIG_DATA`.
///
/// Hives at version 3 or below store every non-inline value in a single cell,
/// regardless of size.
const HSYS_VERSION_4: u32 = 4;

/// Signature of a `_CM_BIG_DATA` cell.
const CM_BIG_DATA_SIGNATURE: u16 = 0x6264; // "db"

/// A Windows registry value.
///
/// A named value attached to a registry key. Values are the leaves of the
/// registry tree - the actual settings that callers read.
///
/// # Implementation Details
///
/// Corresponds to `_CM_KEY_VALUE`.
pub struct WindowsKeyValue<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the owning `_CMHIVE`.
    hive_va: Va,

    /// Address of the `_CM_KEY_VALUE` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsKeyValue<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

bitflags::bitflags! {
    /// Flags stored in `_CM_KEY_VALUE.Flags`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct WindowsKeyValueFlags: u16 {
        /// The value name is stored in a compressed (ASCII) form.
        const COMP_NAME = 0x0001;
    }
}

/// Registry value type.
///
/// Corresponds to `REG_*` constants in the Windows API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsKeyValueType {
    /// No defined type.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_NONE`.
    None,

    /// Null-terminated UTF-16 string.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_SZ`.
    Sz,

    /// UTF-16 string containing unexpanded `%VAR%` references.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_EXPAND_SZ`.
    ExpandSz,

    /// Binary data in any form.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_BINARY`.
    Binary,

    /// A 32-bit number.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_DWORD`.
    Dword,

    /// A 32-bit number in big-endian format.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_DWORD_BIG_ENDIAN`.
    DwordBigEndian,

    /// Symbolic link stored as a UTF-16 string.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_LINK`.
    Link,

    /// Sequence of null-terminated UTF-16 strings, terminated by an empty string.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_MULTI_SZ`.
    MultiSz,

    /// Device-driver resource list (opaque bytes).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_RESOURCE_LIST`.
    ResourceList,

    /// Device-driver resource descriptor (opaque bytes).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_FULL_RESOURCE_DESCRIPTOR`.
    FullResourceDescriptor,

    /// Device-driver resource requirements list (opaque bytes).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_RESOURCE_REQUIREMENTS_LIST`.
    ResourceRequirementsList,

    /// `REG_QWORD` (little-endian 64-bit integer).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `REG_QWORD`.
    Qword,

    /// Type not recognized by this crate.
    Unknown(u32),
}

impl From<WindowsKeyValueType> for u32 {
    fn from(value: WindowsKeyValueType) -> Self {
        match value {
            WindowsKeyValueType::None => 0,
            WindowsKeyValueType::Sz => 1,
            WindowsKeyValueType::ExpandSz => 2,
            WindowsKeyValueType::Binary => 3,
            WindowsKeyValueType::Dword => 4,
            WindowsKeyValueType::DwordBigEndian => 5,
            WindowsKeyValueType::Link => 6,
            WindowsKeyValueType::MultiSz => 7,
            WindowsKeyValueType::ResourceList => 8,
            WindowsKeyValueType::FullResourceDescriptor => 9,
            WindowsKeyValueType::ResourceRequirementsList => 10,
            WindowsKeyValueType::Qword => 11,
            WindowsKeyValueType::Unknown(raw) => raw,
        }
    }
}

impl From<u32> for WindowsKeyValueType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed registry value data, dispatched on [`WindowsKeyValueType`].
///
/// For string variants the trailing NUL (if any) is stripped.
/// For [`WindowsKeyValueData::MultiSz`] each element is likewise stripped
/// and the empty terminator is dropped.
#[derive(Debug, Clone)]
pub enum WindowsKeyValueData {
    /// `REG_NONE`, or any value whose declared length is zero.
    None,

    /// `REG_SZ`.
    Sz(String),

    /// `REG_EXPAND_SZ`.
    ExpandSz(String),

    /// `REG_BINARY`.
    Binary(Vec<u8>),

    /// `REG_DWORD`.
    Dword(u32),

    /// `REG_DWORD_BIG_ENDIAN`.
    DwordBigEndian(u32),

    /// `REG_LINK`.
    Link(String),

    /// `REG_MULTI_SZ`.
    MultiSz(Vec<String>),

    /// `REG_RESOURCE_LIST`.
    ResourceList(Vec<u8>),

    /// `REG_FULL_RESOURCE_DESCRIPTOR`.
    FullResourceDescriptor(Vec<u8>),

    /// `REG_RESOURCE_REQUIREMENTS_LIST`.
    ResourceRequirementsList(Vec<u8>),

    /// `REG_QWORD`.
    Qword(u64),

    /// Value whose type was not recognized.
    Unknown {
        /// Raw `REG_*` type code.
        ty: u32,

        /// Raw data bytes as stored in the hive.
        bytes: Vec<u8>,
    },
}

impl WindowsKeyValueData {
    /// Decodes raw value bytes into the typed enum.
    fn from_raw(value_type: WindowsKeyValueType, bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::from_empty(value_type);
        }

        /// Decodes a UTF-16 byte buffer into a `String`, stripping a single trailing
        /// NUL if present.
        fn decode_utf16(bytes: &[u8]) -> String {
            let units = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            let end = units.iter().rposition(|&ch| ch != 0).map_or(0, |i| i + 1);
            String::from_utf16_lossy(&units[..end])
        }

        /// Decodes a UTF-16 `REG_MULTI_SZ` buffer into a vector of strings, dropping
        /// empty elements that mark the terminator.
        fn decode_utf16_multi(bytes: &[u8]) -> Vec<String> {
            let units = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();

            units
                .split(|&ch| ch == 0)
                .filter(|slice| !slice.is_empty())
                .map(String::from_utf16_lossy)
                .collect()
        }

        /// Decodes the first four bytes of `bytes` as a little-endian `u32`, padding
        /// with zeros if the buffer is short.
        fn decode_u32_le(bytes: &[u8]) -> u32 {
            let mut buffer = [0u8; 4];
            let n = bytes.len().min(4);
            buffer[..n].copy_from_slice(&bytes[..n]);
            u32::from_le_bytes(buffer)
        }

        /// Decodes the first four bytes of `bytes` as a big-endian `u32`, padding
        /// with zeros if the buffer is short.
        fn decode_u32_be(bytes: &[u8]) -> u32 {
            let mut buffer = [0u8; 4];
            let n = bytes.len().min(4);
            buffer[..n].copy_from_slice(&bytes[..n]);
            u32::from_be_bytes(buffer)
        }

        /// Decodes the first eight bytes of `bytes` as a little-endian `u64`,
        /// padding with zeros if the buffer is short.
        fn decode_u64_le(bytes: &[u8]) -> u64 {
            let mut buffer = [0u8; 8];
            let n = bytes.len().min(8);
            buffer[..n].copy_from_slice(&bytes[..n]);
            u64::from_le_bytes(buffer)
        }

        match value_type {
            WindowsKeyValueType::None => Self::None,
            WindowsKeyValueType::Sz => Self::Sz(decode_utf16(&bytes)),
            WindowsKeyValueType::ExpandSz => Self::ExpandSz(decode_utf16(&bytes)),
            WindowsKeyValueType::Link => Self::Link(decode_utf16(&bytes)),
            WindowsKeyValueType::MultiSz => Self::MultiSz(decode_utf16_multi(&bytes)),
            WindowsKeyValueType::Binary => Self::Binary(bytes),
            WindowsKeyValueType::Dword => Self::Dword(decode_u32_le(&bytes)),
            WindowsKeyValueType::DwordBigEndian => Self::DwordBigEndian(decode_u32_be(&bytes)),
            WindowsKeyValueType::Qword => Self::Qword(decode_u64_le(&bytes)),
            WindowsKeyValueType::ResourceList => Self::ResourceList(bytes),
            WindowsKeyValueType::FullResourceDescriptor => Self::FullResourceDescriptor(bytes),
            WindowsKeyValueType::ResourceRequirementsList => Self::ResourceRequirementsList(bytes),
            WindowsKeyValueType::Unknown(raw) => Self::Unknown { ty: raw, bytes },
        }
    }

    /// Returns the empty variant matching `value_type`.
    fn from_empty(value_type: WindowsKeyValueType) -> Self {
        match value_type {
            WindowsKeyValueType::None => Self::None,
            WindowsKeyValueType::Sz => Self::Sz(String::new()),
            WindowsKeyValueType::ExpandSz => Self::ExpandSz(String::new()),
            WindowsKeyValueType::Link => Self::Link(String::new()),
            WindowsKeyValueType::MultiSz => Self::MultiSz(Vec::new()),
            WindowsKeyValueType::Binary => Self::Binary(Vec::new()),
            WindowsKeyValueType::ResourceList => Self::ResourceList(Vec::new()),
            WindowsKeyValueType::FullResourceDescriptor => Self::FullResourceDescriptor(Vec::new()),
            WindowsKeyValueType::ResourceRequirementsList => {
                Self::ResourceRequirementsList(Vec::new())
            }
            WindowsKeyValueType::Dword | WindowsKeyValueType::DwordBigEndian => Self::Unknown {
                ty: u32::from(value_type),
                bytes: Vec::new(),
            },
            WindowsKeyValueType::Qword => Self::Unknown {
                ty: u32::from(value_type),
                bytes: Vec::new(),
            },
            WindowsKeyValueType::Unknown(raw) => Self::Unknown {
                ty: raw,
                bytes: Vec::new(),
            },
        }
    }
}

impl<'a, Driver> WindowsKeyValue<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Signature of a `_CM_KEY_VALUE` (`kv`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `CM_KEY_VALUE_SIGNATURE`.
    pub const SIGNATURE: u16 = 0x6b76; // "kv"

    /// Creates a new key value bound to the given hive.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, hive_va: Va, va: Va) -> Self {
        Self { vmi, hive_va, va }
    }

    /// Returns the signature of the key value.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_VALUE.Signature`.
    pub fn signature(&self) -> Result<u16, VmiError> {
        let CM_KEY_VALUE = offset!(self.vmi, _CM_KEY_VALUE);

        self.vmi.read_u16(self.va + CM_KEY_VALUE.Signature.offset())
    }

    /// Returns the flags of the key value.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_VALUE.Flags`.
    pub fn flags(&self) -> Result<WindowsKeyValueFlags, VmiError> {
        let CM_KEY_VALUE = offset!(self.vmi, _CM_KEY_VALUE);

        let flags = self.vmi.read_u16(self.va + CM_KEY_VALUE.Flags.offset())?;
        Ok(WindowsKeyValueFlags::from_bits_truncate(flags))
    }

    /// Returns the type of the key value.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_VALUE.Type`.
    pub fn value_type(&self) -> Result<WindowsKeyValueType, VmiError> {
        let CM_KEY_VALUE = offset!(self.vmi, _CM_KEY_VALUE);

        let ty = self.vmi.read_u32(self.va + CM_KEY_VALUE.Type.offset())?;
        Ok(WindowsKeyValueType::from(ty))
    }

    /// Returns the name of the key value.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_VALUE.Name`. If the `VALUE_COMP_NAME` bit is
    /// set in `_CM_KEY_VALUE.Flags`, the name is read as an ASCII string.
    /// Otherwise, the name is read as a UTF-16 string.
    pub fn name(&self) -> Result<String, VmiError> {
        let CM_KEY_VALUE = offset!(self.vmi, _CM_KEY_VALUE);

        let flags = self.flags()?;
        let name_length = self
            .vmi
            .read_u16(self.va + CM_KEY_VALUE.NameLength.offset())?;
        let name_va = self.va + CM_KEY_VALUE.Name.offset();

        if flags.contains(WindowsKeyValueFlags::COMP_NAME) {
            self.vmi.read_string_limited(name_va, name_length as usize)
        }
        else {
            self.vmi
                .read_string_utf16_limited(name_va, name_length as usize)
        }
    }

    /// Returns the raw bytes of the key value.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_VALUE.Data`.
    ///
    /// If the `DataLength` field has the `CM_KEY_VALUE_SPECIAL_SIZE` bit set,
    /// the data is stored inline in the `Data` field itself. Otherwise,
    /// the `Data` field contains an index into the hive's cell map where
    /// the actual data is stored. If the data is large enough, it may be
    /// stored as a `_CM_BIG_DATA` structure.
    pub fn data_bytes(&self) -> Result<Vec<u8>, VmiError> {
        let CM_KEY_VALUE = offset!(self.vmi, _CM_KEY_VALUE);

        let data_length_raw = self
            .vmi
            .read_u32(self.va + CM_KEY_VALUE.DataLength.offset())?;

        if data_length_raw & CM_KEY_VALUE_SPECIAL_SIZE != 0 {
            let size = ((data_length_raw & !CM_KEY_VALUE_SPECIAL_SIZE) as usize).min(4);
            let mut buffer = vec![0u8; size];
            self.vmi
                .read(self.va + CM_KEY_VALUE.Data.offset(), &mut buffer)?;
            return Ok(buffer);
        }

        let data_length = data_length_raw as usize;
        if data_length == 0 {
            return Ok(Vec::new());
        }

        // The kernel only stores `_CM_KEY_VALUE.Data` as an `HCELL_INDEX` when
        // `DataLength` is non-zero and the special-size flag is clear, and
        // guarantees that index is valid.
        let data_index = self.vmi.read_u32(self.va + CM_KEY_VALUE.Data.offset())?;
        let hive = WindowsHive::new(self.vmi, self.hive_va);
        let data_va = match hive.cell(WindowsHiveCellIndex::new(data_index))? {
            Some(data_va) => data_va,
            None => return Err(WindowsError::CorruptedStruct("CM_KEY_VALUE.Data").into()),
        };

        if hive.version()? >= HSYS_VERSION_4 && data_length_raw > CM_KEY_VALUE_BIG {
            return self.read_big_data(&hive, data_va, data_length);
        }

        let mut buffer = vec![0u8; data_length];
        self.vmi.read(data_va, &mut buffer)?;
        Ok(buffer)
    }

    /// Returns the parsed data of the key value, interpreting the raw
    /// bytes per [`value_type`].
    ///
    /// [`value_type`]: Self::value_type
    pub fn data(&self) -> Result<WindowsKeyValueData, VmiError> {
        let value_type = self.value_type()?;
        let bytes = self.data_bytes()?;

        Ok(WindowsKeyValueData::from_raw(value_type, bytes))
    }

    /// Reads the contents of a `_CM_BIG_DATA` cell.
    ///
    /// The caller is responsible for confirming the cell is a
    /// `_CM_BIG_DATA` before calling. [`data_bytes`] does so via a
    /// `(version, size)` check. A signature mismatch is logged as a
    /// warning but parsing continues.
    ///
    /// [`data_bytes`]: Self::data_bytes
    fn read_big_data(
        &self,
        hive: &WindowsHive<'a, Driver>,
        big_data_va: Va,
        total_length: usize,
    ) -> Result<Vec<u8>, VmiError> {
        let CM_BIG_DATA = offset!(self.vmi, _CM_BIG_DATA);

        let signature = self
            .vmi
            .read_u16(big_data_va + CM_BIG_DATA.Signature.offset())?;
        if signature != CM_BIG_DATA_SIGNATURE {
            tracing::warn!(
                signature = %Hex(signature),
                expected = %Hex(CM_BIG_DATA_SIGNATURE),
                hive = %hive.va(),
                cell = %big_data_va,
                "cell classified as _CM_BIG_DATA but signature mismatches"
            );
        }

        let count = self
            .vmi
            .read_u16(big_data_va + CM_BIG_DATA.Count.offset())? as usize;
        let list_index = self.vmi.read_u32(big_data_va + CM_BIG_DATA.List.offset())?;

        // The kernel always populates `_CM_BIG_DATA.List` and each segment
        // it points at with valid `HCELL_INDEX`es.
        let list_va = match hive.cell(WindowsHiveCellIndex::new(list_index))? {
            Some(list_va) => list_va,
            None => return Err(WindowsError::CorruptedStruct("CM_BIG_DATA.List").into()),
        };

        let segment_size = CM_KEY_VALUE_BIG as usize;
        let mut buffer = Vec::with_capacity(total_length);
        let mut remaining = total_length;

        for i in 0..count {
            if remaining == 0 {
                break;
            }

            let segment_index = self.vmi.read_u32(list_va + (i as u64) * HCELL_INDEX_SIZE)?;
            let segment_va = match hive.cell(WindowsHiveCellIndex::new(segment_index))? {
                Some(segment_va) => segment_va,
                None => return Err(WindowsError::CorruptedStruct("CM_BIG_DATA.List[]").into()),
            };

            let chunk = remaining.min(segment_size);
            let start = buffer.len();
            buffer.resize(start + chunk, 0);

            self.vmi
                .read(segment_va, &mut buffer[start..start + chunk])?;

            remaining -= chunk;
        }

        Ok(buffer)
    }
}

/// Returns an iterator over the direct values of a key node.
pub(super) fn values_iterator<'a, Driver>(
    vmi: VmiState<'a, WindowsOs<Driver>>,
    hive_va: Va,
    list_index: WindowsHiveCellIndex,
    count: u32,
) -> Result<KeyValueIterator<'a, Driver>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    if count == 0 || list_index.is_nil() {
        return Ok(KeyValueIterator::empty(vmi, hive_va));
    }

    // The kernel only dereferences `_CM_KEY_NODE.ValueList.List` when
    // `Count != 0`, and never plants `HCELL_NIL` in it under that guard.
    let hive = WindowsHive::new(vmi, hive_va);
    let list_va = match hive.cell(list_index)? {
        Some(list_va) => list_va,
        None => return Err(WindowsError::CorruptedStruct("CM_KEY_NODE.ValueList.List").into()),
    };

    Ok(KeyValueIterator::new(vmi, hive_va, list_va, count))
}
