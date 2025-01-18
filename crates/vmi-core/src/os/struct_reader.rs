use isr_macros::Field;

use super::VmiOs;
use crate::{AccessContext, Registers, Va, VmiCore, VmiDriver, VmiError, VmiState};

/// A handler for reading structured data from guest memory.
///
/// Provides safe access to structured data (like C structs) read from guest memory,
/// with proper bounds checking and endianness handling. It reads the data as a byte buffer
/// and provides methods to safely access fields at specific offsets and sizes.
///
/// # Examples
///
/// ```no_run
/// # use isr_macros::{offsets, Field};
/// # use vmi_core::{AccessContext, VmiCore, VmiDriver, VmiError};
/// # use vmi_core::os::StructReader;
///
/// offsets! {
///     #[derive(Debug)]
///     pub struct Offsets {
///         struct _UNICODE_STRING {
///             Length: Field,          // USHORT
///             MaximumLength: Field,   // USHORT
///             Buffer: Field,          // PWSTR
///         }
///     }
/// }
///
/// # fn example<Driver: VmiDriver>(
/// #     vmi: &VmiCore<Driver>,
/// #     ctx: impl Into<AccessContext>,
/// # ) -> Result<(), VmiError> {
/// # let profile = unimplemented!();
///
/// let offsets = Offsets::new(profile)?;
/// let UNICODE_STRING = &offsets._UNICODE_STRING;
///
/// // Read the structure from memory.
/// let us = StructReader::new(vmi, ctx, UNICODE_STRING.effective_len())?;
///
/// // Access the field values.
/// let length = us.read(UNICODE_STRING.Length)?;
/// let buffer = us.read(UNICODE_STRING.Buffer)?;
///
/// # Ok(())
/// # }
/// ```
pub struct StructReader(Vec<u8>);

impl StructReader {
    /// Creates a new structure reader.
    ///
    /// Reads `len` bytes from the guest memory at the specified address into
    /// a new `StructReader` instance. The data can then be accessed using the
    /// [`read`] method with appropriate field descriptors.
    ///
    /// [`read`]: Self::read
    pub fn new<Driver, Os>(vmi: &VmiState<Driver, Os>, va: Va, len: usize) -> Result<Self, VmiError>
    where
        Driver: VmiDriver,
        Os: VmiOs<Driver>,
    {
        Self::new_in(vmi, vmi.registers().address_context(va), len)
    }

    /// Creates a new structure reader.
    ///
    /// Reads `len` bytes from the guest memory at the specified address into
    /// a new `StructReader` instance. The data can then be accessed using the
    /// [`read`] method with appropriate field descriptors.
    ///
    /// [`read`]: Self::read
    pub fn new_in<Driver>(
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AccessContext>,
        len: usize,
    ) -> Result<Self, VmiError>
    where
        Driver: VmiDriver,
    {
        let mut buffer = vec![0u8; len];
        vmi.read(ctx.into(), &mut buffer)?;
        Ok(Self(buffer))
    }

    /// Reads a field value from the data buffer.
    ///
    /// Extracts a value from the buffer using the provided field descriptor,
    /// which specifies the offset and size of the field.
    /// The value is interpreted as a little-endian integer of the appropriate
    /// size and returned as a `u64`.
    ///
    /// # Endianness
    ///
    /// Values are always read as little-endian integers. The returned `u64`
    /// will contain the zero-extended value.
    pub fn read(&self, field: Field) -> Result<u64, VmiError> {
        let offset = field.offset as usize;
        let size = field.size as usize;

        let offset_end = match offset.checked_add(size) {
            Some(offset_end) => offset_end,
            None => return Err(VmiError::OutOfBounds),
        };

        if offset_end > self.0.len() {
            return Err(VmiError::OutOfBounds);
        }

        let data = &self.0[offset..offset_end];

        match size {
            1 => Ok(data[0] as u64),
            2 => Ok(u16::from_le_bytes([data[0], data[1]]) as u64),
            4 => Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64),
            8 => Ok(u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            _ => Err(VmiError::OutOfBounds),
        }
    }
}
