use once_cell::unsync::OnceCell;
use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, WindowsError, WindowsOs, offset};

/// A Windows security identifier.
///
/// A SID names a security principal. The Object Manager attaches one
/// to every securable kernel object, the Security Reference Monitor
/// uses it for access checks, and tokens carry a user SID plus a list
/// of group SIDs.
///
/// # Implementation Details
///
/// Corresponds to `_SID`.
pub struct WindowsSid<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_SID` structure.
    va: Va,

    /// Cached sub-authority array.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SID.SubAuthority`.
    sub_authorities: OnceCell<Vec<u32>>,
}

impl<Driver> VmiVa for WindowsSid<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSid<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Maximum allowed value of `_SID.SubAuthorityCount`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `SID_MAX_SUB_AUTHORITIES`.
    pub const MAX_SUB_AUTHORITIES: u8 = 15;

    /// Creates a new Windows security identifier accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            sub_authorities: OnceCell::new(),
        }
    }

    /// Returns the SID revision byte. Always 1 for valid SIDs.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SID.Revision`.
    pub fn revision(&self) -> Result<u8, VmiError> {
        let SID = offset!(self.vmi, _SID);

        self.vmi.read_u8(self.va + SID.Revision.offset())
    }

    /// Returns the number of sub-authority entries.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SID.SubAuthorityCount`.
    pub fn sub_authority_count(&self) -> Result<u8, VmiError> {
        let SID = offset!(self.vmi, _SID);

        let count = self.vmi.read_u8(self.va + SID.SubAuthorityCount.offset())?;

        Ok(count)
    }

    /// Returns the 48-bit identifier authority value.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SID.IdentifierAuthority`, decoded as a 48-bit
    /// big-endian value.
    pub fn authority(&self) -> Result<u64, VmiError> {
        let SID = offset!(self.vmi, _SID);

        let mut bytes = [0; 8];
        self.vmi
            .read(self.va + SID.IdentifierAuthority.offset(), &mut bytes[2..])?;

        Ok(u64::from_be_bytes(bytes))
    }

    /// Returns the sub-authority array.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SID.SubAuthority`. The array length is
    /// determined by [`sub_authority_count`].
    ///
    /// [`sub_authority_count`]: Self::sub_authority_count
    pub fn sub_authorities(&self) -> Result<&[u32], VmiError> {
        self.sub_authorities
            .get_or_try_init(|| {
                let SID = offset!(self.vmi, _SID);

                let count = self.sub_authority_count()?;

                if count > Self::MAX_SUB_AUTHORITIES {
                    return Err(WindowsError::CorruptedStruct("SID.SubAuthorityCount").into());
                }

                let base = self.va + SID.SubAuthority.offset();

                let mut out = Vec::with_capacity(count as usize);
                for index in 0..u64::from(count) {
                    out.push(self.vmi.read_u32(base + index * 4)?);
                }

                Ok(out)
            })
            .map(Vec::as_slice)
    }
}

impl<Driver> std::fmt::Debug for WindowsSid<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Renders the SID in the standard `S-R-A-S-S...` form.
    ///
    /// Authority is decimal when it fits in 32 bits, hex otherwise,
    /// matching `RtlConvertSidToUnicodeString`. A read failure on any
    /// field aborts rendering and writes `?` instead.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let revision = match self.revision() {
            Ok(revision) => revision,
            Err(_) => return write!(f, "?"),
        };

        let authority = match self.authority() {
            Ok(authority) => authority,
            Err(_) => return write!(f, "?"),
        };

        let sub_authorities = match self.sub_authorities() {
            Ok(sub_authorities) => sub_authorities,
            Err(_) => return write!(f, "?"),
        };

        write!(f, "S-{revision}-")?;

        match authority {
            authority if authority < (1 << 32) => write!(f, "{authority}")?,
            authority => write!(f, "0x{authority:012X}")?,
        }

        for sub_authority in sub_authorities {
            write!(f, "-{sub_authority}")?;
        }

        Ok(())
    }
}

bitflags::bitflags! {
    /// Attribute bitmask stored in `_SID_AND_ATTRIBUTES.Attributes`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct WindowsSidAttributes: u32 {
        /// `SE_GROUP_MANDATORY`.
        const MANDATORY               = 0x0000_0001;

        /// `SE_GROUP_ENABLED_BY_DEFAULT`.
        const ENABLED_BY_DEFAULT      = 0x0000_0002;

        /// `SE_GROUP_ENABLED`.
        const ENABLED                 = 0x0000_0004;

        /// `SE_GROUP_OWNER`.
        const OWNER                   = 0x0000_0008;

        /// `SE_GROUP_USE_FOR_DENY_ONLY`.
        const USE_FOR_DENY_ONLY       = 0x0000_0010;

        /// `SE_GROUP_INTEGRITY`.
        const INTEGRITY               = 0x0000_0020;

        /// `SE_GROUP_INTEGRITY_ENABLED`.
        const INTEGRITY_ENABLED       = 0x0000_0040;

        /// `SE_GROUP_RESOURCE`.
        const RESOURCE                = 0x2000_0000;

        /// `SE_GROUP_LOGON_ID`.
        const LOGON_ID                = 0xC000_0000;
    }
}

/// A Windows `_SID_AND_ATTRIBUTES` element.
///
/// Pairs a SID pointer with a 32-bit attribute bitmask. Appears as the
/// element type of every inline SID list in the kernel.
///
/// # Implementation Details
///
/// Corresponds to `_SID_AND_ATTRIBUTES`.
pub struct WindowsSidAndAttributes<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// The virtual address of the `_SID_AND_ATTRIBUTES` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsSidAndAttributes<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSidAndAttributes<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows `_SID_AND_ATTRIBUTES` accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the address of the SID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SID_AND_ATTRIBUTES.Sid`.
    pub fn sid_va(&self) -> Result<Va, VmiError> {
        let SID_AND_ATTRIBUTES = offset!(self.vmi, _SID_AND_ATTRIBUTES);

        self.vmi
            .read_va_native(self.va + SID_AND_ATTRIBUTES.Sid.offset())
    }

    /// Returns an accessor for the SID itself.
    ///
    /// Shortcut for [`WindowsSid::new`] over [`Self::sid_va`].
    pub fn sid(&self) -> Result<WindowsSid<'a, Driver>, VmiError> {
        Ok(WindowsSid::new(self.vmi, self.sid_va()?))
    }

    /// Returns the attribute bitmask.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SID_AND_ATTRIBUTES.Attributes`.
    pub fn attributes(&self) -> Result<WindowsSidAttributes, VmiError> {
        let SID_AND_ATTRIBUTES = offset!(self.vmi, _SID_AND_ATTRIBUTES);

        let raw = self
            .vmi
            .read_u32(self.va + SID_AND_ATTRIBUTES.Attributes.offset())?;

        Ok(WindowsSidAttributes::from_bits_retain(raw))
    }
}
