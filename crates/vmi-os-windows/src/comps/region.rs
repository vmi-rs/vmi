use once_cell::unsync::OnceCell;
use vmi_core::{
    os::{VmiOsRegion, VmiOsRegionKind},
    Architecture, MemoryAccess, Va, VmiDriver, VmiError, VmiState, VmiVa,
};

use super::macros::impl_offsets;
use crate::{ArchAdapter, OffsetsExt, WindowsControlArea, WindowsOs};

/// A Windows memory region.
///
/// A memory region represents a range of virtual memory allocated
/// within a process. It is managed by the Windows memory manager
/// and described by a **Virtual Address Descriptor (VAD)**.
///
/// # Implementation Details
///
/// Corresponds to `_MMVAD`.
pub struct WindowsRegion<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_MMVAD` structure.
    va: Va,

    /// Cached VAD flags.
    vad_flags: OnceCell<u64>,
}

impl<Driver> VmiVa for WindowsRegion<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<Driver> std::fmt::Debug for WindowsRegion<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let start = self.start();
        let end = self.end();
        let protection = self.protection();
        //let kind = self.kind();

        f.debug_struct("WindowsOsRegion")
            .field("start", &start)
            .field("end", &end)
            .field("protection", &protection)
            //.field("kind", &kind)
            .finish()
    }
}

impl<'a, Driver> WindowsRegion<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows memory region.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, vad: Va) -> Self {
        Self {
            vmi,
            va: vad,
            vad_flags: OnceCell::new(),
        }
    }

    /// Returns the starting VPN of the VAD.
    ///
    /// # Implementation Details
    ///
    /// The starting VPN is calculated from `_MMVAD_SHORT.StartingVpn` and,
    /// if present, `_MMVAD_SHORT.StartingVpnHigh` fields.
    pub fn starting_vpn(&self) -> Result<u64, VmiError> {
        let offsets = self.offsets();
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        let starting_vpn_low = self.vmi.read_field(self.va, &MMVAD_SHORT.StartingVpn)?;
        let starting_vpn_high = match &MMVAD_SHORT.StartingVpnHigh {
            Some(StartingVpnHigh) => self.vmi.read_field(self.va, StartingVpnHigh)?,
            None => 0,
        };

        Ok((starting_vpn_high << 32) | starting_vpn_low)
    }

    /// Returns the ending VPN of the VAD.
    ///
    /// # Implementation Details
    ///
    /// The ending VPN is calculated from `_MMVAD_SHORT.EndingVpn` and,
    /// if present, `_MMVAD_SHORT.EndingVpnHigh` fields.
    pub fn ending_vpn(&self) -> Result<u64, VmiError> {
        let offsets = self.offsets();
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        let ending_vpn_low = self.vmi.read_field(self.va, &MMVAD_SHORT.EndingVpn)?;
        let ending_vpn_high = match &MMVAD_SHORT.EndingVpnHigh {
            Some(EndingVpnHigh) => self.vmi.read_field(self.va, EndingVpnHigh)?,
            None => 0,
        };

        Ok((ending_vpn_high << 32) | ending_vpn_low)
    }

    /// Returns the VAD flags.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMVAD_SHORT.VadFlags`.
    pub fn vad_flags(&self) -> Result<u64, VmiError> {
        self.vad_flags
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let MMVAD_SHORT = &offsets._MMVAD_SHORT;

                self.vmi.read_field(self.va, &MMVAD_SHORT.VadFlags)
            })
            .copied()
    }

    /// Returns the VAD type.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMVAD_SHORT.VadFlags.VadType`.
    pub fn vad_type(&self) -> Result<u8, VmiError> {
        let offsets = self.offsets();
        let MMVAD_FLAGS = &offsets._MMVAD_FLAGS;

        let vad_flags = self.vad_flags()?;
        Ok(MMVAD_FLAGS.VadType.value_from(vad_flags) as u8)
    }

    /// Returns the memory protection of the VAD.
    ///
    /// # Implementation Details
    ///
    /// Calculated from `_MMVAD_SHORT.VadFlags.Protection` field.
    pub fn vad_protection(&self) -> Result<u8, VmiError> {
        let offsets = self.offsets();
        let MMVAD_FLAGS = &offsets._MMVAD_FLAGS;

        let flags = self.vad_flags()?;
        let protection = MMVAD_FLAGS.Protection.value_from(flags) as u8;

        Ok(protection)
    }

    /// Checks if the VAD represents private memory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMVAD_SHORT.VadFlags.PrivateMemory`.
    pub fn private_memory(&self) -> Result<bool, VmiError> {
        let offsets = self.offsets();
        let MMVAD_FLAGS = &offsets._MMVAD_FLAGS;

        let vad_flags = self.vad_flags()?;
        Ok(MMVAD_FLAGS.PrivateMemory.value_from(vad_flags) != 0)
    }

    /// Checks if the memory of the VAD is committed.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMVAD_SHORT.VadFlags.MemCommit` (Windows 7) or
    /// `_MMVAD_SHORT.VadFlags1.MemCommit` (Windows 8+).
    pub fn mem_commit(&self) -> Result<bool, VmiError> {
        let offsets = self.offsets();
        let MMVAD_FLAGS = &offsets._MMVAD_FLAGS;
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        let vad_flags = self.vad_flags()?;

        // If `MMVAD_FLAGS.MemCommit` is present (Windows 7), then we fetch the
        // value from it. Otherwise, we load the `VadFlags1` field from the VAD
        // and fetch it from there.
        let mem_commit = match MMVAD_FLAGS.MemCommit {
            // `MemCommit` is present in `MMVAD_FLAGS`
            Some(MemCommit) => MemCommit.value_from(vad_flags) != 0,
            None => match (&self.offsets().ext(), MMVAD_SHORT.VadFlags1) {
                // `MemCommit` is present in `MMVAD_FLAGS1`
                (Some(OffsetsExt::V2(offsets)), Some(VadFlags1)) => {
                    let MMVAD_FLAGS1 = &offsets._MMVAD_FLAGS1;
                    let vad_flags1 = self.vmi.read_field(self.va, &VadFlags1)?;
                    MMVAD_FLAGS1.MemCommit.value_from(vad_flags1) != 0
                }
                _ => {
                    panic!("Failed to read MemCommit from VAD");
                }
            },
        };

        Ok(mem_commit)
    }

    /// Returns the left child of the VAD.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMVAD_SHORT.Left`.
    pub fn left_child(&self) -> Result<Option<WindowsRegion<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        let left_child = self.vmi.read_field(self.va, &MMVAD_SHORT.Left)?;

        if left_child == 0 {
            return Ok(None);
        }

        Ok(Some(WindowsRegion::new(self.vmi, Va(left_child))))
    }

    /// Returns the right child of the VAD.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMVAD_SHORT.Right`.
    pub fn right_child(&self) -> Result<Option<WindowsRegion<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        let right_child = self.vmi.read_field(self.va, &MMVAD_SHORT.Right)?;

        if right_child == 0 {
            return Ok(None);
        }

        Ok(Some(WindowsRegion::new(self.vmi, Va(right_child))))
    }
}

impl<'a, Driver> VmiOsRegion<'a, Driver> for WindowsRegion<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the starting virtual address of the memory region.
    ///
    /// # Implementation Details
    ///
    /// The starting address is calculated from `_MMVAD_SHORT.StartingVpn` and,
    /// if present, `_MMVAD_SHORT.StartingVpnHigh` fields.
    fn start(&self) -> Result<Va, VmiError> {
        Ok(Va(self.starting_vpn()? << 12))
    }

    /// Returns the ending virtual address of the memory region.
    ///
    /// # Implementation Details
    ///
    /// The ending address is calculated from `_MMVAD_SHORT.EndingVpn` and,
    /// if present, `_MMVAD_SHORT.EndingVpnHigh` fields.
    fn end(&self) -> Result<Va, VmiError> {
        Ok(Va((self.ending_vpn()? + 1) << 12))
    }

    /// Returns the memory protection of the memory region.
    ///
    /// # Implementation Details
    ///
    /// Calculated from `_MMVAD_SHORT.VadFlags.Protection` field.
    fn protection(&self) -> Result<MemoryAccess, VmiError> {
        const MM_ZERO_ACCESS: u8 = 0; // this value is not used.
        const MM_READONLY: u8 = 1;
        const MM_EXECUTE: u8 = 2;
        const MM_EXECUTE_READ: u8 = 3;
        const MM_READWRITE: u8 = 4; // bit 2 is set if this is writable.
        const MM_WRITECOPY: u8 = 5;
        const MM_EXECUTE_READWRITE: u8 = 6;
        const MM_EXECUTE_WRITECOPY: u8 = 7;

        match self.vad_protection()? {
            MM_ZERO_ACCESS => Ok(MemoryAccess::default()),
            MM_READONLY => Ok(MemoryAccess::R),
            MM_EXECUTE => Ok(MemoryAccess::X),
            MM_EXECUTE_READ => Ok(MemoryAccess::RX),
            MM_READWRITE => Ok(MemoryAccess::RW),
            MM_WRITECOPY => Ok(MemoryAccess::RW), // REVIEW: is this correct?
            MM_EXECUTE_READWRITE => Ok(MemoryAccess::RWX),
            MM_EXECUTE_WRITECOPY => Ok(MemoryAccess::RWX), // REVIEW: is this correct?
            _ => Ok(MemoryAccess::default()),
        }
    }

    /// Returns the memory region's kind.
    fn kind(&self) -> Result<VmiOsRegionKind<'a, Driver, Self::Os>, VmiError> {
        let offsets = self.offsets();
        let MMVAD = &offsets._MMVAD;
        let SUBSECTION = &offsets._SUBSECTION;

        const VadImageMap: u8 = 2;

        let vad_type = self.vad_type()?;
        if vad_type != VadImageMap {
            return Ok(VmiOsRegionKind::Private);
        }

        let subsection = Va(self.vmi.read_field(self.va, &MMVAD.Subsection)?);
        let control_area = Va(self.vmi.read_field(subsection, &SUBSECTION.ControlArea)?);

        Ok(VmiOsRegionKind::Mapped(WindowsControlArea::new(
            self.vmi,
            control_area,
        )))
    }
}
