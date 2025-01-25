use once_cell::unsync::OnceCell;
use vmi_core::{
    os::{OsMapped, OsRegionKind, VmiOsRegion},
    Architecture, MemoryAccess, Va, VmiDriver, VmiError, VmiState,
};

use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows OS region.
pub struct WindowsOsRegion<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
    vad_flags: OnceCell<u64>,
}

impl<'a, Driver> WindowsOsRegion<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows OS region.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, vad: Va) -> Self {
        Self {
            vmi,
            va: vad,
            vad_flags: OnceCell::new(),
        }
    }

    /// Extracts the `VadFlags` from a `MMVAD_SHORT` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// return Vad->VadFlags;
    /// ```
    pub fn vad_flags(&self) -> Result<u64, VmiError> {
        let offsets = self.offsets();
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        Ok(*self
            .vad_flags
            .get_or_try_init(|| self.vmi.read_field(self.va, &MMVAD_SHORT.VadFlags))?)
    }
}

impl<'a, Driver> VmiOsRegion for WindowsOsRegion<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn start(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        let starting_vpn_low = self.vmi.read_field(self.va, &MMVAD_SHORT.StartingVpn)?;
        let starting_vpn_high = match &MMVAD_SHORT.StartingVpnHigh {
            Some(StartingVpnHigh) => self.vmi.read_field(self.va, StartingVpnHigh)?,
            None => 0,
        };

        let starting_vpn = (starting_vpn_high << 32) | starting_vpn_low;
        Ok(Va(starting_vpn << 12))
    }

    fn end(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let MMVAD_SHORT = &offsets._MMVAD_SHORT;

        let ending_vpn_low = self.vmi.read_field(self.va, &MMVAD_SHORT.EndingVpn)?;
        let ending_vpn_high = match &MMVAD_SHORT.EndingVpnHigh {
            Some(EndingVpnHigh) => self.vmi.read_field(self.va, EndingVpnHigh)?,
            None => 0,
        };

        let ending_vpn = (ending_vpn_high << 32) | ending_vpn_low;
        Ok(Va((ending_vpn + 1) << 12))
    }

    fn protection(&self) -> Result<MemoryAccess, VmiError> {
        let offsets = self.offsets();
        let MMVAD_FLAGS = &offsets._MMVAD_FLAGS;

        let flags = self.vad_flags()?;
        let protection = MMVAD_FLAGS.Protection.value_from(flags) as u8;

        const MM_ZERO_ACCESS: u8 = 0; // this value is not used.
        const MM_READONLY: u8 = 1;
        const MM_EXECUTE: u8 = 2;
        const MM_EXECUTE_READ: u8 = 3;
        const MM_READWRITE: u8 = 4; // bit 2 is set if this is writable.
        const MM_WRITECOPY: u8 = 5;
        const MM_EXECUTE_READWRITE: u8 = 6;
        const MM_EXECUTE_WRITECOPY: u8 = 7;

        let result = match protection {
            MM_ZERO_ACCESS => MemoryAccess::default(),
            MM_READONLY => MemoryAccess::R,
            MM_EXECUTE => MemoryAccess::X,
            MM_EXECUTE_READ => MemoryAccess::RX,
            MM_READWRITE => MemoryAccess::RW,
            MM_WRITECOPY => MemoryAccess::RW, // REVIEW: is this correct?
            MM_EXECUTE_READWRITE => MemoryAccess::RWX,
            MM_EXECUTE_WRITECOPY => MemoryAccess::RWX, // REVIEW: is this correct?
            _ => MemoryAccess::default(),
        };

        Ok(result)
    }

    fn kind(&self) -> Result<OsRegionKind, VmiError> {
        let offsets = self.offsets();
        let MMVAD = &offsets._MMVAD;
        let MMVAD_FLAGS = &offsets._MMVAD_FLAGS;
        let SUBSECTION = &offsets._SUBSECTION;

        let flags = self.vad_flags()?;
        let vad_type = MMVAD_FLAGS.VadType.value_from(flags) as u8;

        const VadImageMap: u8 = 2;

        if vad_type != VadImageMap {
            return Ok(OsRegionKind::Private);
        }

        let subsection = Va(self.vmi.read_field(self.va, &MMVAD.Subsection)?);
        let control_area = Va(self.vmi.read_field(subsection, &SUBSECTION.ControlArea)?);

        // Note that filename is allocated from paged pool,
        // so this read might fail.
        let path = self.vmi.os().control_area_to_filename(control_area)?;

        Ok(OsRegionKind::Mapped(OsMapped {
            path: Ok(Some(path)),
        }))
    }
}
