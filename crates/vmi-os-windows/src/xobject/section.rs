use once_cell::unsync::OnceCell;
use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use super::{WindowsOsControlArea, WindowsOsFileObject, WindowsOsObject};
use crate::{
    arch::ArchAdapter,
    macros::{impl_offsets, impl_offsets_ext_v1, impl_offsets_ext_v2},
    OffsetsExt, WindowsOs,
};

/// A Windows section object.
pub struct WindowsOsSectionObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: Inner<'a, Driver>,
}

impl<Driver> From<WindowsOsSectionObject<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsOsSectionObject<Driver>) -> Self {
        match &value.inner {
            Inner::V1(inner) => inner.va,
            Inner::V2(inner) => inner.va,
        }
    }
}

impl<'a, Driver> From<WindowsOsSectionObject<'a, Driver>> for WindowsOsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsOsSectionObject<'a, Driver>) -> Self {
        let (vmi, va) = match value.inner {
            Inner::V1(inner) => (inner.vmi, inner.va),
            Inner::V2(inner) => (inner.vmi, inner.va),
        };

        Self::new(vmi, va)
    }
}

impl<'a, Driver> WindowsOsSectionObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows section object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        let inner = match vmi.underlying_os().offsets().ext() {
            Some(OffsetsExt::V1(_)) => Inner::V1(WindowsOsSectionObjectV1::new(vmi, va)),
            Some(OffsetsExt::V2(_)) => Inner::V2(WindowsOsSectionObjectV2::new(vmi, va)),
            None => unimplemented!(),
        };

        Self { inner }
    }

    /// Returns the starting address of the section.
    pub fn start(&self) -> Result<Va, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.start(),
            Inner::V2(inner) => inner.start(),
        }
    }

    /// Returns the ending address of the section.
    pub fn end(&self) -> Result<Va, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.end(),
            Inner::V2(inner) => inner.end(),
        }
    }

    /// Returns the size of the section.
    pub fn size(&self) -> Result<u64, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.size(),
            Inner::V2(inner) => inner.size(),
        }
    }

    /// Returns the flags of the section.
    pub fn flags(&self) -> Result<u64, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.flags(),
            Inner::V2(inner) => inner.flags(),
        }
    }

    /// Returns the file object of the section.
    pub fn file_object(&self) -> Result<Option<WindowsOsFileObject<'a, Driver>>, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.file_object(),
            Inner::V2(inner) => inner.file_object(),
        }
    }
}

enum Inner<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    V1(WindowsOsSectionObjectV1<'a, Driver>),
    V2(WindowsOsSectionObjectV2<'a, Driver>),
}

/// A Windows section object.
struct WindowsOsSectionObjectV1<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_SECTION_OBJECT` structure.
    va: Va,

    /// Cached virtual address of the `_SEGMENT_OBJECT` structure.
    segment: OnceCell<Va>,
}

impl<'a, Driver> WindowsOsSectionObjectV1<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();
    impl_offsets_ext_v1!();

    /// Create a new Windows section object.
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            segment: OnceCell::new(),
        }
    }

    fn start(&self) -> Result<Va, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SECTION_OBJECT = &offsets_ext._SECTION_OBJECT;

        let starting_vpn = self.vmi.read_field(self.va, &SECTION_OBJECT.StartingVa)?;

        Ok(Va(starting_vpn << 12))
    }

    fn end(&self) -> Result<Va, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SECTION_OBJECT = &offsets_ext._SECTION_OBJECT;

        let ending_vpn = self.vmi.read_field(self.va, &SECTION_OBJECT.EndingVa)?;

        Ok(Va((ending_vpn + 1) << 12))
    }

    fn size(&self) -> Result<u64, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SEGMENT_OBJECT = &offsets_ext._SEGMENT_OBJECT;

        let size = self
            .vmi
            .read_field(self.segment()?, &SEGMENT_OBJECT.SizeOfSegment)?;

        Ok(size)
    }

    fn flags(&self) -> Result<u64, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SEGMENT_OBJECT = &offsets_ext._SEGMENT_OBJECT;

        let flags = Va(self
            .vmi
            .read_field(self.segment()?, &SEGMENT_OBJECT.MmSectionFlags)?);

        Ok(self.vmi.read_u32(flags)? as u64)
    }

    fn file_object(&self) -> Result<Option<WindowsOsFileObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let offsets_ext = self.offsets_ext();
        let SEGMENT_OBJECT = &offsets_ext._SEGMENT_OBJECT;
        let MMSECTION_FLAGS = &offsets._MMSECTION_FLAGS;

        let flags = self.flags()?;
        let file = MMSECTION_FLAGS.File.value_from(flags) != 0;

        if !file {
            return Ok(None);
        }

        let control_area = Va(self
            .vmi
            .read_field(self.segment()?, &SEGMENT_OBJECT.ControlArea)?);

        Ok(Some(
            WindowsOsControlArea::new(self.vmi, control_area).file_object()?,
        ))
    }

    fn segment(&self) -> Result<Va, VmiError> {
        self.segment
            .get_or_try_init(|| {
                let offsets_ext = self.offsets_ext();
                let SECTION_OBJECT = &offsets_ext._SECTION_OBJECT;

                let segment = self.vmi.read_field(self.va, &SECTION_OBJECT.Segment)?;

                Ok(Va(segment))
            })
            .copied()
    }
}

struct WindowsOsSectionObjectV2<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_SECTION` structure.
    va: Va,
}

impl<'a, Driver> WindowsOsSectionObjectV2<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();
    impl_offsets_ext_v2!();

    /// Create a new Windows section object.
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    fn start(&self) -> Result<Va, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SECTION = &offsets_ext._SECTION;

        let starting_vpn = self.vmi.read_field(self.va, &SECTION.StartingVpn)?;

        Ok(Va(starting_vpn << 12))
    }

    fn end(&self) -> Result<Va, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SECTION = &offsets_ext._SECTION;

        let ending_vpn = self.vmi.read_field(self.va, &SECTION.EndingVpn)?;

        Ok(Va((ending_vpn + 1) << 12))
    }

    fn size(&self) -> Result<u64, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SECTION = &offsets_ext._SECTION;

        self.vmi.read_field(self.va, &SECTION.SizeOfSection)
    }

    fn flags(&self) -> Result<u64, VmiError> {
        let offsets_ext = self.offsets_ext();
        let SECTION = &offsets_ext._SECTION;

        self.vmi.read_field(self.va, &SECTION.Flags)
    }

    fn file_object(&self) -> Result<Option<WindowsOsFileObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let offsets_ext = self.offsets_ext();
        let MMSECTION_FLAGS = &offsets._MMSECTION_FLAGS;
        let SECTION = &offsets_ext._SECTION;

        let flags = self.flags()?;
        let file = MMSECTION_FLAGS.File.value_from(flags) != 0;

        if !file {
            return Ok(None);
        }

        let control_area = Va(self.vmi.read_field(self.va, &SECTION.ControlArea)?);

        if control_area.0 & 0x3 != 0 {
            let file_object = control_area;
            return Ok(Some(WindowsOsFileObject::new(self.vmi, file_object)));
        }

        Ok(Some(
            WindowsOsControlArea::new(self.vmi, control_area).file_object()?,
        ))
    }
}
