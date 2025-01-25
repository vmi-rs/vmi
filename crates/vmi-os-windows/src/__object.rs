use once_cell::unsync::OnceCell;
use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{
    arch::ArchAdapter,
    offsets::{v1, v2},
    Offsets, OffsetsExt, WindowsOs, WindowsOsExt as _,
};

/// A Windows object.
pub enum WindowsOsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// File object.
    File(WindowsOsFileObject<'a, Driver>),

    /// Section object.
    Section(WindowsOsSectionObject<'a, Driver>),
}

/// A Windows file object.
pub struct WindowsOsFileObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>,
    offsets: &'a Offsets,
    file_object: Va,
}

impl<'a, Driver> WindowsOsFileObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows file object.
    pub fn new(vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>, file_object: Va) -> Self {
        Self {
            vmi,
            offsets: vmi.underlying_os().offsets(),
            file_object,
        }
    }

    /// Extracts the `DeviceObject` from a `FILE_OBJECT` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    /// return DeviceObject;
    /// ```
    pub fn device_object(&self) -> Result<Va, VmiError> {
        let FILE_OBJECT = &self.offsets._FILE_OBJECT;

        self.vmi
            .read_va_native(self.file_object + FILE_OBJECT.DeviceObject.offset)
    }

    /// Extracts the `FileName` from a `FILE_OBJECT` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// UNICODE_STRING FileName = FileObject->FileName;
    /// return FileName;
    /// ```
    ///
    /// # Notes
    ///
    /// This operation might fail as the filename is allocated from paged pool.
    pub fn filename(&self) -> Result<String, VmiError> {
        let FILE_OBJECT = &self.offsets._FILE_OBJECT;

        // Note that filename is allocated from paged pool,
        // so this read might fail.
        self.vmi
            .os()
            .read_unicode_string(self.file_object + FILE_OBJECT.FileName.offset)
    }
}

/// A Windows section object.
pub struct WindowsOsControlArea<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>,
    offsets: &'a Offsets,
    control_area: Va,
}

impl<'a, Driver> WindowsOsControlArea<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows section object.
    pub fn new(vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>, control_area: Va) -> Self {
        Self {
            vmi,
            offsets: vmi.underlying_os().offsets(),
            control_area,
        }
    }

    /// Extracts the `FileObject` from a `CONTROL_AREA` structure.
    pub fn file_object(&self) -> Result<WindowsOsFileObject<'a, Driver>, VmiError> {
        let EX_FAST_REF = &self.offsets._EX_FAST_REF;
        let CONTROL_AREA = &self.offsets._CONTROL_AREA;

        let file_pointer = self
            .vmi
            .read_va_native(self.control_area + CONTROL_AREA.FilePointer.offset)?;

        // The file pointer is in fact an `_EX_FAST_REF` structure,
        // where the low bits are used to store the reference count.
        debug_assert_eq!(EX_FAST_REF.RefCnt.offset, 0);
        debug_assert_eq!(EX_FAST_REF.RefCnt.bit_position, 0);
        let file_pointer = file_pointer & !((1 << EX_FAST_REF.RefCnt.bit_length) - 1);
        //let file_pointer = file_pointer & !0xf;

        Ok(WindowsOsFileObject::new(self.vmi, file_pointer))
    }
}

enum WindowsOsSectionObjectWrapper<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    V1(WindowsOsSectionObjectV1<'a, Driver>),
    V2(WindowsOsSectionObjectV2<'a, Driver>),
}

/// A Windows section object.
pub struct WindowsOsSectionObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: WindowsOsSectionObjectWrapper<'a, Driver>,
}

impl<'a, Driver> WindowsOsSectionObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows section object.
    pub fn new(vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>, section_object: Va) -> Self {
        match vmi.underlying_os().offsets().ext() {
            Some(OffsetsExt::V1(_)) => Self {
                inner: WindowsOsSectionObjectWrapper::V1(WindowsOsSectionObjectV1::new(
                    vmi,
                    section_object,
                )),
            },
            Some(OffsetsExt::V2(_)) => Self {
                inner: WindowsOsSectionObjectWrapper::V2(WindowsOsSectionObjectV2::new(
                    vmi,
                    section_object,
                )),
            },
            None => unimplemented!(),
        }
    }

    /// Returns the starting address of the section.
    pub fn start(&self) -> Result<Va, VmiError> {
        match &self.inner {
            WindowsOsSectionObjectWrapper::V1(section) => section.start(),
            WindowsOsSectionObjectWrapper::V2(section) => section.start(),
        }
    }

    /// Returns the ending address of the section.
    pub fn end(&self) -> Result<Va, VmiError> {
        match &self.inner {
            WindowsOsSectionObjectWrapper::V1(section) => section.end(),
            WindowsOsSectionObjectWrapper::V2(section) => section.end(),
        }
    }

    /// Returns the size of the section.
    pub fn size(&self) -> Result<u64, VmiError> {
        match &self.inner {
            WindowsOsSectionObjectWrapper::V1(section) => section.size(),
            WindowsOsSectionObjectWrapper::V2(section) => section.size(),
        }
    }

    /// Returns the flags of the section.
    pub fn flags(&self) -> Result<u64, VmiError> {
        match &self.inner {
            WindowsOsSectionObjectWrapper::V1(section) => section.flags(),
            WindowsOsSectionObjectWrapper::V2(section) => section.flags(),
        }
    }

    /// Returns the file object of the section.
    pub fn file_object(&self) -> Result<Option<WindowsOsFileObject<'a, Driver>>, VmiError> {
        match &self.inner {
            WindowsOsSectionObjectWrapper::V1(section) => section.file_object(),
            WindowsOsSectionObjectWrapper::V2(section) => section.file_object(),
        }
    }
}

/// A Windows section object.
struct WindowsOsSectionObjectV1<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>,
    offsets: &'a Offsets,
    offsets_ext: &'a v1::Offsets,
    section_object: Va,
    segment: OnceCell<Va>,
}

impl<'a, Driver> WindowsOsSectionObjectV1<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows section object.
    fn new(vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>, section_object: Va) -> Self {
        let offsets = vmi.underlying_os().offsets();
        let offsets_ext = match offsets.ext() {
            Some(OffsetsExt::V1(offsets)) => offsets,
            _ => unreachable!(),
        };

        Self {
            vmi,
            offsets,
            offsets_ext,
            section_object,
            segment: OnceCell::new(),
        }
    }

    fn start(&self) -> Result<Va, VmiError> {
        let SECTION_OBJECT = &self.offsets_ext._SECTION_OBJECT;

        let starting_vpn = self
            .vmi
            .read_field(self.section_object, &SECTION_OBJECT.StartingVa)?;

        Ok(Va(starting_vpn << 12))
    }

    fn end(&self) -> Result<Va, VmiError> {
        let SECTION_OBJECT = &self.offsets_ext._SECTION_OBJECT;

        let ending_vpn = self
            .vmi
            .read_field(self.section_object, &SECTION_OBJECT.EndingVa)?;

        Ok(Va((ending_vpn + 1) << 12))
    }

    fn size(&self) -> Result<u64, VmiError> {
        let SEGMENT_OBJECT = &self.offsets_ext._SEGMENT_OBJECT;

        let size = self
            .vmi
            .read_field(self.segment()?, &SEGMENT_OBJECT.SizeOfSegment)?;

        Ok(size)
    }

    fn flags(&self) -> Result<u64, VmiError> {
        let SEGMENT_OBJECT = &self.offsets_ext._SEGMENT_OBJECT;

        let flags = Va(self
            .vmi
            .read_field(self.segment()?, &SEGMENT_OBJECT.MmSectionFlags)?);

        Ok(self.vmi.read_u32(flags)? as u64)
    }

    fn file_object(&self) -> Result<Option<WindowsOsFileObject<'a, Driver>>, VmiError> {
        let SEGMENT_OBJECT = &self.offsets_ext._SEGMENT_OBJECT;
        let MMSECTION_FLAGS = &self.offsets._MMSECTION_FLAGS;

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
                let SECTION_OBJECT = &self.offsets_ext._SECTION_OBJECT;

                let segment = self
                    .vmi
                    .read_field(self.section_object, &SECTION_OBJECT.Segment)?;

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
    vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>,
    offsets: &'a Offsets,
    offsets_ext: &'a v2::Offsets,
    section_object: Va,
}

impl<'a, Driver> WindowsOsSectionObjectV2<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows section object.
    fn new(vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>, section_object: Va) -> Self {
        let offsets = vmi.underlying_os().offsets();
        let offsets_ext = match offsets.ext() {
            Some(OffsetsExt::V2(offsets)) => offsets,
            _ => unreachable!(),
        };

        Self {
            vmi,
            offsets,
            offsets_ext,
            section_object,
        }
    }

    fn start(&self) -> Result<Va, VmiError> {
        let SECTION = &self.offsets_ext._SECTION;

        let starting_vpn = self
            .vmi
            .read_field(self.section_object, &SECTION.StartingVpn)?;

        Ok(Va(starting_vpn << 12))
    }

    fn end(&self) -> Result<Va, VmiError> {
        let SECTION = &self.offsets_ext._SECTION;

        let ending_vpn = self
            .vmi
            .read_field(self.section_object, &SECTION.EndingVpn)?;

        Ok(Va((ending_vpn + 1) << 12))
    }

    fn size(&self) -> Result<u64, VmiError> {
        let SECTION = &self.offsets_ext._SECTION;

        self.vmi
            .read_field(self.section_object, &SECTION.SizeOfSection)
    }

    fn flags(&self) -> Result<u64, VmiError> {
        let SECTION = &self.offsets_ext._SECTION;

        self.vmi.read_field(self.section_object, &SECTION.Flags)
    }

    fn file_object(&self) -> Result<Option<WindowsOsFileObject<'a, Driver>>, VmiError> {
        let MMSECTION_FLAGS = &self.offsets._MMSECTION_FLAGS;
        let SECTION = &self.offsets_ext._SECTION;

        let flags = self.flags()?;
        let file = MMSECTION_FLAGS.File.value_from(flags) != 0;

        if !file {
            return Ok(None);
        }

        let control_area = Va(self
            .vmi
            .read_field(self.section_object, &SECTION.ControlArea)?);

        if control_area.0 & 0x3 != 0 {
            let file_object = control_area;
            return Ok(Some(WindowsOsFileObject::new(self.vmi, file_object)));
        }

        Ok(Some(
            WindowsOsControlArea::new(self.vmi, control_area).file_object()?,
        ))
    }
}
