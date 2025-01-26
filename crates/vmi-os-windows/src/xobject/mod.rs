mod control_area;
mod directory;
mod file;
mod name_info;
mod section;

use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

pub use self::{
    control_area::WindowsOsControlArea, directory::WindowsOsDirectoryObject,
    file::WindowsOsFileObject, name_info::WindowsOsObjectHeaderNameInfo,
    section::WindowsOsSectionObject,
};
use crate::{
    arch::ArchAdapter,
    macros::{impl_offsets, impl_symbols},
    WindowsObjectType, WindowsOs, WindowsOsExt,
};

/// A Windows object.
pub struct WindowsOsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the object.
    va: Va,
}

impl<'a, Driver> WindowsOsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_symbols!();
    impl_offsets!();

    /// Create a new Windows object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the virtual address of the object.
    pub fn va(&self) -> Va {
        self.va
    }

    /// Returns the virtual address of the `_OBJECT_HEADER` structure.
    ///
    /// # Implementation Details
    ///
    /// `_OBJECT_HEADER` is always at the beginning of the object.
    pub fn header(&self) -> Va {
        let offsets = self.offsets();
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        self.va - OBJECT_HEADER.Body.offset
    }

    /// Returns the name information of the object.
    pub fn name_info(&self) -> Result<Option<WindowsOsObjectHeaderNameInfo<'a, Driver>>, VmiError> {
        let symbols = self.symbols();
        let offsets = self.offsets();
        let ObpInfoMaskToOffset = symbols.ObpInfoMaskToOffset;
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        let info_mask = self
            .vmi
            .read_u8(self.header() + OBJECT_HEADER.InfoMask.offset)?;

        bitflags::bitflags! {
            struct InfoFlags: u8 {
                const CREATOR_INFO = 0x01;
                const NAME_INFO = 0x02;
                const HANDLE_INFO = 0x04;
                const QUOTA_INFO = 0x08;
                const PROCESS_INFO = 0x10;
            }
        }

        let info_flags = InfoFlags::from_bits_truncate(info_mask);
        if !info_flags.contains(InfoFlags::NAME_INFO) {
            return Ok(None);
        }

        // Offset = ObpInfoMaskToOffset[OBJECT_HEADER->InfoMask & (DesiredHeaderBit | (DesiredHeaderBit-1))]

        let mask = info_mask & (InfoFlags::NAME_INFO.bits() | (InfoFlags::NAME_INFO.bits() - 1));
        let mask = mask as u64;

        let kernel_image_base = self.vmi.os().kernel_image_base()?;
        let offset = self
            .vmi
            .read_u8(kernel_image_base + ObpInfoMaskToOffset + mask)? as u64;

        Ok(Some(WindowsOsObjectHeaderNameInfo::new(
            self.vmi,
            self.header() - offset,
        )))
    }

    /// Returns the type of the object.
    pub fn typ(&self) -> Result<Option<WindowsObjectType>, VmiError> {
        self.vmi.os().object_type(self.va)
    }

    /// Returns the kind of the object.
    pub fn kind(&self) -> Result<Option<WindowsOsObjectKind<'a, Driver>>, VmiError> {
        let result = match self.typ()? {
            Some(WindowsObjectType::Directory) => {
                WindowsOsObjectKind::Directory(WindowsOsDirectoryObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectType::File) => {
                WindowsOsObjectKind::File(WindowsOsFileObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectType::Section) => {
                WindowsOsObjectKind::Section(WindowsOsSectionObject::new(self.vmi, self.va))
            }
            _ => return Ok(None),
        };

        Ok(Some(result))
    }

    /// Returns the object as a directory (`_OBJECT_DIRECTORY`).
    pub fn as_directory(&self) -> Option<WindowsOsDirectoryObject<'a, Driver>> {
        match self.kind() {
            Ok(Some(WindowsOsObjectKind::Directory(directory))) => Some(directory),
            _ => None,
        }
    }

    /// Returns the object as a file (`_FILE_OBJECT`).
    pub fn as_file(&self) -> Option<WindowsOsFileObject<'a, Driver>> {
        match self.kind() {
            Ok(Some(WindowsOsObjectKind::File(file))) => Some(file),
            _ => None,
        }
    }

    /// Returns the object as a section (`_SECTION_OBJECT`).
    pub fn as_section(&self) -> Option<WindowsOsSectionObject<'a, Driver>> {
        match self.kind() {
            Ok(Some(WindowsOsObjectKind::Section(section))) => Some(section),
            _ => None,
        }
    }
}

/// A Windows object.
pub enum WindowsOsObjectKind<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Directory object (`_OBJECT_DIRECTORY`).
    Directory(WindowsOsDirectoryObject<'a, Driver>),

    /// File object (`_FILE_OBJECT`).
    File(WindowsOsFileObject<'a, Driver>),

    /// Section object (`_SECTION_OBJECT`).
    Section(WindowsOsSectionObject<'a, Driver>),
}
