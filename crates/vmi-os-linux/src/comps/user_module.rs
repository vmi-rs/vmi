use once_cell::unsync::OnceCell;
use vmi_core::{
    Pa, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsRegion as _, VmiOsUserModule},
};

use super::LinuxRegion;
use crate::{
    ArchAdapter, LinuxError, LinuxOs,
    elf::{self, ElfImage, GuestElfReader},
};

/// A Linux user-mode module: an executable, a shared object or the vDSO
/// that a process maps.
///
/// A module is an image in the process, recorded by its header region, which
/// maps the file's page 0. The vDSO has no file, and its region is its
/// record.
///
/// # Implementation Details
///
/// The module's address is that of the header region's `vm_area_struct`,
/// much as Windows uses an `_LDR_DATA_TABLE_ENTRY` address.
pub struct LinuxUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the header region's `vm_area_struct`.
    va: Va,

    /// Translation root of the process, for reads in user memory.
    root: Pa,

    /// The parsed ELF image.
    elf: OnceCell<ElfImage>,
}

impl<Driver> VmiVa for LinuxUserModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new module from its header region's `vm_area_struct`
    /// address and its process's translation root.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va, root: Pa) -> Self {
        Self {
            vmi,
            va,
            root,
            elf: OnceCell::new(),
        }
    }

    /// Returns the header region of the module.
    pub fn region(&self) -> LinuxRegion<'a, Driver> {
        LinuxRegion::new(self.vmi, self.va)
    }

    /// Returns the parsed ELF headers and dynamic section of the module.
    ///
    /// Only 64-bit images are read. 32-bit ones give `VmiError::NotSupported`.
    /// A module whose file is not ELF, or whose header page is absent, gives
    /// an error.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    pub fn elf(&self) -> Result<&ElfImage, VmiError> {
        self.elf.get_or_try_init(|| {
            let base = self.region().start()?;
            ElfImage::parse(&self.reader(), base)
        })
    }

    /// Returns the object's name from its dynamic section (`DT_SONAME`), if
    /// it has one.
    ///
    /// Programs name a library by this name, which stays the same when the
    /// file name changes. glibc 2.33 and older install the C library as a
    /// file such as `libc-2.33.so`, under the name `libc.so.6`. The vDSO's
    /// name is `linux-vdso.so.1`, and an executable usually has none. A
    /// module whose file is not an ELF image has none either.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the string at `DT_SONAME` in the string table that
    /// `DT_STRTAB` points to. The dynamic section and the string table lie in
    /// user memory, whose pages can be absent.
    pub fn soname(&self) -> Result<Option<String>, VmiError> {
        let reader = self.reader();
        if !elf::is_elf(&reader, self.region().start()?)? {
            return Ok(None);
        }

        self.elf()?.soname(&reader)
    }

    /// Returns a reader of the process's address space.
    fn reader(&self) -> GuestElfReader<'a, Driver> {
        GuestElfReader::new(self.vmi, Some(self.root))
    }

    /// Returns the address of the slot into which ld.so writes a TLS
    /// variable's offset from the thread pointer, for a variable that the
    /// module defines.
    pub(crate) fn tls_offset_slot(&self, name: &str) -> Result<Option<Va>, VmiError> {
        self.elf()?.tls_offset_slot(&self.reader(), name)
    }
}

impl<'a, Driver> VmiOsUserModule<'a, Driver> for LinuxUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the base address of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_start` of the header region.
    fn base_address(&self) -> Result<Va, VmiError> {
        self.region().start()
    }

    /// Returns the size of the module in memory, `.bss` included.
    ///
    /// # Implementation Details
    ///
    /// The span of the `PT_LOAD` segments in the ELF program headers, as
    /// `l_map_end - l_map_start` in glibc's `link_map`. The headers lie in
    /// user memory, whose page can be absent.
    fn size(&self) -> Result<u64, VmiError> {
        Ok(self.elf()?.size())
    }

    /// Returns the name of the module, such as `libc.so.6`.
    ///
    /// # Implementation Details
    ///
    /// The name of the mapped file's dentry (`dentry.d_name`). The vDSO has
    /// no file and gives its `DT_SONAME`, `linux-vdso.so.1`, as `ldd` shows
    /// it.
    fn name(&self) -> Result<String, VmiError> {
        if let Some(file) = self.region().file()? {
            return file.f_path().dentry()?.name();
        }

        match self.elf()?.soname(&self.reader())? {
            Some(soname) => Ok(soname),
            None => Err(LinuxError::CorruptedImage("ELF object name").into()),
        }
    }
}
