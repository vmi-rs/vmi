use once_cell::unsync::OnceCell;
use vmi_core::{
    Pa, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsRegion as _, VmiOsUserModule},
};

use super::LinuxRegion;
use crate::{
    ArchAdapter, LinuxError, LinuxOs,
    elf::{ElfImage, GuestElfReader},
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

    /// Returns a reader of the process's address space.
    fn reader(&self) -> GuestElfReader<'a, Driver> {
        GuestElfReader::new(self.vmi, Some(self.root))
    }

    /// Returns the parsed ELF image.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    fn elf(&self) -> Result<&ElfImage, VmiError> {
        self.elf.get_or_try_init(|| {
            let base = self.region().start()?;
            ElfImage::parse(&self.reader(), base)
        })
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
