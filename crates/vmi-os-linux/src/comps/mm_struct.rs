use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsRegion as _};

use super::{LinuxFile, LinuxRegion};
use crate::{
    ArchAdapter, LinuxOs, MapleTreeIterator,
    iter::{GuestMapleNodeReader, Nearest, maple_tree_lookup, maple_tree_lookup_nearest},
    offset,
};

/// End of the auxiliary vector (`AT_NULL`).
const AT_NULL: u64 = 0;

/// Base address of the vDSO in the auxiliary vector (`AT_SYSINFO_EHDR`).
const AT_SYSINFO_EHDR: u64 = 33;

/// A Linux memory descriptor.
///
/// The memory descriptor describes the address space of a process: its page
/// tables and its memory regions.
///
/// # Implementation Details
///
/// Corresponds to `mm_struct`.
pub struct LinuxMmStruct<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `mm_struct` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxMmStruct<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxMmStruct<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux memory descriptor.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the virtual address of the page global directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.pgd`.
    pub fn pgd(&self) -> Result<Va, VmiError> {
        let MM_STRUCT = offset!(self.vmi, mm_struct);

        self.vmi.read_va_native(self.va + MM_STRUCT.pgd.offset())
    }

    /// Returns the size of the user address space.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.task_size`.
    pub fn task_size(&self) -> Result<u64, VmiError> {
        let MM_STRUCT = offset!(self.vmi, mm_struct);

        self.vmi.read_u64(self.va + MM_STRUCT.task_size.offset())
    }

    /// Returns the executable file of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.exe_file`.
    pub fn exe_file(&self) -> Result<Option<LinuxFile<'a, Driver>>, VmiError> {
        let MM_STRUCT = offset!(self.vmi, mm_struct);

        let exe_file = self
            .vmi
            .read_va_native(self.va + MM_STRUCT.exe_file.offset())?;

        if exe_file.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxFile::new(self.vmi, exe_file)))
    }

    /// Returns the address of the maple tree of the memory regions.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.mm_mt`.
    pub fn mm_mt(&self) -> Va {
        let MM_STRUCT = offset!(self.vmi, mm_struct);

        self.va + MM_STRUCT.mm_mt.offset()
    }

    /// Returns the root entry of the memory regions' maple tree.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.mm_mt.ma_root`.
    fn mm_mt_root(&self) -> Result<u64, VmiError> {
        let MAPLE_TREE = offset!(self.vmi, maple_tree);

        self.vmi
            .read_u64(self.mm_mt() + MAPLE_TREE.ma_root.offset())
    }

    /// Returns an iterator over the memory regions, in the order of their
    /// addresses.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the entries of `mm_struct.mm_mt`.
    pub fn regions(
        &self,
    ) -> impl Iterator<Item = Result<LinuxRegion<'a, Driver>, VmiError>> + use<'a, Driver> {
        let vmi = self.vmi;

        MapleTreeIterator::new(vmi, self.mm_mt())
            .map(move |result| result.map(|entry| LinuxRegion::new(vmi, entry)))
    }

    /// Returns the memory region containing the given address.
    ///
    /// # Implementation Details
    ///
    /// Looks the address up in `mm_struct.mm_mt`, as `find_vma_intersection`
    /// does, and checks the result against `vm_start` and `vm_end`.
    pub fn lookup_region(&self, address: Va) -> Result<Option<LinuxRegion<'a, Driver>>, VmiError> {
        let root = self.mm_mt_root()?;

        let entry = match maple_tree_lookup(&GuestMapleNodeReader::new(self.vmi), root, address.0)?
        {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let region = LinuxRegion::new(self.vmi, entry);
        if address >= region.start()? && address < region.end()? {
            return Ok(Some(region));
        }

        Ok(None)
    }

    /// Returns the memory region containing the given address or, for an
    /// address outside every region, the nearest region below it.
    pub(crate) fn region_at_or_below(
        &self,
        address: Va,
    ) -> Result<Option<LinuxRegion<'a, Driver>>, VmiError> {
        self.nearest_region(address, Nearest::Below)
    }

    /// Returns the memory region containing the given address or, for an
    /// address outside every region, the nearest region above it.
    pub(crate) fn region_at_or_above(
        &self,
        address: Va,
    ) -> Result<Option<LinuxRegion<'a, Driver>>, VmiError> {
        self.nearest_region(address, Nearest::Above)
    }

    /// Returns the memory region nearest to an address in a direction.
    fn nearest_region(
        &self,
        address: Va,
        nearest: Nearest,
    ) -> Result<Option<LinuxRegion<'a, Driver>>, VmiError> {
        let root = self.mm_mt_root()?;
        let reader = GuestMapleNodeReader::new(self.vmi);

        match maple_tree_lookup_nearest(&reader, root, address.0, nearest)? {
            Some(entry) => Ok(Some(LinuxRegion::new(self.vmi, entry))),
            None => Ok(None),
        }
    }

    /// Returns the base address of the vDSO, or `None` for a process
    /// without one.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the `AT_SYSINFO_EHDR` entry of `mm_struct.saved_auxv`,
    /// the auxiliary vector that the kernel passed to the program.
    pub fn vdso_base(&self) -> Result<Option<Va>, VmiError> {
        let MM_STRUCT = offset!(self.vmi, mm_struct);

        let mut buffer = vec![0; MM_STRUCT.saved_auxv.size() as usize];
        self.vmi
            .read(self.va + MM_STRUCT.saved_auxv.offset(), &mut buffer)?;

        let (pairs, _) = buffer.as_chunks::<{ 2 * size_of::<u64>() }>();

        for pair in pairs {
            let (words, _) = pair.as_chunks::<{ size_of::<u64>() }>();

            match u64::from_le_bytes(words[0]) {
                AT_NULL => break,
                AT_SYSINFO_EHDR => return Ok(Some(Va(u64::from_le_bytes(words[1])))),
                _ => {}
            }
        }

        Ok(None)
    }
}
