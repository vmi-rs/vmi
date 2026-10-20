use vmi_core::{
    Pa, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{
        ProcessId, ProcessObject, ThreadObject, VmiOsImageArchitecture, VmiOsProcess,
        VmiOsRegion as _,
    },
};

use super::{LinuxMmStruct, LinuxRegion, LinuxThread, LinuxUserModule, thread::PF_KTHREAD};
use crate::{ArchAdapter, LinuxError, LinuxOs, ListEntryIterator, offset, symbol};

/// Largest user address space of a 32-bit process.
///
/// A process with a 32-bit address space (`TIF_ADDR32`) gets `TASK_SIZE` of
/// `IA32_PAGE_OFFSET` (just below 4 GiB), a 64-bit process `TASK_SIZE_MAX`.
const IA32_TASK_SIZE_MAX: u64 = 0x1_0000_0000;

/// A Linux process.
///
/// A process in Linux is a thread group. Its threads share the address
/// space and the signal handlers, and the first thread, the group leader,
/// represents the process.
///
/// # Implementation Details
///
/// Corresponds to the `task_struct` of a thread group leader.
pub struct LinuxProcess<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `task_struct` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxProcess<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxProcess<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux process.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, process: ProcessObject) -> Self {
        Self { vmi, va: process.0 }
    }

    /// Returns the memory descriptor of the process.
    ///
    /// Kernel threads have none.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.mm`.
    pub fn mm(&self) -> Result<Option<LinuxMmStruct<'a, Driver>>, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        let mm = self.vmi.read_va_native(self.va + TASK_STRUCT.mm.offset())?;

        if mm.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxMmStruct::new(self.vmi, mm)))
    }

    /// Returns the flags of the group leader (`PF_*`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.flags`.
    pub fn flags(&self) -> Result<u32, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        self.vmi.read_u32(self.va + TASK_STRUCT.flags.offset())
    }

    /// Checks if the process is a kernel thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `PF_KTHREAD` in `task_struct.flags`.
    pub fn is_kernel_thread(&self) -> Result<bool, VmiError> {
        Ok(self.flags()? & PF_KTHREAD != 0)
    }

    /// Returns the memory descriptor whose page tables the process uses.
    ///
    /// Kernel threads have no memory descriptor of their own and use the
    /// kernel's page tables, those of `init_mm`.
    fn page_table_mm(&self) -> Result<LinuxMmStruct<'a, Driver>, VmiError> {
        match self.mm()? {
            Some(mm) => Ok(mm),
            None => {
                let init_mm = LinuxOs::symbol_address(self.vmi, symbol!(self.vmi, init_mm))?;
                Ok(LinuxMmStruct::new(self.vmi, init_mm))
            }
        }
    }
}

impl<'a, Driver> VmiOsProcess<'a, Driver> for LinuxProcess<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the process ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.tgid`.
    fn id(&self) -> Result<ProcessId, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        let result = self.vmi.read_u32(self.va + TASK_STRUCT.tgid.offset())?;

        Ok(ProcessId(result))
    }

    /// Returns the process object.
    fn object(&self) -> Result<ProcessObject, VmiError> {
        Ok(ProcessObject(self.va))
    }

    /// Returns the name of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.comm` of the group leader.
    fn name(&self) -> Result<String, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        self.vmi.read_string_limited(
            self.va + TASK_STRUCT.comm.offset(),
            TASK_STRUCT.comm.size() as usize,
        )
    }

    /// Returns the parent process ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.tgid` of `task_struct.real_parent`, the
    /// value that procfs reports as `PPid`.
    fn parent_id(&self) -> Result<ProcessId, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        let real_parent = self
            .vmi
            .read_va_native(self.va + TASK_STRUCT.real_parent.offset())?;

        if real_parent.is_null() {
            return Err(LinuxError::CorruptedStruct("task_struct.real_parent").into());
        }

        let result = self.vmi.read_u32(real_parent + TASK_STRUCT.tgid.offset())?;

        Ok(ProcessId(result))
    }

    /// Returns the architecture of the process.
    ///
    /// # Implementation Details
    ///
    /// A process with a 32-bit address space (`TIF_ADDR32`) has an
    /// `mm_struct.task_size` of at most 4 GiB. Kernel threads have no memory
    /// descriptor and report AMD64.
    fn architecture(&self) -> Result<VmiOsImageArchitecture, VmiError> {
        let mm = match self.mm()? {
            Some(mm) => mm,
            None => return Ok(VmiOsImageArchitecture::Amd64),
        };

        if mm.task_size()? <= IA32_TASK_SIZE_MAX {
            Ok(VmiOsImageArchitecture::X86)
        }
        else {
            Ok(VmiOsImageArchitecture::Amd64)
        }
    }

    /// Returns the process's page table translation root.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the physical address of `mm_struct.pgd`, or of
    /// `init_mm.pgd` for kernel threads.
    fn translation_root(&self) -> Result<Pa, VmiError> {
        let pgd = self.page_table_mm()?.pgd()?;
        self.vmi.translate_address(pgd)
    }

    /// Returns the user-mode page table translation root.
    ///
    /// If KPTI is disabled, this function will return the same value as
    /// [`translation_root`](Self::translation_root).
    ///
    /// # Implementation Details
    ///
    /// Under page table isolation, the kernel allocates the user page table
    /// right after the kernel one (`kernel_to_user_pgdp`).
    fn user_translation_root(&self) -> Result<Pa, VmiError> {
        let root = self.translation_root()?;

        if self.mm()?.is_some() && self.vmi.os().kpti_enabled()? {
            return Ok(Driver::Architecture::user_translation_root(root));
        }

        Ok(root)
    }

    /// Returns the base address of the process image.
    ///
    /// Returns 0 for a process without a memory descriptor or without a
    /// mapping of its executable.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the start of the lowest region whose
    /// `vm_area_struct.vm_file` is `mm_struct.exe_file`.
    fn image_base(&self) -> Result<Va, VmiError> {
        let mm = match self.mm()? {
            Some(mm) => mm,
            None => return Ok(Va(0)),
        };

        let exe_file = match mm.exe_file()? {
            Some(exe_file) => exe_file,
            None => return Ok(Va(0)),
        };

        for region in mm.regions() {
            let region = region?;

            if let Some(file) = region.file()?
                && file.va() == exe_file.va()
            {
                return region.start();
            }
        }

        Ok(Va(0))
    }

    /// Returns an iterator over the process's memory regions.
    ///
    /// Kernel threads have none.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the maple tree `mm_struct.mm_mt`.
    fn regions(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<LinuxRegion<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let regions = self.mm()?.map(|mm| mm.regions());

        Ok(regions.into_iter().flatten())
    }

    /// Returns the memory region containing the given address.
    ///
    /// # Implementation Details
    ///
    /// Looks the address up in the maple tree `mm_struct.mm_mt`, as
    /// `find_vma_intersection` does.
    fn lookup_region(&self, address: Va) -> Result<Option<LinuxRegion<'a, Driver>>, VmiError> {
        match self.mm()? {
            Some(mm) => mm.lookup_region(address),
            None => Ok(None),
        }
    }

    /// Not supported yet.
    fn user_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<LinuxUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        Err::<std::iter::Empty<_>, _>(VmiError::NotSupported)
    }

    /// Not supported yet.
    fn lookup_user_module(
        &self,
        _address: Va,
    ) -> Result<Option<LinuxUserModule<'a, Driver>>, VmiError> {
        Err(VmiError::NotSupported)
    }

    /// Returns an iterator over the threads in the process.
    ///
    /// The group leader comes first.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the list `signal_struct.thread_head` of
    /// `task_struct.signal`, linked through `task_struct.thread_node`.
    fn threads(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<LinuxThread<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let TASK_STRUCT = offset!(self.vmi, task_struct);
        let SIGNAL_STRUCT = offset!(self.vmi, signal_struct);

        let signal = self
            .vmi
            .read_va_native(self.va + TASK_STRUCT.signal.offset())?;

        if signal.is_null() {
            return Err(LinuxError::CorruptedStruct("task_struct.signal").into());
        }

        let vmi = self.vmi;
        Ok(ListEntryIterator::new(
            vmi,
            signal + SIGNAL_STRUCT.thread_head.offset(),
            TASK_STRUCT.thread_node.offset(),
        )
        .map(move |result| result.map(|entry| LinuxThread::new(vmi, ThreadObject(entry)))))
    }

    /// Checks whether the given virtual address is valid in the process.
    ///
    /// This method checks if page-faulting on the address would result in
    /// a successful access. It returns `None` for addresses outside the
    /// user address space, which the process's regions do not describe.
    ///
    /// # Implementation Details
    ///
    /// A user address is valid if a region contains it.
    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError> {
        let mm = match self.mm()? {
            Some(mm) => mm,
            None => return Ok(None),
        };

        if address.0 >= mm.task_size()? {
            return Ok(None);
        }

        Ok(Some(mm.lookup_region(address)?.is_some()))
    }
}
