use vmi_core::{
    Pa, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{
        ProcessId, ProcessObject, ThreadObject, VmiOsImageArchitecture, VmiOsProcess,
        VmiOsRegion as _, VmiOsUserModule as _,
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

    /// Returns an iterator over the process's user-mode modules, in the
    /// order of their addresses.
    ///
    /// Kernel threads have none.
    ///
    /// # Implementation Details
    ///
    /// The header regions of the image files (see
    /// [`LinuxRegion::is_image`]), and the vDSO's region. The
    /// `AT_SYSINFO_EHDR` entry in `mm_struct.saved_auxv` gives the vDSO.
    fn user_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<LinuxUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let mm = match self.mm()? {
            Some(mm) => mm,
            None => return Ok(None.into_iter().flatten()),
        };

        let vmi = self.vmi;
        let root = self.translation_root()?;
        let vdso = mm.vdso_base()?;

        let module = move |region: LinuxRegion<'a, Driver>| -> Result<
            Option<LinuxUserModule<'a, Driver>>,
            VmiError,
        > {
            if is_module_region(&region, vdso)? {
                Ok(Some(LinuxUserModule::new(vmi, region.va(), root)))
            }
            else {
                Ok(None)
            }
        };

        let modules = mm
            .regions()
            .filter_map(move |region| region.and_then(module).transpose());

        Ok(Some(modules).into_iter().flatten())
    }

    /// Returns the user-mode module that contains an address.
    ///
    /// # Implementation Details
    ///
    /// Takes the region at or below the address. A region of an image file
    /// leads to its header region, and an anonymous region right after one,
    /// such as `.bss`, leads to the same image. The address must then lie
    /// within the module's span, which reads its program headers. The
    /// vDSO's region gives the vDSO.
    fn lookup_user_module(
        &self,
        address: Va,
    ) -> Result<Option<LinuxUserModule<'a, Driver>>, VmiError> {
        let mm = match self.mm()? {
            Some(mm) => mm,
            None => return Ok(None),
        };

        let region = match mm.region_at_or_below(address)? {
            Some(region) => region,
            None => return Ok(None),
        };

        let root = self.translation_root()?;

        let region = match region.file()? {
            Some(_) => region,
            None => {
                let start = region.start()?;

                if mm.vdso_base()? == Some(start) {
                    if address < region.end()? {
                        return Ok(Some(LinuxUserModule::new(self.vmi, region.va(), root)));
                    }

                    return Ok(None);
                }

                // An anonymous region right after an image region, such as
                // the image's `.bss`.
                match mm.region_at_or_below(start - 1)? {
                    Some(previous) if previous.end()? == start && previous.file()?.is_some() => {
                        previous
                    }
                    _ => return Ok(None),
                }
            }
        };

        let header = match region.header_region()? {
            Some(header) => header,
            None => return Ok(None),
        };

        if !header.is_image()? {
            return Ok(None);
        }

        let module = LinuxUserModule::new(self.vmi, header.va(), root);
        let base = module.base_address()?;

        if address >= base && address.0 - base.0 < module.size()? {
            return Ok(Some(module));
        }

        Ok(None)
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

/// Checks if a region records a user-mode module: the header region of an
/// image file (page offset 0), or the vDSO's region.
fn is_module_region<Driver>(
    region: &LinuxRegion<'_, Driver>,
    vdso: Option<Va>,
) -> Result<bool, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    if region.file()?.is_none() {
        return Ok(vdso == Some(region.start()?));
    }

    Ok(region.pgoff()? == 0 && region.is_image()?)
}
