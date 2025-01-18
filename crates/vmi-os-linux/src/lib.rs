//! Linux OS-specific VMI operations.

use std::cell::RefCell;

use isr_core::Profile;
use vmi_core::{
    os::{
        OsArchitecture, OsExt, OsImageExportedSymbol, OsMapped, OsModule, OsProcess, OsRegion,
        OsRegionKind, ProcessId, ProcessObject, ThreadId, ThreadObject,
    },
    Architecture, MemoryAccess, Pa, Va, VmiCore, VmiDriver, VmiError, VmiOs, VmiState,
};

mod arch;
use self::arch::ArchAdapter;

mod maple_tree;
pub use self::maple_tree::MapleTree;

mod offsets;
pub use self::offsets::{Offsets, Symbols};

/// VMI operations for the Linux operating system.
///
/// `LinuxOs` provides methods and utilities for introspecting a Linux-based
/// virtual machine. It encapsulates Linux-specific knowledge and operations,
/// allowing for high-level interactions with the guest OS structures and processes.
pub struct LinuxOs<Driver>
where
    Driver: VmiDriver,
{
    offsets: Offsets,
    symbols: Symbols,
    kernel_image_base: RefCell<Option<Va>>,
    kaslr_offset: RefCell<Option<u64>>,

    _marker: std::marker::PhantomData<Driver>,
}

#[allow(non_snake_case, unused_variables)]
impl<Driver> LinuxOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new `LinuxOs` instance.
    pub fn new(profile: &Profile) -> Result<Self, VmiError> {
        Ok(Self {
            offsets: Offsets::new(profile)?,
            symbols: Symbols::new(profile)?,
            kernel_image_base: RefCell::new(None),
            kaslr_offset: RefCell::new(None),
            _marker: std::marker::PhantomData,
        })
    }

    /// Locates and retrieves the Linux banner string from kernel memory.
    ///
    /// The banner string typically contains kernel version information and build details.
    pub fn find_banner(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<String>, VmiError> {
        Driver::Architecture::find_banner(vmi, registers)
    }

    /// Returns the KASLR (Kernel Address Space Layout Randomization) offset.
    ///
    /// This value represents the randomized offset applied to the kernel's base address
    /// when KASLR is enabled.
    pub fn kaslr_offset(&self, vmi: &VmiState<Driver, Self>) -> Result<u64, VmiError> {
        Driver::Architecture::kaslr_offset(vmi, self)
    }

    /// Retrieves the per-CPU base address for the current CPU.
    ///
    /// Linux maintains per-CPU data structures, and this method returns the base
    /// address for accessing such data on the current processor.
    pub fn per_cpu(&self, vmi: &VmiState<Driver, Self>) -> Va {
        Driver::Architecture::per_cpu(vmi, self)
    }

    /// Resolves a file path from a `struct path` pointer.
    ///
    /// Takes into account the process's filesystem root when constructing the
    /// absolute path.
    ///
    /// Returns the resolved path as a string if successful, or `None` if the path
    /// could not be resolved (e.g., if the root is null).
    pub fn d_path(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
        path: Va, // struct path*
    ) -> Result<Option<String>, VmiError> {
        let root = self.process_fs_root(vmi, process)?;
        if root.is_null() {
            return Ok(None);
        }

        Ok(Some(self.construct_path(vmi, path, root)?))
    }

    /// Constructs a file path string from path components in the kernel.
    ///
    /// This method walks the dentry chain to build a complete path, handling
    /// mount points and filesystem boundaries appropriately. Both the `path`
    /// and `root` arguments should be pointers to `struct path` objects.
    pub fn construct_path(
        &self,
        vmi: &VmiState<Driver, Self>,
        path: Va, // struct path*
        root: Va, // struct path*
    ) -> Result<String, VmiError> {
        let __dentry = &self.offsets.dentry;
        let __path = &self.offsets.path;
        let __vfsmount = &self.offsets.vfsmount;
        let __qstr = &self.offsets.qstr;

        let mut result = String::new();

        let mut dentry = vmi.read_va_native(path + __path.dentry.offset)?;

        let mnt = vmi.read_va_native(path + __path.mnt.offset)?;

        let root_dentry = vmi.read_va_native(root + __path.dentry.offset)?;

        let root_mnt = vmi.read_va_native(root + __path.mnt.offset)?;

        while dentry != root_dentry || mnt != root_mnt {
            let mnt_mnt_root = vmi.read_va_native(mnt + __vfsmount.mnt_root.offset)?;

            let dentry_parent = vmi.read_va_native(dentry + __dentry.d_parent.offset)?;

            if dentry == mnt_mnt_root || dentry == dentry_parent {
                break;
            }

            let d_name =
                vmi.read_va_native(dentry + __dentry.d_name.offset + __qstr.name.offset)?;

            let name = vmi.read_string(d_name)?;

            result.insert_str(0, &name);
            result.insert(0, '/');

            dentry = dentry_parent;
        }

        Ok(result)
    }

    /// Constructs an [`OsProcess`] from a `task_struct`.
    pub fn task_struct_to_process(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<OsProcess, VmiError> {
        let __task_struct = &self.offsets.task_struct;

        let id = vmi.read_u32(process.0 + __task_struct.tgid.offset)?;
        let name = match self.process_image_path(vmi, process) {
            Ok(Some(name)) => name,
            _ => vmi.read_string(process.0 + __task_struct.comm.offset)?,
        };
        let translation_root = self.process_pgd(vmi, process)?;

        Ok(OsProcess {
            id: id.into(),
            object: process,
            name,
            translation_root: translation_root.unwrap_or_default(),
        })
    }

    /// Gets the process flags from a `task_struct`.
    ///
    /// Process flags in Linux include information about the process state,
    /// such as whether it's exiting, a kernel thread, etc.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// return task->flags;
    /// ```
    pub fn process_flags(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<u32, VmiError> {
        let __task_struct = &self.offsets.task_struct;

        vmi.read_u32(process.0 + __task_struct.flags.offset)
    }

    /// Gets the address of `mm_struct` from a `task_struct`.
    ///
    /// The `mm_struct` contains the memory management information for a process.
    /// Kernel threads don't have an `mm_struct` and return a null pointer.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// return task->mm;
    /// ```
    pub fn process_mm(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Va, VmiError> {
        let __task_struct = &self.offsets.task_struct;

        vmi.read_va_native(process.0 + __task_struct.mm.offset)
    }

    /// Gets the address of `active_mm` from a `task_struct`.
    ///
    /// The `active_mm` field is used primarily for kernel threads that temporarily
    /// need to use a userspace process's address space.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// return task->active_mm;
    /// ```
    pub fn process_active_mm(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Va, VmiError> {
        let __task_struct = &self.offsets.task_struct;

        vmi.read_va_native(process.0 + __task_struct.active_mm.offset)
    }

    /// Gets the filesystem root of a process.
    ///
    /// Retrieves the root directory entry from the process's `fs_struct`.
    /// This is used for path resolution relative to the process's root.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// return task->fs->root;
    /// ```
    pub fn process_fs_root(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Va, VmiError> {
        // struct path*
        let __task_struct = &self.offsets.task_struct;
        let __fs_struct = &self.offsets.fs_struct;

        let fs = vmi.read_va_native(process.0 + __task_struct.fs.offset)?;

        Ok(fs + __fs_struct.root.offset)
    }

    /// Gets the page directory base (PGD) for a process.
    ///
    /// The PGD is the top-level structure for virtual address translation.
    /// This method handles both regular processes and kernel threads.
    ///
    /// Returns the physical address of the process's page directory base,
    /// or `None` if the process has no address space (e.g., a kernel thread
    /// with no borrowed `mm_struct`).
    pub fn process_pgd(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Option<Pa>, VmiError> {
        let __mm_struct = &self.offsets.mm_struct;

        let mut mm = self.process_mm(vmi, process)?;
        if mm.is_null() {
            mm = self.process_active_mm(vmi, process)?;

            if mm.is_null() {
                return Ok(None);
            }
        }

        let pgd = vmi.read_va_native(mm + __mm_struct.pgd.offset)?;
        Ok(Some(vmi.translate_address(pgd)?))
    }

    /// Gets the path of the executable image for a process.
    ///
    /// Retrieves the full path to the executable by traversing the process's
    /// `mm_struct` and file structures.
    ///
    /// Returns the executable path as a string, or `None` for special processes
    /// like kernel threads or those in the process of exiting.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// if (flags & PF_KTHREAD) {
    ///    return NULL;
    /// }
    ///
    /// if (flags & PF_EXITING) {
    ///   return NULL;
    /// }
    ///
    /// return d_path(task->mm->exe_file->f_path);
    /// ```
    pub fn process_image_path(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Option<String>, VmiError> {
        let __mm_struct = &self.offsets.mm_struct;
        let __file = &self.offsets.file;

        let flags = self.process_flags(vmi, process)?;

        const PF_EXITING: u32 = 0x00000004; // getting shut down
        const PF_KTHREAD: u32 = 0x00200000; // kernel thread

        if flags & PF_KTHREAD != 0 {
            return Ok(None); // self.process_filename(vmi, process);
        }

        if flags & PF_EXITING != 0 {
            let pid = self.process_id(vmi, process)?;
            return Ok(None);
        }

        let mm = self.process_mm(vmi, process)?;
        let exe_file = vmi.read_va_native(mm + __mm_struct.exe_file.offset)?;

        let f_path = exe_file + __file.f_path.offset;
        self.d_path(vmi, process, f_path)
    }

    /// Converts a VMA (Virtual Memory Area) to an [`OsRegion`] structure.
    ///
    /// VMAs represent continuous regions of virtual memory in a process's
    /// address space. This method extracts information about the memory
    /// region's address range, permissions, and backing (file or anonymous).
    pub fn process_vm_area_to_region(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
        entry: Va,
    ) -> Result<OsRegion, VmiError> {
        let __vm_area_struct = &self.offsets.vm_area_struct;
        let __file = &self.offsets.file;

        let start = vmi.read_va_native(entry + __vm_area_struct.vm_start.offset)?;

        let end = vmi.read_va_native(entry + __vm_area_struct.vm_end.offset)?;

        let file = vmi.read_va_native(entry + __vm_area_struct.vm_file.offset)?;

        let flags = u64::from(vmi.read_va_native(entry + __vm_area_struct.vm_flags.offset)?);

        const VM_READ: u64 = 0x00000001;
        const VM_WRITE: u64 = 0x00000002;
        const VM_EXEC: u64 = 0x00000004;
        //const VM_SHARED: u64 = 0x00000008;

        let mut protection = MemoryAccess::default();
        if flags & VM_READ != 0 {
            protection |= MemoryAccess::R;
        }
        if flags & VM_WRITE != 0 {
            protection |= MemoryAccess::W;
        }
        if flags & VM_EXEC != 0 {
            protection |= MemoryAccess::X;
        }

        let kind = if file.is_null() {
            OsRegionKind::Private
        }
        else {
            let f_path = file + __file.f_path.offset;

            let path = self.d_path(vmi, process, f_path);
            OsRegionKind::Mapped(OsMapped { path })
        };

        Ok(OsRegion {
            start,
            end,
            protection,
            kind,
        })
    }
}

#[allow(non_snake_case, unused_variables)]
impl<Driver> VmiOs<Driver> for LinuxOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn kernel_image_base(&self, vmi: &VmiState<Driver, Self>) -> Result<Va, VmiError> {
        Driver::Architecture::kernel_image_base(vmi, self)
    }

    fn kernel_information_string(&self, vmi: &VmiState<Driver, Self>) -> Result<String, VmiError> {
        unimplemented!()
    }

    fn kpti_enabled(&self, vmi: &VmiState<Driver, Self>) -> Result<bool, VmiError> {
        unimplemented!()
    }

    fn modules(&self, vmi: &VmiState<Driver, Self>) -> Result<Vec<OsModule>, VmiError> {
        unimplemented!()
    }

    fn system_process(&self, vmi: &VmiState<Driver, Self>) -> Result<ProcessObject, VmiError> {
        unimplemented!()
    }

    fn thread_id(
        &self,
        vmi: &VmiState<Driver, Self>,
        thread: ThreadObject,
    ) -> Result<ThreadId, VmiError> {
        unimplemented!()
    }

    fn process_id(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<ProcessId, VmiError> {
        let task_struct = &self.offsets.task_struct;

        let result = vmi.read_u32(process.0 + task_struct.tgid.offset)?;

        Ok(ProcessId(result))
    }

    fn current_thread(&self, vmi: &VmiState<Driver, Self>) -> Result<ThreadObject, VmiError> {
        unimplemented!()
    }

    fn current_thread_id(&self, vmi: &VmiState<Driver, Self>) -> Result<ThreadId, VmiError> {
        let task_struct = &self.offsets.task_struct;

        let process = self.current_process(vmi)?;

        if process.is_null() {
            return Err(VmiError::Other("Invalid process"));
        }

        let result = vmi.read_u32(process.0 + task_struct.pid.offset)?;

        Ok(ThreadId(result))
    }

    fn current_process(&self, vmi: &VmiState<Driver, Self>) -> Result<ProcessObject, VmiError> {
        let pcpu_hot_offset = self.symbols.pcpu_hot;
        let pcpu_hot = &self.offsets.pcpu_hot;

        let per_cpu = self.per_cpu(vmi);
        if per_cpu.is_null() {
            return Err(VmiError::Other("Invalid per_cpu"));
        }

        let addr = per_cpu + pcpu_hot_offset + pcpu_hot.current_task.offset;
        let result = vmi.read_va_native(addr)?;

        Ok(ProcessObject(result))
    }

    fn current_process_id(&self, vmi: &VmiState<Driver, Self>) -> Result<ProcessId, VmiError> {
        let process = self.current_process(vmi)?;

        if process.is_null() {
            return Err(VmiError::Other("Invalid process"));
        }

        self.process_id(vmi, process)
    }

    fn processes(&self, vmi: &VmiState<Driver, Self>) -> Result<Vec<OsProcess>, VmiError> {
        let init_task_address = self.symbols.init_task;
        let task_struct = &self.offsets.task_struct;

        let mut result = Vec::new();

        let init_task = Va(init_task_address) + self.kaslr_offset(vmi)?;
        let tasks = init_task + task_struct.tasks.offset;

        self.enumerate_list(vmi, tasks, |entry| {
            let process_object = entry - task_struct.tasks.offset;

            if let Ok(process) = self.task_struct_to_process(vmi, process_object.into()) {
                result.push(process)
            }

            true
        })?;

        Ok(result)
    }

    fn process_parent_process_id(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<ProcessId, VmiError> {
        unimplemented!()
    }

    fn process_architecture(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<OsArchitecture, VmiError> {
        unimplemented!()
    }

    fn process_translation_root(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Pa, VmiError> {
        unimplemented!()
    }

    fn process_user_translation_root(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Pa, VmiError> {
        unimplemented!()
    }

    fn process_filename(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<String, VmiError> {
        let task_struct_comm_offset = 0xBC0;

        vmi.read_string(process.0 + task_struct_comm_offset)
    }

    fn process_image_base(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn process_regions(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
    ) -> Result<Vec<OsRegion>, VmiError> {
        let __mm_struct = &self.offsets.mm_struct;

        let mm = self.process_mm(vmi, process)?;
        if mm.is_null() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();

        let mt = MapleTree::new(vmi, &self.offsets);
        mt.enumerate(mm + __mm_struct.mm_mt.offset, |entry| {
            if entry.is_null() {
                return true;
            }

            match self.process_vm_area_to_region(vmi, process, entry) {
                Ok(region) => result.push(region),
                Err(err) => tracing::warn!(?err, ?entry, "Failed to convert MT entry to region"),
            }

            true
        })?;

        Ok(result)
    }

    fn process_address_is_valid(
        &self,
        vmi: &VmiState<Driver, Self>,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<bool>, VmiError> {
        unimplemented!()
    }

    fn find_process_region(
        &self,
        _vmi: &VmiState<Driver, Self>,
        _process: ProcessObject,
        _address: Va,
    ) -> Result<Option<OsRegion>, VmiError> {
        unimplemented!()
    }

    fn image_architecture(
        &self,
        vmi: &VmiState<Driver, Self>,
        image_base: Va,
    ) -> Result<OsArchitecture, VmiError> {
        unimplemented!()
    }

    fn image_exported_symbols(
        &self,
        vmi: &VmiState<Driver, Self>,
        image_base: Va,
    ) -> Result<Vec<OsImageExportedSymbol>, VmiError> {
        unimplemented!()
    }

    fn syscall_argument(&self, vmi: &VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::syscall_argument(vmi, self, index)
    }

    fn function_argument(&self, vmi: &VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::function_argument(vmi, self, index)
    }

    fn function_return_value(&self, vmi: &VmiState<Driver, Self>) -> Result<u64, VmiError> {
        Driver::Architecture::function_return_value(vmi, self)
    }

    fn last_error(&self, vmi: &VmiState<Driver, Self>) -> Result<Option<u32>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> OsExt<Driver> for LinuxOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn enumerate_list(
        &self,
        vmi: &VmiState<Driver, Self>,
        list_head: Va,
        mut callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        let mut entry = vmi.read_va_native(list_head)?;

        while entry != list_head {
            if !callback(entry) {
                break;
            }

            entry = vmi.read_va_native(entry)?;
        }

        Ok(())
    }

    fn enumerate_tree(
        &self,
        _vmi: &VmiState<Driver, Self>,
        _root: Va,
        _callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        unimplemented!()
    }
}
