use once_cell::unsync::OnceCell;
use vmi_core::{
    Architecture, Pa, Va, VmiError, VmiOs, VmiState, VmiVa,
    driver::VmiRead,
    os::{ProcessId, ProcessObject, VmiOsImageArchitecture, VmiOsProcess},
};

use super::{LinuxFsStruct, LinuxMmStruct, LinuxPath, LinuxVmAreaStruct, macros::impl_offsets};
use crate::{ArchAdapter, LinuxError, LinuxOs};

/// A Linux task struct.
///
/// The `task_struct` is the process descriptor in the Linux kernel,
/// representing a task (process or thread).
///
/// # Implementation Details
///
/// Corresponds to `task_struct`.
pub struct LinuxTaskStruct<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `task_struct` structure.
    va: Va,

    /// Cached flags.
    flags: OnceCell<u32>,
}

impl<Driver> VmiVa for LinuxTaskStruct<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxTaskStruct<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Linux task struct.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, process: ProcessObject) -> Self {
        Self {
            vmi,
            va: process.0,
            flags: OnceCell::new(),
        }
    }

    /// Returns the process flags.
    ///
    /// Process flags in Linux include information about the process state,
    /// such as whether it's exiting, a kernel thread, etc.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.flags`.
    pub fn flags(&self) -> Result<u32, VmiError> {
        self.flags
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let __task_struct = &offsets.task_struct;

                self.vmi.read_u32(self.va + __task_struct.flags.offset())
            })
            .copied()
    }

    /// Returns the memory descriptor (`mm_struct`) of the user-mode process.
    ///
    /// The `mm_struct` contains the memory management information for a process.
    /// Kernel threads don't have an `mm_struct` and return `None`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct->mm`.
    pub fn mm(&self) -> Result<Option<LinuxMmStruct<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let __task_struct = &offsets.task_struct;

        let mm = self
            .vmi
            .read_va_native(self.va + __task_struct.mm.offset())?;

        if mm.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxMmStruct::new(self.vmi, mm)))
    }

    /// Returns the active memory context (`mm_struct`) of the process.
    ///
    /// Used by kernel threads to reference the last used `mm_struct` before
    /// entering kernel mode.
    ///
    /// If a kernel thread ([`mm()`] is `None`) needs memory access,
    /// it temporarily borrows `active_mm` from the last scheduled user-space
    /// process.
    ///
    /// When the kernel thread exits, the original `mm_struct` is restored.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct->active_mm`.
    ///
    /// [`mm()`]: Self::mm
    pub fn active_mm(&self) -> Result<LinuxMmStruct<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __task_struct = &offsets.task_struct;

        let mm = self
            .vmi
            .read_va_native(self.va + __task_struct.active_mm.offset())?;

        if mm.is_null() {
            return Err(LinuxError::CorruptedStruct("task_struct->active_mm").into());
        }

        Ok(LinuxMmStruct::new(self.vmi, mm))
    }

    /// Returns the filesystem context (`fs_struct`) of the process.
    ///
    /// `fs_struct` contains:
    ///   - [`root`]: The process’s root directory (used for chroot).
    ///   - [`pwd`]: The current working directory.
    ///
    /// All threads in the same process share the same `fs_struct`, unless
    /// explicitly changed.
    ///
    /// Kernel threads don't have an `fs_struct` and return `None`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct->fs`.
    ///
    /// [`root`]: LinuxFsStruct::root
    /// [`pwd`]: LinuxFsStruct::pwd
    pub fn fs(&self) -> Result<Option<LinuxFsStruct<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let __task_struct = &offsets.task_struct;
        let __fs_struct = &offsets.fs_struct;

        let fs = self
            .vmi
            .read_va_native(self.va + __task_struct.fs.offset())?;

        if fs.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxFsStruct::new(self.vmi, fs)))
    }

    /// Constructs the absolute path from a `path` structure.
    ///
    /// Takes into account the process's filesystem root when constructing the
    /// absolute path.
    ///
    /// Returns the resolved path as a string if successful, or `None` if the path
    /// could not be resolved (e.g., if the root is null).
    ///
    /// # Implementation Details
    ///
    /// Concatenates `task_struct->fs->root` with the `path` structure to construct
    /// the absolute path.
    pub fn d_path(&self, path: &LinuxPath<Driver>) -> Result<Option<String>, VmiError> {
        let root = match self.fs()? {
            Some(root) => root.root()?,
            None => return Ok(None),
        };

        Ok(Some(LinuxOs::<Driver>::construct_path(
            self.vmi, path, &root,
        )?))
    }

    /// Returns the path of the executable image for a process.
    ///
    /// Returns the executable path as a string, or `None` for special processes
    /// like kernel threads or those in the process of exiting.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `d_path(task->mm->exe_file->f_path)`.
    pub fn image_path(&self) -> Result<Option<String>, VmiError> {
        let flags = self.flags()?;

        const PF_EXITING: u32 = 0x00000004; // getting shut down
        const PF_KTHREAD: u32 = 0x00200000; // kernel thread

        if flags & PF_KTHREAD != 0 {
            return Ok(None);
        }

        if flags & PF_EXITING != 0 {
            return Ok(None);
        }

        let mm = match self.mm()? {
            Some(mm) => mm,
            None => return Ok(None),
        };

        let exe_file = match mm.exe_file()? {
            Some(exe_file) => exe_file,
            None => return Ok(None),
        };

        self.d_path(&exe_file.path()?)
    }
}

impl<'a, Driver> VmiOsProcess<'a, Driver> for LinuxTaskStruct<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    fn id(&self) -> Result<ProcessId, VmiError> {
        let offsets = self.offsets();
        let __task_struct = &offsets.task_struct;

        let result = self.vmi.read_u32(self.va + __task_struct.tgid.offset())?;

        Ok(ProcessId(result))
    }

    fn object(&self) -> Result<ProcessObject, VmiError> {
        Ok(ProcessObject(self.va))
    }

    fn name(&self) -> Result<String, VmiError> {
        let task_struct_comm_offset = 0xBC0;

        self.vmi.read_string(self.va + task_struct_comm_offset)
    }

    fn parent_id(&self) -> Result<ProcessId, VmiError> {
        unimplemented!()
    }

    fn architecture(&self) -> Result<VmiOsImageArchitecture, VmiError> {
        unimplemented!()
    }

    fn translation_root(&self) -> Result<Pa, VmiError> {
        unimplemented!()
    }

    fn user_translation_root(&self) -> Result<Pa, VmiError> {
        unimplemented!()
    }

    fn image_base(&self) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn regions(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs<Driver>>::Region<'a>, VmiError>>,
        VmiError,
    > {
        let mut result = Vec::new();

        let mm = match self.mm()? {
            Some(mm) => mm,
            None => return Ok(result.into_iter()),
        };

        let mt = mm.mm_mt()?;
        mt.enumerate(|node| {
            println!("XXXNode: {}", node);
            if !node.is_null() {
                result.push(Ok(LinuxVmAreaStruct::new(self.vmi, node)));
            }
            true
        })?;

        Ok(result.into_iter())
    }

    fn find_region(
        &self,
        _address: Va,
    ) -> Result<Option<<Self::Os as VmiOs<Driver>>::Region<'a>>, VmiError> {
        unimplemented!()
    }

    fn threads(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs<Driver>>::Thread<'a>, VmiError>>,
        VmiError,
    > {
        #[allow(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn is_valid_address(&self, _address: Va) -> Result<Option<bool>, VmiError> {
        unimplemented!()
    }
}
