//! Linux OS-specific VMI operations.

use std::cell::RefCell;

use isr_core::Profile;
use vmi_core::{
    Architecture, Va, VmiCore, VmiDriver, VmiError, VmiOs, VmiState, VmiVa as _,
    os::{ProcessObject, ThreadObject},
};

mod arch;
use self::arch::ArchAdapter;

mod comps;
pub use self::comps::{
    LinuxDEntry, LinuxFile, LinuxFsStruct, LinuxImage, LinuxMapped, LinuxMmStruct, LinuxModule,
    LinuxPath, LinuxQStr, LinuxTaskStruct, LinuxThread, LinuxVFSMount, LinuxVmAreaStruct,
};

mod error;
pub use self::error::LinuxError;

mod iter;
pub use self::iter::{ListEntryIterator, MapleTree, MapleTreeIteratorNew};

mod offsets;
pub use self::offsets::{Offsets, Symbols};

macro_rules! offset {
    ($vmi:expr, $field:ident) => {
        &__self(&$vmi).offsets.$field
    };
}

macro_rules! symbol {
    ($vmi:expr, $field:ident) => {
        __self(&$vmi).symbols.$field
    };
}

fn __self<'a, Driver>(vmi: &VmiState<'a, Driver, LinuxOs<Driver>>) -> &'a LinuxOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi.underlying_os()
}

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

//#[expect(non_snake_case, unused_variables)]
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
    pub fn kaslr_offset(vmi: VmiState<Driver, Self>) -> Result<u64, VmiError> {
        Driver::Architecture::kaslr_offset(vmi)
    }

    /// Retrieves the per-CPU base address for the current CPU.
    ///
    /// Linux maintains per-CPU data structures, and this method returns the base
    /// address for accessing such data on the current processor.
    pub fn per_cpu(vmi: VmiState<Driver, Self>) -> Va {
        Driver::Architecture::per_cpu(vmi)
    }

    /// Returns an iterator over a doubly-linked list of `LIST_ENTRY` structures.
    ///
    /// This method is used to iterate over a doubly-linked list of `LIST_ENTRY`
    /// structures in memory. It returns an iterator that yields the virtual
    /// addresses of each `LIST_ENTRY` structure in the list.
    pub fn linked_list<'a>(
        vmi: VmiState<'a, Driver, Self>,
        list_head: Va,
        offset: u64,
    ) -> Result<impl Iterator<Item = Result<Va, VmiError>> + 'a, VmiError> {
        Ok(ListEntryIterator::new(vmi, list_head, offset))
    }

    /// Constructs a file path string from path components in the kernel.
    ///
    /// This method walks the dentry chain to build a complete path, handling
    /// mount points and filesystem boundaries appropriately. Both the `path`
    /// and `root` arguments should be pointers to `struct path` objects.
    pub fn construct_path(
        _vmi: VmiState<Driver, Self>,
        path: &LinuxPath<Driver>,
        root: &LinuxPath<Driver>,
    ) -> Result<String, VmiError> {
        let mut dentry = path.dentry()?;
        let mnt = path.mnt()?;
        let root_dentry = root.dentry()?;
        let root_mnt = root.mnt()?;
        let mnt_mnt_root = mnt.mnt_root()?;

        let mut result = String::new();

        while dentry.va() != root_dentry.va() || mnt.va() != root_mnt.va() {
            let dentry_parent = match dentry.parent()? {
                Some(dentry) => dentry,
                None => break,
            };

            if dentry.va() == mnt_mnt_root.va() || dentry.va() == dentry_parent.va() {
                break;
            }

            let name = dentry.name()?.unwrap_or_else(|| String::from("<unknown>"));

            result.insert_str(0, &name);
            result.insert(0, '/');

            dentry = dentry_parent;
        }

        Ok(result)
    }
}

//#[expect(non_snake_case, unused_variables)]
impl<Driver> VmiOs<Driver> for LinuxOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Process<'a> = LinuxTaskStruct<'a, Driver>;
    type Thread<'a> = LinuxThread;
    type Image<'a> = LinuxImage;
    type Module<'a> = LinuxModule;
    type Region<'a> = LinuxVmAreaStruct<'a, Driver>;
    type Mapped<'a> = LinuxMapped;

    fn kernel_image_base(_vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn kernel_information_string(_vmi: VmiState<Driver, Self>) -> Result<String, VmiError> {
        unimplemented!()
    }

    fn kpti_enabled(_vmi: VmiState<Driver, Self>) -> Result<bool, VmiError> {
        unimplemented!()
    }

    fn modules(
        _vmi: VmiState<'_, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'_>, VmiError>> + '_, VmiError> {
        #[expect(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn processes(
        vmi: VmiState<'_, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'_>, VmiError>> + '_, VmiError> {
        let __init_task = symbol!(vmi, init_task);
        let __task_struct = &offset!(vmi, task_struct);

        let init_task = Va(__init_task) + Self::kaslr_offset(vmi)?;
        let tasks = init_task + __task_struct.tasks.offset();

        Ok(Self::linked_list(vmi, tasks, __task_struct.tasks.offset())?
            .map(move |result| result.map(|entry| LinuxTaskStruct::new(vmi, ProcessObject(entry)))))
    }

    fn process(
        vmi: VmiState<'_, Driver, Self>,
        process: ProcessObject,
    ) -> Result<Self::Process<'_>, VmiError> {
        Ok(LinuxTaskStruct::new(vmi, process))
    }

    fn current_process(vmi: VmiState<'_, Driver, Self>) -> Result<Self::Process<'_>, VmiError> {
        let pcpu_hot = symbol!(vmi, pcpu_hot);
        let __pcpu_hot = offset!(vmi, pcpu_hot);

        let per_cpu = Self::per_cpu(vmi);
        if per_cpu.is_null() {
            return Err(LinuxError::CorruptedStruct("per_cpu").into());
        }

        let addr = per_cpu + pcpu_hot + __pcpu_hot.current_task.offset();
        let result = vmi.read_va_native(addr)?;

        Ok(LinuxTaskStruct::new(vmi, ProcessObject(result)))
    }

    fn system_process(vmi: VmiState<'_, Driver, Self>) -> Result<Self::Process<'_>, VmiError> {
        let __init_task = symbol!(vmi, init_task);
        let __task_struct = &offset!(vmi, task_struct);

        let init_task = Va(__init_task) + Self::kaslr_offset(vmi)?;
        Ok(LinuxTaskStruct::new(vmi, ProcessObject(init_task)))
    }

    fn thread(
        _vmi: VmiState<'_, Driver, Self>,
        _thread: ThreadObject,
    ) -> Result<Self::Thread<'_>, VmiError> {
        unimplemented!()
    }

    fn current_thread(_vmi: VmiState<'_, Driver, Self>) -> Result<Self::Thread<'_>, VmiError> {
        unimplemented!()
    }

    fn image(
        _vmi: VmiState<'_, Driver, Self>,
        _image_base: Va,
    ) -> Result<Self::Image<'_>, VmiError> {
        unimplemented!()
    }

    fn module(_vmi: VmiState<'_, Driver, Self>, _module: Va) -> Result<Self::Module<'_>, VmiError> {
        unimplemented!()
    }

    fn region(vmi: VmiState<'_, Driver, Self>, region: Va) -> Result<Self::Region<'_>, VmiError> {
        Ok(LinuxVmAreaStruct::new(vmi, region))
    }

    fn syscall_argument(vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::syscall_argument(vmi, index)
    }

    fn function_argument(vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::function_argument(vmi, index)
    }

    fn function_return_value(vmi: VmiState<Driver, Self>) -> Result<u64, VmiError> {
        Driver::Architecture::function_return_value(vmi)
    }

    fn last_error(_vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError> {
        unimplemented!()
    }
}
