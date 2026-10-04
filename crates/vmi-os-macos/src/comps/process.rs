use std::time::Duration;

use vmi_core::{
    Pa, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{
        ProcessId, ProcessObject, ThreadObject, VmiOsImage as _, VmiOsImageArchitecture,
        VmiOsProcess, VmiOsRegion as _,
    },
};

use super::{
    MacOsOpenFile, MacOsRegion, MacOsThread, MacOsUserModule, MacOsVnode, read_fixed_string,
};
use crate::{
    ArchAdapter, MacOs, MacOsError, MacOsExt as _,
    iter::{MapEntryIterator, QueueIterator},
    macho::{architecture_from_cpu_type, read_u32, read_u64},
    offset,
};

/// Flag in `proc.p_lflag` set when the process has a Mach task.
///
/// Defined as `P_LHASTASK` in `bsd/sys/proc_internal.h`.
const P_LHASTASK: u32 = 0x0000_0002;

/// Upper bound on `proc.p_argslen`, in bytes.
///
/// Matches `ARG_MAX` of macOS.
const MAX_ARGUMENTS_LENGTH: u32 = 1024 * 1024;

/// Prefix of the executable path at the start of the argument area.
///
/// Defined as `EXECUTABLE_KEY` in `bsd/kern/kern_exec.c`.
const EXECUTABLE_PATH_KEY: &[u8] = b"executable_path=";

/// Upper bound on the number of entries in the open file table.
const MAX_OPEN_FILES: i32 = 1 << 20;

/// Upper bound on `dyld_all_image_infos.infoArrayCount`.
const MAX_USER_MODULES: u32 = 1 << 16;

/// Size of `struct dyld_image_info` from `<mach-o/dyld_images.h>`, in bytes.
pub(crate) const DYLD_IMAGE_INFO_SIZE: u64 = 24;

/// Size of the leading fields of `struct dyld_all_image_infos` from
/// `<mach-o/dyld_images.h>` that this crate reads, in bytes.
///
/// The fields are `uint32_t version` at offset 0, `uint32_t infoArrayCount`
/// at offset 4 and `const struct dyld_image_info *infoArray` at offset 8.
const DYLD_ALL_IMAGE_INFOS_HEADER_SIZE: usize = 16;

/// A macOS process.
///
/// A process is a BSD `struct proc`. When the process has a Mach task, the
/// `struct task` immediately follows the `struct proc` in the same
/// allocation.
///
/// # Implementation Details
///
/// Corresponds to `struct proc`.
pub struct MacOsProcess<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `struct proc`.
    va: Va,
}

/// The executable path and the arguments of a process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacOsProcessArguments {
    /// Path of the executable as passed to `execve`.
    pub executable_path: String,

    /// The `argv` strings.
    pub arguments: Vec<String>,
}

impl<Driver> VmiVa for MacOsProcess<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsProcess<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new macOS process.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, process: ProcessObject) -> Self {
        Self { vmi, va: process.0 }
    }

    /// Returns the address of the Mach task of the process.
    ///
    /// Returns `None` when the process has no task, for example after it
    /// exited.
    ///
    /// # Implementation Details
    ///
    /// The task follows the `struct proc` when `proc.p_lflag` has
    /// `P_LHASTASK` set. The size of `struct proc` comes from
    /// [`MacOs::proc_struct_size`].
    pub fn task(&self) -> Result<Option<Va>, VmiError> {
        let proc = offset!(self.vmi, proc);

        let lflag = self.vmi.read_u32(self.va + proc.p_lflag.offset())?;
        if lflag & P_LHASTASK == 0 {
            return Ok(None);
        }

        Ok(Some(self.va + self.vmi.os().proc_struct_size()?))
    }

    /// Returns the address of the `struct _vm_map` of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task.map`.
    pub fn map(&self) -> Result<Option<Va>, VmiError> {
        let task = offset!(self.vmi, task);

        let task_va = match self.task()? {
            Some(task_va) => task_va,
            None => return Ok(None),
        };

        let map = self.vmi.os().read_pointer(task_va + task.map.offset())?;
        Ok((!map.is_null()).then_some(map))
    }

    /// Returns the address of the `struct pmap` of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task.map->pmap`.
    pub fn pmap(&self) -> Result<Option<Va>, VmiError> {
        let vm_map = offset!(self.vmi, _vm_map);

        let map = match self.map()? {
            Some(map) => map,
            None => return Ok(None),
        };

        let pmap = self.vmi.os().read_pointer(map + vm_map.pmap.offset())?;
        Ok((!pmap.is_null()).then_some(pmap))
    }

    /// Returns the effective user ID of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_uid`.
    pub fn uid(&self) -> Result<u32, VmiError> {
        let proc = offset!(self.vmi, proc);

        self.vmi.read_u32(self.va + proc.p_uid.offset())
    }

    /// Returns the effective group ID of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_gid`.
    pub fn gid(&self) -> Result<u32, VmiError> {
        let proc = offset!(self.vmi, proc);

        self.vmi.read_u32(self.va + proc.p_gid.offset())
    }

    /// Returns the longer process name.
    ///
    /// Unlike [`name`], which is truncated to 16 characters, this name holds
    /// up to 32 characters.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_name`.
    ///
    /// [`name`]: VmiOsProcess::name
    pub fn full_name(&self) -> Result<String, VmiError> {
        let proc = offset!(self.vmi, proc);

        read_fixed_string(self.vmi, self.va + proc.p_name.offset(), proc.p_name.size())
    }

    /// Returns the vnode of the executable of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_textvp`.
    pub fn image_vnode(&self) -> Result<Option<MacOsVnode<'a, Driver>>, VmiError> {
        let proc = offset!(self.vmi, proc);

        let vnode = self
            .vmi
            .os()
            .read_pointer(self.va + proc.p_textvp.offset())?;
        Ok((!vnode.is_null()).then(|| MacOsVnode::new(self.vmi, vnode)))
    }

    /// Returns the path of the executable of the process.
    ///
    /// See [`MacOsVnode::path`] for how the path is built.
    pub fn image_path(&self) -> Result<Option<String>, VmiError> {
        match self.image_vnode()? {
            Some(vnode) => vnode.path(),
            None => Ok(None),
        }
    }

    /// Returns the executable path and the arguments of the process.
    ///
    /// # Implementation Details
    ///
    /// Reads `proc.p_argslen` bytes that end at `proc.user_stack` from the
    /// address space of the process. The area starts with the executable
    /// path, followed by NUL padding and `proc.p_argc` argument strings.
    /// The environment strings that follow the arguments are not returned.
    pub fn arguments(&self) -> Result<MacOsProcessArguments, VmiError> {
        let proc = offset!(self.vmi, proc);

        let length = self.vmi.read_u32(self.va + proc.p_argslen.offset())?;
        let count = self.vmi.read_u32(self.va + proc.p_argc.offset())?;
        let user_stack = self.vmi.read_u64(self.va + proc.user_stack.offset())?;

        if length == 0 {
            return Ok(MacOsProcessArguments::default());
        }

        if length > MAX_ARGUMENTS_LENGTH {
            return Err(MacOsError::CorruptedStruct("proc.p_argslen").into());
        }

        let start = match user_stack.checked_sub(length as u64) {
            Some(start) => Va(start),
            None => return Err(MacOsError::CorruptedStruct("proc.user_stack").into()),
        };

        let root = self.translation_root()?;
        let mut data = vec![0u8; length as usize];
        self.vmi.read_in((start, root), &mut data)?;

        Ok(parse_arguments(&data, count as usize))
    }

    /// Returns the time the process started, as the duration since the Unix
    /// epoch.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_start`.
    pub fn start_time(&self) -> Result<Duration, VmiError> {
        let proc = offset!(self.vmi, proc);
        let timeval = offset!(self.vmi, timeval);

        let start = self.va + proc.p_start.offset();
        let seconds = self.vmi.read_u64(start + timeval.tv_sec.offset())?;
        let microseconds = self.vmi.read_u32(start + timeval.tv_usec.offset())?;

        if seconds > i64::MAX as u64 || microseconds >= 1_000_000 {
            return Err(MacOsError::CorruptedStruct("proc.p_start").into());
        }

        Ok(Duration::new(seconds, microseconds * 1000))
    }

    /// Returns the number of threads of the process.
    ///
    /// Returns zero when the process has no task.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task.thread_count`.
    pub fn thread_count(&self) -> Result<u32, VmiError> {
        let task = offset!(self.vmi, task);

        match self.task()? {
            Some(task_va) => self.vmi.read_u32(task_va + task.thread_count.offset()),
            None => Ok(0),
        }
    }

    /// Returns an iterator over the open files of the process.
    ///
    /// # Implementation Details
    ///
    /// Iterates over the non-null entries of `proc.p_fd.fd_ofiles` below
    /// `proc.p_fd.fd_afterlast`, or below `proc.p_fd.fd_nfiles` when
    /// `fd_afterlast` is out of range.
    pub fn open_files(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<MacOsOpenFile<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let proc = offset!(self.vmi, proc);
        let filedesc = offset!(self.vmi, filedesc);

        let vmi = self.vmi;
        let fd = self.va + proc.p_fd.offset();

        let files = vmi.os().read_pointer(fd + filedesc.fd_ofiles.offset())?;
        let nfiles = vmi.read_u32(fd + filedesc.fd_nfiles.offset())? as i32;
        let afterlast = vmi.read_u32(fd + filedesc.fd_afterlast.offset())? as i32;

        if !(0..=MAX_OPEN_FILES).contains(&nfiles) {
            return Err(MacOsError::CorruptedStruct("filedesc.fd_nfiles").into());
        }

        let count = if (0..=nfiles).contains(&afterlast) {
            afterlast
        }
        else {
            nfiles
        };

        let mut entries = Vec::new();
        if !files.is_null() && count > 0 {
            let mut data = vec![0u8; count as usize * 8];
            vmi.read(files, &mut data)?;

            for (fd, entry) in data.chunks_exact(8).enumerate() {
                let raw = u64::from_le_bytes(entry.try_into().expect("8-byte chunk"));
                let fileproc = Driver::Architecture::canonical_address(raw);

                if !fileproc.is_null() {
                    entries.push((fd as i32, fileproc));
                }
            }
        }

        Ok(entries
            .into_iter()
            .map(move |(fd, fileproc)| Ok(MacOsOpenFile::new(vmi, fd, fileproc))))
    }

    /// Returns an iterator over the images loaded by dyld into the process.
    ///
    /// # Implementation Details
    ///
    /// Reads the `struct dyld_all_image_infos` at `task.all_image_info_addr`
    /// in the address space of the process and iterates over its
    /// `infoArray`. The iterator is empty when the process has no task,
    /// when dyld has not registered the structure, or while dyld updates
    /// the array, which it marks by setting `infoArray` to null.
    pub fn user_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<MacOsUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let vmi = self.vmi;
        let (info_array, count, root) = match self.dyld_image_info_array()? {
            Some(result) => result,
            None => (Va(0), 0, Pa(0)),
        };

        Ok((0..count as u64).map(move |index| {
            Ok(MacOsUserModule::new(
                vmi,
                info_array + index * DYLD_IMAGE_INFO_SIZE,
                root,
            ))
        }))
    }

    /// Returns the `infoArray`, `infoArrayCount` and translation root of the
    /// dyld image list, or `None` when there is no list.
    fn dyld_image_info_array(&self) -> Result<Option<(Va, u32, Pa)>, VmiError> {
        let task = offset!(self.vmi, task);

        let task_va = match self.task()? {
            Some(task_va) => task_va,
            None => return Ok(None),
        };

        let all_image_infos = self
            .vmi
            .read_u64(task_va + task.all_image_info_addr.offset())?;
        if all_image_infos == 0 {
            return Ok(None);
        }

        let root = self.translation_root()?;
        let mut header = [0u8; DYLD_ALL_IMAGE_INFOS_HEADER_SIZE];
        self.vmi.read_in((Va(all_image_infos), root), &mut header)?;

        let (count, info_array) = match (read_u32(&header, 4), read_u64(&header, 8)) {
            (Some(count), Some(info_array)) => {
                (count, Driver::Architecture::canonical_address(info_array))
            }
            _ => return Ok(None),
        };

        if info_array.is_null() {
            return Ok(None);
        }

        if count > MAX_USER_MODULES {
            return Err(MacOsError::CorruptedStruct("dyld_all_image_infos.infoArrayCount").into());
        }

        Ok(Some((info_array, count, root)))
    }
}

impl<'a, Driver> VmiOsProcess<'a, Driver> for MacOsProcess<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = MacOs<Driver>;

    /// Returns the process ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_pid`.
    fn id(&self) -> Result<ProcessId, VmiError> {
        let proc = offset!(self.vmi, proc);

        Ok(ProcessId(self.vmi.read_u32(self.va + proc.p_pid.offset())?))
    }

    fn object(&self) -> Result<ProcessObject, VmiError> {
        Ok(ProcessObject(self.va))
    }

    /// Returns the name of the process, truncated to 16 characters.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_comm`.
    fn name(&self) -> Result<String, VmiError> {
        let proc = offset!(self.vmi, proc);

        read_fixed_string(self.vmi, self.va + proc.p_comm.offset(), proc.p_comm.size())
    }

    /// Returns the parent process ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_ppid`.
    fn parent_id(&self) -> Result<ProcessId, VmiError> {
        let proc = offset!(self.vmi, proc);

        Ok(ProcessId(
            self.vmi.read_u32(self.va + proc.p_ppid.offset())?,
        ))
    }

    /// Returns the architecture of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_cputype`. A process that never executed an
    /// image, such as `kernel_task`, has a CPU type of zero and reports the
    /// architecture of the kernel image.
    fn architecture(&self) -> Result<VmiOsImageArchitecture, VmiError> {
        let proc = offset!(self.vmi, proc);

        let cpu_type = self.vmi.read_u32(self.va + proc.p_cputype.offset())? as i32;
        if let Some(architecture) = architecture_from_cpu_type(cpu_type) {
            return Ok(architecture);
        }

        if cpu_type == 0 {
            let kernel_image_base = self.vmi.os().kernel_image_base()?;
            if let Some(architecture) = self.vmi.os().image(kernel_image_base)?.architecture()? {
                return Ok(architecture);
            }
        }

        Err(MacOsError::UnsupportedCpuType(cpu_type).into())
    }

    /// Returns the root of the translation tables of the process.
    ///
    /// Fails with [`VmiError::RootNotPresent`] when the process has no task.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task.map->pmap->ttep`, the physical address of the
    /// table loaded into `TTBR0_EL1` while the process runs.
    fn translation_root(&self) -> Result<Pa, VmiError> {
        let pmap = offset!(self.vmi, pmap);

        let pmap_va = match self.pmap()? {
            Some(pmap_va) => pmap_va,
            None => return Err(VmiError::RootNotPresent),
        };

        Ok(Pa(self.vmi.read_u64(pmap_va + pmap.ttep.offset())?))
    }

    /// Returns the root of the translation tables of the process.
    ///
    /// The user half of the address space is always translated through the
    /// tables of the process, so this is the same as
    /// [`translation_root`](Self::translation_root).
    fn user_translation_root(&self) -> Result<Pa, VmiError> {
        self.translation_root()
    }

    /// Returns the load address of the main executable.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `proc.p_main_exec_load_addr`.
    fn image_base(&self) -> Result<Va, VmiError> {
        let proc = offset!(self.vmi, proc);

        Ok(Va(self
            .vmi
            .read_u64(self.va + proc.p_main_exec_load_addr.offset())?))
    }

    /// Returns an iterator over the memory regions of the process.
    ///
    /// # Implementation Details
    ///
    /// Iterates over the `struct vm_map_entry` list of `task.map`, in
    /// ascending address order.
    fn regions(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<MacOsRegion<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let vmi = self.vmi;
        let iterator = match self.map()? {
            Some(map) => MapEntryIterator::new(vmi, map)?,
            None => MapEntryIterator::empty(vmi),
        };

        Ok(iterator.map(move |result| result.map(|entry| MacOsRegion::new(vmi, entry))))
    }

    /// Returns the memory region containing the given address.
    fn lookup_region(&self, address: Va) -> Result<Option<MacOsRegion<'a, Driver>>, VmiError> {
        for region in self.regions()? {
            let region = region?;

            if address < region.start()? {
                return Ok(None);
            }

            if address < region.end()? {
                return Ok(Some(region));
            }
        }

        Ok(None)
    }

    /// Returns an iterator over the threads of the process.
    ///
    /// # Implementation Details
    ///
    /// Iterates over the `task.threads` queue.
    fn threads(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<MacOsThread<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let task = offset!(self.vmi, task);
        let thread = offset!(self.vmi, thread);

        let vmi = self.vmi;
        let iterator = match self.task()? {
            Some(task_va) => QueueIterator::new(
                vmi,
                task_va + task.threads.offset(),
                thread.task_threads.offset(),
            ),
            None => QueueIterator::empty(vmi),
        };

        Ok(iterator
            .map(move |result| result.map(|entry| MacOsThread::new(vmi, ThreadObject(entry)))))
    }

    /// Checks whether the given virtual address is valid in the process.
    ///
    /// A user address is valid when it translates through the tables of the
    /// process, or when it lies in a memory region with a non-empty
    /// protection, where a page fault would populate it. A kernel address is
    /// valid when it translates through the kernel tables.
    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError> {
        if Driver::Architecture::is_kernel_address(address) {
            let root = self.vmi.translation_root(address);
            return match self.vmi.core().translate_address((address, root)) {
                Ok(_) => Ok(Some(true)),
                Err(VmiError::Translation(_)) => Ok(Some(false)),
                Err(err) => Err(err),
            };
        }

        let root = match self.translation_root() {
            Ok(root) => root,
            Err(VmiError::RootNotPresent) => return Ok(Some(false)),
            Err(err) => return Err(err),
        };

        match self.vmi.core().translate_address((address, root)) {
            Ok(_) => return Ok(Some(true)),
            Err(VmiError::Translation(_)) => {}
            Err(err) => return Err(err),
        }

        match self.lookup_region(address)? {
            Some(region) => Ok(Some(!region.protection()?.is_empty())),
            None => Ok(Some(false)),
        }
    }
}

/// Splits the argument area of a process into the executable path and the
/// first `count` argument strings.
///
/// The executable path carries the `executable_path=` prefix of the apple
/// string that `execve` stores it as, which is removed. The path is followed
/// by NUL padding, which is skipped. A string cut off by the end of `data`
/// is returned as is, and fewer than `count` arguments are returned when
/// `data` ends early.
fn parse_arguments(data: &[u8], count: usize) -> MacOsProcessArguments {
    let (executable_path, rest) = match memchr::memchr(0, data) {
        Some(end) => (&data[..end], &data[end..]),
        None => (data, &data[data.len()..]),
    };

    let executable_path = executable_path
        .strip_prefix(EXECUTABLE_PATH_KEY)
        .unwrap_or(executable_path);

    let padding = rest
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(rest.len());
    let mut rest = &rest[padding..];

    let mut arguments = Vec::new();
    while arguments.len() < count && !rest.is_empty() {
        match memchr::memchr(0, rest) {
            Some(end) => {
                arguments.push(String::from_utf8_lossy(&rest[..end]).into_owned());
                rest = &rest[end + 1..];
            }
            None => {
                arguments.push(String::from_utf8_lossy(rest).into_owned());
                break;
            }
        }
    }

    MacOsProcessArguments {
        executable_path: String::from_utf8_lossy(executable_path).into_owned(),
        arguments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Converts string literals to owned strings.
    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().copied().map(String::from).collect()
    }

    #[test]
    fn skips_padding_after_executable_path() {
        let data =
            b"executable_path=/tmp/orchard-marker\0\0\0\0/tmp/orchard-marker\0-v\0PATH=/usr/bin\0";
        let result = parse_arguments(data, 2);

        assert_eq!(result.executable_path, "/tmp/orchard-marker");
        assert_eq!(result.arguments, strings(&["/tmp/orchard-marker", "-v"]));
    }

    #[test]
    fn keeps_empty_arguments() {
        let data = b"/bin/echo\0\0\0echo\0\0last\0";
        let result = parse_arguments(data, 3);

        assert_eq!(result.arguments, strings(&["echo", "", "last"]));
    }

    #[test]
    fn handles_truncated_buffers() {
        let data = b"/usr/libexec/logd\0\0/usr/libexec/lo";
        let result = parse_arguments(data, 2);

        assert_eq!(result.executable_path, "/usr/libexec/logd");
        assert_eq!(result.arguments, strings(&["/usr/libexec/lo"]));

        let data = b"/sbin/launchd\0\0/sbin/launchd\0";
        let result = parse_arguments(data, 3);

        assert_eq!(result.arguments, strings(&["/sbin/launchd"]));
    }

    #[test]
    fn handles_buffers_without_arguments() {
        assert_eq!(parse_arguments(b"", 1), MacOsProcessArguments::default());

        let result = parse_arguments(b"/sbin/launchd", 1);
        assert_eq!(result.executable_path, "/sbin/launchd");
        assert!(result.arguments.is_empty());

        let result = parse_arguments(b"/sbin/launchd\0\0\0", 1);
        assert!(result.arguments.is_empty());
    }
}
