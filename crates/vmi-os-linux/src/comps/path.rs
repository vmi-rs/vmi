use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{LinuxDentry, LinuxMount, LinuxVfsMount};
use crate::{ArchAdapter, LinuxError, LinuxOs, offset};

/// Maximum number of steps in one path walk. It guards against a corrupt
/// chain of directory entries.
///
/// A path of `PATH_MAX` (4096) bytes has at most 2048 components.
const PATH_STEPS_MAX: usize = 4096;

/// A Linux path.
///
/// A path names a file by its directory entry and the mount that the entry
/// belongs to.
///
/// # Implementation Details
///
/// Corresponds to `path`.
pub struct LinuxPath<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `path` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxPath<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxPath<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux path.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the mount of the path.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `path.mnt`.
    pub fn mnt(&self) -> Result<LinuxVfsMount<'a, Driver>, VmiError> {
        let PATH = offset!(self.vmi, path);

        let mnt = self.vmi.read_va_native(self.va + PATH.mnt.offset())?;

        if mnt.is_null() {
            return Err(LinuxError::CorruptedStruct("path.mnt").into());
        }

        Ok(LinuxVfsMount::new(self.vmi, mnt))
    }

    /// Returns the directory entry of the path.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `path.dentry`.
    pub fn dentry(&self) -> Result<LinuxDentry<'a, Driver>, VmiError> {
        let PATH = offset!(self.vmi, path);

        let dentry = self.vmi.read_va_native(self.va + PATH.dentry.offset())?;

        if dentry.is_null() {
            return Err(LinuxError::CorruptedStruct("path.dentry").into());
        }

        Ok(LinuxDentry::new(self.vmi, dentry))
    }

    /// Returns the absolute path, as seen from the root of the initial mount
    /// namespace.
    ///
    /// Unlike `/proc/<pid>/maps`, the result has no " (deleted)" suffix for
    /// a file that no longer has a name.
    ///
    /// # Implementation Details
    ///
    /// Follows `__prepend_path` in `fs/d_path.c`. The walk goes up through
    /// `dentry.d_parent`. At the root of a mount, it goes on at
    /// `mount.mnt_mountpoint` in `mount.mnt_parent`, until it reaches the
    /// mount that is its own parent.
    pub fn absolute(&self) -> Result<String, VmiError> {
        let dentry = self.dentry()?;
        let mount = self.mnt()?.mount();

        absolute_path(&GuestPathReader { vmi: self.vmi }, dentry.va(), mount.va())
    }
}

/// Source of the parts of a path that the walk reads.
pub(crate) trait PathReader {
    /// Returns the parent of a directory entry (`dentry.d_parent`).
    fn d_parent(&self, dentry: Va) -> Result<Va, VmiError>;

    /// Returns the name of a directory entry (`dentry.d_name`).
    fn d_name(&self, dentry: Va) -> Result<String, VmiError>;

    /// Returns the root directory entry of a mount (`mount.mnt.mnt_root`).
    fn mnt_root(&self, mount: Va) -> Result<Va, VmiError>;

    /// Returns the parent of a mount (`mount.mnt_parent`).
    fn mnt_parent(&self, mount: Va) -> Result<Va, VmiError>;

    /// Returns the mount point of a mount (`mount.mnt_mountpoint`).
    fn mnt_mountpoint(&self, mount: Va) -> Result<Va, VmiError>;
}

/// Builds the absolute path of a directory entry in a mount, as
/// `__prepend_path` in `fs/d_path.c` does.
pub(crate) fn absolute_path(
    reader: &impl PathReader,
    dentry: Va,
    mount: Va,
) -> Result<String, VmiError> {
    let mut dentry = dentry;
    let mut mount = mount;
    let mut names = Vec::new();

    for _ in 0..PATH_STEPS_MAX {
        if dentry == reader.mnt_root(mount)? {
            let parent = reader.mnt_parent(mount)?;

            // The mount that is its own parent is the root of the namespace.
            if parent == mount {
                return Ok(join_names(&names));
            }

            dentry = reader.mnt_mountpoint(mount)?;
            mount = parent;
            continue;
        }

        let parent = reader.d_parent(dentry)?;

        // A root that is not the root of its mount, such as the root of a
        // file system that has no mount. `d_path` stops here as well.
        if parent == dentry {
            return Ok(join_names(&names));
        }

        names.push(reader.d_name(dentry)?);
        dentry = parent;
    }

    Err(LinuxError::CorruptedStruct("dentry.d_parent").into())
}

/// Joins the names of a walk, which come from the file up to the root, into
/// an absolute path.
fn join_names(names: &[String]) -> String {
    if names.is_empty() {
        return String::from("/");
    }

    let mut path = String::new();
    for name in names.iter().rev() {
        path.push('/');
        path.push_str(name);
    }

    path
}

/// Reads the parts of a path from guest memory.
struct GuestPathReader<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,
}

impl<Driver> PathReader for GuestPathReader<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn d_parent(&self, dentry: Va) -> Result<Va, VmiError> {
        Ok(LinuxDentry::new(self.vmi, dentry).parent()?.va())
    }

    fn d_name(&self, dentry: Va) -> Result<String, VmiError> {
        LinuxDentry::new(self.vmi, dentry).name()
    }

    fn mnt_root(&self, mount: Va) -> Result<Va, VmiError> {
        Ok(LinuxMount::new(self.vmi, mount).vfsmount().root()?.va())
    }

    fn mnt_parent(&self, mount: Va) -> Result<Va, VmiError> {
        Ok(LinuxMount::new(self.vmi, mount).parent()?.va())
    }

    fn mnt_mountpoint(&self, mount: Va) -> Result<Va, VmiError> {
        Ok(LinuxMount::new(self.vmi, mount).mountpoint()?.va())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// A file system tree built by hand.
    #[derive(Default)]
    struct Tree {
        /// Parent and name of each directory entry, indexed by its address.
        dentries: HashMap<u64, (u64, &'static str)>,

        /// Root, parent and mount point of each mount, indexed by its
        /// address.
        mounts: HashMap<u64, (u64, u64, u64)>,
    }

    impl Tree {
        /// Adds a directory entry.
        fn dentry(&mut self, address: u64, parent: u64, name: &'static str) {
            self.dentries.insert(address, (parent, name));
        }

        /// Adds a mount.
        fn mount(&mut self, address: u64, root: u64, parent: u64, mountpoint: u64) {
            self.mounts.insert(address, (root, parent, mountpoint));
        }

        /// Returns the absolute path of a directory entry in a mount.
        fn path(&self, dentry: u64, mount: u64) -> Result<String, VmiError> {
            absolute_path(self, Va(dentry), Va(mount))
        }
    }

    impl PathReader for Tree {
        fn d_parent(&self, dentry: Va) -> Result<Va, VmiError> {
            match self.dentries.get(&dentry.0) {
                Some((parent, _name)) => Ok(Va(*parent)),
                None => Err(VmiError::Other("no such dentry")),
            }
        }

        fn d_name(&self, dentry: Va) -> Result<String, VmiError> {
            match self.dentries.get(&dentry.0) {
                Some((_parent, name)) => Ok(String::from(*name)),
                None => Err(VmiError::Other("no such dentry")),
            }
        }

        fn mnt_root(&self, mount: Va) -> Result<Va, VmiError> {
            match self.mounts.get(&mount.0) {
                Some((root, _parent, _mountpoint)) => Ok(Va(*root)),
                None => Err(VmiError::Other("no such mount")),
            }
        }

        fn mnt_parent(&self, mount: Va) -> Result<Va, VmiError> {
            match self.mounts.get(&mount.0) {
                Some((_root, parent, _mountpoint)) => Ok(Va(*parent)),
                None => Err(VmiError::Other("no such mount")),
            }
        }

        fn mnt_mountpoint(&self, mount: Va) -> Result<Va, VmiError> {
            match self.mounts.get(&mount.0) {
                Some((_root, _parent, mountpoint)) => Ok(Va(*mountpoint)),
                None => Err(VmiError::Other("no such mount")),
            }
        }
    }

    /// The root file system with `/usr/lib/libc.so.6`, and a tmpfs on `/run`
    /// with `systemd/journal/seqnum`, as on linux-ubuntu26.
    fn tree() -> Tree {
        let mut tree = Tree::default();

        // The root mount at 0x1000 is its own parent.
        tree.dentry(0x100, 0x100, "/");
        tree.dentry(0x101, 0x100, "usr");
        tree.dentry(0x102, 0x101, "lib");
        tree.dentry(0x103, 0x102, "libc.so.6");
        tree.dentry(0x104, 0x100, "run");
        tree.mount(0x1000, 0x100, 0x1000, 0x100);

        // The tmpfs at 0x2000 is mounted on /run of the root mount.
        tree.dentry(0x200, 0x200, "/");
        tree.dentry(0x201, 0x200, "systemd");
        tree.dentry(0x202, 0x201, "journal");
        tree.dentry(0x203, 0x202, "seqnum");
        tree.mount(0x2000, 0x200, 0x1000, 0x104);

        tree
    }

    #[test]
    fn path_on_the_root_mount() -> Result<(), VmiError> {
        assert_eq!(tree().path(0x103, 0x1000)?, "/usr/lib/libc.so.6");
        Ok(())
    }

    #[test]
    fn path_crosses_a_mount_point() -> Result<(), VmiError> {
        assert_eq!(tree().path(0x203, 0x2000)?, "/run/systemd/journal/seqnum");
        Ok(())
    }

    #[test]
    fn root_of_a_mount_is_its_mount_point() -> Result<(), VmiError> {
        let tree = tree();

        assert_eq!(tree.path(0x200, 0x2000)?, "/run");
        assert_eq!(tree.path(0x100, 0x1000)?, "/");
        Ok(())
    }

    #[test]
    fn cycle_in_parents_ends_with_an_error() {
        let mut tree = tree();

        // Two directory entries that are each other's parent.
        tree.dentry(0x301, 0x302, "a");
        tree.dentry(0x302, 0x301, "b");

        assert!(tree.path(0x301, 0x1000).is_err());
    }
}
