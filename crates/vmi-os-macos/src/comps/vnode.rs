use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, MacOs, MacOsError, MacOsExt as _, offset};

/// Flag in `vnode.v_flag` set on the root vnode of a file system.
///
/// Defined as `VROOT` in `bsd/sys/vnode_internal.h`.
const VROOT: u32 = 0x0000_0001;

/// Upper bound on the length of a vnode name, in bytes.
const MAX_NAME_LENGTH: usize = 1024;

/// Upper bound on the number of vnodes visited while building a path.
const MAX_PATH_DEPTH: usize = 512;

/// A macOS vnode.
///
/// # Implementation Details
///
/// Corresponds to `struct vnode`.
pub struct MacOsVnode<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `struct vnode`.
    va: Va,
}

impl<Driver> VmiVa for MacOsVnode<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsVnode<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new macOS vnode.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the name of the vnode in its parent directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vnode.v_name`.
    pub fn name(&self) -> Result<Option<String>, VmiError> {
        let vnode = offset!(self.vmi, vnode);

        let name = self
            .vmi
            .os()
            .read_pointer(self.va + vnode.v_name.offset())?;
        if name.is_null() {
            return Ok(None);
        }

        Ok(Some(self.vmi.read_string_limited(name, MAX_NAME_LENGTH)?))
    }

    /// Returns the parent directory of the vnode.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vnode.v_parent`.
    pub fn parent(&self) -> Result<Option<MacOsVnode<'a, Driver>>, VmiError> {
        let vnode = offset!(self.vmi, vnode);

        let parent = self
            .vmi
            .os()
            .read_pointer(self.va + vnode.v_parent.offset())?;
        Ok((!parent.is_null()).then(|| MacOsVnode::new(self.vmi, parent)))
    }

    /// Returns the vnode flags.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vnode.v_flag`.
    pub fn flags(&self) -> Result<u32, VmiError> {
        let vnode = offset!(self.vmi, vnode);

        self.vmi.read_u32(self.va + vnode.v_flag.offset())
    }

    /// Checks whether the vnode is the root of a file system.
    ///
    /// # Implementation Details
    ///
    /// Checks `VROOT` in `vnode.v_flag`.
    pub fn is_root(&self) -> Result<bool, VmiError> {
        Ok(self.flags()? & VROOT != 0)
    }

    /// Returns the vnode type, an `enum vtype` value such as `VREG` (1) or
    /// `VDIR` (2).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vnode.v_type`.
    pub fn vnode_type(&self) -> Result<u8, VmiError> {
        let vnode = offset!(self.vmi, vnode);

        self.vmi.read_u8(self.va + vnode.v_type.offset())
    }

    /// Returns the address of the `struct mount` of the file system holding
    /// the vnode.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vnode.v_mount`.
    pub fn mount(&self) -> Result<Option<Va>, VmiError> {
        let vnode = offset!(self.vmi, vnode);

        let mount = self
            .vmi
            .os()
            .read_pointer(self.va + vnode.v_mount.offset())?;
        Ok((!mount.is_null()).then_some(mount))
    }

    /// Returns the vnode that the file system of this vnode is mounted on.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vnode.v_mount->mnt_vnodecovered`.
    pub fn covered_vnode(&self) -> Result<Option<MacOsVnode<'a, Driver>>, VmiError> {
        let mount = offset!(self.vmi, mount);

        let mount_va = match self.mount()? {
            Some(mount_va) => mount_va,
            None => return Ok(None),
        };

        let covered = self
            .vmi
            .os()
            .read_pointer(mount_va + mount.mnt_vnodecovered.offset())?;

        Ok((!covered.is_null()).then(|| MacOsVnode::new(self.vmi, covered)))
    }

    /// Returns the absolute path of the vnode.
    ///
    /// Returns `None` when a vnode on the way to the root has no name.
    ///
    /// # Implementation Details
    ///
    /// Walks `vnode.v_parent` up to `rootvnode`. At the root of a mounted
    /// file system, the walk continues at the vnode it covers,
    /// `vnode.v_mount->mnt_vnodecovered`.
    ///
    /// # Notes
    ///
    /// The path follows the mount hierarchy rather than the APFS firmlinks
    /// that merge the system and data volumes. Files on the data volume
    /// therefore appear under `/System/Volumes/Data`, for example
    /// `/System/Volumes/Data/private/tmp/file` instead of `/tmp/file`.
    pub fn path(&self) -> Result<Option<String>, VmiError> {
        let rootvnode = self.vmi.os().rootvnode()?;

        vnode_path(self.va, rootvnode, |va| {
            let vnode = MacOsVnode::new(self.vmi, va);

            if vnode.is_root()? {
                let covered = vnode.covered_vnode()?;
                return Ok(VnodeStep::MountRoot {
                    covered: covered.map_or(Va(0), |covered| covered.va),
                });
            }

            Ok(VnodeStep::Entry {
                name: vnode.name()?,
                parent: vnode.parent()?.map_or(Va(0), |parent| parent.va),
            })
        })
    }
}

/// The information about one vnode needed to build a path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VnodeStep {
    /// The root of a file system, mounted on the vnode at `covered`, or not
    /// mounted on anything when `covered` is null.
    MountRoot {
        /// Address of the covered vnode.
        covered: Va,
    },

    /// A named entry in its parent directory at `parent`.
    Entry {
        /// Name of the entry, or `None` when the vnode has no name.
        name: Option<String>,

        /// Address of the parent directory, or null.
        parent: Va,
    },
}

/// Builds the absolute path of the vnode at `start`.
///
/// `step` describes the vnode at the given address. The walk ends at
/// `rootvnode`, at a null link, or at a file system root that covers no
/// vnode. It fails when it visits more than [`MAX_PATH_DEPTH`] vnodes.
fn vnode_path(
    start: Va,
    rootvnode: Va,
    mut step: impl FnMut(Va) -> Result<VnodeStep, VmiError>,
) -> Result<Option<String>, VmiError> {
    let mut components = Vec::new();
    let mut current = start;

    for _ in 0..MAX_PATH_DEPTH {
        if current.is_null() || current == rootvnode {
            return Ok(Some(join_components(&components)));
        }

        match step(current)? {
            VnodeStep::MountRoot { covered } => current = covered,
            VnodeStep::Entry { name, parent } => {
                match name {
                    Some(name) => components.push(name),
                    None => return Ok(None),
                }

                current = parent;
            }
        }
    }

    Err(MacOsError::CorruptedStruct("vnode path too deep").into())
}

/// Joins path components collected from the leaf to the root into an
/// absolute path.
fn join_components(components: &[String]) -> String {
    if components.is_empty() {
        return String::from("/");
    }

    let mut path = String::new();
    for component in components.iter().rev() {
        path.push('/');
        path.push_str(component);
    }

    path
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Address of the root vnode of the system volume.
    const ROOT: Va = Va(0x1000);

    /// Returns a named entry step.
    fn entry(name: &str, parent: u64) -> VnodeStep {
        VnodeStep::Entry {
            name: Some(String::from(name)),
            parent: Va(parent),
        }
    }

    /// Builds the path of `start` over the vnode graph `graph`.
    fn path(graph: &HashMap<u64, VnodeStep>, start: u64) -> Result<Option<String>, VmiError> {
        vnode_path(Va(start), ROOT, |va| match graph.get(&va.0) {
            Some(step) => Ok(step.clone()),
            None => Err(VmiError::OutOfBounds),
        })
    }

    /// Returns a graph with the data volume mounted on
    /// `/System/Volumes/Data`.
    fn graph() -> HashMap<u64, VnodeStep> {
        HashMap::from([
            (0x2000, entry("System", ROOT.0)),
            (0x3000, entry("Volumes", 0x2000)),
            (0x4000, entry("Data", 0x3000)),
            // Root of the data volume, mounted on `Data`.
            (
                0x5000,
                VnodeStep::MountRoot {
                    covered: Va(0x4000),
                },
            ),
            (0x6000, entry("private", 0x5000)),
            (0x7000, entry("tmp", 0x6000)),
            (0x8000, entry("orchard-marker", 0x7000)),
            // A file system root that is not mounted anywhere.
            (0x9000, VnodeStep::MountRoot { covered: Va(0) }),
            (0xa000, entry("file", 0x9000)),
            (
                0xb000,
                VnodeStep::Entry {
                    name: None,
                    parent: Va(0x7000),
                },
            ),
        ])
    }

    #[test]
    fn crosses_mount_points() {
        assert_eq!(
            path(&graph(), 0x8000).unwrap().as_deref(),
            Some("/System/Volumes/Data/private/tmp/orchard-marker")
        );
    }

    #[test]
    fn stops_at_root() {
        assert_eq!(path(&graph(), ROOT.0).unwrap().as_deref(), Some("/"));
        assert_eq!(path(&graph(), 0x2000).unwrap().as_deref(), Some("/System"));
        assert_eq!(path(&graph(), 0xa000).unwrap().as_deref(), Some("/file"));
    }

    #[test]
    fn rejects_unnamed_vnodes() {
        assert_eq!(path(&graph(), 0xb000).unwrap(), None);
    }

    #[test]
    fn bounds_cycles() {
        let graph = HashMap::from([(0x2000, entry("a", 0x3000)), (0x3000, entry("b", 0x2000))]);
        assert!(path(&graph, 0x2000).is_err());
    }
}
