use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{WindowsHiveCellIndex, key_value::values_iterator};
use crate::{ArchAdapter, KeyNodeIterator, KeyValueIterator, WindowsKeyValue, WindowsOs, offset};

/// A Windows registry key node.
///
/// A registry key as stored in a hive. The Configuration Manager reads it
/// when opening or modifying a key, and a KCB caches the resolution.
///
/// # Implementation Details
///
/// Corresponds to `_CM_KEY_NODE`.
pub struct WindowsKeyNode<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the owning `_CMHIVE`.
    hive_va: Va,

    /// Address of the `_CM_KEY_NODE` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsKeyNode<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

bitflags::bitflags! {
    /// Flags stored in `_CM_KEY_NODE.Flags`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct WindowsKeyNodeFlags: u16 {
        /// This key (and all its children) is volatile.
        const VOLATILE      = 0x0001;

        /// This key marks a boundary to another hive (sort of a link).
        /// The null value entry contains the hive and hive index of the root
        /// of the child hive.
        const HIVE_EXIT     = 0x0002;

        /// This key is the root of a particular hive.
        const HIVE_ENTRY    = 0x0004;

        /// This key cannot be deleted, period.
        const NO_DELETE     = 0x0008;

        /// This key is really a symbolic link.
        const SYM_LINK      = 0x0010;

        /// The name for this key is stored in a compressed (ASCII) form.
        const COMP_NAME     = 0x0020;

        /// There is no real key backing this, return the predefined handle.
        /// Predefined handles are stashed in `ValueList.Count`.
        const PREDEF_HANDLE = 0x0040;
    }
}

impl<'a, Driver> WindowsKeyNode<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Signature of a `_CM_KEY_NODE` (`kn`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `CM_KEY_NODE_SIGNATURE`.
    pub const KEY_NODE_SIGNATURE: u16 = 0x6b6e;

    /// Signature of a hive-mount link node (`kl`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `CM_LINK_NODE_SIGNATURE`.
    pub const LINK_NODE_SIGNATURE: u16 = 0x6b6c;

    /// Creates a new key node bound to the given hive.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, hive_va: Va, va: Va) -> Self {
        Self { vmi, hive_va, va }
    }

    /// Returns the signature of the key node.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_NODE.Signature`.
    pub fn signature(&self) -> Result<u16, VmiError> {
        let CM_KEY_NODE = offset!(self.vmi, _CM_KEY_NODE);

        self.vmi.read_u16(self.va + CM_KEY_NODE.Signature.offset())
    }

    /// Returns the flags of the key node.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_NODE.Flags`.
    pub fn flags(&self) -> Result<WindowsKeyNodeFlags, VmiError> {
        let CM_KEY_NODE = offset!(self.vmi, _CM_KEY_NODE);

        let flags = self.vmi.read_u16(self.va + CM_KEY_NODE.Flags.offset())?;
        Ok(WindowsKeyNodeFlags::from_bits_truncate(flags))
    }

    /// Returns the name of the key.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_NODE.Name`. If the `KEY_COMP_NAME` bit is
    /// set in `_CM_KEY_NODE.Flags`, the name is read as an ASCII string.
    /// Otherwise, the name is read as a UTF-16 string.
    pub fn name(&self) -> Result<String, VmiError> {
        let CM_KEY_NODE = offset!(self.vmi, _CM_KEY_NODE);

        let flags = self.flags()?;

        let name_length = self.vmi.read_field(self.va, &CM_KEY_NODE.NameLength)?;
        let name = self.va + CM_KEY_NODE.Name.offset();

        if flags.contains(WindowsKeyNodeFlags::COMP_NAME) {
            self.vmi.read_string_limited(name, name_length as usize)
        }
        else {
            self.vmi
                .read_string_utf16_limited(name, name_length as usize)
        }
    }

    /// Returns an iterator over the direct subkeys of this key, chaining
    /// stable then volatile.
    ///
    /// # Implementation Details
    ///
    /// Walks `_CM_KEY_NODE.SubKeyLists[Stable]` then `_CM_KEY_NODE.SubKeyLists[Volatile]`.
    pub fn subkeys(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsKeyNode<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        Ok(std::iter::chain(
            self.stable_subkeys()?,
            self.volatile_subkeys()?,
        ))
    }

    /// Returns the total number of direct subkeys (stable + volatile).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_NODE.SubKeyCount[Stable] + _CM_KEY_NODE.SubKeyCount[Volatile]`.
    pub fn subkey_count(&self) -> Result<u32, VmiError> {
        let CM_KEY_NODE = offset!(self.vmi, _CM_KEY_NODE);
        let counts = self.va + CM_KEY_NODE.SubKeyCounts.offset();
        let stable = self.vmi.read_u32(counts)?;
        let volatile = self.vmi.read_u32(counts + 4)?;
        Ok(stable.saturating_add(volatile))
    }

    /// Returns an iterator over the stable (on-disk) subkeys.
    ///
    /// # Implementation Details
    ///
    /// Walks `_CM_KEY_NODE.SubKeyLists[Stable]`.
    pub fn stable_subkeys(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<WindowsKeyNode<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let CM_KEY_NODE = offset!(self.vmi, _CM_KEY_NODE);

        let counts = self.va + CM_KEY_NODE.SubKeyCounts.offset();
        let lists = self.va + CM_KEY_NODE.SubKeyLists.offset();

        let count = self.vmi.read_u32(counts)?;
        let root = self.vmi.read_u32(lists)?;

        Ok(KeyNodeIterator::new(
            self.vmi,
            self.hive_va,
            WindowsHiveCellIndex::new(root),
            count,
        ))
    }

    /// Returns an iterator over the volatile (in-memory only) subkeys.
    ///
    /// # Implementation Details
    ///
    /// Walks `_CM_KEY_NODE.SubKeyLists[Volatile]`.
    pub fn volatile_subkeys(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<WindowsKeyNode<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let CM_KEY_NODE = offset!(self.vmi, _CM_KEY_NODE);

        let counts = self.va + CM_KEY_NODE.SubKeyCounts.offset();
        let lists = self.va + CM_KEY_NODE.SubKeyLists.offset();

        let count = self.vmi.read_u32(counts + 4)?;
        let root = self.vmi.read_u32(lists + 4)?;

        Ok(KeyNodeIterator::new(
            self.vmi,
            self.hive_va,
            WindowsHiveCellIndex::new(root),
            count,
        ))
    }

    /// Returns an iterator over the direct values of this key.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CM_KEY_NODE.ValueList`.
    pub fn values(&self) -> Result<KeyValueIterator<'a, Driver>, VmiError> {
        let CM_KEY_NODE = offset!(self.vmi, _CM_KEY_NODE);
        let CHILD_LIST = offset!(self.vmi, _CHILD_LIST);

        let value_list = self.va + CM_KEY_NODE.ValueList.offset();
        let count = self.vmi.read_u32(value_list + CHILD_LIST.Count.offset())?;
        let list_index = self.vmi.read_u32(value_list + CHILD_LIST.List.offset())?;

        values_iterator(
            self.vmi,
            self.hive_va,
            WindowsHiveCellIndex::new(list_index),
            count,
        )
    }

    /// Resolves a relative path to a descendant key.
    ///
    /// Splits `path` on `\\` and descends one component at a time. Empty
    /// segments are ignored. Name comparison is ASCII-case-insensitive.
    ///
    /// Returns `Ok(None)` if a component does not exist. An empty path
    /// returns this node.
    ///
    /// Does not follow `HIVE_EXIT` links into other hives.
    pub fn lookup(
        &self,
        path: impl AsRef<str>,
    ) -> Result<Option<WindowsKeyNode<'a, Driver>>, VmiError> {
        let path = path.as_ref();
        let mut current = WindowsKeyNode::new(self.vmi, self.hive_va, self.va);

        for component in path.split('\\').filter(|component| !component.is_empty()) {
            current = match current.child(component)? {
                Some(current) => current,
                None => return Ok(None),
            };
        }

        Ok(Some(current))
    }

    /// Returns the direct subkey with the given name, if any.
    ///
    /// `name` is treated as a single component. It is not split on `\\`,
    /// so `child("Microsoft\\Windows")` will never match a real subkey -
    /// use [`lookup`] for path traversal.
    ///
    /// Walks [`subkeys`] and matches names with ASCII-case-insensitive
    /// comparison.
    ///
    /// Per-subkey read errors do not abort the search. A paged-out cell
    /// in the middle of a long subkey list would otherwise mask later
    /// matches. Errors are skipped.
    ///
    /// [`lookup`]: Self::lookup
    /// [`subkeys`]: Self::subkeys
    pub fn child(
        &self,
        name: impl AsRef<str>,
    ) -> Result<Option<WindowsKeyNode<'a, Driver>>, VmiError> {
        let name = name.as_ref();

        for subkey in self.subkeys()? {
            let subkey = match subkey {
                Ok(subkey) => subkey,
                Err(err) => {
                    tracing::trace!(%err, "skipping subkey while searching for {name:?}");
                    continue;
                }
            };

            match subkey.name() {
                Ok(subkey_name) => {
                    if subkey_name.eq_ignore_ascii_case(name) {
                        return Ok(Some(subkey));
                    }

                    continue;
                }
                Err(err) => {
                    tracing::trace!(%err, "skipping unreadable subkey name");
                    continue;
                }
            }
        }

        Ok(None)
    }

    /// Returns the value with the given name, if any.
    ///
    /// Pass an empty `name` to look up the unnamed default value of the
    /// key.
    ///
    /// Walks `values()` and matches names with ASCII-case-insensitive
    /// comparison.
    ///
    /// Per-value read errors do not abort the search. A paged-out cell in
    /// the middle of a long value list would otherwise mask later matches.
    /// Errors are skipped.
    pub fn value(
        &self,
        name: impl AsRef<str>,
    ) -> Result<Option<WindowsKeyValue<'a, Driver>>, VmiError> {
        let name = name.as_ref();

        for value in self.values()? {
            let value = match value {
                Ok(value) => value,
                Err(err) => {
                    tracing::trace!(%err, "skipping value while searching for {name:?}");
                    continue;
                }
            };

            match value.name() {
                Ok(value_name) => {
                    if value_name.eq_ignore_ascii_case(name) {
                        return Ok(Some(value));
                    }

                    continue;
                }
                Err(err) => {
                    tracing::trace!(%err, "skipping unreadable value name");
                    continue;
                }
            }
        }

        Ok(None)
    }
}
