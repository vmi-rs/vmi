use std::cell::OnceCell;

use isr_macros::{Bitfield, Field};
use vmi_core::{
    MemoryAccess, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsRegion, VmiOsRegionKind},
};

use super::{MacOsMapped, MacOsVnode};
use crate::{ArchAdapter, MacOs, MacOsError, MacOsExt as _, offset};

/// `vme_kind` of an entry that maps a VM object.
///
/// Defined as `VME_KIND_OBJECT` in `osfmk/vm/vm_map_xnu.h`.
const VME_KIND_OBJECT: u64 = 0;

/// `vme_kind` of an entry that maps a submap.
///
/// Defined as `VME_KIND_SUBMAP` in `osfmk/vm/vm_map_xnu.h`.
const VME_KIND_SUBMAP: u64 = 3;

/// Read permission in a `vm_prot_t`.
const VM_PROT_READ: u64 = 0x1;

/// Write permission in a `vm_prot_t`.
const VM_PROT_WRITE: u64 = 0x2;

/// Execute permission in a `vm_prot_t`.
const VM_PROT_EXECUTE: u64 = 0x4;

/// Upper bound on the number of VM objects and pagers visited while
/// resolving the file behind a region.
const MAX_OBJECT_CHAIN: usize = 64;

/// A memory region of a macOS process.
///
/// # Implementation Details
///
/// Corresponds to `struct vm_map_entry`.
pub struct MacOsRegion<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `struct vm_map_entry`.
    va: Va,

    /// Cached bytes of the `struct vm_map_entry`.
    entry: OnceCell<Vec<u8>>,
}

impl<Driver> VmiVa for MacOsRegion<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<Driver> std::fmt::Debug for MacOsRegion<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("MacOsRegion")
            .field("start", &self.start())
            .field("end", &self.end())
            .field("protection", &self.protection())
            .finish()
    }
}

impl<'a, Driver> MacOsRegion<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new memory region from the address of its
    /// `struct vm_map_entry`.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            entry: OnceCell::new(),
        }
    }

    /// Returns the bytes of the `struct vm_map_entry`.
    ///
    /// # Notes
    ///
    /// The bytes are cached after the first read.
    fn entry(&self) -> Result<&[u8], VmiError> {
        if let Some(entry) = self.entry.get() {
            return Ok(entry);
        }

        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        let mut entry = vec![0u8; vm_map_entry.len()];
        self.vmi.read(self.va, &mut entry)?;
        Ok(self.entry.get_or_init(|| entry))
    }

    /// Reads a field of the cached entry.
    fn field(&self, field: &Field) -> Result<u64, VmiError> {
        Ok(read_le(self.entry()?, field.offset(), field.size()))
    }

    /// Reads a bitfield of the cached entry.
    ///
    /// Bytes of the underlying field that lie past the end of the entry
    /// read as zero. They hold no bits of the bitfield.
    fn bitfield(&self, bitfield: &Bitfield) -> Result<u64, VmiError> {
        let value = read_le(self.entry()?, bitfield.offset(), bitfield.size());
        Ok(bitfield.extract(value))
    }

    /// Returns the raw `vm_prot_t` of the current protection.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_map_entry.protection`.
    pub fn vm_protection(&self) -> Result<u8, VmiError> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        Ok(self.bitfield(&vm_map_entry.protection)? as u8)
    }

    /// Returns the raw `vm_prot_t` of the maximum protection.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_map_entry.max_protection`.
    pub fn vm_max_protection(&self) -> Result<u8, VmiError> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        Ok(self.bitfield(&vm_map_entry.max_protection)? as u8)
    }

    /// Returns the maximum protection of the region.
    pub fn max_protection(&self) -> Result<MemoryAccess, VmiError> {
        Ok(memory_access(self.vm_max_protection()? as u64))
    }

    /// Returns the VM tag of the region, a `VM_MEMORY_*` value from
    /// `<mach/vm_statistics.h>` such as `VM_MEMORY_MALLOC_TINY` (7) or
    /// `VM_MEMORY_STACK` (30).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_map_entry.vme_alias`.
    pub fn tag(&self) -> Result<u16, VmiError> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        Ok(self.bitfield(&vm_map_entry.vme_alias)? as u16)
    }

    /// Returns the kind of object the entry maps, a `vme_kind_t` value.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_map_entry.vme_kind`.
    fn vme_kind(&self) -> Result<u64, VmiError> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        self.bitfield(&vm_map_entry.vme_kind)
    }

    /// Returns the pointer packed into `vm_map_entry.vme_value`.
    ///
    /// The pointer is stored with its low bits shifted out, so it is the
    /// value shifted back by the bit position of the bitfield.
    fn vme_pointer(&self) -> Result<Va, VmiError> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        let value = self.bitfield(&vm_map_entry.vme_value)?;
        Ok(Driver::Architecture::canonical_address(
            value << vm_map_entry.vme_value.bit_position(),
        ))
    }

    /// Checks whether the region maps a submap, such as the dyld shared
    /// region.
    pub fn is_submap(&self) -> Result<bool, VmiError> {
        Ok(self.vme_kind()? == VME_KIND_SUBMAP)
    }

    /// Returns the address of the `struct vm_object` that the region maps.
    ///
    /// Returns `None` for submaps, kernel objects and regions without an
    /// object, such as reserved ranges.
    pub fn object(&self) -> Result<Option<Va>, VmiError> {
        if self.vme_kind()? != VME_KIND_OBJECT {
            return Ok(None);
        }

        let object = self.vme_pointer()?;
        Ok((!object.is_null()).then_some(object))
    }

    /// Returns the address of the `struct _vm_map` of the submap that the
    /// region maps.
    pub fn submap(&self) -> Result<Option<Va>, VmiError> {
        if !self.is_submap()? {
            return Ok(None);
        }

        let submap = self.vme_pointer()?;
        Ok((!submap.is_null()).then_some(submap))
    }

    /// Returns the vnode of the file that backs the region.
    ///
    /// # Implementation Details
    ///
    /// Follows `vm_object.shadow` to the bottom of the shadow chain and
    /// inspects the pager of that object. A vnode pager yields its vnode.
    /// The dyld, shared region and Apple protect pagers wrap another VM
    /// object, which is resolved the same way. Any other pager, or no pager,
    /// means the region is anonymous memory.
    pub fn vnode(&self) -> Result<Option<MacOsVnode<'a, Driver>>, VmiError> {
        let mut object = match self.object()? {
            Some(object) => object,
            None => return Ok(None),
        };

        let os = self.vmi.underlying_os();
        let vm_object = offset!(self.vmi, vm_object);
        let memory_object = offset!(self.vmi, memory_object);
        let vnode_pager = offset!(self.vmi, vnode_pager);

        // Pairs of pager operations and the offset of the backing object in
        // the matching pager structure.
        let wrapping_pagers = [
            (
                os.symbols.dyld_pager_ops,
                os.offsets
                    .dyld_pager
                    .as_ref()
                    .map(|pager| pager.dyld_backing_object.offset()),
            ),
            (
                os.symbols.shared_region_pager_ops,
                os.offsets
                    .shared_region_pager
                    .as_ref()
                    .map(|pager| pager.srp_backing_object.offset()),
            ),
            (
                os.symbols.apple_protect_pager_ops,
                os.offsets
                    .apple_protect_pager
                    .as_ref()
                    .map(|pager| pager.backing_object.offset()),
            ),
        ];

        for _ in 0..MAX_OBJECT_CHAIN {
            let shadow = self
                .vmi
                .os()
                .read_pointer(object + vm_object.shadow.offset())?;

            if !shadow.is_null() {
                object = shadow;
                continue;
            }

            let pager = self
                .vmi
                .os()
                .read_pointer(object + vm_object.pager.offset())?;

            if pager.is_null() {
                return Ok(None);
            }

            let ops = self
                .vmi
                .os()
                .read_pointer(pager + memory_object.mo_pager_ops.offset())?;

            if ops.0 == os.symbols.vnode_pager_ops {
                let vnode = self
                    .vmi
                    .os()
                    .read_pointer(pager + vnode_pager.vnode_handle.offset())?;

                return Ok((!vnode.is_null()).then(|| MacOsVnode::new(self.vmi, vnode)));
            }

            let backing_object_offset =
                wrapping_pagers
                    .iter()
                    .find_map(|&(pager_ops, backing_object_offset)| {
                        match (pager_ops, backing_object_offset) {
                            (Some(pager_ops), Some(offset)) if pager_ops == ops.0 => Some(offset),
                            _ => None,
                        }
                    });

            let backing_object_offset = match backing_object_offset {
                Some(backing_object_offset) => backing_object_offset,
                None => return Ok(None),
            };

            object = self.vmi.os().read_pointer(pager + backing_object_offset)?;

            if object.is_null() {
                return Ok(None);
            }
        }

        Err(MacOsError::CorruptedStruct("vm_object chain too long").into())
    }
}

impl<'a, Driver> VmiOsRegion<'a, Driver> for MacOsRegion<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = MacOs<Driver>;

    /// Returns the start address of the region.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_map_entry.vme_start`.
    fn start(&self) -> Result<Va, VmiError> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        Ok(Va(self.field(&vm_map_entry.vme_start)?))
    }

    /// Returns the end address of the region, exclusive.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_map_entry.vme_end`.
    fn end(&self) -> Result<Va, VmiError> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        Ok(Va(self.field(&vm_map_entry.vme_end)?))
    }

    /// Returns the current protection of the region.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_map_entry.protection`.
    fn protection(&self) -> Result<MemoryAccess, VmiError> {
        Ok(memory_access(self.vm_protection()? as u64))
    }

    /// Returns the kind of the region.
    ///
    /// A region backed by a file is [`MappedImage`] when its maximum
    /// protection allows execution and [`MappedData`] otherwise. Anonymous
    /// memory, kernel objects and submaps are [`Private`].
    ///
    /// [`MappedImage`]: VmiOsRegionKind::MappedImage
    /// [`MappedData`]: VmiOsRegionKind::MappedData
    /// [`Private`]: VmiOsRegionKind::Private
    fn kind(&self) -> Result<VmiOsRegionKind<'a, MacOs<Driver>>, VmiError> {
        let vnode = match self.vnode()? {
            Some(vnode) => vnode,
            None => return Ok(VmiOsRegionKind::Private),
        };

        let mapped = MacOsMapped::new(self.vmi, vnode.va());

        if self.vm_max_protection()? as u64 & VM_PROT_EXECUTE != 0 {
            Ok(VmiOsRegionKind::MappedImage(mapped))
        }
        else {
            Ok(VmiOsRegionKind::MappedData(mapped))
        }
    }
}

/// Converts a `vm_prot_t` to a [`MemoryAccess`].
fn memory_access(protection: u64) -> MemoryAccess {
    let mut result = MemoryAccess::empty();

    if protection & VM_PROT_READ != 0 {
        result |= MemoryAccess::R;
    }

    if protection & VM_PROT_WRITE != 0 {
        result |= MemoryAccess::W;
    }

    if protection & VM_PROT_EXECUTE != 0 {
        result |= MemoryAccess::X;
    }

    result
}

/// Reads a little-endian integer of `size` bytes at `offset`.
///
/// Bytes past the end of `data` read as zero.
fn read_le(data: &[u8], offset: u64, size: u64) -> u64 {
    let mut value = [0u8; 8];
    let start = (offset as usize).min(data.len());
    let end = (offset as usize + (size as usize).min(8)).min(data.len());

    value[..end - start].copy_from_slice(&data[start..end]);
    u64::from_le_bytes(value)
}
