use vmi_arch_amd64::Cr3;
use vmi_core::{
    os::{ProcessId, ProcessObject, ThreadObject, VmiOsImageArchitecture, VmiOsProcess},
    Architecture, Pa, Va, VmiDriver, VmiError, VmiState, VmiVa,
};

use super::{
    super::{
        macros::impl_offsets, peb::WindowsWow64Kind, WindowsHandleTable, WindowsPeb, WindowsRegion,
        WindowsSession,
    },
    WindowsObject, WindowsThread,
};
use crate::{
    offsets::{v1, v2},
    ArchAdapter, ListEntryIterator, OffsetsExt, TreeNodeIterator, WindowsOs,
};

/// A Windows process.
///
/// A process in Windows is represented by the `_EPROCESS` structure,
/// which contains metadata about its execution state, memory layout,
/// and handles.
///
/// # Implementation Details
///
/// Corresponds to `_EPROCESS`.
pub struct WindowsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_EPROCESS` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsProcess<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsProcess<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsProcess<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows process.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, process: ProcessObject) -> Self {
        Self { vmi, va: process.0 }
    }

    /// Returns the process environment block (PEB).
    ///
    /// # Implementation Details
    ///
    /// The function first reads the `_EPROCESS.WoW64Process` field to determine
    /// if the process is a 32-bit process. If the field is `NULL`, the process
    /// is 64-bit. Otherwise, the function reads the `_EWOW64PROCESS.Peb` field
    /// to get the 32-bit PEB.
    pub fn peb(&self) -> Result<WindowsPeb<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let root = self.translation_root()?;

        let wow64 = self
            .vmi
            .read_va_native(self.va + EPROCESS.WoW64Process.offset())?;

        if wow64.is_null() {
            let peb64 = self.vmi.read_va_native(self.va + EPROCESS.Peb.offset())?;

            Ok(WindowsPeb::new(
                self.vmi,
                peb64,
                root,
                WindowsWow64Kind::Native,
            ))
        }
        else {
            let peb32 = match &offsets.ext {
                Some(OffsetsExt::V1(_)) => wow64,
                Some(OffsetsExt::V2(v2)) => self
                    .vmi
                    .read_va_native(wow64 + v2._EWOW64PROCESS.Peb.offset())?,
                None => panic!("OffsetsExt not set"),
            };

            Ok(WindowsPeb::new(
                self.vmi,
                peb32,
                root,
                WindowsWow64Kind::X86,
            ))
        }
    }

    /// Returns the session of the process.
    pub fn session(&self) -> Result<Option<WindowsSession<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let session = self
            .vmi
            .read_va_native(self.va + EPROCESS.Session.offset())?;

        if session.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsSession::new(self.vmi, session)))
    }

    /// Returns the handle table of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.ObjectTable`.
    pub fn handle_table(&self) -> Result<WindowsHandleTable<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let handle_table = self
            .vmi
            .read_va_native(self.va + EPROCESS.ObjectTable.offset())?;

        Ok(WindowsHandleTable::new(self.vmi, handle_table))
    }

    /// Returns the root of the virtual address descriptor (VAD) tree.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.VadRoot->BalancedRoot` for Windows 7 and
    /// `_EPROCESS.VadRoot->Root` for Windows 8.1 and later.
    pub fn vad_root(&self) -> Result<Option<WindowsRegion<'a, Driver>>, VmiError> {
        let node = match &self.offsets().ext() {
            Some(OffsetsExt::V1(offsets)) => self.vad_root_v1(offsets)?,
            Some(OffsetsExt::V2(offsets)) => self.vad_root_v2(offsets)?,
            None => panic!("OffsetsExt not set"),
        };

        if node.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsRegion::new(self.vmi, node)))
    }

    fn vad_root_v1(&self, offsets_ext: &v1::Offsets) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;
        let MM_AVL_TABLE = &offsets_ext._MM_AVL_TABLE;

        // The `_MM_AVL_TABLE::BalancedRoot` field is of `_MMADDRESS_NODE` type,
        // which represents the root.
        let vad_root = self.va + EPROCESS.VadRoot.offset() + MM_AVL_TABLE.BalancedRoot.offset();

        Ok(vad_root)
    }

    fn vad_root_v2(&self, offsets_ext: &v2::Offsets) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;
        let RTL_AVL_TREE = &offsets_ext._RTL_AVL_TREE;

        // The `RTL_AVL_TREE::Root` field is of pointer type (`_RTL_BALANCED_NODE*`),
        // thus we need to dereference it to get the actual node.
        let vad_root = self
            .vmi
            .read_va_native(self.va + EPROCESS.VadRoot.offset() + RTL_AVL_TREE.Root.offset())?;

        Ok(vad_root)
    }

    /// Returns the VAD hint node.
    ///
    /// The VAD hint is an optimization used by Windows to speed up VAD lookups.
    /// This method returns the address of the hint node in the VAD tree.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.VadRoot->NodeHint` for Windows 7 and
    /// `_EPROCESS.VadRoot->Hint` for Windows 8.1 and later.
    pub fn vad_hint(&self) -> Result<Option<WindowsRegion<'a, Driver>>, VmiError> {
        let node = match &self.offsets().ext() {
            Some(OffsetsExt::V1(offsets)) => self.vad_hint_v1(offsets)?,
            Some(OffsetsExt::V2(offsets)) => self.vad_hint_v2(offsets)?,
            None => panic!("OffsetsExt not set"),
        };

        if node.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsRegion::new(self.vmi, node)))
    }

    fn vad_hint_v1(&self, offsets_ext: &v1::Offsets) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;
        let MM_AVL_TABLE = &offsets_ext._MM_AVL_TABLE;

        self.vmi
            .read_va_native(self.va + EPROCESS.VadRoot.offset() + MM_AVL_TABLE.NodeHint.offset())
    }

    fn vad_hint_v2(&self, _offsets_ext: &v2::Offsets) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let VadHint = EPROCESS
            .VadHint
            .expect("VadHint is not present in common offsets");

        self.vmi.read_va_native(self.va + VadHint.offset())
    }
}

impl<'a, Driver> VmiOsProcess<'a, Driver> for WindowsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the process ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.UniqueProcessId`.
    fn id(&self) -> Result<ProcessId, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let result = self
            .vmi
            .read_u32(self.va + EPROCESS.UniqueProcessId.offset())?;

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
    /// Corresponds to `_EPROCESS.ImageFileName`.
    fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        self.vmi
            .read_string(self.va + EPROCESS.ImageFileName.offset())
    }

    /// Returns the parent process ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.InheritedFromUniqueProcessId`.
    fn parent_id(&self) -> Result<ProcessId, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let result = self
            .vmi
            .read_u32(self.va + EPROCESS.InheritedFromUniqueProcessId.offset())?;

        Ok(ProcessId(result))
    }

    /// Returns the architecture of the process.
    ///
    /// # Implementation Details
    ///
    /// The function reads the `_EPROCESS.WoW64Process` field to determine if the
    /// process is a 32-bit process. If the field is `NULL`, the process is 64-bit.
    /// Otherwise, the process is 32-bit.
    fn architecture(&self) -> Result<VmiOsImageArchitecture, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let wow64process = self
            .vmi
            .read_va_native(self.va + EPROCESS.WoW64Process.offset())?;

        if wow64process.is_null() {
            Ok(VmiOsImageArchitecture::Amd64)
        }
        else {
            Ok(VmiOsImageArchitecture::X86)
        }
    }

    /// Returns the process's page table translation root.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPROCESS.DirectoryTableBase`.
    fn translation_root(&self) -> Result<Pa, VmiError> {
        let offsets = self.offsets();
        let KPROCESS = &offsets._KPROCESS;

        // let current_process = self.vmi.os().current_process()?.object()?;
        //
        // if self.va == current_process.0 {
        //     return Ok(self.vmi.translation_root(self.va));
        // }

        let root = Cr3(self
            .vmi
            .read_va_native(self.va + KPROCESS.DirectoryTableBase.offset())?
            .0);

        Ok(root.into())
    }

    /// Returns the user-mode page table translation root.
    ///
    /// If KPTI is disabled, this function will return the same value as
    /// [`translation_root`](Self::translation_root).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPROCESS.UserDirectoryTableBase`.
    fn user_translation_root(&self) -> Result<Pa, VmiError> {
        let offsets = self.offsets();
        let KPROCESS = &offsets._KPROCESS;
        let UserDirectoryTableBase = match &KPROCESS.UserDirectoryTableBase {
            Some(UserDirectoryTableBase) => UserDirectoryTableBase,
            None => return self.translation_root(),
        };

        let root = Cr3(self
            .vmi
            .read_va_native(self.va + UserDirectoryTableBase.offset())?
            .0);

        if root.0 < Driver::Architecture::PAGE_SIZE {
            return self.translation_root();
        }

        Ok(root.into())
    }

    /// Returns the base address of the process image.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.SectionBaseAddress`.
    fn image_base(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        self.vmi
            .read_va_native(self.va + EPROCESS.SectionBaseAddress.offset())
    }

    /// Returns an iterator over the process's memory regions (VADs).
    ///
    /// # Implementation Details
    ///
    /// The function iterates over the VAD tree of the process.
    fn regions(
        &self,
    ) -> Result<impl Iterator<Item = Result<WindowsRegion<'a, Driver>, VmiError>>, VmiError> {
        let iterator = match self.vad_root()? {
            Some(vad_root) => TreeNodeIterator::new(self.vmi, vad_root.va()),
            None => TreeNodeIterator::empty(self.vmi),
        };

        Ok(iterator.map(move |result| result.map(|vad| WindowsRegion::new(self.vmi, vad))))
    }

    /// Finds the memory region (VAD) containing the given address.
    ///
    /// This method efficiently searches the VAD tree to find the VAD node that
    /// corresponds to the given virtual address within the process's address
    /// space.
    ///
    /// Returns the matching VAD if found, or `None` if the address is not
    /// within any VAD.
    ///
    /// # Implementation Details
    ///
    /// The functionality is similar to the Windows kernel's internal
    /// `MiLocateAddress()` function.
    fn find_region(&self, address: Va) -> Result<Option<WindowsRegion<'a, Driver>>, VmiError> {
        let vad = match self.vad_hint()? {
            Some(vad) => vad,
            None => return Ok(None),
        };

        let vpn = address.0 >> 12;

        if vpn >= vad.starting_vpn()? && vpn <= vad.ending_vpn()? {
            return Ok(Some(vad));
        }

        let mut next = self.vad_root()?;
        while let Some(vad) = next {
            if vpn < vad.starting_vpn()? {
                next = vad.left_child()?;
            }
            else if vpn > vad.ending_vpn()? {
                next = vad.right_child()?;
            }
            else {
                return Ok(Some(vad));
            }
        }

        Ok(None)
    }

    /// Returns an iterator over the threads in the process.
    ///
    /// # Notes
    ///
    /// Both `_EPROCESS` and `_KPROCESS` structures contain the same list
    /// of threads.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.ThreadListHead`.
    fn threads(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as vmi_core::VmiOs<Driver>>::Thread<'a>, VmiError>>,
        VmiError,
    > {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;
        let ETHREAD = &offsets._ETHREAD;

        Ok(ListEntryIterator::new(
            self.vmi,
            self.va + EPROCESS.ThreadListHead.offset(),
            ETHREAD.ThreadListEntry.offset(),
        )
        .map(move |result| result.map(|entry| WindowsThread::new(self.vmi, ThreadObject(entry)))))
    }

    /// Checks whether the given virtual address is valid in the process.
    ///
    /// This method checks if page-faulting on the address would result in
    /// a successful access.
    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError> {
        //
        // So, the logic is roughly as follows:
        // - Translate the address and try to find the page table entry.
        //   - If the page table entry is found:
        //     - If the page is present, the address is valid.
        //     - If the page is in transition AND not a prototype, the address is valid.
        // - Find the VAD for the address.
        //   - If the VAD is not found, the address is invalid.
        // - If the VadType is VadImageMap, the address is valid.
        //   - If the VadType is not VadImageMap, we don't care (VadAwe, physical
        //     memory, ...).
        // - If the PrivateMemory bit is not set, the address is invalid.
        // - If the MemCommit bit is not set, the address is invalid.
        //
        // References:
        // - MmAccessFault
        // - MiDispatchFault
        // - MiQueryAddressState
        // - MiCheckVirtualAddress
        //

        if Driver::Architecture::is_page_present_or_transition(self.vmi, address)? {
            return Ok(Some(true));
        }

        let vad = match self.find_region(address)? {
            Some(vad) => vad,
            None => return Ok(Some(false)),
        };

        const MM_ZERO_ACCESS: u8 = 0; // this value is not used.
        const MM_DECOMMIT: u8 = 0x10; // NO_ACCESS, Guard page
        const MM_NOACCESS: u8 = 0x18; // NO_ACCESS, Guard_page, nocache.

        const VadImageMap: u8 = 2;

        if matches!(
            vad.vad_protection()?,
            MM_ZERO_ACCESS | MM_DECOMMIT | MM_NOACCESS
        ) {
            return Ok(Some(false));
        }

        Ok(Some(
            // Private memory must be committed.
            (vad.private_memory()? && vad.mem_commit()?) ||

            // Non-private memory must be mapped from an image.
            // Note that this isn't actually correct, because
            // some parts of the image might not be committed,
            // or they can have different protection than the VAD.
            //
            // However, figuring out the correct protection would
            // be quite complex, so we just assume that the image
            // is always committed and has the same protection as
            // the VAD.
            (!vad.private_memory()? && vad.vad_type()? == VadImageMap),
        ))
    }
}
