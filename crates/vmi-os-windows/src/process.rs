use vmi_arch_amd64::Cr3;
use vmi_core::{
    os::{OsArchitecture, ProcessId, ProcessObject, VmiOsProcess},
    Architecture, Pa, Va, VmiDriver, VmiError, VmiState,
};

use crate::{
    arch::ArchAdapter,
    handle_table::WindowsHandleTable,
    macros::impl_offsets,
    offsets::{v1, v2},
    peb::{WindowsPeb, WindowsWow64Kind},
    region::WindowsRegion,
    OffsetsExt, TreeNodeIterator, WindowsOs,
};

/// A Windows OS process (`_EPROCESS`).
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

impl<Driver> From<WindowsProcess<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsProcess<Driver>) -> Self {
        value.va
    }
}

impl<'a, Driver> WindowsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows OS process.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, process: ProcessObject) -> Self {
        Self { vmi, va: process.0 }
    }

    /// Returns the `_PEB` structure of the process.
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
            .read_va_native(self.va + EPROCESS.WoW64Process.offset)?;

        if wow64.is_null() {
            let peb64 = self.vmi.read_va_native(self.va + EPROCESS.Peb.offset)?;

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
                    .read_va_native(wow64 + v2._EWOW64PROCESS.Peb.offset)?,
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

    /// Returns the handle table of the process.
    pub fn handle_table(&self) -> Result<WindowsHandleTable<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let handle_table = self
            .vmi
            .read_va_native(self.va + EPROCESS.ObjectTable.offset)?;

        Ok(WindowsHandleTable::new(self.vmi.clone(), handle_table))
    }

    /// Returns the address of the root node in the VAD tree.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.VadRoot->BalancedRoot` for Windows 7 and
    /// `_EPROCESS.VadRoot->Root` for Windows 8.1 and later.
    pub fn vad_root(&self) -> Result<WindowsRegion<'a, Driver>, VmiError> {
        let node = match &self.offsets().ext() {
            Some(OffsetsExt::V1(offsets)) => self.vad_root_v1(offsets)?,
            Some(OffsetsExt::V2(offsets)) => self.vad_root_v2(offsets)?,
            None => panic!("OffsetsExt not set"),
        };

        Ok(WindowsRegion::new(self.vmi, node))
    }

    fn vad_root_v1(&self, offsets_ext: &v1::Offsets) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;
        let MM_AVL_TABLE = &offsets_ext._MM_AVL_TABLE;

        // The `_MM_AVL_TABLE::BalancedRoot` field is of `_MMADDRESS_NODE` type,
        // which represents the root.
        let vad_root = self.va + EPROCESS.VadRoot.offset + MM_AVL_TABLE.BalancedRoot.offset;

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
            .read_va_native(self.va + EPROCESS.VadRoot.offset + RTL_AVL_TREE.Root.offset)?;

        Ok(vad_root)
    }

    /// Returns the address of the hint node in the VAD tree.
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
            .read_va_native(self.va + EPROCESS.VadRoot.offset + MM_AVL_TABLE.NodeHint.offset)
    }

    fn vad_hint_v2(&self, _offsets_ext: &v2::Offsets) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let VadHint = EPROCESS
            .VadHint
            .expect("VadHint is not present in common offsets");

        self.vmi.read_va_native(self.va + VadHint.offset)
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
            .read_u32(self.va + EPROCESS.UniqueProcessId.offset)?;

        Ok(ProcessId(result))
    }

    /// Returns the process object.
    fn object(&self) -> Result<ProcessObject, VmiError> {
        Ok(ProcessObject(self.va))
    }

    /// Returns the filename of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_EPROCESS.ImageFileName`.
    fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        self.vmi
            .read_string(self.va + EPROCESS.ImageFileName.offset)
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
            .read_u32(self.va + EPROCESS.InheritedFromUniqueProcessId.offset)?;

        Ok(ProcessId(result))
    }

    /// Returns the architecture of the process.
    ///
    /// # Implementation Details
    ///
    /// The function reads the `_EPROCESS.WoW64Process` field to determine if the
    /// process is a 32-bit process. If the field is `NULL`, the process is 64-bit.
    /// Otherwise, the process is 32-bit.
    fn architecture(&self) -> Result<OsArchitecture, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let wow64process = self
            .vmi
            .read_va_native(self.va + EPROCESS.WoW64Process.offset)?;

        if wow64process.is_null() {
            Ok(OsArchitecture::Amd64)
        }
        else {
            Ok(OsArchitecture::X86)
        }
    }

    /// Returns the translation root of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPROCESS.DirectoryTableBase`.
    fn translation_root(&self) -> Result<Pa, VmiError> {
        let offsets = self.offsets();
        let KPROCESS = &offsets._KPROCESS;

        let current_process = self.vmi.os().current_process()?.object()?;

        if self.va == current_process.0 {
            return Ok(self.vmi.translation_root(self.va));
        }

        let root = Cr3(self
            .vmi
            .read_va_native(self.va + KPROCESS.DirectoryTableBase.offset)?
            .0);

        Ok(root.into())
    }

    /// Retrieves the base address of the user translation root.
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
            .read_va_native(self.va + UserDirectoryTableBase.offset)?
            .0);

        if root.0 < Driver::Architecture::PAGE_SIZE {
            return self.translation_root();
        }

        Ok(root.into())

        /*

                let KPROCESS = &self.offsets.common._KPROCESS;
        let UserDirectoryTableBase = match &KPROCESS.UserDirectoryTableBase {
            Some(UserDirectoryTableBase) => UserDirectoryTableBase,
            None => return self.process_translation_root(vmi, process),
        };

        let root = u64::from(vmi.read_va_native(process.0 + UserDirectoryTableBase.offset)?);

        if root < Driver::Architecture::PAGE_SIZE {
            return self.process_translation_root(vmi, process);
        }

        Ok(Cr3(root).into())
        self.vmi.os().process_user_translation_root(self.object()?)

         */
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
            .read_va_native(self.va + EPROCESS.SectionBaseAddress.offset)
    }

    /// Returns the regions of the process.
    ///
    /// # Implementation Details
    ///
    /// The function iterates over the VAD tree of the process.
    fn regions(
        &self,
    ) -> Result<impl Iterator<Item = Result<WindowsRegion<'a, Driver>, VmiError>>, VmiError> {
        Ok(TreeNodeIterator::new(self.vmi, self.vad_root()?.into())?
            .map(move |result| result.map(|vad| WindowsRegion::new(self.vmi, vad))))
    }

    /// Locates the VAD that encompasses a specific virtual address in the process.
    ///
    /// This method efficiently searches the VAD tree to find the VAD node that
    /// corresponds to the given virtual address within the process's address
    /// space. Its functionality is similar to the Windows kernel's internal
    /// `MiLocateAddress()` function.
    ///
    /// Returns the matching VAD if found, or `None` if the address is not
    /// within any VAD.
    fn find_region(&self, address: Va) -> Result<Option<WindowsRegion<'a, Driver>>, VmiError> {
        let vad = match self.vad_hint()? {
            Some(vad) => vad,
            None => return Ok(None),
        };

        let vpn = address.0 >> 12;

        if vpn >= vad.starting_vpn()? && vpn <= vad.ending_vpn()? {
            return Ok(Some(vad));
        }

        let mut next = Some(self.vad_root()?);
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

    /// Checks if a given virtual address is valid in the process.
    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError> {
        Driver::Architecture::process_address_is_valid(self.vmi, ProcessObject(self.va), address)
    }
}
