//! VMI driver for Xen core dump.

mod arch;
mod dump;

use std::{collections::HashMap, path::Path};

use vmi_core::{
    Gfn, VcpuId, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryRegisters, VmiRead},
};

pub use self::arch::ArchAdapter;
use self::dump::Dump;

/// VMI driver for Xen core dump.
pub struct VmiXenCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    pub(crate) dump: Dump,
    pfn_cache: HashMap<Gfn, usize>,
    max_gfn: Gfn,
    _marker: std::marker::PhantomData<Arch>,
}

impl<Arch> VmiXenCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a new VMI driver for Xen core dump.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, VmiError> {
        let dump = Dump::new(path)?;

        let mut pfn_cache = HashMap::new();
        let mut max_gfn = Gfn(0);
        for (index, &pfn) in dump.xen_pfn().map_err(VmiError::driver)?.iter().enumerate() {
            // > The value, ~(uint64_t)0, means invalid pfn and the
            // > corresponding page has zero.
            //
            // ref: https://github.com/xen-project/xen/blob/staging/docs/misc/dump-core-format.txt#L95
            if pfn == 0 || pfn == !0 {
                continue;
            }

            pfn_cache.insert(Gfn(pfn), index);
            max_gfn = max_gfn.max(Gfn(pfn));
        }

        Ok(Self {
            dump,
            pfn_cache,
            max_gfn,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<Arch> VmiDriver for VmiXenCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: self.dump.page_size(),
            page_shift: 12,
            max_gfn: self.max_gfn,
            vcpus: 0,
        })
    }
}

impl<Arch> VmiRead for VmiXenCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        let index = self
            .pfn_cache
            .get(&gfn)
            .copied()
            .ok_or(VmiError::OutOfBounds)?;

        let pages = self.dump.xen_pages().map_err(VmiError::driver)?;
        let start = index * self.dump.page_size() as usize;
        let end = start + self.dump.page_size() as usize;
        let content = &pages[start..end];

        Ok(VmiMappedPage::new(Vec::from(content)))
    }
}

impl<Arch> VmiQueryRegisters for VmiXenCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Arch::registers(self, vcpu)
    }
}
