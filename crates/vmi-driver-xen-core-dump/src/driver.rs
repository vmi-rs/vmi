use std::{collections::HashMap, path::Path};

use vmi_core::{Architecture, Gfn, VcpuId, VmiInfo, VmiMappedPage};

use crate::{ArchAdapter, Error, dump::Dump};

/// VMI driver for Xen core dump.
pub struct XenCoreDumpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    pub(crate) dump: Dump,
    pfn_cache: HashMap<Gfn, usize>,
    max_gfn: Gfn,
    _marker: std::marker::PhantomData<Arch>,
}

impl<Arch> XenCoreDumpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let dump = Dump::new(path)?;

        let mut pfn_cache = HashMap::new();
        let mut max_gfn = Gfn(0);
        for (index, &pfn) in dump.xen_pfn()?.iter().enumerate() {
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

    pub fn info(&self) -> Result<VmiInfo, Error> {
        Ok(VmiInfo {
            page_size: self.dump.page_size(),
            page_shift: 12,
            max_gfn: self.max_gfn,
            vcpus: 0,
        })
    }

    pub fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, Error> {
        Arch::registers(self, vcpu)
    }

    pub fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, Error> {
        let index = self
            .pfn_cache
            .get(&gfn)
            .copied()
            .ok_or(Error::OutOfBounds)?;

        let pages = self.dump.xen_pages()?;
        let start = index * self.dump.page_size() as usize;
        let end = start + self.dump.page_size() as usize;
        let content = &pages[start..end];

        Ok(VmiMappedPage::new(Vec::from(content)))
    }
}
