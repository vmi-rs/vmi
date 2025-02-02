use std::{collections::HashMap, path::Path, time::Duration};

use vmi_core::{
    Architecture, Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiEvent, VmiEventResponse,
    VmiInfo, VmiMappedPage,
};

use crate::{dump::Dump, ArchAdapter, Error};

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

    pub fn pause(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn resume(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, Error> {
        Arch::registers(self, vcpu)
    }

    pub fn set_registers(&self, _vcpu: VcpuId, _registers: Arch::Registers) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn memory_access(&self, _gfn: Gfn, _view: View) -> Result<MemoryAccess, Error> {
        Err(Error::NotSupported)
    }

    pub fn set_memory_access(
        &self,
        _gfn: Gfn,
        _view: View,
        _access: MemoryAccess,
    ) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn set_memory_access_with_options(
        &self,
        _gfn: Gfn,
        _view: View,
        _access: MemoryAccess,
        _options: MemoryAccessOptions,
    ) -> Result<(), Error> {
        Err(Error::NotSupported)
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

    pub fn write_page(
        &self,
        _gfn: Gfn,
        _offset: u64,
        _content: &[u8],
    ) -> Result<VmiMappedPage, Error> {
        Err(Error::NotSupported)
    }

    pub fn allocate_gfn(&self, _gfn: Gfn) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn free_gfn(&self, _gfn: Gfn) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn default_view(&self) -> View {
        View(0)
    }

    pub fn create_view(&self, _default_access: MemoryAccess) -> Result<View, Error> {
        Err(Error::NotSupported)
    }

    pub fn destroy_view(&self, _view: View) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn switch_to_view(&self, _view: View) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn change_view_gfn(&self, _view: View, _old_gfn: Gfn, _new_gfn: Gfn) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn reset_view_gfn(&self, _view: View, _gfn: Gfn) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn monitor_enable(&self, _option: Arch::EventMonitor) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn monitor_disable(&self, _option: Arch::EventMonitor) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn inject_interrupt(
        &self,
        _vcpu: VcpuId,
        _interrupt: Arch::Interrupt,
    ) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn events_pending(&self) -> usize {
        0
    }

    pub fn event_processing_overhead(&self) -> Duration {
        Duration::from_secs(0)
    }

    pub fn wait_for_event(
        &self,
        _timeout: Duration,
        _handler: impl FnMut(&VmiEvent<Arch>) -> VmiEventResponse<Arch>,
    ) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn reset_state(&self) -> Result<(), Error> {
        Err(Error::NotSupported)
    }
}
