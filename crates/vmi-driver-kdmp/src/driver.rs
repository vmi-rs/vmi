use std::path::Path;

use kdmp_parser::{gxa::Gpa, map::MappedFileReader, parse::KernelDumpParser, phys::Reader};
use vmi_core::{Architecture, Gfn, VcpuId, VmiInfo, VmiMappedPage};

use crate::{ArchAdapter, Error};

/// VMI driver for Xen core dump.
pub struct KdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    pub(crate) dump: KernelDumpParser,
    _marker: std::marker::PhantomData<Arch>,
}

impl<Arch> KdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let dump = KernelDumpParser::with_reader(MappedFileReader::new(path)?)?;

        Ok(Self {
            dump,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn info(&self) -> Result<VmiInfo, Error> {
        Ok(VmiInfo {
            page_size: 4096,
            page_shift: 12,
            max_gfn: Gfn(0),
            vcpus: 0,
        })
    }

    pub fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, Error> {
        Arch::registers(self, vcpu)
    }

    pub fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, Error> {
        let reader = Reader::new(&self.dump);

        let mut content = [0u8; 4096];
        reader.read_exact(Gpa::new(gfn.0 << 12), &mut content)?;

        Ok(VmiMappedPage::new(Vec::from(content)))
    }
}
