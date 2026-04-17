//! VMI driver for kernel memory dump.

mod arch;

use std::path::Path;

use kdmp_parser::{gxa::Gpa, map::MappedFileReader, parse::KernelDumpParser, phys::Reader};
use vmi_core::{
    Gfn, Pa, Va, VcpuId, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryRegisters, VmiRead},
};

pub use self::arch::{
    ArchAdapter,
    header64::{ExceptionRecord64, Header64},
};

/// VMI driver for kernel memory dump.
pub struct VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    pub(crate) dump: KernelDumpParser,
    _marker: std::marker::PhantomData<Arch>,
}

impl<Arch> VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a new VMI driver for kernel memory dump.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, VmiError> {
        let reader = MappedFileReader::new(path)?;
        let dump = KernelDumpParser::with_reader(reader).map_err(map_kdmp_error)?;

        Ok(Self {
            dump,
            _marker: std::marker::PhantomData,
        })
    }

    /// Returns the dump header.
    pub fn header(&self) -> Arch::Header {
        Arch::header(self)
    }
}

impl<Arch> VmiDriver for VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: 4096,
            page_shift: 12,
            max_gfn: Gfn(0),
            vcpus: 0,
        })
    }
}

impl<Arch> VmiRead for VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        let reader = Reader::new(&self.dump);

        let mut content = [0u8; 4096];
        reader
            .read_exact(Gpa::new(gfn.0 << 12), &mut content)
            .map_err(map_kdmp_error)?;

        Ok(VmiMappedPage::new(Vec::from(content)))
    }
}

impl<Arch> VmiQueryRegisters for VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Arch::registers(self, vcpu)
    }
}

/// Converts a [`kdmp_parser`] error into a [`VmiError`], translating page-read
/// failures into page faults so callers see a [`VmiError::Translation`]
/// instead of an opaque driver error.
pub(crate) fn map_kdmp_error(err: kdmp_parser::error::Error) -> VmiError {
    match err {
        kdmp_parser::error::Error::PageRead(kdmp_parser::error::PageReadError::NotPresent {
            gva,
            ..
        }) => VmiError::page_fault((Va(u64::from(gva)), Pa(0))),
        kdmp_parser::error::Error::PageRead(kdmp_parser::error::PageReadError::NotInDump {
            gva: Some((gva, _)),
            ..
        }) => VmiError::page_fault((Va(u64::from(gva)), Pa(0))),
        other => VmiError::driver(other),
    }
}
