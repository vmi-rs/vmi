use vmi_arch_amd64::Amd64;
use vmi_core::{Va, VmiCore, VmiDriver, VmiError};

use super::ArchAdapter;

impl<Driver> ArchAdapter<Driver> for Amd64
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn copy_bytes_to_stack(
        vmi: &VmiCore<Driver>,
        registers: &mut Self::Registers,
        data: &[u8],
        alignment: usize,
    ) -> Result<Va, VmiError> {
        let mut addr = registers.rsp;
        addr -= data.len() as u64;
        addr &= !(alignment as u64 - 1);

        vmi.write((addr.into(), registers.cr3.into()), data)?;

        registers.rsp = addr;
        Ok(Va(addr))
    }
}
