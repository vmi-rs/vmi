use vmi_arch_amd64::{Amd64, Cr3};
use vmi_core::{Pa, VmiDriver, VmiOs, VmiSession, VmiState};

use super::ArchAdapter;

impl<Driver> ArchAdapter<Driver> for Amd64
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn with_translation_root<'a, Os>(
        vmi: &'a VmiSession<Os>,
        registers: &'a mut Self::Registers,
        root: Pa,
    ) -> VmiState<'a, Os>
    where
        Os: VmiOs<Architecture = Self>,
    {
        registers.cr3 = Cr3(root.0);
        vmi.with_registers(registers)
    }
}
