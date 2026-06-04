use vmi_arch_arm64::Arm64;
use vmi_core::{Pa, VmiDriver, VmiOs, VmiSession, VmiState};

use super::ArchAdapter;

impl<Driver> ArchAdapter<Driver> for Arm64
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
        registers.ttbr0_el1 = root.0;
        vmi.with_registers(registers)
    }
}
