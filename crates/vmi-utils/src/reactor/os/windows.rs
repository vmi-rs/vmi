use isr_cache::{Entry, IsrCache};
use isr_core::Profile;
use vmi_arch_amd64::{Amd64, Interrupt, PageFaultErrorCode};
use vmi_core::{PageFault, VmiContext, VmiError, VmiState, driver::VmiRead};
use vmi_os_windows::WindowsOs;

use super::{super::ModuleSymbols, OsAdapter};
use crate::resolver::Resolved;

impl<Driver> OsAdapter for WindowsOs<Driver>
where
    Driver: VmiRead<Architecture = Amd64>,
{
    fn module_symbols<'a>(
        _vmi: &VmiState<Self>,
        isr: &IsrCache,
        resolved: &Resolved<Self>,
        entry: &'a mut Option<Entry>,
    ) -> Result<ModuleSymbols<'a>, VmiError> {
        let codeview = resolved.debug_signature.clone();
        let profile = entry.insert(isr.entry_from_codeview(codeview)?).profile()?;
        Ok(profile.into())
    }

    fn profile_symbol_offset(_profile: &Profile, value: u64) -> Option<u64> {
        Some(value)
    }

    fn page_fault(_vmi: &VmiContext<Self>, fault: PageFault) -> Option<Interrupt> {
        Some(Interrupt::page_fault_with_error_code(
            fault.va,
            PageFaultErrorCode::empty(),
        ))
    }
}
