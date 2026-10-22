use isr_cache::{Entry, IsrCache};
use isr_core::Profile;
use vmi_arch_amd64::{Amd64, Interrupt};
use vmi_core::{
    Architecture as _, PageFault, Registers as _, Va, VmiContext, VmiError, VmiState, VmiVa as _,
    arch::Interrupt as _,
    driver::VmiRead,
    os::{VmiOsImage as _, VmiOsModule as _, VmiOsProcess as _},
};
use vmi_os_linux::{LinuxModule, LinuxOs};

use super::{super::ModuleSymbols, OsAdapter};
use crate::resolver::Resolved;

impl<Driver> OsAdapter for LinuxOs<Driver>
where
    Driver: VmiRead<Architecture = Amd64>,
{
    fn module_symbols<'a>(
        vmi: &VmiState<Self>,
        _isr: &IsrCache,
        resolved: &Resolved<Self>,
        _entry: &'a mut Option<Entry>,
    ) -> Result<ModuleSymbols<'a>, VmiError> {
        let image_base = resolved.image_base;

        if !Amd64::is_kernel_address(image_base) {
            let root = vmi.os().process(resolved.process)?.translation_root()?;

            let mut registers = *vmi.registers();
            registers.set_translation_root(root.0, image_base);

            let vmi = vmi.with_registers(&registers);
            return Ok(vmi.os().image(image_base)?.exports()?.into());
        }

        if vmi.os().kernel_image_base()? == image_base {
            return Ok(vmi.os().image(image_base)?.exports()?.into());
        }

        let module = vmi
            .os()
            .find_module(|module: &LinuxModule<Driver>| Ok(module.base_address()? == image_base))?;

        match module {
            Some(module) => {
                tracing::debug!(module = %module.va(), "reading module kallsyms");
                Ok(module.symbols()?.into())
            }
            None => Err(VmiError::Other("kernel module not found")),
        }
    }

    fn profile_symbol_offset(profile: &Profile, value: u64) -> Option<u64> {
        value.checked_sub(profile.find_symbol("_text")?)
    }

    fn page_fault(vmi: &VmiContext<Self>, fault: PageFault) -> Option<Interrupt> {
        //
        // The guest can take the page fault only in the address space of the
        // current thread, for a user address, and while that thread runs in
        // user mode. A handler that reads another process's memory faults
        // under that process's root.
        //

        if Amd64::is_kernel_address(fault.va)
            || Amd64::is_kernel_address(Va(vmi.registers().rip))
            || fault.root != vmi.translation_root(fault.va)
        {
            return None;
        }

        Some(Interrupt::page_fault(fault))
    }
}
