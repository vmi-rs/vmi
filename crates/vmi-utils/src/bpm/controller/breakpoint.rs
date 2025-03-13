use vmi_core::{
    Architecture, Gfn, MemoryAccess, Pa, Registers as _, Va, View, VmiCore, VmiDriver, VmiError,
    VmiEvent,
    arch::{EventInterrupt as _, EventReason},
};

use super::TapController;
use crate::interceptor::Interceptor;

#[doc = include_str!("breakpoint.md")]
pub struct BreakpointController<Driver>
where
    Driver: VmiDriver,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    interceptor: Interceptor<Driver>,
}

impl<Driver> BreakpointController<Driver>
where
    Driver: VmiDriver,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    /// Checks if the given event was caused by a software breakpoint.
    pub fn is_breakpoint(
        vmi: &VmiCore<Driver>,
        event: &VmiEvent<Driver::Architecture>,
    ) -> Result<bool, VmiError> {
        let interrupt = match event.reason().as_software_breakpoint() {
            Some(interrupt) => interrupt,
            None => return Ok(false),
        };

        let va = Va(event.registers().instruction_pointer());
        let pa = Driver::Architecture::pa_from_gfn(interrupt.gfn())
            + Driver::Architecture::va_offset(va);

        let mut content = vec![0; Driver::Architecture::BREAKPOINT.len()];
        vmi.read(pa, &mut content)?;

        Ok(content == Driver::Architecture::BREAKPOINT)
    }
}

impl<Driver> TapController for BreakpointController<Driver>
where
    Driver: VmiDriver,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    type Driver = Driver;

    fn new() -> Self {
        Self {
            interceptor: Interceptor::new(),
        }
    }

    fn check_event(&self, event: &VmiEvent<Driver::Architecture>) -> Option<(View, Gfn)> {
        let interrupt = event.reason().as_software_breakpoint()?;
        let view = event.view()?;

        Some((view, interrupt.gfn()))
    }

    fn insert_breakpoint(
        &mut self,
        vmi: &VmiCore<Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        self.interceptor.insert_breakpoint(vmi, pa, view)?;
        Ok(())
    }

    fn remove_breakpoint(
        &mut self,
        vmi: &VmiCore<Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        let breakpoint_was_removed = self.interceptor.remove_breakpoint(vmi, pa, view)?;
        debug_assert_eq!(breakpoint_was_removed, Some(true));
        Ok(())
    }

    fn monitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        vmi.set_memory_access(gfn, view, MemoryAccess::X)
    }

    fn unmonitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        vmi.set_memory_access(gfn, view, MemoryAccess::RWX)
    }
}
