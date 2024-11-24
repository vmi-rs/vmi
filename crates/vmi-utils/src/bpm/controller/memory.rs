use vmi_core::{
    arch::{Architecture as _, EventMemoryAccess as _, EventReason as _},
    Gfn, MemoryAccess, Pa, View, VmiCore, VmiDriver, VmiError, VmiEvent,
};

use super::TapController;

#[doc = include_str!("memory.md")]
pub struct MemoryController<Driver>
where
    Driver: VmiDriver,
{
    _marker: std::marker::PhantomData<Driver>,
}

impl<Driver> TapController for MemoryController<Driver>
where
    Driver: VmiDriver,
{
    type Driver = Driver;

    fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }

    fn check_event(&self, event: &VmiEvent<Driver::Architecture>) -> Option<(View, Gfn)> {
        let memory_access = event.reason().as_memory_access()?;

        if !memory_access.access().contains(MemoryAccess::X) {
            return None;
        }

        let view = event.view()?;

        let gfn = Driver::Architecture::gfn_from_pa(memory_access.pa());
        Some((view, gfn))
    }

    fn insert_breakpoint(
        &mut self,
        _vmi: &VmiCore<Driver>,
        _pa: Pa,
        _view: View,
    ) -> Result<(), VmiError> {
        Ok(())
    }

    fn remove_breakpoint(
        &mut self,
        _vmi: &VmiCore<Driver>,
        _pa: Pa,
        _view: View,
    ) -> Result<(), VmiError> {
        Ok(())
    }

    fn monitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        vmi.set_memory_access(gfn, view, MemoryAccess::RW)
    }

    fn unmonitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        vmi.set_memory_access(gfn, view, MemoryAccess::RWX)
    }
}
