mod breakpoint;
mod memory;
use vmi_core::{Gfn, Pa, View, VmiCore, VmiDriver, VmiError, VmiEvent};

pub use self::{breakpoint::BreakpointController, memory::MemoryController};

/// Trait for breakpoint controller implementations.
pub trait TapController {
    /// VMI driver type.
    type Driver: VmiDriver;

    /// Creates a new `TapController`.
    fn new() -> Self;

    /// Checks if the given event was caused by a breakpoint.
    fn check_event(
        &self,
        event: &VmiEvent<<Self::Driver as VmiDriver>::Architecture>,
    ) -> Option<(View, Gfn)>;

    /// Inserts a breakpoint at the given physical address.
    fn insert_breakpoint(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError>;

    /// Removes a breakpoint at the given physical address.
    fn remove_breakpoint(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError>;

    /// Monitors the given guest frame number.
    fn monitor(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError>;

    /// Unmonitors the given guest frame number.
    fn unmonitor(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError>;
}
