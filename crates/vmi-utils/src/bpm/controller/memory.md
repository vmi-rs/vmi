Implements "memory breakpoints" by manipulating memory access permissions rather
than modifying instructions.

When a breakpoint is inserted, the page is marked as non-executable - the guest
can read or write to the page but cannot execute code from it without triggering
an exception.

When a VCPU tries to execute code from the protected page, a [`VmiEvent`] is
generated with a [memory access] reason. As with the [`BreakpointController`],
you can check if the event came from a breakpoint manager using
[`BreakpointManager::contains_by_event`] or [`BreakpointManager::get_by_event`].

Regular read and write operations proceed normally without generating events.

[software breakpoint]: vmi_core::arch::EventReason::as_software_breakpoint
[memory access]: vmi_core::arch::EventReason::as_memory_access
[`BreakpointController`]: crate::bpm::BreakpointController
[`BreakpointManager::contains_by_event`]: crate::bpm::BreakpointManager::contains_by_event
[`BreakpointManager::get_by_event`]: crate::bpm::BreakpointManager::get_by_event
