Uses software breakpoint instructions (like `INT3` on x86) to implement
breakpoints.

When a breakpoint is inserted, the memory page is marked as execute-only -
meaning the guest can execute code from the page but cannot read or modify it
without triggering an exception. This effectively hides the breakpoint from the
guest.

When a VCPU executes the breakpoint instruction, a [`VmiEvent`] is generated
with a reason indicating a [software breakpoint]. The user can verify if this
event came from a breakpoint manager using
[`BreakpointManager::contains_by_event`] or [`BreakpointManager::get_by_event`].

If a VCPU tries to read from or write to a page containing breakpoints, a
[`VmiEvent`] is generated with a [memory access] reason.

Read access exceptions can typically be handled by (fast-)single-stepping
the instruction in an unmodified [`default_view`](VmiCore::default_view).

Write exceptions need careful consideration as they could overwrite breakpoint
instructions - you can either ignore them or remove the affected breakpoint
from the manager.

[software breakpoint]: vmi_core::arch::EventReason::as_software_breakpoint
[memory access]: vmi_core::arch::EventReason::as_memory_access
[`BreakpointManager::contains_by_event`]: crate::bpm::BreakpointManager::contains_by_event
[`BreakpointManager::get_by_event`]: crate::bpm::BreakpointManager::get_by_event