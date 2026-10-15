Uses software breakpoint instructions (like `INT3` on x86) to implement
breakpoints.

When a breakpoint is inserted, the memory page is marked as execute-only -
meaning the guest can execute code from the page but cannot read or modify it
without triggering an exception. This effectively hides the breakpoint from the
guest.

When a vCPU executes the breakpoint instruction, a [`VmiEvent`] is generated
with a reason indicating a [software breakpoint]. The user can verify if this
event came from a breakpoint manager using
[`BreakpointManager::contains_by_event`] or [`BreakpointManager::get_by_event`].

If a vCPU tries to read from or write to a page containing breakpoints, a
[`VmiEvent`] is generated with a [memory access] reason.

Read access exceptions can typically be handled by (fast-)single-stepping
the instruction in an unmodified [`default_view`](VmiCore::default_view).

Write exceptions must be single-stepped in the default view with other vCPUs
paused. Before allowing execution in the breakpoint view again, call
[`BreakpointManager::refresh_page`] for the modified original frame. This
refreshes saved instructions, reapplies every owned breakpoint, and remaps the
fully patched shadow to synchronize instruction visibility.

All breakpoint mutations require paused guest execution. Multi-byte breakpoint
instructions must be aligned to their instruction size and fit within a page.
Removing the last owner restores the original mapping and frees its shadow.
Call [`BreakpointManager::clear`] before destroying the view. Cleanup propagates
errors and retains unreclaimed frames and permissions for retry. Do not resume
guest execution after a mutation error until recovery or cleanup succeeds.

[software breakpoint]: vmi_core::arch::EventReason::as_software_breakpoint
[memory access]: vmi_core::arch::EventReason::as_memory_access
[`BreakpointManager::contains_by_event`]: crate::bpm::BreakpointManager::contains_by_event
[`BreakpointManager::get_by_event`]: crate::bpm::BreakpointManager::get_by_event
[`BreakpointManager::refresh_page`]: crate::bpm::BreakpointManager::refresh_page
[`BreakpointManager::clear`]: crate::bpm::BreakpointManager::clear