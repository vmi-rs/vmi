//! Field-shaped accessors for `#[tracing::instrument(fields(...))]`.
//!
//! Each function wraps a single VMI accessor so it returns a primitive
//! `Option<T>` instead of `Result<Newtype<T>, VmiError>`.
//!
//! - Errors collapse to `None`, which drops the field from the span
//!   instead of poisoning it with an error string.
//! - Newtype wrappers like `ProcessId(u32)` and `View(u16)` unwrap to
//!   their inner primitive, so structured-output subscribers emit a
//!   number rather than a `Debug`-formatted struct.
//!
//! # Example
//!
//! ```ignore
//! #[tracing::instrument(
//!     skip_all,
//!     fields(
//!         view = vmi::trace::event_view(vmi.event()),
//!         pid  = vmi::trace::current_process_id(vmi),
//!         tid  = vmi::trace::current_thread_id(vmi),
//!     )
//! )]
//! fn dispatch(...) { ... }
//! ```

use crate::{
    Architecture, VmiEvent, VmiState,
    driver::VmiDriver,
    os::{VmiOs, VmiOsProcess, VmiOsThread, VmiOsUserModule},
};

/// Returns the view of the given event, if available.
pub fn event_view<Arch>(event: &VmiEvent<Arch>) -> Option<u16>
where
    Arch: Architecture,
{
    event.view().map(|view| view.0)
}

/// Returns the thread ID of the given thread, if available.
pub fn thread_id<'a, Driver>(thread: &impl VmiOsThread<'a, Driver>) -> Option<u32>
where
    Driver: VmiDriver,
{
    thread.id().ok().map(|tid| tid.0)
}

/// Returns the process ID of the given process, if available.
pub fn process_id<'a, Driver>(process: &impl VmiOsProcess<'a, Driver>) -> Option<u32>
where
    Driver: VmiDriver,
{
    process.id().ok().map(|pid| pid.0)
}

/// Returns the name of the process, if available.
pub fn process_name<'a, Driver>(process: &impl VmiOsProcess<'a, Driver>) -> Option<String>
where
    Driver: VmiDriver,
{
    process.name().ok()
}

/// Returns the name of the given user module, if available.
pub fn user_module_name<'a, Driver>(module: &impl VmiOsUserModule<'a, Driver>) -> Option<String>
where
    Driver: VmiDriver,
{
    module.name().ok()
}

/// Returns the thread ID of the current thread, if available.
pub fn current_thread_id<Os>(vmi: &VmiState<Os>) -> Option<u32>
where
    Os: VmiOs,
{
    thread_id(&vmi.os().current_thread().ok()?)
}

/// Returns the process ID of the current process, if available.
pub fn current_process_id<Os>(vmi: &VmiState<Os>) -> Option<u32>
where
    Os: VmiOs,
{
    process_id(&vmi.os().current_process().ok()?)
}

/// Returns the name of the current process, if available.
pub fn current_process_name<Os>(vmi: &VmiState<Os>) -> Option<String>
where
    Os: VmiOs,
{
    process_name(&vmi.os().current_process().ok()?)
}
