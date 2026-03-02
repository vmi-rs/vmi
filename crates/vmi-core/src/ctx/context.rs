use super::{VmiOsState, state::VmiState};
use crate::{VmiCore, VmiEvent, VmiOs};

/// A VMI context.
///
/// The context combines access to a [`VmiState`] with [`VmiEvent`] to
/// provide unified access to VMI operations in the context of a specific
/// event.
///
/// This structure is created inside the [`VmiSession::handle`] method and
/// passed to the [`VmiHandler::handle_event`] method to handle VMI events.
///
/// [`VmiHandler::handle_event`]: crate::VmiHandler::handle_event
pub struct VmiContext<'a, Os>
where
    Os: VmiOs,
{
    /// The VMI session.
    state: &'a VmiState<'a, Os>,

    /// The VMI event.
    event: &'a VmiEvent<Os::Architecture>,
}

impl<Os> Clone for VmiContext<'_, Os>
where
    Os: VmiOs,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<Os> Copy for VmiContext<'_, Os> where Os: VmiOs {}

impl<'a, Os> std::ops::Deref for VmiContext<'a, Os>
where
    Os: VmiOs,
{
    type Target = VmiState<'a, Os>;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<'a, Os> VmiContext<'a, Os>
where
    Os: VmiOs,
{
    /// Creates a new VMI context.
    pub fn new(state: &'a VmiState<'a, Os>, event: &'a VmiEvent<Os::Architecture>) -> Self {
        debug_assert_eq!(state.registers() as *const _, event.registers() as *const _);

        Self { state, event }
    }

    // Note that `core()` and `underlying_os()` and other methods are delegated
    // to the `VmiState`.

    /// Returns the VMI session.
    pub fn state(&self) -> VmiState<'a, Os> {
        *self.state
    }

    /// Returns the current VMI event.
    pub fn event(&self) -> &VmiEvent<Os::Architecture> {
        self.event
    }

    /// Returns a wrapper providing access to OS-specific operations.
    pub fn os(&self) -> VmiOsContext<'_, Os> {
        VmiOsContext {
            state: self.state.os(),
            event: self.event,
        }
    }
}

/// Wrapper providing access to OS-specific operations.
pub struct VmiOsContext<'a, Os>
where
    Os: VmiOs,
{
    /// The VMI OS state.
    state: VmiOsState<'a, Os>,

    /// The VMI event.
    event: &'a VmiEvent<Os::Architecture>,
}

impl<'a, Os> std::ops::Deref for VmiOsContext<'a, Os>
where
    Os: VmiOs,
{
    type Target = VmiOsState<'a, Os>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<Os> VmiOsContext<'_, Os>
where
    Os: VmiOs,
{
    /// Returns the VMI context.
    pub fn core(&self) -> &VmiCore<Os::Driver> {
        self.state.core()
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &Os {
        self.state.underlying_os()
    }

    /// Returns the current VMI event.
    pub fn event(&self) -> &VmiEvent<Os::Architecture> {
        self.event
    }
}
