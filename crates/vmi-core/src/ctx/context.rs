use super::{state::VmiState, VmiOsState};
use crate::{os::VmiOs, VmiCore, VmiDriver, VmiEvent};

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
pub struct VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI session.
    state: &'a VmiState<'a, Driver, Os>,

    /// The VMI event.
    event: &'a VmiEvent<Driver::Architecture>,
}

impl<Driver, Os> Clone for VmiContext<'_, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<Driver, Os> Copy for VmiContext<'_, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
}

impl<'a, Driver, Os> std::ops::Deref for VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    type Target = VmiState<'a, Driver, Os>;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<'a, Driver, Os> VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new VMI context.
    pub fn new(
        state: &'a VmiState<'a, Driver, Os>,
        event: &'a VmiEvent<Driver::Architecture>,
    ) -> Self {
        debug_assert_eq!(state.registers() as *const _, event.registers() as *const _);

        Self { state, event }
    }

    // Note that `core()` and `underlying_os()` and other methods are delegated
    // to the `VmiState`.

    /// Returns the VMI session.
    pub fn state(&self) -> VmiState<'a, Driver, Os> {
        *self.state
    }

    /// Returns the current VMI event.
    pub fn event(&self) -> &VmiEvent<Driver::Architecture> {
        self.event
    }

    /// Returns a wrapper providing access to OS-specific operations.
    pub fn os(&self) -> VmiOsContext<Driver, Os> {
        VmiOsContext {
            state: self.state.os(),
            event: self.event,
        }
    }
}

/// Wrapper providing access to OS-specific operations.
pub struct VmiOsContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI OS state.
    state: VmiOsState<'a, Driver, Os>,

    /// The VMI event.
    event: &'a VmiEvent<Driver::Architecture>,
}

impl<'a, Driver, Os> std::ops::Deref for VmiOsContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    type Target = VmiOsState<'a, Driver, Os>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<Driver, Os> VmiOsContext<'_, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Returns the VMI context.
    pub fn core(&self) -> &VmiCore<Driver> {
        self.state.core()
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &Os {
        self.state.underlying_os()
    }

    /// Returns the current VMI event.
    pub fn event(&self) -> &VmiEvent<Driver::Architecture> {
        self.event
    }
}
