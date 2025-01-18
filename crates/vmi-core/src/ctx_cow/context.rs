use std::borrow::Cow;

use super::{state::VmiState, VmiOsState, VmiSession};
use crate::{os::VmiOs, VmiCore, VmiDriver, VmiEvent};

/// A VMI context.
///
/// `VmiContext` combines access to a [`VmiState`] with [`VmiEvent`] to
/// provide unified access to VMI operations in the context of a specific event.
///
/// This structure is created inside the [`VmiState::handle`] method and
/// passed to the [`VmiHandler::handle_event`] method to handle VMI events.
///
/// [`VmiHandler::handle_event`]: crate::VmiHandler::handle_event
pub struct VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI session.
    state: Cow<'a, VmiState<'a, Driver, Os>>,

    /// The VMI event.
    event: &'a VmiEvent<Driver::Architecture>,
}

impl<'a, Driver, Os> std::ops::Deref for VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    type Target = VmiState<'a, Driver, Os>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<'a, Driver, Os> VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new VMI context.
    pub fn new(
        session: impl Into<Cow<'a, VmiSession<'a, Driver, Os>>>,
        event: &'a VmiEvent<Driver::Architecture>,
    ) -> Self {
        Self {
            state: VmiState::new(session, event.registers()).into(),
            event,
        }
    }

    // Note that `core()` and `underlying_os()` are delegated to the `VmiState`.

    /// Returns the VMI session.
    pub fn state(&self) -> &VmiState<'a, Driver, Os> {
        &self.state
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
    /// The VMI session.
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

impl<'a, Driver, Os> VmiOsContext<'a, Driver, Os>
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
