use std::{io::ErrorKind, time::Duration};

use super::{context::VmiContext, cow::VmiCow, VmiState};
use crate::{os::VmiOs, Architecture, VmiCore, VmiDriver, VmiError, VmiHandler};

/// A VMI session.
///
/// The session combines a [`VmiCore`] with an OS-specific [`VmiOs`]
/// implementation to provide unified access to both low-level VMI operations
/// and higher-level OS abstractions.
pub struct VmiSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI core providing low-level VM introspection capabilities.
    core: &'a VmiCore<Driver>,

    /// The OS-specific operations and abstractions.
    os: &'a Os,
}

impl<Driver, Os> std::ops::Deref for VmiSession<'_, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    type Target = VmiCore<Driver>;

    fn deref(&self) -> &Self::Target {
        self.core
    }
}

impl<'a, Driver, Os> VmiSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new VMI session.
    pub fn new(core: &'a VmiCore<Driver>, os: &'a Os) -> Self {
        Self { core, os }
    }

    /// Creates a new VMI context with the specified registers.
    pub fn with_registers(
        &'a self,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
    ) -> VmiState<'a, Driver, Os> {
        VmiState::new(self, registers)
    }

    /// Returns the VMI core.
    pub fn core(&self) -> &'a VmiCore<Driver> {
        self.core
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &'a Os {
        self.os
    }

    /// Waits for an event to occur and processes it with the provided handler.
    ///
    /// This method blocks until an event occurs or the specified timeout is
    /// reached. When an event occurs, it is passed to the provided callback
    /// function for processing.
    pub fn wait_for_event(
        &self,
        timeout: Duration,
        handler: &mut impl VmiHandler<Driver, Os>,
    ) -> Result<(), VmiError> {
        self.core.wait_for_event(timeout, |event| {
            handler.handle_event(VmiContext::new(self, event))
        })
    }

    /// Enters the main event handling loop that processes VMI events until
    /// finished.
    pub fn handle<Handler>(
        &self,
        handler_factory: impl FnOnce(&VmiSession<Driver, Os>) -> Result<Handler, VmiError>,
    ) -> Result<Option<Handler::Output>, VmiError>
    where
        Handler: VmiHandler<Driver, Os>,
    {
        self.handle_with_timeout(Duration::from_millis(5000), handler_factory)
    }

    /// Enters the main event handling loop that processes VMI events until
    /// finished, with a timeout for each event.
    pub fn handle_with_timeout<Handler>(
        &self,
        timeout: Duration,
        handler_factory: impl FnOnce(&VmiSession<Driver, Os>) -> Result<Handler, VmiError>,
    ) -> Result<Option<Handler::Output>, VmiError>
    where
        Handler: VmiHandler<Driver, Os>,
    {
        let mut result;
        let mut handler = handler_factory(self)?;

        loop {
            result = handler.check_completion();

            if result.is_some() {
                break;
            }

            match self.wait_for_event(timeout, &mut handler) {
                Err(VmiError::Timeout) => {
                    tracing::trace!("timeout");
                    handler.handle_timeout(self);
                }
                Err(VmiError::Io(err)) if err.kind() == ErrorKind::Interrupted => {
                    tracing::trace!("interrupted");
                    handler.handle_interrupted(self);
                    break;
                }
                Err(err) => return Err(err),
                Ok(_) => {}
            }
        }

        tracing::trace!("disabling monitor");
        self.core.reset_state()?;
        tracing::trace!(pending_events = self.events_pending());

        let _pause_guard = self.pause_guard()?;
        if self.events_pending() > 0 {
            match self.wait_for_event(Duration::from_millis(0), &mut handler) {
                Err(VmiError::Timeout) => {
                    tracing::trace!("timeout");
                }
                Err(err) => return Err(err),
                Ok(_) => {}
            }
        }

        Ok(result)
    }
}

////////////////////////////////////////////////////////////////////////////////

impl<'a, Driver, Os> From<VmiSession<'a, Driver, Os>> for VmiCow<'a, VmiSession<'a, Driver, Os>>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn from(value: VmiSession<'a, Driver, Os>) -> Self {
        VmiCow::Owned(value)
    }
}

impl<'a, Driver, Os> From<&'a VmiSession<'a, Driver, Os>> for VmiCow<'a, VmiSession<'a, Driver, Os>>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn from(value: &'a VmiSession<'a, Driver, Os>) -> Self {
        VmiCow::Borrowed(value)
    }
}
