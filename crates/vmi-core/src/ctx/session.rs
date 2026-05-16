use std::{io::ErrorKind, time::Duration};

use super::{VmiState, context::VmiContext};
use crate::{
    Architecture, VcpuId, VmiCore, VmiError, VmiHandler,
    driver::{VmiDriver, VmiEventControl, VmiQueryRegisters, VmiVmControl},
    os::{NoOS, VmiOs},
};

/// A VMI session.
///
/// The session combines a [`VmiCore`] with an OS-specific [`VmiOs`]
/// implementation to provide unified access to both low-level VMI operations
/// and higher-level OS abstractions.
pub struct VmiSession<'a, Os>
where
    Os: VmiOs,
{
    /// The VMI core providing low-level VM introspection capabilities.
    core: &'a VmiCore<Os::Driver>,

    /// The OS-specific operations and abstractions.
    os: &'a Os,
}

impl<Os> Clone for VmiSession<'_, Os>
where
    Os: VmiOs,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<Os> Copy for VmiSession<'_, Os> where Os: VmiOs {}

impl<Os> std::ops::Deref for VmiSession<'_, Os>
where
    Os: VmiOs,
{
    type Target = VmiCore<Os::Driver>;

    fn deref(&self) -> &Self::Target {
        self.core
    }
}

impl<'a, Os> VmiSession<'a, Os>
where
    Os: VmiOs,
{
    /// Creates a new VMI session.
    pub fn new(core: &'a VmiCore<Os::Driver>, os: &'a Os) -> Self {
        Self { core, os }
    }

    /// Creates a new VMI state with the specified registers.
    pub fn with_registers(
        &'a self,
        registers: &'a <Os::Architecture as Architecture>::Registers,
    ) -> VmiState<'a, Os> {
        VmiState::new(self, registers)
    }

    /// Creates a new VMI session without an OS-specific implementation.
    pub fn without_os(&self) -> VmiSession<'a, NoOS<Os::Driver>> {
        VmiSession {
            core: self.core,
            os: const { &NoOS(std::marker::PhantomData) },
        }
    }

    /// Returns the VMI core.
    pub fn core(&self) -> &'a VmiCore<Os::Driver> {
        self.core
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &'a Os {
        self.os
    }
}

///////////////////////////////////////////////////////////////////////////////
// VmiEventControl
///////////////////////////////////////////////////////////////////////////////

impl<'a, Os> VmiSession<'a, Os>
where
    Os: VmiOs,
    Os::Driver: VmiEventControl,
{
    /// Waits for an event to occur and processes it with the provided handler.
    ///
    /// This method blocks until an event occurs or the specified timeout is
    /// reached. When an event occurs, it is passed to the provided callback
    /// function for processing.
    pub fn wait_for_event(
        &self,
        timeout: Duration,
        handler: &mut impl VmiHandler<Os>,
    ) -> Result<(), VmiError> {
        self.core.wait_for_event(timeout, |event| {
            let state = VmiState::new(self, event.registers());
            handler.handle_event(VmiContext::new(&state, event))
        })
    }
}

///////////////////////////////////////////////////////////////////////////////
// VmiEventControl + VmiVmControl
///////////////////////////////////////////////////////////////////////////////

impl<'a, Os> VmiSession<'a, Os>
where
    Os: VmiOs,
    Os::Driver: VmiEventControl + VmiVmControl,
{
    /// Enters the main event handling loop that processes VMI events until
    /// finished.
    pub fn handle<Handler>(
        &self,
        handler_factory: impl FnOnce(&VmiSession<Os>) -> Result<Handler, VmiError>,
    ) -> Result<Option<Handler::Output>, VmiError>
    where
        Handler: VmiHandler<Os>,
    {
        self.handle_with_timeout(Duration::from_millis(5000), handler_factory)
    }

    /// Enters the main event handling loop that processes VMI events until
    /// finished, with a timeout for each event.
    pub fn handle_with_timeout<Handler>(
        &self,
        timeout: Duration,
        handler_factory: impl FnOnce(&VmiSession<Os>) -> Result<Handler, VmiError>,
    ) -> Result<Option<Handler::Output>, VmiError>
    where
        Handler: VmiHandler<Os>,
    {
        let mut result;
        let mut handler = handler_factory(self)?;

        loop {
            result = handler.poll();

            if result.is_some() {
                break;
            }

            match self.wait_for_event(timeout, &mut handler) {
                Ok(_) => {}
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
            }
        }

        tracing::trace!("disabling monitor");
        handler.cleanup(self);
        self.core.reset_state()?;
        tracing::trace!(pending_events = self.events_pending());

        let _pause_guard = self.core().pause_guard()?;
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

///////////////////////////////////////////////////////////////////////////////
// VmiQueryRegisters + VmiVmControl
///////////////////////////////////////////////////////////////////////////////

impl<'a, Os> VmiSession<'a, Os>
where
    Os: VmiOs,
    Os::Driver: VmiQueryRegisters + VmiVmControl,
{
    /// Pauses the virtual machine, snapshots the boot CPU registers, and
    /// returns a guard that resumes the VM when dropped.
    pub fn pause_guard(&self) -> Result<VmiSessionPauseGuard<'_, Os>, VmiError> {
        VmiSessionPauseGuard::new(self)
    }
}

/// A guard that pauses the virtual machine and snapshots the boot CPU
/// registers on creation, then resumes the VM on drop.
///
/// Unlike [`VmiPauseGuard`], this guard carries enough register context to
/// build a [`VmiState`] via [`state`], so callers can introspect the paused
/// guest without separately querying registers.
///
/// [`VmiPauseGuard`]: crate::VmiPauseGuard
/// [`state`]: Self::state
pub struct VmiSessionPauseGuard<'a, Os>
where
    Os: VmiOs,
    Os::Driver: VmiQueryRegisters + VmiVmControl,
{
    session: &'a VmiSession<'a, Os>,
    registers: <<Os::Driver as VmiDriver>::Architecture as Architecture>::Registers,
}

impl<'a, Os> VmiSessionPauseGuard<'a, Os>
where
    Os: VmiOs,
    Os::Driver: VmiQueryRegisters + VmiVmControl,
{
    /// Creates a new pause guard.
    pub fn new(session: &'a VmiSession<'a, Os>) -> Result<Self, VmiError> {
        session.driver().pause()?;

        let registers = match session.registers(VcpuId(0)) {
            Ok(registers) => registers,
            Err(err) => {
                if let Err(resume_err) = session.driver().resume() {
                    tracing::error!(
                        err = %resume_err,
                        "failed to resume after register-query failure"
                    );
                }
                return Err(err);
            }
        };

        Ok(Self { session, registers })
    }

    /// Returns the state captured when the guard was created, bound to
    /// the boot CPU (`VcpuId(0)`) registers.
    pub fn state(&self) -> VmiState<'_, Os> {
        VmiState::new(self.session, &self.registers)
    }
}

impl<Os> Drop for VmiSessionPauseGuard<'_, Os>
where
    Os: VmiOs,
    Os::Driver: VmiQueryRegisters + VmiVmControl,
{
    fn drop(&mut self) {
        if let Err(err) = self.session.driver().resume() {
            tracing::error!(%err, "failed to resume the virtual machine");
        }
    }
}
