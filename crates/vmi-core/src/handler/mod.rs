mod termination;

use std::{
    ops::ControlFlow,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

pub use self::termination::VmiTerminationHandler;
use crate::{VmiContext, VmiEventResponse, VmiOs, VmiSession};

/// A trait for handling VMI events.
///
/// A factory that creates a handler implementing this trait is passed to
/// the [`VmiSession::handle`] method to handle VMI events.
///
/// [`VmiSession::handle`]: crate::VmiSession::handle
pub trait VmiHandler<Os>
where
    Os: VmiOs,
{
    /// The output type of the handler.
    type Output;

    /// Called for each VMI event.
    ///
    /// The returned [`VmiEventResponse`] tells the hypervisor how to resume
    /// the vCPU that triggered the event.
    fn handle_event(&mut self, event: VmiContext<Os>) -> VmiEventResponse<Os::Architecture>;

    /// Called when the event loop times out waiting for the next event.
    ///
    /// This is useful for periodic housekeeping while the guest is idle.
    fn handle_timeout(&mut self, _session: &VmiSession<Os>) {}

    /// Called when the event loop is interrupted by a signal.
    ///
    /// Typically used to initiate a graceful shutdown. If the handler can be
    /// torn down now, this method should return [`ControlFlow::Break`].
    /// Otherwise, for example while a hijacked thread still runs injected
    /// code, it should return [`ControlFlow::Continue`]. The event loop then
    /// keeps handling events until [`poll`](Self::poll) returns `Some`, or
    /// until a second signal arrives.
    fn handle_interrupted(&mut self, _session: &VmiSession<Os>) -> ControlFlow<()> {
        ControlFlow::Break(())
    }

    /// Called once before the session tears down monitoring.
    ///
    /// This gives the handler an opportunity to release resources that
    /// depend on the session (views, memory access permissions, event
    /// monitors) before the session calls [`reset_state`].
    ///
    /// # Notes
    ///
    /// The guest is paused while this method runs. Do not wait here for the
    /// guest to do something, because it cannot run until the cleanup is
    /// done.
    ///
    /// [`reset_state`]: crate::VmiCore::reset_state
    fn cleanup(&mut self, _session: &VmiSession<Os>) {}

    /// Checks if the handler has completed.
    ///
    /// This method is called after each event is handled. If the handler
    /// has completed, this method should return the output of the handler.
    /// Otherwise, it should return `None`.
    fn poll(&mut self) -> Option<Self::Output> {
        None
    }
}

/// Extension methods on [`VmiHandler`].
///
/// The blanket impl is the only impl of this trait, so implementors of
/// [`VmiHandler`] cannot override the default bodies.
pub trait VmiHandlerExt<Os>: VmiHandler<Os> + Sized
where
    Os: VmiOs,
{
    /// Wraps the handler in a [`VmiTerminationHandler`] that interrupts it
    /// at `deadline`.
    fn with_deadline(self, deadline: Instant) -> VmiTerminationHandler<Self> {
        VmiTerminationHandler::new(self).with_deadline(deadline)
    }

    /// Wraps the handler in a [`VmiTerminationHandler`] with a flag that
    /// interrupts it once the flag becomes `true`.
    fn with_termination_flag(
        self,
        termination_flag: Arc<AtomicBool>,
    ) -> VmiTerminationHandler<Self> {
        VmiTerminationHandler::new(self).with_termination_flag(termination_flag)
    }

    /// Wraps the handler in a [`VmiTerminationHandler`] that gives it
    /// `termination_timeout` to finish once interrupted.
    fn with_termination_timeout(
        self,
        termination_timeout: Duration,
    ) -> VmiTerminationHandler<Self> {
        VmiTerminationHandler::new(self).with_termination_timeout(termination_timeout)
    }
}

impl<Os, Handler> VmiHandlerExt<Os> for Handler
where
    Os: VmiOs,
    Handler: VmiHandler<Os>,
{
}
