use std::{
    ops::ControlFlow,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{VmiContext, VmiEventResponse, VmiHandler, VmiOs, VmiSession};

/// Termination state of a [`VmiTerminationHandler`].
enum TerminationState {
    /// The handler has not been interrupted.
    Running,

    /// The handler was interrupted and is given time to finish.
    ///
    /// The [`Instant`] records when the handler was interrupted. The
    /// termination timeout counts from it.
    Interrupted(Instant),

    /// The handler was interrupted and is no longer waited for. The event
    /// loop ends at the next poll.
    Terminated,
}

/// Handler that interrupts another handler at a deadline or once a
/// termination flag is set.
///
/// [`VmiHandlerExt`] adds it to any handler, for example with
/// [`VmiHandlerExt::with_deadline`]. The wrapped handler is interrupted
/// through [`VmiHandler::handle_interrupted`], as if by a signal.
///
/// If the guest causes no events, the event loop wakes up only once per
/// wait timeout. The deadline, the termination flag and the termination
/// timeout can then take effect up to one wait timeout late.
///
/// The output is `None` if the event loop ended without the output of the
/// wrapped handler, after it was interrupted.
///
/// [`VmiHandlerExt`]: crate::VmiHandlerExt
/// [`VmiHandlerExt::with_deadline`]: crate::VmiHandlerExt::with_deadline
pub struct VmiTerminationHandler<Handler> {
    /// Handler that processes the events.
    handler: Handler,

    /// Optional time at which the handler is interrupted.
    deadline: Option<Instant>,

    /// Optional flag that interrupts the handler once it becomes `true`.
    termination_flag: Option<Arc<AtomicBool>>,

    /// Optional time the handler has to finish once interrupted.
    termination_timeout: Option<Duration>,

    /// Current termination state of the handler.
    state: TerminationState,
}

impl<Handler> VmiTerminationHandler<Handler> {
    /// Creates a new termination handler with the given handler.
    pub fn new(handler: Handler) -> Self {
        Self {
            handler,
            deadline: None,
            termination_flag: None,
            termination_timeout: None,
            state: TerminationState::Running,
        }
    }

    /// Sets the time at which the handler is interrupted.
    pub fn with_deadline(self, deadline: Instant) -> Self {
        Self {
            deadline: Some(deadline),
            ..self
        }
    }

    /// Installs a flag that interrupts the handler once it becomes `true`.
    pub fn with_termination_flag(self, termination_flag: Arc<AtomicBool>) -> Self {
        Self {
            termination_flag: Some(termination_flag),
            ..self
        }
    }

    /// Sets the time the handler has to finish once interrupted, by a
    /// signal, the deadline or the termination flag. When the time runs
    /// out, the event loop ends without the output of the handler.
    pub fn with_termination_timeout(self, termination_timeout: Duration) -> Self {
        Self {
            termination_timeout: Some(termination_timeout),
            ..self
        }
    }

    /// Interrupts the handler once the deadline passes or the termination
    /// flag is set.
    fn check_termination<Os>(&mut self, session: &VmiSession<Os>)
    where
        Os: VmiOs,
        Handler: VmiHandler<Os>,
    {
        if !matches!(self.state, TerminationState::Running) {
            return;
        }

        let timed_out = self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline);

        let terminated = self
            .termination_flag
            .as_ref()
            .is_some_and(|termination_flag| termination_flag.load(Ordering::Relaxed));

        if timed_out || terminated {
            self.interrupt(session);
        }
    }

    /// Interrupts the handler. If it was interrupted before, stops waiting
    /// for it.
    fn interrupt<Os>(&mut self, session: &VmiSession<Os>)
    where
        Os: VmiOs,
        Handler: VmiHandler<Os>,
    {
        self.state = match self.state {
            TerminationState::Running => match self.handler.handle_interrupted(session) {
                ControlFlow::Break(()) => TerminationState::Terminated,
                ControlFlow::Continue(()) => TerminationState::Interrupted(Instant::now()),
            },
            TerminationState::Interrupted(_) | TerminationState::Terminated => {
                TerminationState::Terminated
            }
        };
    }
}

impl<Os, Handler> VmiHandler<Os> for VmiTerminationHandler<Handler>
where
    Os: VmiOs,
    Handler: VmiHandler<Os>,
{
    type Output = Option<Handler::Output>;

    fn handle_event(&mut self, vmi: VmiContext<Os>) -> VmiEventResponse<Os::Architecture> {
        self.check_termination(&vmi);
        self.handler.handle_event(vmi)
    }

    fn handle_timeout(&mut self, session: &VmiSession<Os>) {
        self.check_termination(session);
        self.handler.handle_timeout(session);
    }

    fn handle_interrupted(&mut self, session: &VmiSession<Os>) -> ControlFlow<()> {
        self.interrupt(session);

        match self.state {
            TerminationState::Interrupted(_) => ControlFlow::Continue(()),
            TerminationState::Running | TerminationState::Terminated => ControlFlow::Break(()),
        }
    }

    fn cleanup(&mut self, session: &VmiSession<Os>) {
        self.handler.cleanup(session);
    }

    fn poll(&mut self) -> Option<Self::Output> {
        if let Some(output) = self.handler.poll() {
            return Some(Some(output));
        }

        match self.state {
            TerminationState::Running => None,
            TerminationState::Interrupted(interrupted_at) => {
                let termination_timeout = self.termination_timeout?;
                if interrupted_at.elapsed() < termination_timeout {
                    return None;
                }

                tracing::warn!("handler did not finish in time");
                Some(None)
            }
            TerminationState::Terminated => Some(None),
        }
    }
}
