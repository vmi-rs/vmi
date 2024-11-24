use crate::{VmiContext, VmiDriver, VmiEventResponse, VmiOs, VmiSession};

/// A trait for handling VMI events.
///
/// A factory that creates a handler implementing this trait is passed to
/// the [`VmiSession::handle`] method to handle VMI events.
///
/// [`VmiSession::handle`]: crate::VmiSession::handle
pub trait VmiHandler<Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The output type of the handler.
    type Output;

    /// Handles a VMI event.
    fn handle_event(
        &mut self,
        event: VmiContext<Driver, Os>,
    ) -> VmiEventResponse<Driver::Architecture>;

    /// Handles a timeout event.
    fn handle_timeout(&mut self, _session: &VmiSession<Driver, Os>) {}

    /// Handles an interrupted event.
    fn handle_interrupted(&mut self, _session: &VmiSession<Driver, Os>) {}

    /// Checks if the handler has completed.
    ///
    /// This method is called after each event is handled. If the handler
    /// has completed, this method should return the output of the handler.
    /// Otherwise, it should return `None`.
    fn check_completion(&self) -> Option<Self::Output> {
        None
    }
}
