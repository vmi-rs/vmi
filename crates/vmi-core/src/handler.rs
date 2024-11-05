use crate::{VmiContext, VmiDriver, VmiEventResponse, VmiOs};

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
    /// Handles a VMI event.
    fn handle_event(
        &mut self,
        event: VmiContext<Driver, Os>,
    ) -> VmiEventResponse<Driver::Architecture>;

    /// Returns whether the handler has finished processing events.
    fn finished(&self) -> bool {
        false
    }
}
