use vmi_core::{VmiContext, VmiOs};

use super::{ArchAdapter, Bridge, BridgeHandler, BridgePacket, BridgeResponse};

/// A bridge dispatcher.
///
/// Dispatches request to the appropriate handler based on the request code.
pub trait BridgeDispatch<Os, T = ()>
where
    Os: VmiOs,
{
    /// Marker for an empty dispatcher.
    ///
    /// Set to `true` in the implementation for the `()` type.
    const EMPTY: bool = false;

    /// Dispatch the request.
    fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Os>,
        packet: BridgePacket,
    ) -> Option<Result<BridgeResponse<T>, BridgePacket>>;
}

/// No-op dispatcher that never handles any packet.
impl<Os, T> BridgeDispatch<Os, T> for ()
where
    Os: VmiOs,
{
    const EMPTY: bool = true;

    fn dispatch(
        &mut self,
        _vmi: &VmiContext<'_, Os>,
        _packet: BridgePacket,
    ) -> Option<Result<BridgeResponse<T>, BridgePacket>> {
        None
    }
}

/// Blanket impl that lets any single [`BridgeHandler`] be used as a dispatcher.
impl<Os, T, Handler> BridgeDispatch<Os, T> for Handler
where
    Os: VmiOs,
    Os::Architecture: ArchAdapter,
    Handler: BridgeHandler<Os, T>,
{
    fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Os>,
        packet: BridgePacket,
    ) -> Option<Result<BridgeResponse<T>, BridgePacket>> {
        try_dispatch(vmi, packet, self)
    }
}

/// Forwards dispatch to the wrapped handlers.
impl<Os, Dispatch, T> BridgeDispatch<Os, T> for Bridge<Os, Dispatch, T>
where
    Os: VmiOs,
    Os::Architecture: ArchAdapter,
    Dispatch: BridgeDispatch<Os, T>,
{
    fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Os>,
        packet: BridgePacket,
    ) -> Option<Result<BridgeResponse<T>, BridgePacket>> {
        self.handlers.dispatch(vmi, packet)
    }
}

/// Attempts to dispatch a packet to a single handler.
///
/// Returns `None` if the handler's magic or request code does not match.
/// Returns `Some(Ok(response))` if the handler produced a response.
/// Returns `Some(Err(packet))` if the handler matched but returned `None`.
fn try_dispatch<Os, T, Handler>(
    vmi: &VmiContext<'_, Os>,
    packet: BridgePacket,
    handler: &mut Handler,
) -> Option<Result<BridgeResponse<T>, BridgePacket>>
where
    Os: VmiOs,
    Os::Architecture: ArchAdapter,
    Handler: BridgeHandler<Os, T>,
{
    // Skip if the handler requires a specific magic and it doesn't match.
    if let Some(magic) = Handler::MAGIC
        && packet.magic() != magic
    {
        return None;
    }

    // Skip if the request code doesn't match this handler.
    if packet.request() != Handler::REQUEST {
        return None;
    }

    match handler.handle(vmi, packet) {
        Some(mut response) => {
            // Stamp verification values into the response so the guest
            // can confirm it is talking to the expected host handler.
            if let Some(value) = Handler::VERIFY_VALUE1 {
                response = response.with_value1(value);
            }
            if let Some(value) = Handler::VERIFY_VALUE2 {
                response = response.with_value2(value);
            }
            if let Some(value) = Handler::VERIFY_VALUE3 {
                response = response.with_value3(value);
            }
            if let Some(value) = Handler::VERIFY_VALUE4 {
                response = response.with_value4(value);
            }

            Some(Ok(response))
        }
        // Handler matched but produced no response.
        None => Some(Err(packet)),
    }
}

/// Implements [`BridgeDispatch`] for tuples of [`BridgeHandler`]s.
///
/// Handlers are tried in order; the first matching handler wins.
macro_rules! impl_bridge_dispatch {
    ($($ty:ident),*) => {
        #[allow(non_snake_case)]
        impl<Os, T, $($ty),*> BridgeDispatch<Os, T> for ($($ty),+,)
        where
            Os: VmiOs,
            Os::Architecture: ArchAdapter,
            $($ty: BridgeHandler<Os, T>,)+
        {
            fn dispatch(
                &mut self,
                vmi: &VmiContext<'_, Os>,
                packet: BridgePacket
            ) -> Option<Result<BridgeResponse<T>, BridgePacket>> {
                let ($($ty,)+) = self;

                $(
                    if let Some(result) = try_dispatch(vmi, packet, $ty) {
                        return Some(result);
                    }
                )*

                None
            }
        }
    };
}

impl_bridge_dispatch!(B1);
impl_bridge_dispatch!(B1, B2);
impl_bridge_dispatch!(B1, B2, B3);
impl_bridge_dispatch!(B1, B2, B3, B4);
impl_bridge_dispatch!(B1, B2, B3, B4, B5);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9, B10);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15);
impl_bridge_dispatch!(B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16);
