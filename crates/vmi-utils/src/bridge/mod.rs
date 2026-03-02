//! Bridge utilities.

mod packet;
mod response;

use vmi_core::{VmiContext, VmiOs};

pub use self::{packet::BridgePacket, response::BridgeResponse};

/// A bridge dispatcher.
pub trait BridgeDispatch<Os, T = ()>
where
    Os: VmiOs,
{
    /// Dispatch the request.
    fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Os>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<T>>;
}

/// A bridge handler.
pub trait BridgeHandler<Os, T = ()>: BridgeDispatch<Os, T>
where
    Os: VmiOs,
{
    /// Marker for an empty handler.
    ///
    /// Set to `true` in the implementation for the `()` type.
    const EMPTY: bool = false;

    /// The magic number.
    const MAGIC: u32;

    /// The request code.
    const REQUEST: u16;

    /// The first verification value.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RAX`
    const VERIFY_VALUE1: Option<u64> = None;

    /// The second verification value.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RBX`
    const VERIFY_VALUE2: Option<u64> = None;

    /// The third verification value.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RCX`
    const VERIFY_VALUE3: Option<u64> = None;

    /// The fourth verification value.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RDX`
    const VERIFY_VALUE4: Option<u64> = None;
}

macro_rules! impl_bridge_dispatch {
    ($($ty:ident),*) => {
        #[allow(non_snake_case)]
        impl<Os, T, $($ty),*> BridgeDispatch<Os, T> for ($($ty),+,)
        where
            Os: VmiOs,
            $($ty: BridgeHandler<Os, T>,)+
        {
            fn dispatch(&mut self, vmi: &VmiContext<'_, Os>, packet: BridgePacket) -> Option<BridgeResponse<T>> {
                let ($($ty,)+) = self;

                $(
                    if packet.request() == <$ty as BridgeHandler<Os, T>>::REQUEST {
                        return $ty.dispatch(vmi, packet);
                    }
                )*

                None
            }
        }
    };
}

impl<Os, T> BridgeDispatch<Os, T> for ()
where
    Os: VmiOs,
{
    fn dispatch(
        &mut self,
        _vmi: &VmiContext<'_, Os>,
        _packet: BridgePacket,
    ) -> Option<BridgeResponse<T>> {
        None
    }
}

impl<Os, T> BridgeHandler<Os, T> for ()
where
    Os: VmiOs,
{
    const EMPTY: bool = true;
    const MAGIC: u32 = 0;
    const REQUEST: u16 = 0;
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
impl_bridge_dispatch!(
    B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15
);
impl_bridge_dispatch!(
    B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16
);

/// A bridge.
pub struct Bridge<Os, B, T = ()>
where
    Os: VmiOs,
    B: BridgeDispatch<Os, T>,
{
    handlers: B,
    _phantom: std::marker::PhantomData<(Os, T)>,
}

impl<Os, B, T> Bridge<Os, B, T>
where
    Os: VmiOs,
    B: BridgeDispatch<Os, T>,
{
    /// Creates a new bridge.
    pub fn new(handlers: B) -> Self {
        Self {
            handlers,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Os, B, T> BridgeDispatch<Os, T> for Bridge<Os, B, T>
where
    Os: VmiOs,
    B: BridgeDispatch<Os, T>,
{
    fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Os>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<T>> {
        self.handlers.dispatch(vmi, packet)
    }
}
