//! Bridge utilities.

mod packet;
mod response;

use vmi_core::{VmiContext, VmiDriver, VmiOs};

pub use self::{packet::BridgePacket, response::BridgeResponse};

/// A bridge dispatcher.
pub trait BridgeDispatch<Driver, Os, T = ()>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Dispatch the request.
    fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Driver, Os>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<T>>;
}

/// A bridge handler.
pub trait BridgeHandler<Driver, Os, T = ()>: BridgeDispatch<Driver, Os, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
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
        impl<Driver, Os, T, $($ty),*> BridgeDispatch<Driver, Os, T> for ($($ty),+,)
        where
            Driver: VmiDriver,
            Os: VmiOs<Driver>,
            $($ty: BridgeHandler<Driver, Os, T>,)+
        {
            fn dispatch(&mut self, vmi: &VmiContext<'_, Driver, Os>, packet: BridgePacket) -> Option<BridgeResponse<T>> {
                let ($($ty,)+) = self;

                $(
                    if packet.request() == <$ty as BridgeHandler<Driver, Os, T>>::REQUEST {
                        return $ty.dispatch(vmi, packet);
                    }
                )*

                None
            }
        }
    };
}

impl<Driver, Os, T> BridgeDispatch<Driver, Os, T> for ()
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn dispatch(
        &mut self,
        _vmi: &VmiContext<'_, Driver, Os>,
        _packet: BridgePacket,
    ) -> Option<BridgeResponse<T>> {
        None
    }
}

impl<Driver, Os, T> BridgeHandler<Driver, Os, T> for ()
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
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
pub struct Bridge<Driver, Os, B, T = ()>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
    B: BridgeDispatch<Driver, Os, T>,
{
    handlers: B,
    _phantom: std::marker::PhantomData<(Driver, Os, T)>,
}

impl<Driver, Os, B, T> Bridge<Driver, Os, B, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
    B: BridgeDispatch<Driver, Os, T>,
{
    /// Creates a new bridge.
    pub fn new(handlers: B) -> Self {
        Self {
            handlers,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Driver, Os, B, T> BridgeDispatch<Driver, Os, T> for Bridge<Driver, Os, B, T>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
    B: BridgeDispatch<Driver, Os, T>,
{
    fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Driver, Os>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<T>> {
        self.handlers.dispatch(vmi, packet)
    }
}
