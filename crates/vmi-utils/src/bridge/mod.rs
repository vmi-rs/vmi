//! Guest-host communication bridge for VMI.
//!
//! The bridge provides a structured IPC mechanism between code running
//! inside a guest VM (typically injected shellcode) and the host-side
//! VMI monitor. Communication happens through CPU registers: the guest
//! executes a VMCALL (or CPUID) instruction, the hypervisor delivers
//! the event to the monitor, which reads a [`BridgePacket`] from the
//! registers, dispatches it to the appropriate handler, and writes
//! the [`BridgeResponse`] back.
//!
//! # Traits
//!
//! - [`BridgeContract`] - static constants for magic matching and
//!   response verification.
//! - [`BridgeHandler`] - handles a single request code, identified by
//!   [`REQUEST`](BridgeHandler::REQUEST).
//! - [`BridgeDispatch`] - routes packets to the correct handler.
//!   Automatically implemented for individual handlers and tuples (of
//!   up to 16 handlers).
//!
//! # Usage
//!
//! Define a handler by implementing [`BridgeContract`] and
//! [`BridgeHandler`]:
//!
//! ```ignore
//! struct HelloBridge;
//!
//! impl BridgeContract for HelloBridge {
//!     const MAGIC: Option<u32> = Some(0x4b454b57);
//! }
//!
//! impl BridgeHandler<MyOs, MyResult> for HelloBridge {
//!     const REQUEST: u16 = 0x0000;
//!
//!     fn handle(
//!         &mut self,
//!         _vmi: &VmiContext<'_, MyOs>,
//!         packet: BridgePacket,
//!     ) -> Option<BridgeResponse<MyResult>> {
//!         Some(BridgeResponse::default())
//!     }
//! }
//! ```
//!
//! Compose multiple handlers into a [`Bridge`] via a tuple:
//!
//! ```ignore
//! let bridge = Bridge::new((
//!     HelloBridge::new(),
//!     FileTransferBridge::new(),
//!     EnvironmentBridge::new(),
//! ));
//! ```
//!
//! Then dispatch incoming events:
//!
//! ```ignore
//! if let Some(result) = bridge.dispatch(vmi) {
//!     match result {
//!         Ok(response) => {
//!             response.write_to(&mut registers);
//!             if let Some(result) = response.into_result() {
//!                 // Handler signaled completion.
//!             }
//!         }
//!         Err(packet) => {
//!             // Handler matched but returned no response.
//!         }
//!     }
//! }
//! ```

mod arch;
mod dispatch;
mod handler;
mod packet;
mod response;

use vmi_core::{VmiContext, VmiOs};

pub use self::{
    arch::ArchAdapter,
    dispatch::BridgeDispatch,
    handler::{BridgeContract, BridgeHandler},
    packet::BridgePacket,
    response::BridgeResponse,
};

/// Top-level bridge that reads packets from VMI events and dispatches
/// them to the registered handlers.
///
/// Wraps a [`BridgeDispatch`] implementation (a single handler, a tuple
/// of handlers, or `()` for no-op) and provides a convenience
/// [`dispatch`](Self::dispatch) method that reads a [`BridgePacket`]
/// from the current event's registers before routing it.
///
/// # Examples
///
/// ```ignore
/// // Compose multiple handlers:
/// let bridge = Bridge::new((
///     HelloBridge::new(),
///     FileTransferBridge::new(),
///     EnvironmentBridge::new(),
/// ));
///
/// // Or use a no-op bridge when no guest communication is needed:
/// let bridge = Bridge::<MyOs, ()>::default();
/// ```
pub struct Bridge<Os, Dispatch, T = ()>
where
    Os: VmiOs,
    Dispatch: BridgeDispatch<Os, T>,
{
    handlers: Dispatch,
    _phantom: std::marker::PhantomData<(Os, T)>,
}

impl<Os, Dispatch, T> Bridge<Os, Dispatch, T>
where
    Os: VmiOs,
    Dispatch: BridgeDispatch<Os, T>,
{
    /// Creates a new bridge with the given handlers.
    pub fn new(handlers: Dispatch) -> Self {
        Self {
            handlers,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Reads a [`BridgePacket`] from the current VMI event and dispatches
    /// it to the registered handlers.
    ///
    /// Returns:
    /// - `None` - no handler matched the packet's magic/request.
    /// - `Some(Ok(response))` - a handler produced a response.
    /// - `Some(Err(packet))` - a handler matched but returned no response
    ///   (typically an unrecognized method).
    pub fn dispatch(
        &mut self,
        vmi: &VmiContext<'_, Os>,
    ) -> Option<Result<BridgeResponse<T>, BridgePacket>>
    where
        Os::Architecture: ArchAdapter,
    {
        self.handlers.dispatch(vmi, BridgePacket::from(vmi))
    }
}

impl<Os, Dispatch, T> Default for Bridge<Os, Dispatch, T>
where
    Os: VmiOs,
    Dispatch: BridgeDispatch<Os, T> + Default,
{
    fn default() -> Self {
        Self::new(Dispatch::default())
    }
}
