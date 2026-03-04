use vmi_core::{VmiContext, VmiOs};

use super::{BridgePacket, BridgeResponse};

/// Static contract for a bridge handler.
///
/// Defines optional matching and verification constants used by the
/// dispatch logic:
///
/// - [`MAGIC`](Self::MAGIC) filters incoming packets by magic number.
///   When `None`, the handler accepts packets regardless of magic.
/// - [`VERIFY_VALUE1`](Self::VERIFY_VALUE1)–[`VERIFY_VALUE4`](Self::VERIFY_VALUE4)
///   are written into the response registers after a successful
///   dispatch, allowing the guest to verify it is communicating with
///   the expected host handler.
pub trait BridgeContract {
    /// Magic number to match against incoming packets.
    ///
    /// When `None`, the magic check is skipped and the handler accepts
    /// packets with any magic value.
    const MAGIC: Option<u32> = None;

    /// First verification value written into the response.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RAX`
    const VERIFY_VALUE1: Option<u64> = None;

    /// Second verification value written into the response.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RBX`
    const VERIFY_VALUE2: Option<u64> = None;

    /// Third verification value written into the response.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RCX`
    const VERIFY_VALUE3: Option<u64> = None;

    /// Fourth verification value written into the response.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RDX`
    const VERIFY_VALUE4: Option<u64> = None;
}

/// A bridge handler for a specific request code.
///
/// Each handler is identified by its [`REQUEST`](Self::REQUEST) code and
/// optionally filtered by the [`MAGIC`](BridgeContract::MAGIC) from its
/// [`BridgeContract`]. Within a single request, handlers can further
/// distinguish sub-operations via [`BridgePacket::method()`].
///
/// The [`handle`](Self::handle) return value controls the dispatch outcome:
///
/// - `Some(response)` - request was handled; the response is written
///   back to guest registers.
/// - `None` - request code matched but no response was produced (e.g.,
///   an unrecognized method). The dispatcher treats this as an error.
pub trait BridgeHandler<Os, T = ()>: BridgeContract
where
    Os: VmiOs,
{
    /// The request code that this handler responds to.
    const REQUEST: u16;

    /// Handles a bridge request.
    ///
    /// The `packet` contains the magic, request, method, and up to four
    /// payload values extracted from guest registers.
    fn handle(
        &mut self,
        vmi: &VmiContext<'_, Os>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<T>>;
}
