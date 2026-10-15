//! libxpc and libdispatch observation points, located by symbol name.
//!
//! Names have one leading symbol underscore stripped, as the engine passes
//! them: the local `__xpc_connection_pack_message` arrives as
//! `_xpc_connection_pack_message` and the export `_xpc_connection_send_message`
//! as `xpc_connection_send_message`.

use super::IpcHook;

/// A user-space function whose entry is observed under each traced root.
pub(super) struct HookSpec {
    /// Symbol name with one leading underscore stripped.
    pub(super) name: &'static str,

    /// Semantic event reported by this observation point.
    pub(super) kind: IpcHook,
}

/// libxpc entry points.
pub(super) const XPC: &[HookSpec] = &[
    HookSpec {
        name: "xpc_connection_send_message",
        kind: IpcHook::Send,
    },
    HookSpec {
        name: "xpc_connection_send_message_with_reply",
        kind: IpcHook::SendWithReply,
    },
    HookSpec {
        name: "xpc_connection_send_message_with_reply_sync",
        kind: IpcHook::SendSync,
    },
    HookSpec {
        name: "_xpc_connection_pack_message",
        kind: IpcHook::Pack,
    },
    HookSpec {
        name: "_xpc_serializer_pack",
        kind: IpcHook::Serialize,
    },
    HookSpec {
        name: "_xpc_connection_unpack_message",
        kind: IpcHook::Unpack,
    },
    HookSpec {
        name: "xpc_receive_mach_msg",
        kind: IpcHook::Receive,
    },
    HookSpec {
        name: "_xpc_connection_call_event_handler",
        kind: IpcHook::Handler,
    },
    HookSpec {
        name: "_xpc_connection_reply_callout",
        kind: IpcHook::ReplyHandler,
    },
    HookSpec {
        name: "xpc_dictionary_create_reply",
        kind: IpcHook::CreateReply,
    },
    HookSpec {
        name: "xpc_connection_create_from_endpoint",
        kind: IpcHook::FromEndpoint,
    },
    HookSpec {
        // `_xpc_endpoint_copy_listener_port(port)` receives the endpoint's
        // port name and returns it (libxpc.dylib.i64 @0x18055d8e4)
        name: "_xpc_endpoint_copy_listener_port",
        kind: IpcHook::EndpointPort,
    },
    HookSpec {
        name: "_xpc_look_up_endpoint",
        kind: IpcHook::LookupEndpoint,
    },
    HookSpec {
        name: "xpc_connection_activate",
        kind: IpcHook::Activate,
    },
    HookSpec {
        name: "xpc_connection_resume",
        kind: IpcHook::Resume,
    },
    HookSpec {
        name: "_xpc_pipe_mach_msg",
        kind: IpcHook::PipeSend,
    },
    HookSpec {
        name: "_xpc_dictionary_dispose",
        kind: IpcHook::DictionaryDispose,
    },
    HookSpec {
        name: "_xpc_connection_dispose",
        kind: IpcHook::ConnectionDispose,
    },
];

/// libdispatch entry points.
///
/// Every continuation invocation, including those inlined into the lane and
/// workloop drains, reaches `_dispatch_client_callout(ctxt, func)`.
pub(super) const DISPATCH: &[HookSpec] = &[
    HookSpec {
        name: "dispatch_mach_msg_create",
        kind: IpcHook::DispatchCreate,
    },
    HookSpec {
        name: "_dispatch_mach_msg_dispose",
        kind: IpcHook::DispatchDispose,
    },
    HookSpec {
        name: "_dispatch_lane_push",
        kind: IpcHook::ContinuationPush,
    },
    HookSpec {
        name: "_dispatch_root_queue_push",
        kind: IpcHook::ContinuationPush,
    },
    HookSpec {
        name: "_dispatch_main_queue_push",
        kind: IpcHook::ContinuationPush,
    },
    HookSpec {
        name: "_dispatch_continuation_pop",
        kind: IpcHook::ContinuationPop,
    },
    HookSpec {
        name: "_dispatch_client_callout",
        kind: IpcHook::ContinuationCall,
    },
];
