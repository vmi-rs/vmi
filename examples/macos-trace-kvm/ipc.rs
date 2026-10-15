//! XPC and Mach transport attribution.
//!
//! Cross-process joins use the same live kernel `ipc_kmsg` allocation observed
//! during copyin, send, copyout and user delivery. A Mach port name, message
//! ID, payload, timestamp or parent PID is never a cross-process identity.
//! Kernel entry points, argument positions and layouts come from the KDK DWARF
//! profile. libxpc and libdispatch entry points come from the images' symbol
//! tables, libdispatch object layouts from its published source, and object
//! arguments are checked against their runtime class. libxpc's private objects
//! are not read: payloads and sender audit tokens come from the bytes of the
//! Mach message. The backend must report process and thread exit, exec and
//! abandoned returns to retire lifetimes and execution scopes.

use std::collections::{HashMap, HashSet, VecDeque};

use vmi::{Pa, Va, VmiContext, VmiError, os::macos::MacOs};

use self::kernel::{
    Bits, COMPLEX, GUARDED_PORT_DESCRIPTOR, KernelTypes, LOCAL_SHIFT, OOL_PORTS_DESCRIPTOR,
    PORT_DESCRIPTOR, PSEUDO_RECEIVE, REMOTE_MASK,
};
pub use self::kernel::{KernelLayout, argument, enumerator};
use crate::{Driver, objc::ObjcRuntime, style::Palette, values::Values};

mod hooks;
mod kernel;

/// Maximum retained transport observations and local object associations.
const CAPACITY: usize = 16_384;
/// Maximum descriptors inspected in one message.
const DESCRIPTORS: u64 = 32;
/// Maximum individual rights inspected in an out-of-line port array.
const ARRAY_PORTS: u64 = 32;
/// The XPC Mach reply message ID verified in `_xpc_connection_pack_message`.
const REPLY_MESSAGE: u32 = 0x2000_0000;
/// libdispatch continuations store flags rather than a vtable pointer below
/// this value, libdispatch-1542.0.4 `src/queue_internal.h:1027`.
const CONTINUATION_FLAGS_LIMIT: u64 = 0x1000;
/// `dc_func` in `DISPATCH_CONTINUATION_HEADER`, after the flags, priority,
/// `do_next` and voucher words, libdispatch-1542.0.4
/// `src/queue_internal.h:1031-1046`.
const CONTINUATION_FUNCTION: u64 = 0x20;
/// `dc_ctxt`, the word after `dc_func`.
const CONTINUATION_CONTEXT: u64 = 0x28;
/// `dmsg_destructor` in `struct dispatch_mach_msg_s`, after the object header,
/// options, reply port, priority and voucher, libdispatch-1542.0.4
/// `src/mach_internal.h:68-83`. It is zero
/// (`DISPATCH_MACH_MSG_DESTRUCTOR_DEFAULT`) exactly when the message is
/// stored inline.
const MESSAGE_DESTRUCTOR: u64 = 0x48;
/// `dmsg_msg` or `dmsg_buf`, the header pointer or the inline header, after
/// `dmsg_size`.
const MESSAGE_STORAGE: u64 = 0x58;
/// `MACH_MSG_TRAILER_FORMAT_0`, xnu-12377.121.6 `osfmk/mach/message.h:716`.
const TRAILER_FORMAT: u32 = 0;
/// Sizes of the format 0 trailers that contain an audit token:
/// `mach_msg_audit_trailer_t`, `mach_msg_context_trailer_t` and
/// `mach_msg_mac_trailer_t` (message.h:784-810).
const AUDIT_TRAILER_SIZES: [u32; 3] = [52, 60, 68];
/// Offset of `msgh_audit` after the trailer type, size, sequence number and
/// security token (message.h:784-790).
const TRAILER_AUDIT: u64 = 20;

/// Backend-provided identity of one live process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessIdentity {
    /// Kernel task address, not the PID or a task-local Mach name.
    pub task: u64,
    /// Process ID for display and comparison with received audit metadata.
    pub pid: u32,
    /// User translation root active for this image lifetime.
    pub root: Pa,
}

/// Entry snapshot supplied by the breakpoint backend.
#[derive(Clone, Copy, Debug)]
pub struct HookContext {
    /// Live process identity resolved from the current kernel thread.
    pub process: ProcessIdentity,
    /// Kernel thread identity preserved across vCPU migration.
    pub thread: u64,
    /// Integer registers captured before replaying the hooked instruction.
    pub registers: [u64; 31],
    /// Stack pointer at the observation boundary.
    pub sp: u64,
    /// Address of the intercepted instruction.
    pub pc: u64,
}

/// A semantic observation point located by symbol name.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpcHook {
    /// Public one-way connection-send intent.
    Send,
    /// Public asynchronous request intent.
    SendWithReply,
    /// Public synchronous request and object-return boundary.
    SendSync,
    /// Connection dictionary to serializer association before consumption.
    Pack,
    /// General graph serialization, including pipe and bootstrap messages.
    Serialize,
    /// Connection dispatch message to decoded dictionary association.
    Unpack,
    /// General receive decoder with its output object in argument five.
    Receive,
    /// Real receiver event-handler execution boundary.
    Handler,
    /// Original serializer to asynchronous reply-handler execution boundary.
    ReplyHandler,
    /// Destructive incoming-dictionary to reply-dictionary transfer.
    CreateReply,
    /// Endpoint-to-connection relationship, not service execution.
    FromEndpoint,
    /// Endpoint port name read by `xpc_connection_create_from_endpoint`.
    EndpointPort,
    /// Named launchd endpoint acquisition with an output Mach name.
    LookupEndpoint,
    /// Connection activation intent, not a launch or received work.
    Activate,
    /// Connection resume intent, not a launch or received work.
    Resume,
    /// Pipe Mach transport submission and result.
    PipeSend,
    /// Dictionary object lifetime retirement.
    DictionaryDispose,
    /// Connection object lifetime retirement.
    ConnectionDispose,
    /// Dispatch message creation, including exact receive-buffer copies.
    DispatchCreate,
    /// Dispatch message object lifetime retirement.
    DispatchDispose,
    /// Explicit continuation enqueue with the continuation in X1.
    ContinuationPush,
    /// Explicit continuation execution with the continuation in X0.
    ContinuationPop,
    /// Client callout `_dispatch_client_callout(ctxt, func)`, reached by every
    /// continuation invocation including those inlined into queue drains.
    ContinuationCall,
    /// User message to fresh kernel-message allocation and rights conversion.
    KernelCopyin,
    /// Kernel send submission and its actual Mach transport result.
    KernelSend,
    /// Exact kernel-message dequeue and receiver rights conversion.
    KernelCopyout,
    /// Exact kernel-message to user receive-buffer delivery and result.
    KernelDeliver,
    /// Kernel-message allocation retirement before address reuse.
    KernelMessageFree,
    /// Receive-right destruction, invalidating endpoint relationships.
    KernelPortDestroy,
    /// Port allocation retirement before address reuse.
    KernelPortFree,
}

/// A breakpoint that the backend installs and replays without guest changes.
#[derive(Clone, Copy, Debug)]
pub struct HookRequest {
    /// Relocated kernel or slid user entry address.
    pub address: u64,
    /// Process translation root, or `None` for a global kernel observer hook.
    pub root: Option<Pa>,
    /// Observation delivered when this breakpoint executes.
    pub kind: IpcHook,
}

/// Output of one hook or lifecycle observation.
#[derive(Default)]
pub struct IpcObservation {
    /// State to pair with a same-thread dynamic return breakpoint.
    pub pending: Option<PendingIpc>,
    /// Additional observation breakpoints.
    pub hooks: Vec<HookRequest>,
    /// Distinct intent, transport, receive, execution or incomplete records.
    pub lines: Vec<String>,
    /// Authoritatively related live processes whose roots can be enabled.
    pub related: Vec<ProcessIdentity>,
}

/// Opaque state retained by the backend until return or abandonment.
pub struct PendingIpc {
    /// Process lifetime captured at entry.
    lifetime: u64,
    /// Thread identity captured at entry.
    thread: u64,
    /// Hook-specific entry snapshot.
    state: PendingState,
}

/// Hook-specific state without copied dictionaries or guest payload buffers.
enum PendingState {
    /// Public send intent and optional synchronous reply return.
    Intent {
        /// Exact public intent observation.
        event: u64,
        /// Whether this API returns a decoded reply object.
        synchronous: bool,
    },
    /// A packed serializer or raw graph header.
    Pack {
        /// Exact enclosing intent observation.
        event: u64,
        /// Original serializer argument for graph serialization.
        serializer: u64,
        /// Whether the return is a header rather than a serializer.
        graph: bool,
        /// Whether this frame established a private send intent.
        owns_intent: bool,
        /// Whether this frame prints the packed payload, false for a graph
        /// serialization inside a connection pack.
        payload: bool,
    },
    /// An incoming dispatch message and optional decoder output location.
    Decode {
        /// Exact received transport observation if available.
        event: Option<u64>,
        /// Output object pointer, or zero for direct object returns.
        output: u64,
        /// Dispatch allocation whose temporary receive association is retired.
        dispatch: u64,
        /// Payload decoded from the message before the decoder consumed it.
        payload: String,
        /// Sender audit token from the message trailer.
        audit: Option<[u32; 8]>,
    },
    /// Execution scope that must end at this exact callback return.
    Scope {
        /// Unique nested execution token.
        token: u64,
        /// Exact request, or a mask for unobserved nested work.
        event: Option<u64>,
    },
    /// Reply creation after the original metadata has been consumed.
    Reply {
        /// Original received request observation.
        event: Option<u64>,
    },
    /// Endpoint-to-connection construction, whose port name
    /// `_xpc_endpoint_copy_listener_port` reports during the call.
    Endpoint,
    /// Launchd endpoint lookup with its bounded service-name snapshot.
    Lookup {
        /// Output Mach name pointer captured before the routine executes.
        output: u64,
        /// Bounded escaped service name.
        service: String,
        /// Endpoint lookup flags, distinct from an activation result.
        flags: u64,
    },
    /// Mach pipe transport result.
    Pipe {
        /// Exact pipe or serialized graph observation.
        event: u64,
    },
    /// A dispatch message created from a raw buffer.
    Dispatch {
        /// Source buffer's exact transport observation.
        event: Option<u64>,
    },
    /// Kernel copyin and its original task-local header names.
    Copyin {
        /// Fresh kernel message allocation.
        kmsg: u64,
        /// Original destination name in the sender's IPC space.
        remote: u32,
        /// Original reply name in the sender's IPC space.
        local: u32,
        /// Exact packed user buffer observation if available.
        event: Option<u64>,
    },
    /// Kernel send with identity captured before another CPU can dequeue it.
    Send {
        /// Exact live kernel message observation.
        event: u64,
    },
    /// Kernel copyout with rights captured before conversion to local names.
    Copyout {
        /// Exact dequeued kernel allocation.
        kmsg: u64,
        /// Matched sender observation.
        event: u64,
        /// Original kernel header storage.
        header: u64,
        /// Original port allocations and converted field locations.
        rights: Vec<TransferredRight>,
    },
    /// Kernel user delivery with the pre-free receive buffer parameters.
    Deliver {
        /// Exact kernel allocation consumed by delivery.
        kmsg: u64,
        /// Matched sender observation.
        event: u64,
        /// Original user receive buffer base.
        address: u64,
        /// Original receive buffer capacity.
        size: u32,
        /// Kernel receive result structure surviving allocation retirement.
        result: u64,
        /// Verified receive placement options.
        options: u64,
    },
}

/// One process lifetime assigned locally and never inferred from PID reuse.
struct Process {
    /// Latest backend identity, updated only by explicit exec or registration.
    identity: ProcessIdentity,
    /// Monotonic lifetime distinguishing task-address reuse.
    lifetime: u64,
    /// libxpc and libdispatch entry points of this process's images.
    symbols: HashMap<&'static str, u64>,
    /// Entry points already requested for this root.
    installed: HashSet<&'static str>,
    /// Observed request whose scoped creation produced this process.
    launch: Option<u64>,
}

/// A transport observation retained independently of transient guest objects.
struct Message {
    /// Sender identity at the exact observed send boundary.
    sender: ProcessIdentity,
    /// Sender lifetime, distinct from a reused kernel task address.
    sender_lifetime: u64,
    /// Observed dictionary or graph object address.
    object: u64,
    /// Optional active request execution that explicitly delegated this send.
    parent: Option<u64>,
    /// Exact original request when this observation is a reply.
    reply_to: Option<u64>,
    /// Underlying destination allocation identity after successful copyin.
    destination: Option<Port>,
    /// Underlying reply endpoint allocation identity after successful copyin.
    reply_endpoint: Option<Port>,
    /// Actual kernel send result, not the public XPC API return value.
    transport: Option<u32>,
    /// Receiver process and lifetime observed on exact kernel copyout.
    receiver: Option<(ProcessIdentity, u64)>,
    /// Exact successful kernel-to-user delivery, required by nested decoder
    /// fallback.
    delivered: bool,
    /// Whether reply transport was observed on the original request.
    replied: bool,
}

/// Port allocation identity, invalidated by destruction and free observations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Port {
    /// PAC-stripped kernel port allocation address.
    object: u64,
    /// Monotonic allocation generation, never a task-local numerical name.
    generation: u64,
}

/// One converted right observed inside an exact delivered kernel message.
struct TransferredRight {
    /// Address of the converted kernel header or descriptor field.
    location: u64,
    /// Live underlying allocation identity before copyout consumes it.
    port: Port,
    /// Whether the converted field points to an out-of-line user name array.
    array_index: Option<u64>,
    /// Source of the transfer for output.
    source: &'static str,
    /// Kernel disposition before conversion, checked against Mach type enums.
    disposition: u8,
}

/// An explicitly observed callback execution scope.
struct Scope {
    /// Unique token that permits precise nested return and unwind cleanup.
    token: u64,
    /// Request or reply observation executing this callback.
    event: Option<u64>,
    /// Exact continuation when this scope already encloses its inline callout.
    continuation: Option<u64>,
}

/// A continuation enqueue association, including its immutable callout
/// snapshot.
struct Continuation {
    /// Request whose active callback enqueued this exact continuation.
    event: u64,
    /// `dc_func` when the continuation was enqueued.
    function: u64,
    /// `dc_ctxt` when the continuation was enqueued.
    context: u64,
}

/// Global authoritative IPC correlation with bounded local state.
#[derive(Default)]
pub struct IpcTracker {
    /// Kernel entry points and layouts from the kernel profile.
    kernel: KernelLayout,
    /// Kernel hooks already requested.
    installed_kernel: bool,
    /// Hooks whose arguments had an unexpected class, reported once.
    mismatched: HashSet<(IpcHook, usize)>,
    /// Current process lifetimes by kernel task address.
    processes: HashMap<u64, Process>,
    /// Monotonic identity source shared by messages, scopes and allocations.
    next: u64,
    /// Retained observations by their non-guest event IDs.
    messages: HashMap<u64, Message>,
    /// Insertion order for deterministic bounded eviction.
    order: VecDeque<u64>,
    /// User buffers joined to their exact packed or delivered messages.
    wire: HashMap<(u64, u64), u64>,
    /// Dispatch messages joined through serialization or observed buffer
    /// copies.
    dispatch: HashMap<(u64, u64), u64>,
    /// Serializers joined to public intent and asynchronous reply callbacks.
    serializers: HashMap<(u64, u64), u64>,
    /// Incoming and reply dictionaries joined through decoder/create-reply
    /// paths.
    dictionaries: HashMap<(u64, u64), u64>,
    /// Live exact kernel-message allocations joined during user copyin.
    kmsgs: HashMap<u64, u64>,
    /// Live port allocation identities, retired before address reuse.
    ports: HashMap<u64, Port>,
    /// Observed task-local name to live kernel allocation conversions.
    rights: HashMap<(u64, u32), Port>,
    /// Outstanding request identities indexed by their live reply endpoint.
    reply_endpoints: HashMap<Port, Vec<u64>>,
    /// Public send scopes for nesting pack and graph serializer observations.
    intents: HashMap<(u64, u64), Vec<u64>>,
    /// Active receiver/reply/explicit async execution scopes per thread
    /// lifetime.
    scopes: HashMap<(u64, u64), Vec<Scope>>,
    /// Exact queued continuation identities associated with active request
    /// work.
    continuations: HashMap<(u64, u64), Continuation>,
    /// Queued continuations by process lifetime, function and context.
    callouts: HashMap<(u64, u64, u64), u64>,
    /// Dispatch message created inside an active connection pack, zero until
    /// `dispatch_mach_msg_create` returns, by process lifetime and thread.
    created: HashMap<(u64, u64), u64>,
    /// Endpoint port names reported inside an active
    /// `xpc_connection_create_from_endpoint`, by process lifetime and thread.
    endpoints: HashMap<(u64, u64), Option<u32>>,
}

impl IpcTracker {
    /// Supplies the kernel entry points and layouts read from the kernel
    /// profile.
    pub fn configure_kernel(&mut self, layout: KernelLayout) {
        self.kernel = layout;
    }

    /// Registers an initially traced process or an authoritatively related
    /// root.
    pub fn enable_process(&mut self, identity: ProcessIdentity) {
        self.process_lifetime(identity);
    }

    /// Records a libxpc or libdispatch entry point and reports whether it was
    /// consumed.
    ///
    /// `name` has one leading symbol underscore stripped.
    pub fn configure_process_symbol(
        &mut self,
        identity: ProcessIdentity,
        name: &str,
        address: u64,
    ) -> bool {
        let name = match hooks::DISPATCH
            .iter()
            .chain(hooks::XPC)
            .map(|spec| spec.name)
            .find(|candidate| *candidate == name)
        {
            Some(name) => name,
            None => return false,
        };
        self.enable_process(identity);
        if let Some(process) = self.processes.get_mut(&identity.task) {
            process.symbols.entry(name).or_insert(address);
        }
        true
    }

    /// Requests the kernel observer hooks once.
    pub fn kernel_hooks(&mut self) -> IpcObservation {
        let mut observation = IpcObservation::default();
        if self.installed_kernel {
            return observation;
        }
        self.installed_kernel = true;
        observation
            .hooks
            .extend(self.kernel.hooks.iter().map(|hook| HookRequest {
                address: hook.address,
                root: None,
                kind: hook.kind,
            }));
        observation
    }

    /// Requests the libxpc and libdispatch hooks under this process's own root.
    ///
    /// Each entry point is requested once; a missing symbol is reported once.
    pub fn process_hooks(&mut self, identity: ProcessIdentity) -> IpcObservation {
        self.enable_process(identity);
        let mut observation = IpcObservation::default();
        let process = match self.processes.get_mut(&identity.task) {
            Some(process) => process,
            None => return observation,
        };
        for spec in hooks::DISPATCH.iter().chain(hooks::XPC) {
            if !process.installed.insert(spec.name) {
                continue;
            }
            match process.symbols.get(spec.name) {
                Some(&address) => observation.hooks.push(HookRequest {
                    address,
                    root: Some(identity.root),
                    kind: spec.kind,
                }),
                None => observation.lines.push(format!(
                    "ipc incomplete: missing symbol {} in pid={}",
                    spec.name, identity.pid
                )),
            }
        }
        observation
    }

    /// Checks the runtime class of hook arguments, reporting a mismatch once.
    fn arguments_match(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        kind: IpcHook,
        registers: &[u64; 31],
        decode: &mut Option<(&mut Values, &mut ObjcRuntime, &Palette)>,
        observation: &mut IpcObservation,
    ) -> Result<bool, VmiError> {
        for &(index, classes) in argument_classes(kind) {
            if class_is(vmi, registers[index], classes, decode)? {
                continue;
            }
            if self.mismatched.insert((kind, index)) {
                observation.lines.push(format!(
                    "ipc incomplete: {kind:?} argument {index} is not {}, observation skipped",
                    classes.join(" or ")
                ));
            }
            return Ok(false);
        }
        Ok(true)
    }

    /// Reads the argument registers of a kernel hook.
    fn kernel_arguments(&self, kind: IpcHook, registers: &[u64; 31]) -> [u64; 4] {
        match self.kernel.hooks.iter().find(|hook| hook.kind == kind) {
            Some(hook) => hook.arguments.map(|index| registers[index]),
            None => [0; 4],
        }
    }

    /// Captures an entry without running guest code or claiming API intent is
    /// delivery.
    pub fn entry(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        context: HookContext,
        kind: IpcHook,
        mut decode: Option<(&mut Values, &mut ObjcRuntime, &Palette)>,
    ) -> Result<IpcObservation, VmiError> {
        let lifetime = self.process_lifetime(context.process);
        let r = &context.registers;
        let key = (lifetime, context.thread);
        let k = self.kernel_arguments(kind, r);
        let result: Result<IpcObservation, VmiError> = (|| {
            let mut observation = IpcObservation::default();
            if !self.arguments_match(vmi, kind, r, &mut decode, &mut observation)? {
                return Ok(observation);
            }
            let mut state = None;
            match kind {
                IpcHook::Send | IpcHook::SendWithReply | IpcHook::SendSync => {
                    let reply_to =
                        self.dictionaries
                            .get(&(lifetime, r[1]))
                            .copied()
                            .filter(|event| {
                                self.messages
                                    .get(event)
                                    .is_some_and(|message| message.receiver.is_some())
                            });
                    let event = self.new_message(&context, r[1], reply_to, &mut observation);
                    self.intents.entry(key).or_default().push(event);
                    observation.lines.push(format!("ipc #{event} send-intent pid={} connection={:#x} object={:#x} parent={:?} reply-to={reply_to:?}", context.process.pid, r[0], r[1], self.messages[&event].parent));
                    state = Some(PendingState::Intent {
                        event,
                        synchronous: kind == IpcHook::SendSync,
                    });
                }
                IpcHook::Pack | IpcHook::Serialize => {
                    let existing = self
                        .intents
                        .get(&key)
                        .and_then(|stack| stack.last())
                        .copied();
                    let event = match existing {
                        Some(event) => event,
                        None => {
                            let reply_to = self.dictionaries.get(&(lifetime, r[1])).copied();
                            let event =
                                self.new_message(&context, r[1], reply_to, &mut observation);
                            self.intents.entry(key).or_default().push(event);
                            observation.lines.push(format!(
                                "ipc #{event} serialize-intent pid={} object={:#x}",
                                context.process.pid, r[1]
                            ));
                            event
                        }
                    };
                    let payload = kind == IpcHook::Pack || !self.created.contains_key(&key);
                    if kind == IpcHook::Pack {
                        self.created.insert(key, 0);
                    }
                    state = Some(PendingState::Pack {
                        event,
                        serializer: if kind == IpcHook::Serialize { r[0] } else { 0 },
                        graph: kind == IpcHook::Serialize,
                        owns_intent: existing.is_none(),
                        payload,
                    });
                }
                IpcHook::Unpack | IpcHook::Receive => {
                    let dm = if kind == IpcHook::Unpack { r[1] } else { r[0] };
                    let header = dispatch_header(vmi, dm)?;
                    let event = self.consume_received(lifetime, dm, header, &mut observation);
                    if event.is_none() {
                        observation.lines.push(format!("ipc receive-incomplete pid={} dispatch={dm:#x}: transport identity unobserved", context.process.pid));
                    }
                    state = Some(PendingState::Decode {
                        event,
                        output: if kind == IpcHook::Receive { r[4] } else { 0 },
                        dispatch: dm,
                        payload: message_payload(vmi, header, &mut decode),
                        audit: trailer_audit(vmi, header)?,
                    });
                }
                IpcHook::Handler | IpcHook::ReplyHandler => {
                    let event = self.dictionaries.get(&(lifetime, r[1])).copied();
                    if let Some(event) = event {
                        let original = if kind == IpcHook::ReplyHandler {
                            self.serializers.get(&(lifetime, r[0])).copied()
                        }
                        else {
                            None
                        };
                        observation.lines.push(format!(
                            "ipc #{event} {}-begin pid={} object={:#x} request={original:?}",
                            if kind == IpcHook::Handler {
                                "handler"
                            }
                            else {
                                "reply-handler"
                            },
                            context.process.pid,
                            r[1]
                        ));
                        if kind == IpcHook::ReplyHandler
                            && let Some(original) = original
                            && self
                                .messages
                                .get(&event)
                                .is_none_or(|message| message.reply_to != Some(original))
                        {
                            observation.lines.push(format!("ipc #{event} incomplete: reply serializer does not match observed reply transport #{original}"));
                        }
                        state = Some(self.begin_scope(key, Some(event), None, &mut observation));
                    }
                    else {
                        observation.lines.push(format!(
                            "ipc {}-incomplete pid={} object={:#x}: decoded transport unobserved",
                            if kind == IpcHook::Handler {
                                "handler"
                            }
                            else {
                                "reply-handler"
                            },
                            context.process.pid,
                            r[1]
                        ));
                        state = Some(self.begin_scope(key, None, None, &mut observation));
                    }
                }
                IpcHook::CreateReply => {
                    state = Some(PendingState::Reply {
                        event: self.dictionaries.get(&(lifetime, r[0])).copied(),
                    });
                }
                IpcHook::FromEndpoint => {
                    self.endpoints.insert(key, None);
                    state = Some(PendingState::Endpoint);
                }
                IpcHook::EndpointPort => {
                    if let Some(port) = self.endpoints.get_mut(&key) {
                        *port = Some(r[0] as u32);
                    }
                }
                IpcHook::LookupEndpoint => {
                    state = Some(PendingState::Lookup {
                        output: r[7],
                        service: bounded_name(vmi, r[0])?,
                        flags: r[5],
                    });
                }
                IpcHook::Activate | IpcHook::Resume => {
                    observation.lines.push(format!(
                        "ipc endpoint-{} pid={} connection={:#x} execution=unobserved",
                        if kind == IpcHook::Activate {
                            "activation-intent"
                        }
                        else {
                            "resume-intent"
                        },
                        context.process.pid,
                        r[0]
                    ));
                }
                IpcHook::PipeSend => {
                    let event = match self
                        .serializers
                        .get(&(lifetime, r[0]))
                        .copied()
                        .or(self.wire.get(&(lifetime, r[1])).copied())
                    {
                        Some(event) => event,
                        None => self.new_message(&context, 0, None, &mut observation),
                    };
                    self.insert_wire(lifetime, r[1], event, &mut observation);
                    observation.lines.push(format!(
                        "ipc #{event} pipe-submit pid={} header={:#x} options={:#x}",
                        context.process.pid, r[1], r[2]
                    ));
                    state = Some(PendingState::Pipe { event });
                }
                IpcHook::DictionaryDispose => {
                    self.dictionaries.remove(&(lifetime, r[0]));
                }
                IpcHook::ConnectionDispose => {
                    observation.lines.push(format!(
                        "ipc connection-retired pid={} object={:#x}",
                        context.process.pid, r[0]
                    ));
                }
                IpcHook::DispatchCreate => {
                    state = Some(PendingState::Dispatch {
                        event: self.wire.get(&(lifetime, r[0])).copied(),
                    });
                }
                IpcHook::DispatchDispose => {
                    self.dispatch.remove(&(lifetime, r[0]));
                    let header = dispatch_header(vmi, r[0])?;
                    self.wire.remove(&(lifetime, header));
                }
                IpcHook::ContinuationPush => {
                    if let Some(event) = self.active(key) {
                        if r[1] != 0 && vmi.read_u64(Va(r[1]))? < CONTINUATION_FLAGS_LIMIT {
                            let continuation = Continuation {
                                event,
                                function: user_pointer(
                                    vmi.read_u64(Va(r[1] + CONTINUATION_FUNCTION))?,
                                ),
                                context: vmi.read_u64(Va(r[1] + CONTINUATION_CONTEXT))?,
                            };
                            if self.continuations.len() >= CAPACITY
                                && !self.continuations.contains_key(&(lifetime, r[1]))
                            {
                                observation.lines.push(format!(
                                    "ipc #{event} incomplete: continuation capacity reached"
                                ));
                            }
                            else {
                                self.insert_continuation(lifetime, r[1], continuation);
                                observation.lines.push(format!("ipc #{event} async-enqueue pid={} continuation={:#x} queue={:#x}", context.process.pid, r[1], r[0]));
                            }
                        }
                    }
                    else if let Some(previous) = self.remove_continuation(lifetime, r[1]) {
                        observation.lines.push(format!("ipc #{} async-incomplete: continuation re-enqueued outside observed execution", previous.event));
                    }
                }
                IpcHook::ContinuationPop => {
                    let dc = r[0];
                    if let Some(continuation) = self.remove_continuation(lifetime, dc) {
                        let function = user_pointer(vmi.read_u64(Va(dc + CONTINUATION_FUNCTION))?);
                        let argument = vmi.read_u64(Va(dc + CONTINUATION_CONTEXT))?;
                        if function == continuation.function && argument == continuation.context {
                            observation.lines.push(format!(
                                "ipc #{} async-begin pid={} continuation={dc:#x}",
                                continuation.event, context.process.pid
                            ));
                            state = Some(self.begin_scope(
                                key,
                                Some(continuation.event),
                                Some(dc),
                                &mut observation,
                            ));
                        }
                        else {
                            observation.lines.push(format!("ipc #{} async-incomplete: continuation {dc:#x} changed before invocation", continuation.event));
                            state = Some(self.begin_scope(key, None, Some(dc), &mut observation));
                        }
                    }
                    else if self.active(key).is_some()
                        && !self
                            .scopes
                            .get(&key)
                            .and_then(|scopes| scopes.last())
                            .is_some_and(|scope| scope.continuation == Some(dc))
                    {
                        state = Some(self.begin_scope(key, None, Some(dc), &mut observation));
                    }
                }
                IpcHook::ContinuationCall => {
                    let (argument, function) = (r[0], user_pointer(r[1]));
                    if let Some(&dc) = self.callouts.get(&(lifetime, function, argument))
                        && let Some(continuation) = self.remove_continuation(lifetime, dc)
                    {
                        observation.lines.push(format!(
                            "ipc #{} async-begin pid={} continuation={dc:#x}",
                            continuation.event, context.process.pid
                        ));
                        state = Some(self.begin_scope(
                            key,
                            Some(continuation.event),
                            Some(dc),
                            &mut observation,
                        ));
                    }
                }
                IpcHook::KernelCopyin => {
                    let (kmsg, context_address) = (k[0], k[1]);
                    let types = match self.kernel.types {
                        Some(types) => types,
                        None => return Ok(observation),
                    };
                    let wire = vmi.read_u64(Va(context_address + types.send_message))?;
                    let remote = vmi.read_u32(Va(context_address + types.send_remote))?;
                    let local = vmi.read_u32(Va(context_address + types.send_local))?;
                    let event = self.wire.get(&(lifetime, wire)).copied();
                    if event.is_some() {
                        self.wire.remove(&(lifetime, wire));
                    }
                    if let Some(previous) = self.kmsgs.remove(&kmsg) {
                        observation.lines.push(format!("ipc #{previous} incomplete: kernel message allocation reused before observed retirement"));
                    }
                    let reply = self
                        .rights
                        .get(&(lifetime, remote))
                        .copied()
                        .and_then(|port| self.reply_request(port, lifetime));
                    if event.is_some() || reply.is_some() {
                        state = Some(PendingState::Copyin {
                            kmsg,
                            remote,
                            local,
                            event,
                        });
                    }
                }
                IpcHook::KernelSend => {
                    let kmsg = k[0];
                    if let Some(event) = self.kmsgs.get(&kmsg).copied() {
                        state = Some(PendingState::Send { event });
                        observation.lines.push(format!(
                            "ipc #{event} transport-submit pid={} kmsg={kmsg:#x}",
                            context.process.pid
                        ));
                    }
                }
                IpcHook::KernelCopyout => {
                    let kmsg = k[0];
                    if let Some(event) = self.kmsgs.get(&kmsg).copied()
                        && let Some(types) = self.kernel.types
                    {
                        let header = kernel_header(vmi, &types, kmsg)?;
                        let rights = self.snapshot_rights(vmi, &types, header, &mut observation)?;
                        if let Some(message) = self.messages.get_mut(&event) {
                            message.receiver = Some((context.process, lifetime));
                        }
                        observation.related.push(context.process);
                        observation.lines.push(format!(
                            "ipc #{event} receiver-dequeue pid={} kmsg={kmsg:#x} execution=unobserved",
                            context.process.pid
                        ));
                        state = Some(PendingState::Copyout {
                            kmsg,
                            event,
                            header,
                            rights,
                        });
                    }
                }
                IpcHook::KernelDeliver => {
                    let (kmsg, buffers, result, options) = (k[0], k[1], k[2], k[3]);
                    if let Some(event) = self.kmsgs.get(&kmsg).copied()
                        && let Some(types) = self.kernel.types
                    {
                        if vmi.read_u32(Va(result + types.result_name))? == PSEUDO_RECEIVE {
                            observation.lines.push(format!(
                                "ipc #{event} returned-to-sender pid={} kmsg={kmsg:#x}: send failed, pseudo-receive is not a delivery",
                                context.process.pid
                            ));
                        }
                        else {
                            state = Some(PendingState::Deliver {
                                kmsg,
                                event,
                                address: vmi.read_u64(Va(buffers + types.receive_address))?,
                                size: vmi.read_u32(Va(buffers + types.receive_size))?,
                                result,
                                options,
                            });
                        }
                    }
                }
                IpcHook::KernelMessageFree => {
                    let kmsg = k[0];
                    if self.kmsgs.contains_key(&kmsg)
                        && let Some(types) = self.kernel.types
                    {
                        if kept_alive(
                            &types,
                            read_bits(vmi, kmsg, types.kmsg_type)?,
                            read_bits(vmi, kmsg, types.keep_alive)?,
                        ) {
                            observation.lines.push(format!(
                                "ipc #{} kernel-message-kept-alive kmsg={kmsg:#x}",
                                self.kmsgs[&kmsg]
                            ));
                        }
                        else if let Some(event) = self.kmsgs.remove(&kmsg) {
                            observation.lines.push(format!(
                                "ipc #{event} kernel-message-retired kmsg={kmsg:#x}"
                            ));
                        }
                    }
                }
                IpcHook::KernelPortDestroy | IpcHook::KernelPortFree => {
                    let object = kernel_pointer(k[0]);
                    if let Some(port) = self.ports.remove(&object) {
                        self.rights.retain(|_, value| *value != port);
                        self.reply_endpoints.remove(&port);
                        observation.lines.push(format!(
                            "ipc endpoint-retired object={:#x} generation={} reason={kind:?}",
                            port.object, port.generation
                        ));
                    }
                }
            }
            if let Some(state) = state {
                observation.pending = Some(PendingIpc {
                    lifetime,
                    thread: context.thread,
                    state,
                });
            }
            Ok(observation)
        })();
        if result.is_err() {
            self.scopes.remove(&key);
            self.intents.remove(&key);
        }
        result
    }

    /// Completes one exact entry/return pair before the caller resumes
    /// execution.
    pub fn returned(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        context: HookContext,
        pending: PendingIpc,
        raw: u64,
        mut decode: Option<(&mut Values, &mut ObjcRuntime, &Palette)>,
    ) -> Result<IpcObservation, VmiError> {
        let mut observation = IpcObservation::default();
        if self
            .processes
            .get(&context.process.task)
            .is_none_or(|process| {
                process.lifetime != pending.lifetime || process.identity != context.process
            })
            || context.thread != pending.thread
        {
            return Ok(self.abandoned(context, pending, "process/thread lifetime changed"));
        }
        let lifetime = pending.lifetime;
        let key = (lifetime, pending.thread);
        let result: Result<IpcObservation, VmiError> = (|| {
            match pending.state {
                PendingState::Intent { event, synchronous } => {
                    self.remove_intent(key, event);
                    if synchronous {
                        let observed = self.dictionaries.get(&(lifetime, raw)).copied();
                        observation.lines.push(format!(
                            "ipc #{event} sync-return object={raw:#x} observed-reply={observed:?}"
                        ));
                        if observed.and_then(|reply| {
                            self.messages
                                .get(&reply)
                                .and_then(|message| message.reply_to)
                        }) != Some(event)
                        {
                            observation.lines.push(format!("ipc #{event} incomplete: synchronous result has no matching observed reply transport"));
                        }
                    }
                }
                PendingState::Pack {
                    event,
                    serializer,
                    graph,
                    owns_intent,
                    payload,
                } => {
                    if owns_intent {
                        self.remove_intent(key, event);
                    }
                    // A graph serialization inside a connection pack sees the
                    // message the pack has created so far without consuming it
                    let created = if graph {
                        self.created.get(&key).copied()
                    }
                    else {
                        self.created.remove(&key)
                    }
                    .filter(|dm| *dm != 0);
                    if raw != 0 {
                        let serializer = if graph { serializer } else { raw };
                        let wire = match (graph, created) {
                            (true, _) => Some(raw),
                            (false, Some(dm)) => Some(dispatch_header(vmi, dm)?),
                            (false, None) => {
                                observation.lines.push(format!("ipc #{event} incomplete: no dispatch_mach_msg_create observed inside pack"));
                                None
                            }
                        };
                        if let Some(wire) = wire {
                            self.insert_wire(lifetime, wire, event, &mut observation);
                        }
                        self.insert_association(
                            Association::Serializer,
                            lifetime,
                            serializer,
                            event,
                            &mut observation,
                        );
                        if let Some(dm) = created {
                            self.insert_association(
                                Association::Dispatch,
                                lifetime,
                                dm,
                                event,
                                &mut observation,
                            );
                        }
                        let mut line = format!(
                            "ipc #{event} packed serializer={serializer:#x} dispatch={} header={}",
                            hex(created),
                            hex(wire)
                        );
                        if payload && let Some(wire) = wire {
                            line.push_str(" payload=");
                            line.push_str(&message_payload(vmi, wire, &mut decode));
                        }
                        observation.lines.push(line);
                    }
                }
                PendingState::Decode {
                    event,
                    output,
                    dispatch,
                    payload,
                    audit,
                } => {
                    if let Some(event) = event
                        && self.dispatch.get(&(lifetime, dispatch)) == Some(&event)
                    {
                        self.dispatch.remove(&(lifetime, dispatch));
                    }
                    let object = if output != 0 && raw as u32 == 0 {
                        vmi.read_u64(Va(output))?
                    }
                    else if output == 0 {
                        raw
                    }
                    else {
                        0
                    };
                    if object != 0 {
                        if let Some(event) = event {
                            let mut audit_matches = true;
                            if let Some(audit) = audit
                                && let Some(message) = self.messages.get(&event)
                            {
                                observation.lines.push(format!("ipc #{event} sender-audit token={audit:?} transport-sender-pid={} audit-pid={} pidversion={}", message.sender.pid, audit[5], audit[7]));
                                audit_matches = audit[5] == message.sender.pid;
                            }
                            if audit_matches {
                                self.insert_association(
                                    Association::Dictionary,
                                    lifetime,
                                    object,
                                    event,
                                    &mut observation,
                                );
                                observation.lines.push(format!(
                                    "ipc #{event} decoded pid={} object={object:#x} payload={payload}",
                                    context.process.pid
                                ));
                            }
                            else {
                                self.dictionaries.remove(&(lifetime, object));
                                observation.lines.push(format!("ipc #{event} incomplete: audit sender differs from observed kernel sender, execution propagation disabled"));
                            }
                        }
                        else {
                            observation.lines.push(format!(
                                "ipc decoded-incomplete pid={} object={object:#x} payload={payload}",
                                context.process.pid
                            ));
                        }
                    }
                }
                PendingState::Scope { token, event } => {
                    let ended = self.end_scope(key, token);
                    observation.lines.push(format!(
                        "ipc execution-{} request={event:?} pid={} thread={:#x}",
                        if ended {
                            "end"
                        }
                        else {
                            "incomplete-scope-retired"
                        },
                        context.process.pid,
                        pending.thread
                    ));
                }
                PendingState::Reply { event } => {
                    if let Some(event) = event {
                        if raw != 0 {
                            self.insert_association(
                                Association::Dictionary,
                                lifetime,
                                raw,
                                event,
                                &mut observation,
                            );
                            observation.lines.push(format!(
                                "ipc #{event} reply-created pid={} object={raw:#x}",
                                context.process.pid
                            ));
                        }
                        else {
                            observation.lines.push(format!(
                                "ipc #{event} reply-unavailable: create_reply returned null"
                            ));
                        }
                    }
                    else if raw != 0 {
                        observation.lines.push(format!("ipc reply-incomplete pid={} object={raw:#x}: original request unobserved", context.process.pid));
                    }
                }
                PendingState::Endpoint => {
                    let port = self.endpoints.remove(&key).flatten();
                    observation.lines.push(format!("ipc endpoint-connection pid={} port={port:?} connection={raw:#x} kernel-endpoint={:?} execution=unobserved", context.process.pid, port.and_then(|name| self.rights.get(&(lifetime, name)).copied())));
                }
                PendingState::Lookup {
                    output,
                    service,
                    flags,
                } => {
                    let port = if raw as u32 == 0 && output != 0 {
                        Some(vmi.read_u32(Va(output))?)
                    }
                    else {
                        None
                    };
                    observation.lines.push(format!("ipc launchd-endpoint-acquisition pid={} service={service} flags={flags:#x} result={:#x} port={port:?} kernel-endpoint={:?} execution=unobserved", context.process.pid, raw as u32, port.and_then(|name| self.rights.get(&(lifetime, name)).copied())));
                }
                PendingState::Pipe { event } => {
                    observation.lines.push(format!(
                        "ipc #{event} pipe-result={:#x} receiver-execution=separate",
                        raw as u32
                    ));
                }
                PendingState::Dispatch { event } => {
                    if raw != 0 {
                        if let Some(created) = self.created.get_mut(&key) {
                            *created = raw;
                        }
                        if let Some(event) = event {
                            self.insert_association(
                                Association::Dispatch,
                                lifetime,
                                raw,
                                event,
                                &mut observation,
                            );
                            let header = dispatch_header(vmi, raw)?;
                            self.insert_wire(lifetime, header, event, &mut observation);
                        }
                    }
                }
                PendingState::Copyin {
                    kmsg,
                    remote,
                    local,
                    event,
                } => {
                    if raw as u32 == 0
                        && let Some(types) = self.kernel.types
                    {
                        let header = kernel_header(vmi, &types, kmsg)?;
                        let destination_object =
                            kernel_pointer(vmi.read_u64(Va(header + types.header_remote))?);
                        let reply_object =
                            kernel_pointer(vmi.read_u64(Va(header + types.header_local))?);
                        let destination = self.port(destination_object);
                        let reply = self.port(reply_object);
                        let msgid = vmi.read_u32(Va(header + types.header_id))?;
                        let inferred_reply = if msgid == REPLY_MESSAGE {
                            destination.and_then(|port| self.reply_request(port, lifetime))
                        }
                        else {
                            None
                        };
                        let event = match event {
                            Some(event) => Some(event),
                            None => inferred_reply.map(|request| {
                                self.new_message(&context, 0, Some(request), &mut observation)
                            }),
                        };
                        if let Some(event) = event {
                            let original = self
                                .messages
                                .get(&event)
                                .and_then(|message| message.reply_to);
                            let reply_matches = match original {
                                Some(request) => {
                                    self.messages.get(&request).is_some_and(|message| {
                                        message.reply_endpoint == destination
                                            && destination.is_some()
                                            && message
                                                .receiver
                                                .is_some_and(|(_, receiver)| receiver == lifetime)
                                    })
                                }
                                None => true,
                            };
                            if !reply_matches {
                                observation.lines.push(format!("ipc #{event} incomplete: reply dictionary lineage differs from live transport endpoint"));
                            }
                            if let Some(message) = self.messages.get_mut(&event) {
                                message.destination = destination;
                                message.reply_endpoint = reply;
                                if !reply_matches {
                                    message.reply_to = None;
                                }
                                else if message.reply_to.is_none() {
                                    message.reply_to = inferred_reply;
                                }
                            }
                            if let Some(port) = destination {
                                self.insert_right(lifetime, remote, port, event, &mut observation);
                            }
                            if let Some(port) = reply {
                                self.insert_right(lifetime, local, port, event, &mut observation);
                            }
                            if let Some(port) = reply {
                                let requests = self.reply_endpoints.entry(port).or_default();
                                if !requests.contains(&event) {
                                    requests.push(event);
                                }
                            }
                            self.kmsgs.insert(kmsg, event);
                            observation.lines.push(format!("ipc #{event} kernel-copyin pid={} kmsg={kmsg:#x} endpoint={destination:?} reply-endpoint={reply:?}", context.process.pid));
                        }
                    }
                    else if let Some(event) = event {
                        observation.lines.push(format!(
                            "ipc #{event} copyin-failed result={:#x}",
                            raw as u32
                        ));
                    }
                }
                PendingState::Send { event } => {
                    if let Some(message) = self.messages.get_mut(&event) {
                        message.transport = Some(raw as u32);
                    }
                    observation.lines.push(format!(
                        "ipc #{event} transport-result={:#x} receiver-execution=separate",
                        raw as u32
                    ));
                }
                PendingState::Copyout {
                    kmsg,
                    event,
                    header,
                    rights,
                } => {
                    if raw as u32 == 0 {
                        for right in rights {
                            let name = match right.array_index {
                                Some(index) => {
                                    let array = vmi.read_u64(Va(right.location))?;
                                    vmi.read_u32(Va(array + index * 4))?
                                }
                                None => vmi.read_u32(Va(right.location))?,
                            };
                            if name != 0 && name != u32::MAX {
                                self.insert_right(
                                    lifetime,
                                    name,
                                    right.port,
                                    event,
                                    &mut observation,
                                );
                                observation.lines.push(format!("ipc #{event} endpoint-transfer pid={} name={name:#x} endpoint={:?} source={} disposition={}", context.process.pid, right.port, right.source, self.kernel.disposition(u64::from(right.disposition))));
                            }
                        }
                        observation.lines.push(format!("ipc #{event} receiver-copyout pid={} kmsg={kmsg:#x} header={header:#x}", context.process.pid));
                    }
                    else {
                        observation.lines.push(format!(
                            "ipc #{event} receive-copyout-failed result={:#x}",
                            raw as u32
                        ));
                    }
                }
                PendingState::Deliver {
                    kmsg,
                    event,
                    address,
                    size,
                    result,
                    options,
                } => {
                    if self.kmsgs.get(&kmsg) == Some(&event) {
                        self.kmsgs.remove(&kmsg);
                    }
                    if raw as u32 == 0
                        && let Some(types) = self.kernel.types
                    {
                        let message_size = vmi.read_u32(Va(result + types.result_message))?;
                        let trailer_size = vmi.read_u32(Va(result + types.result_trailer))?;
                        let aux_size = vmi.read_u32(Va(result + types.result_auxiliary))?;
                        let address = delivered_address(
                            address,
                            size,
                            message_size,
                            trailer_size,
                            aux_size,
                            options & types.linear_vector != 0 && options & types.stack != 0,
                        );
                        match address {
                            Some(address) => {
                                self.insert_wire(lifetime, address, event, &mut observation);
                                if let Some(message) = self.messages.get_mut(&event) {
                                    message.delivered = true;
                                }
                                let sender = self.messages.get(&event).map(|message| {
                                    (
                                        message.sender.pid,
                                        message.sender_lifetime,
                                        message.object,
                                        message.destination,
                                        message.transport,
                                    )
                                });
                                observation.lines.push(format!("ipc #{event} received pid={} header={address:#x} bytes={message_size} sender={sender:?} execution=unobserved", context.process.pid));
                                if let Some(request) = self
                                    .messages
                                    .get(&event)
                                    .and_then(|message| message.reply_to)
                                {
                                    if let Some(message) = self.messages.get_mut(&request) {
                                        message.replied = true;
                                    }
                                    self.retire_reply(request);
                                    observation.lines.push(format!(
                                        "ipc #{event} reply-transport request=#{request}"
                                    ));
                                }
                            }
                            None => observation.lines.push(format!(
                                "ipc #{event} incomplete: inconsistent receive buffer size"
                            )),
                        }
                    }
                    else {
                        observation.lines.push(format!(
                            "ipc #{event} user-delivery-failed result={:#x}",
                            raw as u32
                        ));
                    }
                }
            }
            Ok(observation)
        })();
        if result.is_err() {
            self.scopes.remove(&key);
            self.intents.remove(&key);
        }
        result
    }

    /// Retires an unwound or nonreturning observation without inventing a
    /// return.
    pub fn abandoned(
        &mut self,
        context: HookContext,
        pending: PendingIpc,
        reason: &str,
    ) -> IpcObservation {
        let key = (pending.lifetime, pending.thread);
        let mut observation = IpcObservation::default();
        match pending.state {
            PendingState::Scope { token, event } => {
                self.end_scope(key, token);
                observation.lines.push(format!(
                    "ipc execution-incomplete request={event:?} pid={} reason={reason}",
                    context.process.pid
                ));
            }
            PendingState::Intent { event, .. } => {
                self.remove_intent(key, event);
                observation
                    .lines
                    .push(format!("ipc #{event} send-incomplete reason={reason}"));
            }
            PendingState::Decode {
                event, dispatch, ..
            } => {
                if let Some(event) = event
                    && self.dispatch.get(&(pending.lifetime, dispatch)) == Some(&event)
                {
                    self.dispatch.remove(&(pending.lifetime, dispatch));
                }
                observation.lines.push(format!(
                    "ipc decode-incomplete request={event:?} pid={} reason={reason}",
                    context.process.pid
                ));
            }
            PendingState::Pack {
                event,
                owns_intent,
                graph,
                ..
            } => {
                if !graph {
                    self.created.remove(&key);
                }
                if owns_intent {
                    self.remove_intent(key, event);
                }
                observation
                    .lines
                    .push(format!("ipc #{event} pack-incomplete reason={reason}"));
            }
            PendingState::Endpoint => {
                self.endpoints.remove(&key);
                observation.lines.push(format!(
                    "ipc endpoint-connection-incomplete pid={} reason={reason}",
                    context.process.pid
                ));
            }
            _ => observation.lines.push(format!(
                "ipc observation-incomplete pid={} thread={:#x} reason={reason}",
                context.process.pid, pending.thread
            )),
        }
        observation
    }

    /// Records a proven process-creation edge at the parent's exact thread
    /// boundary.
    pub fn process_created(
        &mut self,
        parent: ProcessIdentity,
        child: ProcessIdentity,
        thread: u64,
    ) -> IpcObservation {
        let lifetime = self.process_lifetime(parent);
        let cause = self.active((lifetime, thread));
        self.enable_process(child);
        if let Some(process) = self.processes.get_mut(&child.task) {
            process.launch = cause;
        }
        let mut observation = IpcObservation::default();
        observation.lines.push(format!("ipc process-created parent-pid={} child-pid={} thread={thread:#x} request={cause:?} relationship={}", parent.pid, child.pid, if cause.is_some() { "observed-handler-delegated-launch" } else { "creation-only-causal-propagation-unobserved" }));
        if cause.is_some() {
            observation.related.push(child);
        }
        observation
    }

    /// Records successful exec, preserving only an explicitly observed launch
    /// edge.
    pub fn process_exec(
        &mut self,
        before: ProcessIdentity,
        after: ProcessIdentity,
        thread: u64,
        path: &str,
    ) -> IpcObservation {
        let lifetime = self.process_lifetime(before);
        let cause = self
            .active((lifetime, thread))
            .or(self.processes[&before.task].launch);
        self.retire_local(lifetime);
        self.processes.remove(&before.task);
        self.enable_process(after);
        if let Some(process) = self.processes.get_mut(&after.task) {
            process.launch = cause;
        }
        let mut observation = IpcObservation::default();
        observation.lines.push(format!(
            "ipc process-exec pid={} path={path:?} request={cause:?} relationship={}",
            after.pid,
            if cause.is_some() {
                "observed-launch-lineage"
            }
            else {
                "exec-only-causal-propagation-unobserved"
            }
        ));
        if cause.is_some() {
            observation.related.push(after);
        }
        observation
    }

    /// Retires all local identities and scopes at observed process exit.
    pub fn process_exited(&mut self, identity: ProcessIdentity) -> IpcObservation {
        let mut observation = IpcObservation::default();
        if let Some(process) = self.processes.remove(&identity.task) {
            self.retire_local(process.lifetime);
            observation.lines.push(format!(
                "ipc process-retired pid={} lifetime={}",
                identity.pid, process.lifetime
            ));
        }
        observation
    }

    /// Retires active execution and public-send state at observed thread exit.
    pub fn thread_exited(&mut self, identity: ProcessIdentity, thread: u64) -> IpcObservation {
        let mut observation = IpcObservation::default();
        if let Some(process) = self.processes.get(&identity.task) {
            let key = (process.lifetime, thread);
            if let Some(scopes) = self.scopes.remove(&key) {
                for scope in scopes {
                    observation.lines.push(format!(
                        "ipc execution-incomplete request={:?}: thread {thread:#x} exited",
                        scope.event
                    ));
                }
            }
            self.intents.remove(&key);
        }
        observation
    }

    /// Assigns a monotonic local identity independent of guest pointer values.
    fn serial(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Obtains or establishes the lifetime of a backend-provided live process.
    fn process_lifetime(&mut self, identity: ProcessIdentity) -> u64 {
        match self.processes.get(&identity.task) {
            Some(process) if process.identity == identity => return process.lifetime,
            Some(process) => {
                let lifetime = process.lifetime;
                self.retire_local(lifetime);
                self.processes.remove(&identity.task);
            }
            None => {}
        }
        let lifetime = self.serial();
        self.processes.insert(
            identity.task,
            Process {
                identity,
                lifetime,
                symbols: HashMap::new(),
                installed: HashSet::new(),
                launch: None,
            },
        );
        lifetime
    }

    /// Reads the innermost explicit request execution on one live thread.
    fn active(&self, key: (u64, u64)) -> Option<u64> {
        self.scopes
            .get(&key)
            .and_then(|scopes| scopes.last())
            .and_then(|scope| scope.event)
    }

    /// Begins a callback scope with a separately paired return token.
    fn begin_scope(
        &mut self,
        key: (u64, u64),
        mut event: Option<u64>,
        continuation: Option<u64>,
        observation: &mut IpcObservation,
    ) -> PendingState {
        let token = self.serial();
        let scopes = self.scopes.entry(key).or_default();
        if scopes.len() >= 64 {
            scopes.clear();
            event = None;
            observation.lines.push(
                "ipc execution-incomplete: callback nesting limit reached, propagation disabled"
                    .into(),
            );
        }
        scopes.push(Scope {
            token,
            event,
            continuation,
        });
        PendingState::Scope { token, event }
    }

    /// Ends this scope and any nested observations abandoned by unwinding.
    fn end_scope(&mut self, key: (u64, u64), token: u64) -> bool {
        let mut ended = false;
        if let Some(scopes) = self.scopes.get_mut(&key) {
            if let Some(index) = scopes.iter().position(|scope| scope.token == token) {
                scopes.truncate(index);
                ended = true;
            }
            if scopes.is_empty() {
                self.scopes.remove(&key);
            }
        }
        ended
    }

    /// Removes one public intent without pairing unrelated simultaneous sends.
    fn remove_intent(&mut self, key: (u64, u64), event: u64) {
        if let Some(intents) = self.intents.get_mut(&key) {
            if let Some(index) = intents.iter().rposition(|value| *value == event) {
                intents.remove(index);
            }
            if intents.is_empty() {
                self.intents.remove(&key);
            }
        }
    }

    /// Creates one real observation and explicitly retires bounded old state.
    fn new_message(
        &mut self,
        context: &HookContext,
        object: u64,
        reply_to: Option<u64>,
        observation: &mut IpcObservation,
    ) -> u64 {
        let lifetime = self.process_lifetime(context.process);
        if self.messages.len() >= CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.retire_reply(old);
            self.messages.remove(&old);
            self.wire.retain(|_, value| *value != old);
            self.dispatch.retain(|_, value| *value != old);
            self.serializers.retain(|_, value| *value != old);
            self.dictionaries.retain(|_, value| *value != old);
            self.kmsgs.retain(|_, value| *value != old);
            self.continuations.retain(|_, value| value.event != old);
            self.scopes.retain(|_, scopes| {
                for scope in scopes.iter_mut() {
                    if scope.event == Some(old) {
                        scope.event = None;
                    }
                }
                !scopes.is_empty()
            });
            observation.lines.push(format!(
                "ipc #{old} incomplete: correlation retention limit reached"
            ));
        }
        let event = self.serial();
        self.messages.insert(
            event,
            Message {
                sender: context.process,
                sender_lifetime: lifetime,
                object,
                parent: self.active((lifetime, context.thread)),
                reply_to,
                destination: None,
                reply_endpoint: None,
                transport: None,
                receiver: None,
                delivered: false,
                replied: false,
            },
        );
        self.order.push_back(event);
        event
    }

    /// Obtains an observed underlying port allocation identity.
    fn port(&mut self, object: u64) -> Option<Port> {
        if object == 0 || object == u64::MAX {
            return None;
        }
        match self.ports.get(&object).copied() {
            Some(port) => Some(port),
            None => {
                if self.ports.len() >= CAPACITY {
                    return None;
                }
                let port = Port {
                    object,
                    generation: self.serial(),
                };
                self.ports.insert(object, port);
                Some(port)
            }
        }
    }

    /// Joins a Mach reply only by its live endpoint and exact receiver
    /// lifetime.
    fn reply_request(&self, destination: Port, sender_lifetime: u64) -> Option<u64> {
        let mut candidates = self
            .reply_endpoints
            .get(&destination)?
            .iter()
            .copied()
            .filter(|event| {
                self.messages.get(event).is_some_and(|message| {
                    !message.replied
                        && message
                            .receiver
                            .is_some_and(|(_, lifetime)| lifetime == sender_lifetime)
                })
            });
        let first = candidates.next();
        if candidates.next().is_some() {
            None
        }
        else {
            first
        }
    }

    /// Consumes authoritative delivery before considering an active nested
    /// decoder.
    fn consume_received(
        &mut self,
        lifetime: u64,
        dispatch: u64,
        header: u64,
        observation: &mut IpcObservation,
    ) -> Option<u64> {
        let event = self.wire.remove(&(lifetime, header)).or_else(|| {
            self.dispatch
                .get(&(lifetime, dispatch))
                .copied()
                .filter(|event| {
                    self.messages
                        .get(event)
                        .filter(|message| message.delivered)
                        .and_then(|message| message.receiver)
                        .is_some_and(|(_, receiver)| receiver == lifetime)
                })
        });
        if let Some(event) = event {
            self.insert_association(
                Association::Dispatch,
                lifetime,
                dispatch,
                event,
                observation,
            );
        }
        event
    }

    /// Retires one completed or evicted request from its exact endpoint index.
    fn retire_reply(&mut self, event: u64) {
        if let Some(port) = self
            .messages
            .get(&event)
            .and_then(|message| message.reply_endpoint)
            && let Some(requests) = self.reply_endpoints.get_mut(&port)
        {
            requests.retain(|request| *request != event);
            if requests.is_empty() {
                self.reply_endpoints.remove(&port);
            }
        }
    }

    /// Inserts one bounded raw buffer association.
    fn insert_wire(
        &mut self,
        lifetime: u64,
        address: u64,
        event: u64,
        observation: &mut IpcObservation,
    ) {
        if self.wire.len() >= CAPACITY && !self.wire.contains_key(&(lifetime, address)) {
            observation.lines.push(format!(
                "ipc #{event} incomplete: wire association capacity reached"
            ));
        }
        else if address != 0 {
            self.wire.insert((lifetime, address), event);
        }
    }

    /// Inserts one bounded local object association.
    fn insert_association(
        &mut self,
        association: Association,
        lifetime: u64,
        address: u64,
        event: u64,
        observation: &mut IpcObservation,
    ) {
        let map = match association {
            Association::Dispatch => &mut self.dispatch,
            Association::Serializer => &mut self.serializers,
            Association::Dictionary => &mut self.dictionaries,
        };
        if map.len() >= CAPACITY && !map.contains_key(&(lifetime, address)) {
            observation.lines.push(format!(
                "ipc #{event} incomplete: {association:?} association capacity reached"
            ));
        }
        else if address != 0 {
            map.insert((lifetime, address), event);
        }
    }

    /// Inserts only valid local names with an explicit association bound.
    fn insert_right(
        &mut self,
        lifetime: u64,
        name: u32,
        port: Port,
        event: u64,
        observation: &mut IpcObservation,
    ) {
        if name == 0 || name == u32::MAX {
            return;
        }
        if self.rights.len() >= CAPACITY && !self.rights.contains_key(&(lifetime, name)) {
            observation.lines.push(format!(
                "ipc #{event} incomplete: endpoint-name association capacity reached"
            ));
        }
        else {
            self.rights.insert((lifetime, name), port);
        }
    }

    /// Captures kernel rights before copyout replaces them with local names.
    fn snapshot_rights(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        types: &KernelTypes,
        header: u64,
        observation: &mut IpcObservation,
    ) -> Result<Vec<TransferredRight>, VmiError> {
        let mut rights = Vec::new();
        let bits = vmi.read_u32(Va(header + types.header_bits))?;
        // Copyout stores the destination's local name in msgh_local_port and
        // the reply right's name in msgh_remote_port.
        for (field, converted, source, disposition) in [
            (
                types.header_remote,
                types.header_local,
                "destination",
                bits & REMOTE_MASK,
            ),
            (
                types.header_local,
                types.header_remote,
                "reply-endpoint",
                (bits >> LOCAL_SHIFT) & REMOTE_MASK,
            ),
        ] {
            if let Some(port) = self.port(kernel_pointer(vmi.read_u64(Va(header + field))?)) {
                rights.push(TransferredRight {
                    location: header + converted,
                    port,
                    array_index: None,
                    source,
                    disposition: disposition as u8,
                });
            }
        }
        if bits & COMPLEX != 0 {
            let count = u64::from(vmi.read_u32(Va(header + types.descriptor_count))?);
            if count > DESCRIPTORS {
                observation.lines.push(format!("ipc endpoint-transfer incomplete: {count} descriptors, inspecting {DESCRIPTORS}"));
            }
            for index in 0..count.min(DESCRIPTORS) {
                let descriptor = header + types.descriptors + index * types.descriptor_size;
                match read_bits(vmi, descriptor, types.descriptor_type)? {
                    PORT_DESCRIPTOR | GUARDED_PORT_DESCRIPTOR => {
                        let location = descriptor + types.port_name;
                        if let Some(port) = self.port(kernel_pointer(vmi.read_u64(Va(location))?)) {
                            rights.push(TransferredRight {
                                location,
                                port,
                                array_index: None,
                                source: "descriptor",
                                disposition: read_bits(vmi, descriptor, types.port_disposition)?
                                    as u8,
                            });
                        }
                    }
                    OOL_PORTS_DESCRIPTOR => {
                        let location = descriptor + types.array_address;
                        let array = kernel_pointer(vmi.read_u64(Va(location))?);
                        let count = u64::from(vmi.read_u32(Va(descriptor + types.array_count))?);
                        if count > ARRAY_PORTS {
                            observation.lines.push(format!("ipc endpoint-transfer incomplete: {count} out-of-line rights, inspecting {ARRAY_PORTS}"));
                        }
                        if array != 0 {
                            let disposition =
                                read_bits(vmi, descriptor, types.array_disposition)? as u8;
                            for index in 0..count.min(ARRAY_PORTS) {
                                if let Some(port) =
                                    self.port(kernel_pointer(vmi.read_u64(Va(array + index * 8))?))
                                {
                                    rights.push(TransferredRight {
                                        location,
                                        port,
                                        array_index: Some(index),
                                        source: "out-of-line-port",
                                        disposition,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(rights)
    }

    /// Records a queued continuation under both of its lookup keys.
    fn insert_continuation(&mut self, lifetime: u64, dc: u64, continuation: Continuation) {
        if let Some(previous) = self.continuations.remove(&(lifetime, dc)) {
            self.callouts
                .remove(&(lifetime, previous.function, previous.context));
        }
        self.callouts
            .insert((lifetime, continuation.function, continuation.context), dc);
        self.continuations.insert((lifetime, dc), continuation);
    }

    /// Removes a queued continuation from both of its lookup keys.
    fn remove_continuation(&mut self, lifetime: u64, dc: u64) -> Option<Continuation> {
        let continuation = self.continuations.remove(&(lifetime, dc))?;
        if self
            .callouts
            .get(&(lifetime, continuation.function, continuation.context))
            == Some(&dc)
        {
            self.callouts
                .remove(&(lifetime, continuation.function, continuation.context));
        }
        Some(continuation)
    }

    /// Retires process-local objects, buffers, rights and callback propagation.
    fn retire_local(&mut self, lifetime: u64) {
        self.wire.retain(|(owner, _), _| *owner != lifetime);
        self.dispatch.retain(|(owner, _), _| *owner != lifetime);
        self.serializers.retain(|(owner, _), _| *owner != lifetime);
        self.dictionaries.retain(|(owner, _), _| *owner != lifetime);
        self.rights.retain(|(owner, _), _| *owner != lifetime);
        self.intents.retain(|(owner, _), _| *owner != lifetime);
        self.scopes.retain(|(owner, _), _| *owner != lifetime);
        self.continuations
            .retain(|(owner, _), _| *owner != lifetime);
        self.callouts.retain(|(owner, _, _), _| *owner != lifetime);
        self.created.retain(|(owner, _), _| *owner != lifetime);
        self.endpoints.retain(|(owner, _), _| *owner != lifetime);
    }
}

/// Bounded local association families.
#[derive(Debug)]
enum Association {
    /// Dispatch transport object.
    Dispatch,
    /// XPC serializer and reply handler context.
    Serializer,
    /// Decoded incoming or constructed reply dictionary.
    Dictionary,
}

/// Object arguments whose runtime class each hook's private prototype
/// implies, checked in the libxpc IDA database
/// (`work/re/TraceObjectsIpc/libxpc.dylib.i64`) for the private functions.
fn argument_classes(kind: IpcHook) -> &'static [(usize, &'static [&'static str])] {
    const CONNECTION: &[&str] = &["OS_xpc_connection"];
    const DICTIONARY: &[&str] = &["OS_xpc_dictionary"];
    const SERIALIZER: &[&str] = &["OS_xpc_serializer"];
    const MESSAGE: &[&str] = &["OS_dispatch_mach_msg"];
    match kind {
        IpcHook::Send | IpcHook::SendWithReply | IpcHook::SendSync | IpcHook::Pack => {
            &[(0, CONNECTION), (1, DICTIONARY)]
        }
        IpcHook::Serialize | IpcHook::PipeSend => &[(0, SERIALIZER)],
        IpcHook::Unpack => &[(0, CONNECTION), (1, MESSAGE)],
        IpcHook::Receive | IpcHook::DispatchDispose => &[(0, MESSAGE)],
        IpcHook::Handler | IpcHook::Activate | IpcHook::Resume | IpcHook::ConnectionDispose => {
            &[(0, CONNECTION)]
        }
        IpcHook::CreateReply => &[(0, DICTIONARY)],
        IpcHook::DictionaryDispose => &[(0, &["OS_xpc_dictionary", "OS_xpc_error"])],
        IpcHook::FromEndpoint => &[(0, &["OS_xpc_endpoint"])],
        _ => &[],
    }
}

/// Checks an object's runtime class.
///
/// Without a process decoder, or when the runtime metadata is not readable
/// yet, the class cannot be checked and the object is accepted.
fn class_is(
    vmi: &VmiContext<MacOs<Driver>>,
    object: u64,
    classes: &[&str],
    decode: &mut Option<(&mut Values, &mut ObjcRuntime, &Palette)>,
) -> Result<bool, VmiError> {
    let objc = match decode.as_mut() {
        Some((_, objc, _)) => objc,
        None => return Ok(true),
    };
    if object == 0 {
        return Ok(false);
    }
    match objc.class_info(vmi, object)? {
        Some(info) => Ok(classes.contains(&info.name.as_str())),
        None => Ok(true),
    }
}

/// Reads a field located by byte offset and bit range.
fn read_bits(vmi: &VmiContext<MacOs<Driver>>, base: u64, bits: Bits) -> Result<u64, VmiError> {
    let mut raw = [0_u8; 8];
    let count = bits.bytes().min(8);
    vmi.read(Va(base + bits.offset), &mut raw[..count])?;
    Ok(bits.extract(&raw[..count]))
}

/// Reports whether `ipc_kmsg_free` keeps the message allocated.
///
/// xnu `osfmk/ipc/ipc_kmsg.c:1038-1041` returns early for an all-inlined
/// message whose keep-alive state still has the owned bit, as
/// `ipc_kmsg_keep_alive_done_using` (`ipc_kmsg.c:925-945`) decides.
fn kept_alive(types: &KernelTypes, kind: u64, keep_alive: u64) -> bool {
    kind == types.all_inlined && keep_alive & types.keep_alive_owned != 0
}

/// Formats an optional address.
fn hex(value: Option<u64>) -> String {
    match value {
        Some(value) => format!("{value:#x}"),
        None => String::from("unobserved"),
    }
}

/// Strips arm64e pointer authentication without claiming authentication.
fn user_pointer(raw: u64) -> u64 {
    raw & 0x0000_ffff_ffff_ffff
}

/// Strips kernel data PAC and restores canonical kernel VA sign extension.
fn kernel_pointer(raw: u64) -> u64 {
    if raw == 0 || raw == u64::MAX {
        raw
    }
    else {
        (raw & 0x0000_ffff_ffff_ffff) | 0xffff_0000_0000_0000
    }
}

/// Resolves inline or separately allocated kernel message header storage,
/// following `ikm_header` (xnu `osfmk/ipc/ipc_kmsg.c:288-300`).
fn kernel_header(
    vmi: &VmiContext<MacOs<Driver>>,
    types: &KernelTypes,
    object: u64,
) -> Result<u64, VmiError> {
    let kind = read_bits(vmi, object, types.kmsg_type)?;
    if kind == types.all_inlined {
        Ok(object + types.big_data)
    }
    else if kind == types.udata_ool {
        Ok(object + types.small_data)
    }
    else {
        Ok(kernel_pointer(vmi.read_u64(Va(object + types.kdata))?))
    }
}

/// Computes the exact user receive address, including stack placement when
/// the receive options request a linear vector on the stack.
fn delivered_address(
    address: u64,
    size: u32,
    message: u32,
    trailer: u32,
    auxiliary: u32,
    stack: bool,
) -> Option<u64> {
    if stack {
        let occupied = message.checked_add(trailer)?.checked_add(auxiliary)?;
        address.checked_add(u64::from(size.checked_sub(occupied)?))
    }
    else if message <= size {
        Some(address)
    }
    else {
        None
    }
}

/// Renders the XPC payload of a Mach message when a process decoder exists.
fn message_payload(
    vmi: &VmiContext<MacOs<Driver>>,
    header: u64,
    decode: &mut Option<(&mut Values, &mut ObjcRuntime, &Palette)>,
) -> String {
    match decode.as_mut() {
        Some((values, _, palette)) => values.message(vmi, header, palette),
        None => format!("<{header:#x} decoder-unavailable>"),
    }
}

/// Resolves a dispatch message's Mach header, stored inline exactly when its
/// destructor is the default.
fn dispatch_header(vmi: &VmiContext<MacOs<Driver>>, object: u64) -> Result<u64, VmiError> {
    let object = user_pointer(object);
    if vmi.read_u32(Va(object + MESSAGE_DESTRUCTOR))? == 0 {
        Ok(object + MESSAGE_STORAGE)
    }
    else {
        Ok(user_pointer(vmi.read_u64(Va(object + MESSAGE_STORAGE))?))
    }
}

/// Reads the sender audit token from the trailer that follows a received
/// Mach message, when the trailer carries one.
fn trailer_audit(
    vmi: &VmiContext<MacOs<Driver>>,
    header: u64,
) -> Result<Option<[u32; 8]>, VmiError> {
    let read = || -> Result<Option<[u32; 8]>, VmiError> {
        let size = vmi.read_u32(Va(header + 4))?;
        let trailer = header + u64::from((size + 3) & !3);
        if vmi.read_u32(Va(trailer))? != TRAILER_FORMAT
            || !AUDIT_TRAILER_SIZES.contains(&vmi.read_u32(Va(trailer + 4))?)
        {
            return Ok(None);
        }
        let mut token = [0_u32; 8];
        for (index, word) in token.iter_mut().enumerate() {
            *word = vmi.read_u32(Va(trailer + TRAILER_AUDIT + index as u64 * 4))?;
        }
        Ok(Some(token))
    };
    match read() {
        Ok(token) => Ok(token),
        Err(VmiError::Translation(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Captures an escaped service name with a fixed byte-read bound.
fn bounded_name(vmi: &VmiContext<MacOs<Driver>>, address: u64) -> Result<String, VmiError> {
    let mut bytes = Vec::with_capacity(256);
    for index in 0..256_u64 {
        let byte = vmi.read_u8(Va(address + index))?;
        if byte == 0 {
            return Ok(format!("{:?}", String::from_utf8_lossy(&bytes)));
        }
        bytes.push(byte);
    }
    Ok(format!("{:?}<truncated>", String::from_utf8_lossy(&bytes)))
}

/// Pure boundary tests for receive placement and nested causal isolation.
#[cfg(test)]
mod tests {
    use super::{
        Continuation, IpcObservation, IpcTracker, Pa, PendingState, ProcessIdentity,
        delivered_address,
    };

    /// A callout finds its queued continuation, and a re-enqueued continuation
    /// replaces its stale callout key.
    #[test]
    fn callout_index_follows_continuations() {
        let mut tracker = IpcTracker::default();
        let queued = |function, context| Continuation {
            event: 7,
            function,
            context,
        };
        tracker.insert_continuation(1, 0x5000, queued(0xa0, 0xb0));
        tracker.insert_continuation(1, 0x5000, queued(0xa0, 0xc0));
        assert_eq!(tracker.callouts.get(&(1, 0xa0, 0xb0)), None);
        assert_eq!(tracker.callouts.get(&(1, 0xa0, 0xc0)), Some(&0x5000));
        assert!(tracker.remove_continuation(1, 0x5000).is_some());
        assert!(tracker.callouts.is_empty());
        assert!(tracker.remove_continuation(1, 0x5000).is_none());
    }

    /// A reused outgoing buffer must not hide the reply delivered into that
    /// buffer.
    #[test]
    fn delivered_reply_supersedes_outgoing_dispatch() {
        let mut tracker = IpcTracker::default();
        let mut observation = IpcObservation::default();
        tracker.dispatch.insert((1, 0x2000), 7);
        tracker.wire.insert((1, 0x1000), 9);
        assert_eq!(
            tracker.consume_received(1, 0x2000, 0x1000, &mut observation),
            Some(9)
        );
        assert!(!tracker.wire.contains_key(&(1, 0x1000)));
        assert_eq!(
            tracker.consume_received(2, 0x2000, 0x1000, &mut observation),
            None
        );
        assert_eq!(
            tracker.consume_received(1, 0x2000, 0x1000, &mut observation),
            None
        );
    }

    /// Rejects oversized receive results and checked placement arithmetic
    /// overflow.
    #[test]
    fn receive_placement_checks_bounds() {
        assert_eq!(
            delivered_address(0x1000, 128, 64, 32, 16, false),
            Some(0x1000)
        );
        assert_eq!(
            delivered_address(0x1000, 128, 64, 32, 16, true),
            Some(0x1010)
        );
        assert_eq!(delivered_address(0x1000, 63, 64, 0, 0, false), None);
        assert_eq!(delivered_address(0x1000, 128, 64, 64, 1, true), None);
        assert_eq!(delivered_address(u64::MAX, 128, 64, 0, 0, true), None);
    }

    /// Prevents unobserved reentrant callbacks from inheriting an outer
    /// request.
    #[test]
    fn unknown_nested_scope_masks_request() {
        let mut tracker = IpcTracker::default();
        let mut observation = IpcObservation::default();
        let key = (1, 2);
        tracker.begin_scope(key, Some(7), None, &mut observation);
        let unknown = tracker.begin_scope(key, None, None, &mut observation);
        assert_eq!(tracker.active(key), None);
        match unknown {
            PendingState::Scope { token, .. } => {
                assert!(tracker.end_scope(key, token));
            }
            _ => panic!("scope state expected"),
        }
        assert_eq!(tracker.active(key), Some(7));
    }

    /// Rejects task-address reuse and image-root changes as the same lifetime.
    #[test]
    fn process_identity_changes_retire_local_scope() {
        let mut tracker = IpcTracker::default();
        let mut observation = IpcObservation::default();
        let before = ProcessIdentity {
            task: 1,
            pid: 2,
            root: Pa(0x1000),
        };
        let old = tracker.process_lifetime(before);
        tracker.begin_scope((old, 3), Some(7), None, &mut observation);
        let after = ProcessIdentity {
            task: 1,
            pid: 2,
            root: Pa(0x2000),
        };
        assert_ne!(tracker.process_lifetime(after), old);
        assert_eq!(tracker.active((old, 3)), None);
    }

    /// Exceeds the scope bound without leaving any older request active.
    #[test]
    fn scope_limit_disables_propagation() {
        let mut tracker = IpcTracker::default();
        let mut observation = IpcObservation::default();
        for _ in 0..65 {
            tracker.begin_scope((1, 2), Some(7), None, &mut observation);
        }
        assert_eq!(tracker.active((1, 2)), None);
        assert!(!observation.lines.is_empty());
    }
}
