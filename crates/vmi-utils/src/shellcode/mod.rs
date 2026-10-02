//! Opinionated shellcode injection and guest-host communication primitives.
//!
//! Recipes are intended for short sequences of API calls. Longer recipes are
//! increasingly error-prone, and failures become harder to recover from.
//!
//! More complex operations are better implemented in shellcode, leaving the
//! recipe responsible only for loading and starting the payload.
//!
//! # How it starts
//!
//! The built-in implementation supports Windows guests on x64.
//!
//! A *recipe* is a list of setup steps. Building a recipe does not run
//! anything in the guest.
//!
//! An injector temporarily redirects an existing guest thread to execute
//! those steps. This is what "hijacking a thread" means. The recipe allocates
//! executable memory in the guest, copies the payload into it, then
//! calls the shellcode or starts a new thread for it.
//!
//! You are encouraged to use the [`scfw`] shellcode framework to build C++
//! shellcode into raw `.bin` files and embed them with `include_bytes!`:
//!
//! ```text
//! C++ shellcode -> .bin file -> payload -> allocation -> execution
//! ```
//!
//! # Choosing a recipe
//!
//! There are two choices:
//!
//! - **User mode or kernel mode:** run in an ordinary guest process or inside
//!   the guest operating system's kernel.
//! - **Call or spawn:** run on the hijacked thread or create a new thread.
//!
//! | Recipe                            | Payload runs on                 | Recipe finishes when    |
//! | --------------------------------- | ------------------------------- | ----------------------- |
//! | [`user_shellcode_call_recipe`]    | Hijacked user-mode thread       | Payload returns         |
//! | [`user_shellcode_spawn_recipe`]   | New thread in the guest process | Thread has been created |
//! | [`kernel_shellcode_call_recipe`]  | Hijacked thread in kernel mode  | Payload returns         |
//! | [`kernel_shellcode_spawn_recipe`] | New system thread               | Thread has been created |
//!
//! A finished spawn recipe does not mean the payload has finished.
//!
//! Call mode keeps the hijacked thread busy until the payload returns.
//! In kernel mode, that thread may already hold locks, so payload operations
//! must be safe in that context.
//!
//! Kernel spawn mode runs in the `System` process. A handle or memory address
//! that is valid in the original process may not be valid there.
//!
//! # Passing parameters
//!
//! Parameters tell the payload what to work with, such as a file path or a
//! guest file handle. The recipe can pass them in two ways:
//!
//! - Pass a reference to a type implementing [`Parameters`] to encode
//!   a block of parameters. The recipe copies that block alongside the code
//!   and passes its address in guest memory to the payload.
//! - Pass [`ParameterValue`] to pass a `u64` directly, such as a guest
//!   file handle. This does not append a parameter block.
//!
//! The encoded format must match how the payload reads its parameters.
//! A pointer into the host Rust program is not a pointer into guest memory.
//!
//! # Shared host-guest contract
//!
//! ## Terms
//!
//! - **Shellcode** is the code that runs in the guest.
//! - **Parameters** are the inputs passed to shellcode.
//! - A **payload** contains shellcode, any parameter block, padding, and any wrapper.
//! - An **allocation** is memory allocated in the guest for the payload.
//! - A **response** is the bridge reply.
//! - **Output** is the optional value returned to the caller.
//!
//! ## Parameter encoding and entry arguments
//!
//! [`Parameters::ALIGNMENT`] aligns the start of the parameter block.
//! The writer and reader do not insert internal padding. Each shellcode
//! defines its field order and optional-field conditions.
//!
//! [`Parameter`] is the single resolved entry value - either a block
//! address or an exact scalar such as a handle.
//!
//! ## Bridge routing, status, and output
//!
//! A bridge packet's `magic` identifies the protocol, `request` selects
//! a handler, and `method` selects an operation within that handler.
//! Its `value1`-`value4` fields carry 64-bit operation-specific values.
//! The shellcode bridge uses [`BRIDGE_MAGIC`] and verifies response slots 3
//! and 4 against [`BRIDGE_VERIFY_VALUE3`] and [`BRIDGE_VERIFY_VALUE4`].
//!
//! See [`EncodedStatus`] for the status layout.
//!
//! Predefined [`StatusKind`] values:
//!
//! - [`SUCCESS`](StatusKind::SUCCESS): `0x00`
//! - [`WAITING`](StatusKind::WAITING): `0x01`
//! - [`INVALID_PARAMETERS`](StatusKind::INVALID_PARAMETERS): `0xfd`
//! - [`OPERATION_FAILED`](StatusKind::OPERATION_FAILED): `0xfe`
//! - [`ABORTED`](StatusKind::ABORTED): `0xff`
//!
//! The caller decides whether [`BridgeResponse::output`] reports
//! progress or finishes an operation.
//!
//! # Messages and cleanup
//!
//! A payload can use a bridge to send requests or report results to the host.
//! The x64 examples notify the host with a special CPU instruction (`VMCALL`).
//! The host handles the event, supplies a response, and resumes guest execution.
//!
//! A result message does not necessarily mean the payload thread has exited.
//! The payload may still need to clean up and return.
//!
//! After the recipe successfully starts the payload, the payload owns its
//! guest memory allocation and must free it. The `scfw` example payloads handle
//! this cleanup automatically.
//!
//! For a complete example, see the [Windows shellcode walkthrough].
//!
//! [`scfw`]: https://github.com/vmi-rs/scfw
//! [Windows shellcode walkthrough]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-shellcode/README.md
//! [`BridgeResponse::output`]: crate::bridge::BridgeResponse::output

mod arch;
mod bridge;
mod os;
mod parameters;
mod payload;
mod recipe;
mod status;

pub use self::{
    arch::ArchAdapter,
    bridge::{BRIDGE_MAGIC, BRIDGE_VERIFY_VALUE3, BRIDGE_VERIFY_VALUE4, impl_bridge_contract},
    os::OsAdapter,
    parameters::{Parameter, ParameterSource, ParameterValue, ParameterWriter, Parameters},
    payload::Payload,
    recipe::RetryState,
    status::{EncodedStatus, Stage, Status, StatusKind, impl_stage},
};
use crate::injector::Recipe;

/// Data retained by an OS-specific kernel-mode shellcode recipe.
pub type KernelRecipeData<Os> = <Os as OsAdapter>::KernelRecipeData;

/// Data retained by an OS-specific user-mode shellcode recipe.
pub type UserRecipeData<Os> = <Os as OsAdapter>::UserRecipeData;

/// A kernel-mode shellcode recipe for `Os`.
pub type KernelRecipe<Os> = Recipe<Os, KernelRecipeData<Os>>;

/// A user-mode shellcode recipe for `Os`.
pub type UserRecipe<Os> = Recipe<Os, UserRecipeData<Os>>;

/// Builds a kernel-mode shellcode recipe that calls the payload on the
/// hijacked thread.
///
/// The recipe completes when the payload returns.
pub fn kernel_shellcode_call_recipe<Os>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ParameterSource,
) -> KernelRecipe<Os>
where
    Os: OsAdapter,
{
    Os::kernel_shellcode_call_recipe(shellcode, parameter)
}

/// Builds a kernel-mode shellcode recipe that spawns a system thread for
/// the payload.
///
/// The recipe completes when the thread has been created.
pub fn kernel_shellcode_spawn_recipe<Os>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ParameterSource,
) -> KernelRecipe<Os>
where
    Os: OsAdapter,
{
    Os::kernel_shellcode_spawn_recipe(shellcode, parameter)
}

/// Builds a user-mode shellcode recipe that calls the payload on the
/// hijacked thread.
///
/// The recipe completes when the payload returns.
pub fn user_shellcode_call_recipe<Os>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ParameterSource,
) -> UserRecipe<Os>
where
    Os: OsAdapter,
{
    Os::user_shellcode_call_recipe(shellcode, parameter)
}

/// Builds a user-mode shellcode recipe that spawns a guest thread for
/// the payload.
///
/// The recipe completes when the thread has been created.
pub fn user_shellcode_spawn_recipe<Os>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ParameterSource,
) -> UserRecipe<Os>
where
    Os: OsAdapter,
{
    Os::user_shellcode_spawn_recipe(shellcode, parameter)
}
