//! Opinionated shellcode injection and guest-host communication primitives.
//!
//! Recipes are intended for short sequences of API calls. Longer recipes are
//! increasingly error-prone, and failures become harder to recover from.
//!
//! More complex operations are better implemented in shellcode, leaving the
//! recipe responsible only for loading and starting the payload.

mod os;
mod payload;
mod protocol;
mod recipe;

#[cfg(test)]
pub use self::payload::encode_parameters;
pub use self::{
    os::OsAdapter,
    payload::{
        ParameterWriter, ShellcodeParameter, ShellcodeParameterSource, ShellcodeParameterValue,
        ShellcodeParameters,
    },
    protocol::{
        BRIDGE_MAGIC, BRIDGE_VERIFY_VALUE3, BRIDGE_VERIFY_VALUE4, BridgeStage, BridgeStatusCode,
        Status, StatusKind, impl_bridge_contract, impl_bridge_stage,
    },
};
use crate::injector::Recipe;

/// Data retained by an OS-specific kernel-mode shellcode recipe.
pub type KernelShellcodeRecipeData<Os> = <Os as OsAdapter>::KernelRecipeData;

/// Data retained by an OS-specific user-mode shellcode recipe.
pub type UserShellcodeRecipeData<Os> = <Os as OsAdapter>::UserRecipeData;

/// A kernel-mode shellcode recipe for `Os`.
pub type KernelShellcodeRecipe<Os> = Recipe<Os, KernelShellcodeRecipeData<Os>>;

/// A user-mode shellcode recipe for `Os`.
pub type UserShellcodeRecipe<Os> = Recipe<Os, UserShellcodeRecipeData<Os>>;

/// Builds a kernel-mode shellcode recipe that calls the payload on the
/// hijacked thread.
///
/// The recipe completes when the payload returns.
pub fn kernel_shellcode_call_recipe<Os>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> KernelShellcodeRecipe<Os>
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
    parameter: impl ShellcodeParameterSource,
) -> KernelShellcodeRecipe<Os>
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
    parameter: impl ShellcodeParameterSource,
) -> UserShellcodeRecipe<Os>
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
    parameter: impl ShellcodeParameterSource,
) -> UserShellcodeRecipe<Os>
where
    Os: OsAdapter,
{
    Os::user_shellcode_spawn_recipe(shellcode, parameter)
}
