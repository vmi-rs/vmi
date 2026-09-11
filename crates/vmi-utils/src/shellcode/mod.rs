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

#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
use self::payload::ShellcodePayload;
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

/// Builds a kernel-mode shellcode recipe for `Os`.
pub fn kernel_shellcode_recipe<Os>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> KernelShellcodeRecipe<Os>
where
    Os: OsAdapter,
{
    Os::kernel_shellcode_recipe(shellcode, parameter)
}

/// Builds a user-mode shellcode recipe for `Os`.
pub fn user_shellcode_recipe<Os>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> UserShellcodeRecipe<Os>
where
    Os: OsAdapter,
{
    Os::user_shellcode_recipe(shellcode, parameter)
}
