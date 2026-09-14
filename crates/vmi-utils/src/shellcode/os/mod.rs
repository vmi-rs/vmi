#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
mod windows;

use vmi_core::VmiOs;

use super::ShellcodeParameterSource;
use crate::injector::Recipe;

/// Operating system-specific shellcode injection functionality.
pub trait OsAdapter: VmiOs {
    /// Data retained by a kernel-mode shellcode recipe.
    type KernelRecipeData;

    /// Data retained by a user-mode shellcode recipe.
    type UserRecipeData;

    /// Builds a kernel-mode shellcode recipe that calls the payload on the
    /// hijacked thread.
    ///
    /// The recipe completes when the payload returns.
    fn kernel_shellcode_call_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::KernelRecipeData>;

    /// Builds a kernel-mode shellcode recipe that spawns a system thread for
    /// the payload.
    ///
    /// The recipe completes when the thread has been created.
    fn kernel_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::KernelRecipeData>;

    /// Builds a user-mode shellcode recipe that calls the payload on the
    /// hijacked thread.
    ///
    /// The recipe completes when the payload returns.
    fn user_shellcode_call_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::UserRecipeData>;

    /// Builds a user-mode shellcode recipe that spawns a guest thread for
    /// the payload.
    ///
    /// The recipe completes when the thread has been created.
    fn user_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::UserRecipeData>;
}
