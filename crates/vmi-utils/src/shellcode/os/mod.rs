#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
mod windows;

use vmi_core::VmiOs;

use super::ShellcodeParameterSource;
use crate::injector::Recipe;

/// Operating system-specific shellcode injection functionality.
pub trait OsAdapter: VmiOs + Sized {
    /// Data retained by a kernel-mode shellcode recipe.
    type KernelRecipeData;

    /// Data retained by a user-mode shellcode recipe.
    type UserRecipeData;

    /// Builds a kernel-mode shellcode recipe.
    fn kernel_shellcode_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::KernelRecipeData>;

    /// Builds a user-mode shellcode recipe.
    fn user_shellcode_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::UserRecipeData>;
}
