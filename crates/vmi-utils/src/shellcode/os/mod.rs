#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
mod windows;

use vmi_core::{VmiOs, os::ProcessId};

use super::{ParameterSource, RetryPolicy};
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
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::KernelRecipeData>;

    /// Builds a kernel-mode shellcode recipe that spawns a system thread for
    /// the payload.
    ///
    /// The recipe completes when the thread has been created.
    fn kernel_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::KernelRecipeData>;

    /// Builds a user-mode shellcode recipe that calls the payload on the
    /// hijacked thread.
    ///
    /// The recipe completes when the payload returns.
    fn user_shellcode_call_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::UserRecipeData>;

    /// Builds a user-mode shellcode recipe that spawns a guest thread for
    /// the payload.
    ///
    /// The recipe completes when the thread has been created.
    fn user_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::UserRecipeData>;

    /// Builds a kernel-mode recipe that spawns a user-mode thread for the
    /// payload in the process that `pid` identifies.
    ///
    /// The recipe completes when the thread has been created.
    fn user_shellcode_spawn_from_kernel_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
        pid: ProcessId,
    ) -> Recipe<Self, Self::KernelRecipeData>;
}
