//! Kernel-file shellcode recipes: create a guest file from kernel mode.

mod bridge;
mod parameters;
mod recipe;

pub use self::{
    bridge::{KernelFileBridge, KernelFileStatus},
    parameters::KernelFileParameters,
    recipe::{kernel_file_call_recipe, kernel_file_spawn_recipe},
};
