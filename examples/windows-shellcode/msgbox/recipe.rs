use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{UserRecipe, user_shellcode_call_recipe, user_shellcode_spawn_recipe},
};

use super::parameters::MsgboxParameters;

/// Compiled `msgbox` shellcode.
const MSGBOX_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/msgbox.bin"
));

/// Builds a recipe that runs the `msgbox` shellcode on the hijacked thread.
///
/// The recipe completes after the shellcode returns.
#[tracing::instrument(name = "msgbox_call", skip_all)]
pub fn msgbox_call_recipe<Driver>(parameters: &MsgboxParameters) -> UserRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_call_recipe(MSGBOX_SHELLCODE, parameters)
}

/// Builds a recipe that runs the `msgbox` shellcode on a guest thread.
///
/// The recipe completes once the guest thread has been created.
/// The injector remains active until the shellcode reports its final result.
#[tracing::instrument(name = "msgbox_spawn", skip_all)]
pub fn msgbox_spawn_recipe<Driver>(parameters: &MsgboxParameters) -> UserRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_spawn_recipe(MSGBOX_SHELLCODE, parameters)
}
