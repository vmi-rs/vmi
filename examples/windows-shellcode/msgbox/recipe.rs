use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{
        UserShellcodeRecipe, user_shellcode_call_recipe, user_shellcode_spawn_recipe,
    },
};

use super::parameters::MsgboxParameters;

/// Msgbox shellcode embedded from the selected `scfw` build artifact.
const MSGBOX_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/msgbox.bin"
));

/// Builds the msgbox recipe that calls the payload on the hijacked thread.
///
/// The recipe completes only after the message box has been dismissed and the
/// payload has returned, so the hijacked thread stays inside `MessageBoxA` for
/// the whole time the box is on screen.
#[tracing::instrument(name = "msgbox_call", skip_all)]
pub fn msgbox_call_recipe<Driver>(
    parameters: &MsgboxParameters,
) -> UserShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_call_recipe(MSGBOX_SHELLCODE, parameters)
}

/// Builds the msgbox recipe that spawns a guest thread for the payload.
///
/// The recipe completes once the thread has been created, leaving the hijacked
/// thread free to resume while the new thread displays the message box.
#[tracing::instrument(name = "msgbox_spawn", skip_all)]
pub fn msgbox_spawn_recipe<Driver>(
    parameters: &MsgboxParameters,
) -> UserShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_spawn_recipe(MSGBOX_SHELLCODE, parameters)
}
