use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{UserShellcodeRecipe, user_shellcode_spawn_recipe},
};

use super::parameters::MsgboxParameters;

/// Msgbox shellcode embedded from the selected `scfw` build artifact.
const MSGBOX_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/msgbox.bin"
));

/// Builds the msgbox shellcode injection recipe.
#[tracing::instrument(name = "msgbox", skip_all)]
pub fn msgbox_recipe<Driver>(
    parameters: &MsgboxParameters,
) -> UserShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_spawn_recipe(MSGBOX_SHELLCODE, parameters)
}
