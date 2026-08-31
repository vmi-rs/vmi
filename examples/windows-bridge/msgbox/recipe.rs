use vmi::{arch::amd64::Amd64, driver::VmiMemory, os::windows::WindowsOs, utils::injector::Recipe};

use super::parameters::MsgboxParameters;
use crate::recipe::{ShellcodeRecipeData, shellcode_recipe};

/// Msgbox shellcode embedded from the selected SCFW build artifact.
const MSGBOX_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/scfw/build-x64/shellcodes/msgbox/msgbox.bin"
));

/// Builds the msgbox shellcode injection recipe.
#[tracing::instrument(name = "msgbox", skip_all)]
pub fn msgbox_recipe<Driver>(
    parameters: &MsgboxParameters,
) -> Recipe<WindowsOs<Driver>, ShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    shellcode_recipe(MSGBOX_SHELLCODE, parameters)
}
