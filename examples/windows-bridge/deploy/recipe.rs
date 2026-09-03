use vmi::{arch::amd64::Amd64, driver::VmiMemory, os::windows::WindowsOs, utils::injector::Recipe};

use super::parameters::DeployParameters;
use crate::bridge::{UserShellcodeRecipeData, user_shellcode_recipe};

/// Deploy shellcode embedded from the selected SCFW build artifact.
const DEPLOY_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/scfw/build-x64/shellcodes/deploy/deploy.bin"
));

/// Builds the deploy shellcode injection recipe.
#[tracing::instrument(name = "deploy", skip_all)]
pub fn deploy_recipe<Driver>(
    parameters: &DeployParameters,
) -> Recipe<WindowsOs<Driver>, UserShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_recipe(DEPLOY_SHELLCODE, parameters)
}
