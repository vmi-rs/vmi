use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{UserShellcodeRecipe, user_shellcode_spawn_recipe},
};

use super::parameters::DeployParameters;

/// Deploy shellcode embedded from the selected `scfw` build artifact.
const DEPLOY_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/deploy.bin"
));

/// Builds the deploy shellcode injection recipe.
#[tracing::instrument(name = "deploy", skip_all)]
pub fn deploy_recipe<Driver>(
    parameters: &DeployParameters,
) -> UserShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_spawn_recipe(DEPLOY_SHELLCODE, parameters)
}
