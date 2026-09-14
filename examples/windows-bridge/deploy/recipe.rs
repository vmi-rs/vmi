use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{UserRecipe, user_shellcode_spawn_recipe},
};

use super::parameters::DeployParameters;

/// Compiled `deploy` shellcode.
const DEPLOY_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/deploy.bin"
));

/// Builds a recipe that runs the `deploy` shellcode on a guest thread.
///
/// The recipe completes once the guest thread has been created.
#[tracing::instrument(name = "deploy", skip_all)]
pub fn deploy_recipe<Driver>(parameters: &DeployParameters) -> UserRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    user_shellcode_spawn_recipe(DEPLOY_SHELLCODE, parameters)
}
