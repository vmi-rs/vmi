use vmi::{arch::amd64::Amd64, driver::VmiMemory, os::windows::WindowsOs, utils::injector::Recipe};

use super::parameters::PullParameters;
use crate::recipe::{ShellcodeRecipeData, shellcode_recipe};

/// Pull shellcode embedded from the selected SCFW build artifact.
const PULL_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scfw/build-x64/shellcodes/pull/pull.bin"
));

/// Builds the pull shellcode injection recipe.
#[tracing::instrument(name = "pull_recipe", skip_all)]
pub(crate) fn pull_recipe<Driver>(
    parameters: &PullParameters,
) -> Recipe<WindowsOs<Driver>, ShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    shellcode_recipe(PULL_SHELLCODE, parameters)
}
