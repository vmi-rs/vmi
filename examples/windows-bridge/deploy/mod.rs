//! Deploy shellcode recipe: downloads, extracts, or executes content in a Windows guest.

mod bridge;
mod parameters;
mod recipe;

#[cfg(test)]
pub use self::parameters::encode_parameters;
pub use self::{
    bridge::{DeployBridge, DeployPolicy, DeployStage, DeployStatus, ExecuteResponse},
    parameters::DeployParameters,
    recipe::deploy_recipe,
};
