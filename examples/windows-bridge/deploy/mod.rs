//! `deploy` shellcode.
//!
//! Handles downloading, extracting, and executing content in a Windows guest.

mod bridge;
mod command;
mod parameters;
mod recipe;

pub use self::{
    bridge::{DeployBridge, DeployPolicy, DeployStatus},
    command::{DeployArguments, run},
};
