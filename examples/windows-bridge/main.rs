//! Runs the `deploy` shellcode through VMI and optionally monitors the launched process.

#[path = "../common/mod.rs"]
mod common;

mod deploy;
mod file_transfer;
mod monitor;

use anyhow::Error;
use clap::{Parser, Subcommand};

use crate::deploy::DeployArguments;

/// Command-line interface for the `windows-bridge` example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Command to run.
    #[command(subcommand)]
    command: Command,
}

/// Command selected on the command line.
#[derive(Debug, Subcommand)]
enum Command {
    /// Runs the `deploy` shellcode in a Windows process.
    Deploy(DeployArguments),
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let setup = common::VmiSetup::new()?;
    let session = setup.session();
    let profile = setup.profile();

    match cli.command {
        Command::Deploy(arguments) => {
            deploy::run(&session, profile, setup.terminate_flag(), arguments)
        }
    }
}
