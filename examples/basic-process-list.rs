//! This example demonstrates how to enumerate the running processes of a
//! Windows guest running inside a Xen domain.

mod common;

use anyhow::Error;
use vmi::os::VmiOsProcess as _;

fn main() -> Result<(), Error> {
    let setup = common::VmiSetup::new()?;
    let session = setup.session();

    // Pause the VM to get consistent state.
    let paused = session.pause_guard()?;

    // Create a new `VmiState` with the boot CPU registers.
    let vmi = paused.state();

    // Get the list of processes and print them.
    for process in vmi.os().processes()? {
        let process = process?;

        println!(
            "{} [{}] {} (root @ {})",
            process.object()?,
            process.id()?,
            process.name()?,
            process.translation_root()?
        );
    }

    Ok(())
}
