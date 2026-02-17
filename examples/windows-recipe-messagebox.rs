//! # [`recipe!`] example
//!
//! This example demonstrates how to write a simple recipe.
//!
//! The recipe is injected into the `explorer.exe` process and shows
//! a message box.
//!
//! # Possible log output
//!
//! ```text
//! DEBUG domain_id=XenDomainId(102)
//! DEBUG found MZ base_address=0xfffff80002861000
//!  INFO profile already exists profile_path="cache/windows/ntkrnlmp.pdb/3844dbb920174967be7aa4a2c20430fa2/profile.json"
//!  INFO Creating VMI session
//!  INFO found explorer.exe pid=1248 object=0xfffffa80030e9060
//! DEBUG injector{vcpu=2 rip=0x0000000077c618ca}:memory_access: thread hijacked current_tid=1488
//! DEBUG injector{vcpu=2 rip=0x0000000077c618ca}:memory_access: recipe step index=0
//! DEBUG injector{vcpu=1 rip=0x0000000077c618ca}:memory_access: recipe finished result=0x0000000000000001
//! ```

mod common;

use vmi::{
    VcpuId, VmiDriver,
    arch::amd64::Amd64,
    os::{VmiOsProcess as _, windows::WindowsOs},
    utils::injector::{InjectorHandler, Recipe, recipe},
};

struct MessageBox {
    caption: String,
    text: String,
}

impl MessageBox {
    pub fn new(caption: impl AsRef<str>, text: impl AsRef<str>) -> Self {
        Self {
            caption: caption.as_ref().to_string(),
            text: text.as_ref().to_string(),
        }
    }
}

#[rustfmt::skip]
fn recipe_factory<Driver>(data: MessageBox) -> Recipe<Driver, WindowsOs<Driver>, MessageBox>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    recipe![
        Recipe::<_, WindowsOs<Driver>, _>::new(data),
        {
            inject! {
                user32!MessageBoxA(
                    0,                          // hWnd
                    data![text],                // lpText
                    data![caption],             // lpCaption
                    0                           // uType
                )
            }
        }
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (session, _profile) = common::create_vmi_session()?;

    let explorer_pid = {
        // This block is used to drop the pause guard after the PID is found.
        // If the `session.handle()` would be called with the VM paused, no
        // events would be triggered.
        let _pause_guard = session.pause_guard()?;

        let registers = session.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);

        let explorer = match common::find_process(&vmi, "explorer.exe")? {
            Some(explorer) => explorer,
            None => {
                tracing::error!("explorer.exe not found");
                return Ok(());
            }
        };

        tracing::info!(
            pid = %explorer.id()?,
            object = %explorer.object()?,
            "found explorer.exe"
        );

        explorer.id()?
    };

    session.handle(|session| {
        InjectorHandler::new(
            session,
            explorer_pid,
            recipe_factory(MessageBox::new(
                "Hello, World!",
                "This is a message box from the VMI!",
            )),
        )
    })?;

    Ok(())
}
