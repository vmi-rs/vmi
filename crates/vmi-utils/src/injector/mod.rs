//! Code injection functionality.
//!
//! This module provides mechanisms for injecting and executing code in
//! a running process or kernel. It handles thread hijacking, code execution
//! monitoring, and cleanup. The injection process is defined using recipes -
//! declarative sequences of steps that specify what code to inject and how to
//! execute it.
//!
//! # Limitations
//!
//! The injector currently only supports Windows OS and AMD64 architecture.
//! Injections into 32-bit processes are not currently supported.
//!
//! # Examples
//!
//!  Inject a `MessageBox()` call into a running process:
//!
//! ```no_run
//! use vmi::{
//!     arch::amd64::Amd64,
//!     driver::VmiMemory,
//!     os::windows::WindowsOs,
//!     utils::injector::{recipe, InjectorHandler, Recipe},
//! };
//!
//! struct MessageBox {
//!     caption: String,
//!     text: String,
//! }
//!
//! impl MessageBox {
//!     pub fn new(caption: impl AsRef<str>, text: impl AsRef<str>) -> Self {
//!         Self {
//!             caption: caption.as_ref().to_string(),
//!             text: text.as_ref().to_string(),
//!         }
//!     }
//! }
//!
//! fn recipe_factory<Driver>(data: MessageBox) -> Recipe<Driver, WindowsOs<Driver>, MessageBox>
//! where
//!     Driver: VmiMemory<Architecture = Amd64>,
//! {
//!     recipe![
//!         Recipe::<_, WindowsOs<Driver>, _>::new(data),
//!         {
//!             inject! {
//!                 user32!MessageBoxA(
//!                     0,                          // hWnd
//!                     data![text],                // lpText
//!                     data![caption],             // lpCaption
//!                     0                           // uType
//!                 )
//!             }
//!         }
//!     ]
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # use vmi::driver::xen::VmiXenDriver;
//! # let vmi: vmi::VmiSession<VmiXenDriver<Amd64>, WindowsOs<VmiXenDriver<Amd64>>> = unimplemented!();
//! # let pid = unimplemented!();
//! #
//! // Create and execute the injection handler
//! vmi.handle(|vmi| {
//!     InjectorHandler::new(
//!         vmi,
//!         pid,
//!         recipe_factory(MessageBox::new(
//!             "Hello from VMI",
//!             "Injected message box!"
//!         )),
//!     )
//! })?;
//! #
//! # Ok(())
//! # }
//! ```

use vmi_core::{
    Pa, Va, View, VmiDriver,
    os::{ProcessId, ThreadId, VmiOs},
};

mod arch;
pub use self::arch::ArchAdapter;

mod os;
pub use self::os::OsAdapter;

mod argument;
pub use self::argument::{Argument, ArgumentData};

mod call;
pub use self::call::CallBuilder;

#[doc(hidden)]
pub mod macros;
#[doc(inline)]
pub use crate::_private_recipe as recipe;
use crate::bridge::{BridgeHandler, BridgePacket};

mod recipe;
pub use self::recipe::{
    ImageSymbolCache, Recipe, RecipeContext, RecipeControlFlow, RecipeExecutor,
};

/// Result code for the injector.
pub type InjectorResultCode = u64;

/// A handler for managing code injection into a running system.
///
/// The handler monitors CPU events to hijack threads, inject code, and track execution.
/// It uses recipes to define the injection sequence and maintains state about the
/// injection process.
pub struct InjectorHandler<Driver, Os, T, Bridge = ()>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver> + OsAdapter<Driver>,
    Bridge: BridgeHandler<Driver, Os, InjectorResultCode>,
{
    /// Process ID being injected into.
    pub(super) pid: ProcessId,

    /// Thread ID that was hijacked for injection.
    pub(super) tid: Option<ThreadId>,

    /// Whether a thread has been successfully hijacked.
    pub(super) hijacked: bool,

    /// Virtual address of the instruction pointer in the hijacked thread.
    pub(super) ip_va: Option<Va>,

    /// Physical address of the instruction pointer in the hijacked thread.
    pub(super) ip_pa: Option<Pa>,

    /// Executor for running the injection recipe.
    pub(super) recipe: RecipeExecutor<Driver, Os, T>,

    /// Memory view used for injection operations.
    pub(super) view: View,

    /// Bridge.
    pub(super) bridge: Bridge,

    /// Whether the injection has completed.
    pub(super) finished: Option<Result<InjectorResultCode, BridgePacket>>,
}
