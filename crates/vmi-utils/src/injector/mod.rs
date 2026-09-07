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
//!     utils::injector::{recipe, Recipe, UserInjectorHandler},
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
//! fn recipe_factory<Driver>(data: MessageBox) -> Recipe<WindowsOs<Driver>, MessageBox>
//! where
//!     Driver: VmiMemory<Architecture = Amd64>,
//! {
//!     recipe![
//!         Recipe::<WindowsOs<Driver>>::new(data),
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
//! # fn example<Driver>(
//! #     vmi: &vmi::VmiSession<WindowsOs<Driver>>,
//! #     pid: vmi::os::ProcessId,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     Driver: vmi::driver::VmiFullDriver<Architecture = Amd64>,
//! # {
//! // Create and execute the injection handler
//! vmi.handle(|vmi| {
//!     UserInjectorHandler::new(
//!         vmi,
//!         recipe_factory(MessageBox::new(
//!             "Hello from VMI",
//!             "Injected message box!"
//!         )),
//!     )?
//!     .with_pid(pid)
//! })?;
//! #
//! # Ok(())
//! # }
//! ```

use vmi_core::{VmiContext, VmiError, VmiEventResponse, VmiHandler, VmiSession, os::ProcessId};

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
use crate::bridge::BridgeDispatch;

mod recipe;
pub use self::recipe::{
    ImageSymbolCache, Recipe, RecipeContext, RecipeControlFlow, RecipeExecutor,
};

/// Marker trait for the privilege level of injected code.
///
/// See [`KernelMode`] and [`UserMode`].
pub trait ExecutionMode {}

/// Kernel-mode injection: code executes in kernel context.
pub struct KernelMode;
impl ExecutionMode for KernelMode {}

/// User-mode injection: code executes in the context of a target process.
pub struct UserMode;
impl ExecutionMode for UserMode {}

/// Maps an OS to its mode-specific injector handler implementation.
///
/// Each OS implements this trait once per [`ExecutionMode`], providing
/// the concrete handler type that performs the actual injection.
pub trait InjectorExecutionAdapter<Mode, T, Bridge>: OsAdapter
where
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Self>,
{
    /// The concrete handler type for this OS and execution mode.
    type Handler: InjectorHandlerAdapter<Self, Mode, T, Bridge>;
}

/// Constructs and configures an injector handler without a bridge.
pub trait InjectorHandlerFactory<Os, Mode, T>: InjectorHandlerAdapter<Os, Mode, T, ()>
where
    Os: InjectorExecutionAdapter<Mode, T, ()>,
    Mode: ExecutionMode,
{
    /// Creates a new handler without a guest-host bridge.
    fn new(vmi: &VmiSession<Os>, recipe: Recipe<Os, T>) -> Result<Self, VmiError>;

    /// Attaches a bridge for guest-host communication.
    fn with_bridge<Bridge>(
        self,
        bridge: Bridge,
    ) -> <Os as InjectorExecutionAdapter<Mode, T, Bridge>>::Handler
    where
        Bridge: BridgeDispatch<Os>,
        Os: InjectorExecutionAdapter<Mode, T, Bridge>;
}

/// Interface that mode-specific injector handlers must implement.
///
/// Provides configuration methods for the concrete handler selected by
/// [`InjectorExecutionAdapter`].
pub trait InjectorHandlerAdapter<Os, Mode, T, Bridge>: VmiHandler<Os> + Sized
where
    Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Os>,
{
    /// Restricts injection to a specific process.
    fn with_pid(self, pid: ProcessId) -> Result<Self, VmiError>;
}

/// Generic injector handler that delegates to an OS- and mode-specific
/// implementation.
///
/// Prefer the [`KernelInjectorHandler`] and [`UserInjectorHandler`] type
/// aliases. Start with [`InjectorHandler::new`], then attach a custom
/// [`BridgeDispatch`] using [`InjectorHandler::with_bridge`] when needed.
pub struct InjectorHandler<Os, Mode, T, Bridge = ()>
where
    Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Os>,
{
    inner: <Os as InjectorExecutionAdapter<Mode, T, Bridge>>::Handler,
    _marker: std::marker::PhantomData<(Os, Mode, T, Bridge)>,
}

impl<Os, Mode, T> InjectorHandler<Os, Mode, T, ()>
where
    Os: InjectorExecutionAdapter<Mode, T, ()>,
    <Os as InjectorExecutionAdapter<Mode, T, ()>>::Handler: InjectorHandlerFactory<Os, Mode, T>,
    Mode: ExecutionMode,
{
    /// Creates a new injector handler without a guest-host bridge.
    pub fn new(vmi: &VmiSession<Os>, recipe: Recipe<Os, T>) -> Result<Self, VmiError> {
        Ok(Self {
            inner: <Os as InjectorExecutionAdapter<Mode, T, ()>>::Handler::new(vmi, recipe)?,
            _marker: std::marker::PhantomData,
        })
    }

    /// Attaches a custom bridge for guest-host communication.
    pub fn with_bridge<Bridge>(self, bridge: Bridge) -> InjectorHandler<Os, Mode, T, Bridge>
    where
        Bridge: BridgeDispatch<Os>,
        Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    {
        InjectorHandler {
            inner: self.inner.with_bridge(bridge),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<Os, Mode, T, Bridge> InjectorHandler<Os, Mode, T, Bridge>
where
    Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Os>,
{
    /// Restricts injection to a specific process.
    pub fn with_pid(self, pid: ProcessId) -> Result<Self, VmiError> {
        Ok(Self {
            inner: self.inner.with_pid(pid)?,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<Os, Mode, T, Bridge> VmiHandler<Os> for InjectorHandler<Os, Mode, T, Bridge>
where
    Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Os>,
{
    type Output =
        <<Os as InjectorExecutionAdapter<Mode, T, Bridge>>::Handler as VmiHandler<Os>>::Output;

    fn handle_event(&mut self, vmi: VmiContext<Os>) -> VmiEventResponse<Os::Architecture> {
        self.inner.handle_event(vmi)
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.inner.poll()
    }
}

/// Kernel-mode injector handler.
///
/// Attach a custom [`BridgeDispatch`] with [`InjectorHandler::with_bridge`].
pub type KernelInjectorHandler<Os, T, Bridge = ()> = InjectorHandler<Os, KernelMode, T, Bridge>;

/// User-mode injector handler.
///
/// Attach a custom [`BridgeDispatch`] with [`InjectorHandler::with_bridge`].
pub type UserInjectorHandler<Os, T, Bridge = ()> = InjectorHandler<Os, UserMode, T, Bridge>;
