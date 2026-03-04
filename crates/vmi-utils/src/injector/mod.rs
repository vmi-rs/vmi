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
//!         Recipe::<WindowsOs<Driver>, _>::new(data),
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
//! # let vmi: vmi::VmiSession<WindowsOs<VmiXenDriver<Amd64>>> = unimplemented!();
//! # let pid = unimplemented!();
//! #
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

/// Result code for the injector.
pub type InjectorResultCode = u64;

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
    Bridge: BridgeDispatch<Self, InjectorResultCode>,
{
    /// The concrete handler type for this OS and execution mode.
    type Handler: InjectorHandlerAdapter<Self, Mode, T, Bridge>;
}

/// Interface that mode-specific injector handlers must implement.
///
/// Provides construction and configuration methods for the concrete
/// handler selected by [`InjectorExecutionAdapter`].
pub trait InjectorHandlerAdapter<Os, Mode, T, Bridge>: VmiHandler<Os> + Sized
where
    Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Os, InjectorResultCode>,
{
    /// Creates a new handler with a bridge for guest-host communication.
    fn with_bridge(
        vmi: &VmiSession<Os>,
        bridge: Bridge,
        recipe: Recipe<Os, T>,
    ) -> Result<Self, VmiError>;

    /// Restricts injection to a specific process.
    fn with_pid(self, pid: ProcessId) -> Result<Self, VmiError>;
}

/// Generic injector handler that delegates to an OS- and mode-specific
/// implementation.
///
/// Prefer the [`KernelInjectorHandler`] and [`UserInjectorHandler`] type
/// aliases for the common case without a bridge. When a custom
/// [`BridgeDispatch`] is needed, use this type directly with an explicit
/// `Bridge` parameter.
pub struct InjectorHandler<Os, Mode, T, Bridge = ()>
where
    Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Os, InjectorResultCode>,
{
    inner: <Os as InjectorExecutionAdapter<Mode, T, Bridge>>::Handler,
    _marker: std::marker::PhantomData<(Os, Mode, T, Bridge)>,
}

impl<Os, Mode, T, Bridge> InjectorHandler<Os, Mode, T, Bridge>
where
    Os: InjectorExecutionAdapter<Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeDispatch<Os, InjectorResultCode>,
{
    /// Creates a new injector handler with a default (no-op) bridge.
    pub fn new(vmi: &VmiSession<Os>, recipe: Recipe<Os, T>) -> Result<Self, VmiError>
    where
        Bridge: Default,
    {
        Self::with_bridge(vmi, Bridge::default(), recipe)
    }

    /// Creates a new injector handler with a custom bridge for
    /// guest-host communication.
    pub fn with_bridge(
        vmi: &VmiSession<Os>,
        bridge: Bridge,
        recipe: Recipe<Os, T>,
    ) -> Result<Self, VmiError> {
        Ok(Self {
            inner: <Os as InjectorExecutionAdapter<Mode, T, Bridge>>::Handler::with_bridge(
                vmi, bridge, recipe,
            )?,
            _marker: std::marker::PhantomData,
        })
    }

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
    Bridge: BridgeDispatch<Os, InjectorResultCode>,
{
    type Output =
        <<Os as InjectorExecutionAdapter<Mode, T, Bridge>>::Handler as VmiHandler<Os>>::Output;

    fn handle_event(&mut self, vmi: VmiContext<Os>) -> VmiEventResponse<Os::Architecture> {
        self.inner.handle_event(vmi)
    }

    fn poll(&self) -> Option<Self::Output> {
        self.inner.poll()
    }
}

/// Kernel-mode injector handler without a bridge.
///
/// For injection with a custom [`BridgeDispatch`], use
/// [`InjectorHandler<Os, KernelMode, T, Bridge>`] directly.
pub type KernelInjectorHandler<Os, T> = InjectorHandler<Os, KernelMode, T>;

/// User-mode injector handler without a bridge.
///
/// For injection with a custom [`BridgeDispatch`], use
/// [`InjectorHandler<Os, UserMode, T, Bridge>`] directly.
pub type UserInjectorHandler<Os, T> = InjectorHandler<Os, UserMode, T>;
