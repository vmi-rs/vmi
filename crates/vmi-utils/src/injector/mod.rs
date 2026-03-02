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

use vmi_core::{
    VmiContext, VmiDriver, VmiError, VmiEventResponse, VmiHandler, VmiSession, os::ProcessId,
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
use crate::bridge::BridgeHandler;

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
pub trait InjectorExecutionAdapter<Driver, Mode, T, Bridge>: OsAdapter<Driver>
where
    Driver: VmiDriver,
    Mode: ExecutionMode,
    Bridge: BridgeHandler<Driver, Self, InjectorResultCode>,
{
    /// The concrete handler type for this OS and execution mode.
    type Handler: InjectorHandlerAdapter<Driver, Self, Mode, T, Bridge>;
}

/// Interface that mode-specific injector handlers must implement.
///
/// Provides construction and configuration methods for the concrete
/// handler selected by [`InjectorExecutionAdapter`].
pub trait InjectorHandlerAdapter<Driver, Os, Mode, T, Bridge>:
    VmiHandler<Driver, Os> + Sized
where
    Driver: VmiDriver,
    Os: InjectorExecutionAdapter<Driver, Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeHandler<Driver, Os, InjectorResultCode>,
{
    /// Creates a new handler with a bridge for guest-host communication.
    fn with_bridge(
        vmi: &VmiSession<Driver, Os>,
        bridge: Bridge,
        recipe: Recipe<Driver, Os, T>,
    ) -> Result<Self, VmiError>;

    /// Restricts injection to a specific process.
    fn with_pid(self, pid: ProcessId) -> Result<Self, VmiError>;
}

/// Generic injector handler that delegates to an OS- and mode-specific
/// implementation.
///
/// Prefer the [`KernelInjectorHandler`] and [`UserInjectorHandler`] type
/// aliases for the common case without a bridge. When a custom
/// [`BridgeHandler`] is needed, use this type directly with an explicit
/// `Bridge` parameter.
pub struct InjectorHandler<Driver, Os, Mode, T, Bridge = ()>
where
    Driver: VmiDriver,
    Os: InjectorExecutionAdapter<Driver, Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeHandler<Driver, Os, InjectorResultCode>,
{
    inner: <Os as InjectorExecutionAdapter<Driver, Mode, T, Bridge>>::Handler,
    _marker: std::marker::PhantomData<(Driver, Os, Mode, T, Bridge)>,
}

impl<Driver, Os, Mode, T, Bridge> InjectorHandler<Driver, Os, Mode, T, Bridge>
where
    Driver: VmiDriver,
    Os: InjectorExecutionAdapter<Driver, Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeHandler<Driver, Os, InjectorResultCode>,
{
    /// Creates a new injector handler with a default (no-op) bridge.
    pub fn new(
        vmi: &VmiSession<Driver, Os>,
        recipe: Recipe<Driver, Os, T>,
    ) -> Result<Self, VmiError>
    where
        Bridge: Default,
    {
        Self::with_bridge(vmi, Bridge::default(), recipe)
    }

    /// Creates a new injector handler with a custom bridge for
    /// guest-host communication.
    pub fn with_bridge(
        vmi: &VmiSession<Driver, Os>,
        bridge: Bridge,
        recipe: Recipe<Driver, Os, T>,
    ) -> Result<Self, VmiError> {
        Ok(Self {
            inner: <Os as InjectorExecutionAdapter<Driver, Mode, T, Bridge>>::Handler::with_bridge(
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

impl<Driver, Os, Mode, T, Bridge> VmiHandler<Driver, Os>
    for InjectorHandler<Driver, Os, Mode, T, Bridge>
where
    Driver: VmiDriver,
    Os: InjectorExecutionAdapter<Driver, Mode, T, Bridge>,
    Mode: ExecutionMode,
    Bridge: BridgeHandler<Driver, Os, InjectorResultCode>,
{
    type Output =
        <<Os as InjectorExecutionAdapter<Driver, Mode, T, Bridge>>::Handler as VmiHandler<
            Driver,
            Os,
        >>::Output;

    fn handle_event(
        &mut self,
        vmi: VmiContext<Driver, Os>,
    ) -> VmiEventResponse<<Driver as VmiDriver>::Architecture> {
        self.inner.handle_event(vmi)
    }

    fn check_completion(&self) -> Option<Self::Output> {
        self.inner.check_completion()
    }
}

/// Kernel-mode injector handler without a bridge.
///
/// For injection with a custom [`BridgeHandler`], use
/// [`InjectorHandler<Driver, Os, KernelMode, T, Bridge>`] directly.
pub type KernelInjectorHandler<Driver, Os, T> = InjectorHandler<Driver, Os, KernelMode, T>;

/// User-mode injector handler without a bridge.
///
/// For injection with a custom [`BridgeHandler`], use
/// [`InjectorHandler<Driver, Os, UserMode, T, Bridge>`] directly.
pub type UserInjectorHandler<Driver, Os, T> = InjectorHandler<Driver, Os, UserMode, T>;
