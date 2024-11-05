use vmi_core::Va;

use super::Argument;

/// A builder struct for constructing calls to system functions, encapsulating
/// the function's address and its required arguments.
pub struct CallBuilder {
    /// The target function's virtual address.
    pub(super) function_address: Va,

    /// The arguments to pass to the function.
    pub(super) arguments: Vec<Argument>,
}

impl CallBuilder {
    /// Creates a new `CallBuilder` instance for a specified function address.
    pub fn new(function_address: Va) -> Self {
        Self {
            function_address,
            arguments: Vec::new(),
        }
    }

    /// Adds an argument to the function call being built.
    pub fn with_argument(mut self, argument: impl Into<Argument>) -> Self {
        self.arguments.push(argument.into());
        self
    }
}
