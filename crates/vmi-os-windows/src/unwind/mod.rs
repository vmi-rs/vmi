//! Stack unwinding support for Windows.
//!
//! This module provides types and traits for walking the call stack
//! of a Windows process using PE exception directory information.

pub mod amd64;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{ArchAdapter, WindowsOs, pe::PeImage};

/// A single frame in a stack trace.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The instruction pointer for this frame.
    pub instruction_pointer: Va,

    /// The stack pointer for this frame.
    pub stack_pointer: Va,

    /// The first four parameters (home space) from this frame.
    pub params: [u64; 4],

    /// True if this frame was produced by unwinding through a machine frame
    /// (UWOP_PUSH_MACHFRAME), indicating an interrupt, exception, or syscall
    /// boundary.
    pub machine_frame: bool,
}

/// Outcome of one unwind step.
#[derive(Debug, Clone)]
pub enum Unwound {
    /// A frame was successfully unwound.
    Frame(Frame),

    /// Bottom of the stack reached via a normal zero return address.
    End,

    /// Bottom of the stack reached via `UWOP_PUSH_MACHFRAME` with a zero
    /// RIP. Signals a trap handler at the bottom of the stack.
    MachineEnd,
}

/// A stack unwinder for a specific architecture.
///
/// Given the current unwind context and image, produces the next
/// frame by reading unwind metadata from the PE exception directory
/// and adjusting the context accordingly.
pub trait Unwinder<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Architecture-specific register.
    type Context;

    /// Unwinds one stack frame.
    fn unwind(
        &self,
        vmi: &VmiState<WindowsOs<Driver>>,
        image_base: Va,
        image: &impl PeImage,
        context: &mut Self::Context,
    ) -> Result<Unwound, VmiError>;
}
