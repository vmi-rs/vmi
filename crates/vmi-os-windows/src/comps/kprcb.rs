use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::ThreadObject};

use super::macros::impl_offsets;
use crate::{
    ArchAdapter, CONTEXT_AMD64, KSPECIAL_REGISTERS_AMD64, WindowsContext, WindowsError, WindowsOs,
    WindowsSpecialRegisters, WindowsThread,
};

/// A Windows kernel processor control block (KPRCB).
///
/// The KPRCB is an opaque, per-processor structure embedded within
/// the KPCR. While the KPCR (`_KPCR`) is the top-level per-processor
/// region (anchored at `gs:[0]`), the KPRCB is its main body, holding
/// the current/next/idle thread pointers, saved processor context,
/// and scheduling state.
///
/// # Implementation Details
///
/// Corresponds to `_KPRCB`.
pub struct WindowsKernelProcessorBlock<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// The virtual address of the `_KPRCB` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsKernelProcessorBlock<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsKernelProcessorBlock<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new kernel processor control block.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the thread currently executing on this processor.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPRCB.CurrentThread`.
    pub fn current_thread(&self) -> Result<WindowsThread<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let KPRCB = &offsets._KPRCB;

        let result = self
            .vmi
            .read_va_native(self.va + KPRCB.CurrentThread.offset())?;

        if result.is_null() {
            return Err(WindowsError::CorruptedStruct("KPRCB.CurrentThread").into());
        }

        Ok(WindowsThread::new(self.vmi, ThreadObject(result)))
    }

    /// Returns the next thread scheduled to execute on this processor, if any.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPRCB.NextThread`.
    pub fn next_thread(&self) -> Result<Option<WindowsThread<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let KPRCB = &offsets._KPRCB;

        let result = self
            .vmi
            .read_va_native(self.va + KPRCB.NextThread.offset())?;

        if result.is_null() {
            // NextThread can be NULL.
            return Ok(None);
        }

        Ok(Some(WindowsThread::new(self.vmi, ThreadObject(result))))
    }

    /// Returns the idle thread for this processor.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPRCB.IdleThread`.
    pub fn idle_thread(&self) -> Result<WindowsThread<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let KPRCB = &offsets._KPRCB;

        let result = self
            .vmi
            .read_va_native(self.va + KPRCB.IdleThread.offset())?;

        if result.is_null() {
            return Err(WindowsError::CorruptedStruct("KPRCB.IdleThread").into());
        }

        Ok(WindowsThread::new(self.vmi, ThreadObject(result)))
    }

    /// Returns the processor's special registers.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPRCB.ProcessorState.SpecialRegisters`.
    pub fn processor_special_registers(&self) -> Result<impl WindowsSpecialRegisters, VmiError> {
        let offsets = self.offsets();
        let KPRCB = &offsets._KPRCB;
        let KPROCESSOR_STATE = &offsets._KPROCESSOR_STATE;

        self.vmi.read_struct::<KSPECIAL_REGISTERS_AMD64>(
            self.va + KPRCB.ProcessorState.offset() + KPROCESSOR_STATE.SpecialRegisters.offset(),
        )
    }

    /// Returns the processor's saved thread context.
    ///
    /// On Windows 7 and later, reads the context via `_KPRCB.Context` pointer,
    /// which may reference a dynamically-allocated buffer for extended state
    /// (XSAVE/AVX). Falls back to the embedded `ProcessorState.ContextFrame`
    /// when the pointer is NULL (pre-Win7 or early boot).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KPRCB.Context` or `_KPRCB.ProcessorState.ContextFrame`.
    pub fn processor_context(&self) -> Result<impl WindowsContext, VmiError> {
        let offsets = self.offsets();
        let KPRCB = &offsets._KPRCB;
        let KPROCESSOR_STATE = &offsets._KPROCESSOR_STATE;

        // KPRCB::Context is present since Windows 7. It is a pointer that
        // normally points to ProcessorState.ContextFrame, but may point to a
        // larger dynamically-allocated buffer when the CPU supports extended
        // state (XSAVE/AVX).
        //
        // On pre-Win7 systems the field doesn't exist, and during very early
        // boot (before KiInitializePcr runs) it may be NULL.  In either case,
        // fall back to reading ProcessorState.ContextFrame directly.

        let addr = self.vmi.read_va_native(self.va + KPRCB.Context.offset())?;

        if addr.is_null() {
            self.vmi.read_struct::<CONTEXT_AMD64>(
                self.va + KPRCB.ProcessorState.offset() + KPROCESSOR_STATE.ContextFrame.offset(),
            )
        }
        else {
            self.vmi.read_struct::<CONTEXT_AMD64>(addr)
        }
    }
}
