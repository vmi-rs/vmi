use vmi_core::{Architecture, Pa, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{WindowsWow64Kind, macros::impl_offsets};
use crate::{ArchAdapter, WindowsOs, WindowsPeb};

/// A Windows thread environment block (TEB).
///
/// The TEB is a user-mode structure that stores thread-specific information,
/// such as the last error value and thread-local storage.
/// This structure supports both **32-bit and 64-bit** TEBs.
///
/// # Implementation Details
///
/// Corresponds to `_TEB`.
pub struct WindowsTeb<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_TEB` structure.
    va: Va,

    /// The translation root.
    root: Pa,

    /// The kind of the process.
    kind: WindowsWow64Kind,
}

impl<Driver> VmiVa for WindowsTeb<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsTeb<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows TEB object.
    pub fn new(
        vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        Self {
            vmi,
            va,
            root,
            kind,
        }
    }

    /// Returns the process environment block (PEB) associated with the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.ProcessEnvironmentBlock`.
    pub fn peb(&self) -> Result<Option<WindowsPeb<'a, Driver>>, VmiError> {
        let field = match self.kind {
            WindowsWow64Kind::Native => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB;
                TEB.ProcessEnvironmentBlock
            }
            WindowsWow64Kind::X86 => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB32;
                TEB.ProcessEnvironmentBlock
            }
        };

        let va = Va(self.vmi.read_field_in((self.va, self.root), &field)?);

        if va.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsPeb::new(self.vmi, va, self.root, self.kind)))
    }

    /// Returns the last error value for the thread.
    ///
    /// The equivalent of `GetLastError()` in the Windows API.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.LastErrorValue`.
    pub fn last_error_value(&self) -> Result<u32, VmiError> {
        let offset = match self.kind {
            WindowsWow64Kind::Native => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB;
                TEB.LastErrorValue.offset()
            }
            WindowsWow64Kind::X86 => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB32;
                TEB.LastErrorValue.offset()
            }
        };

        self.vmi.read_u32_in((self.va + offset, self.root))
    }

    /// Returns the last status value for the current thread.
    ///
    /// In Windows, the last status value is typically used to store error codes
    /// or success indicators from system calls. This method reads this value
    /// from the Thread Environment Block (TEB) of the current thread, providing
    /// insight into the outcome of recent operations performed by the thread.
    ///
    /// Returns `None` if the TEB is not available.
    ///
    /// # Notes
    ///
    /// `LastStatusValue` is a `NTSTATUS` value, whereas `LastError` is a Win32
    /// error code. The two values are related but not identical. You can obtain
    /// the Win32 error code by calling
    /// [`WindowsTeb::last_error_value`](crate::WindowsTeb::last_error_value).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.LastStatusValue`.
    pub fn last_status_value(&self) -> Result<u32, VmiError> {
        let offset = match self.kind {
            WindowsWow64Kind::Native => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB;
                TEB.LastStatusValue.offset()
            }
            WindowsWow64Kind::X86 => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB32;
                TEB.LastStatusValue.offset()
            }
        };

        self.vmi.read_u32_in((self.va + offset, self.root))
    }

    /// Returns the value of the specified thread-local storage (TLS) slot.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.TlsSlots[index]`.
    pub fn tls_slot(&self, index: usize) -> Result<u64, VmiError> {
        const TLS_MINIMUM_AVAILABLE: usize = 64;
        debug_assert!(
            index < TLS_MINIMUM_AVAILABLE,
            "TLS slot index out of bounds: {index}"
        );

        let field = match self.kind {
            WindowsWow64Kind::Native => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB;
                TEB.TlsSlots
            }
            WindowsWow64Kind::X86 => {
                let offsets = self.offsets();
                let TEB = &offsets.common._TEB32;
                TEB.TlsSlots
            }
        };

        let size = (field.size() as usize) / TLS_MINIMUM_AVAILABLE;
        debug_assert!(size == 4 || size == 8, "Unexpected TLS slot size: {size}");

        let offset = field.offset() + (index * size) as u64;
        self.vmi.read_uint_in((self.va + offset, self.root), size)
    }
}
