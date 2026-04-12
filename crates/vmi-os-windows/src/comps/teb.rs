use vmi_core::{Pa, Registers as _, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{WindowsPeb, WindowsPebBase, WindowsWow64Kind};
use crate::{
    WindowsOs,
    arch::{ArchAdapter, StructLayout, StructLayout32, StructLayout64},
};

/// Field offsets for a `_TEB` structure.
pub trait Teb<Layout>
where
    Layout: StructLayout,
{
    /// Offset of the `ProcessEnvironmentBlock` field.
    const OFFSET_PROCESS_ENVIRONMENT_BLOCK: u64;

    /// Offset of the `LastErrorValue` field.
    const OFFSET_LAST_ERROR_VALUE: u64;

    /// Offset of the `LastStatusValue` field.
    const OFFSET_LAST_STATUS_VALUE: u64;

    /// Offset of the `TlsSlots` field.
    const OFFSET_TLS_SLOTS: u64;
}

/// `_TEB` structure layout.
pub struct TebLayout;

impl Teb<StructLayout32> for TebLayout {
    const OFFSET_PROCESS_ENVIRONMENT_BLOCK: u64 = 0x30;
    const OFFSET_LAST_ERROR_VALUE: u64 = 0x34;
    const OFFSET_LAST_STATUS_VALUE: u64 = 0x0bf4;
    const OFFSET_TLS_SLOTS: u64 = 0x0e10;
}

impl Teb<StructLayout64> for TebLayout {
    const OFFSET_PROCESS_ENVIRONMENT_BLOCK: u64 = 0x60;
    const OFFSET_LAST_ERROR_VALUE: u64 = 0x68;
    const OFFSET_LAST_STATUS_VALUE: u64 = 0x1250;
    const OFFSET_TLS_SLOTS: u64 = 0x1480;
}

/// TEB accessor with a compile-time pointer width.
///
/// # Implementation Details
///
/// Corresponds to `_TEB`.
pub struct WindowsTebBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    TebLayout: Teb<Layout>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// The virtual address of the `_TEB` structure.
    va: Va,

    /// The translation root.
    root: Pa,

    _marker: std::marker::PhantomData<Layout>,
}

impl<'a, Driver, Layout> WindowsTebBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    TebLayout: Teb<Layout>,
{
    /// Creates a new TEB accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self {
            vmi,
            va,
            root,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the process environment block (PEB) associated with the thread.
    pub fn peb(&self) -> Result<Option<WindowsPebBase<'a, Driver, Layout>>, VmiError>
    where
        super::peb::PebLayout: super::peb::Peb<Layout>,
    {
        let va = Layout::read_va(
            self.vmi,
            (
                self.va + TebLayout::OFFSET_PROCESS_ENVIRONMENT_BLOCK,
                self.root,
            ),
        )?;

        if va.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsPebBase::new(self.vmi, va, self.root)))
    }

    /// Returns the last error value for the thread.
    pub fn last_error_value(&self) -> Result<u32, VmiError> {
        self.vmi
            .read_u32_in((self.va + TebLayout::OFFSET_LAST_ERROR_VALUE, self.root))
    }

    /// Returns the last status value for the thread.
    pub fn last_status_value(&self) -> Result<u32, VmiError> {
        self.vmi
            .read_u32_in((self.va + TebLayout::OFFSET_LAST_STATUS_VALUE, self.root))
    }

    /// Returns the value of the specified thread-local storage (TLS) slot.
    pub fn tls_slot(&self, index: usize) -> Result<u64, VmiError> {
        const TLS_MINIMUM_AVAILABLE: usize = 64;
        debug_assert!(
            index < TLS_MINIMUM_AVAILABLE,
            "TLS slot index out of bounds: {index}"
        );

        let offset = TebLayout::OFFSET_TLS_SLOTS + (index as u64) * Layout::ADDRESS_WIDTH;
        self.vmi.read_uint_in(
            (self.va + offset, self.root),
            Layout::ADDRESS_WIDTH as usize,
        )
    }
}

enum WindowsTebWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    W32(WindowsTebBase<'a, Driver, StructLayout32>),
    W64(WindowsTebBase<'a, Driver, StructLayout64>),
}

impl<'a, Driver> WindowsTebWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn w32(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W32(WindowsTebBase::new(vmi, va, root))
    }

    fn w64(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W64(WindowsTebBase::new(vmi, va, root))
    }

    fn native(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        match vmi.registers().address_width() {
            4 => Self::w32(vmi, va, root),
            8 => Self::w64(vmi, va, root),
            _ => panic!("Unsupported address width"),
        }
    }

    fn peb(&self) -> Result<Option<WindowsPeb<'a, Driver>>, VmiError> {
        match self {
            Self::W32(inner) => Ok(inner.peb()?.map(WindowsPeb::from)),
            Self::W64(inner) => Ok(inner.peb()?.map(WindowsPeb::from)),
        }
    }

    fn last_error_value(&self) -> Result<u32, VmiError> {
        match self {
            Self::W32(inner) => inner.last_error_value(),
            Self::W64(inner) => inner.last_error_value(),
        }
    }

    fn last_status_value(&self) -> Result<u32, VmiError> {
        match self {
            Self::W32(inner) => inner.last_status_value(),
            Self::W64(inner) => inner.last_status_value(),
        }
    }

    fn tls_slot(&self, index: usize) -> Result<u64, VmiError> {
        match self {
            Self::W32(inner) => inner.tls_slot(index),
            Self::W64(inner) => inner.tls_slot(index),
        }
    }
}

/// TEB accessor with a runtime pointer width.
///
/// The TEB is a user-mode structure that stores thread-specific information,
/// such as the last error value and thread-local storage.
///
/// # Implementation Details
///
/// Corresponds to `_TEB`.
pub struct WindowsTeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    inner: WindowsTebWrapper<'a, Driver>,
}

impl<'a, Driver> From<WindowsTebBase<'a, Driver, StructLayout32>> for WindowsTeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsTebBase<'a, Driver, StructLayout32>) -> Self {
        Self {
            inner: WindowsTebWrapper::W32(value),
        }
    }
}

impl<'a, Driver> From<WindowsTebBase<'a, Driver, StructLayout64>> for WindowsTeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsTebBase<'a, Driver, StructLayout64>) -> Self {
        Self {
            inner: WindowsTebWrapper::W64(value),
        }
    }
}

impl<Driver> VmiVa for WindowsTeb<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        match &self.inner {
            WindowsTebWrapper::W32(inner) => inner.va,
            WindowsTebWrapper::W64(inner) => inner.va,
        }
    }
}

impl<'a, Driver> WindowsTeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new TEB accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self::with_kind(vmi, va, vmi.translation_root(va), WindowsWow64Kind::Native)
    }

    /// Creates a new TEB accessor with an explicit address space root and
    /// pointer width.
    pub fn with_kind(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        let inner = match kind {
            WindowsWow64Kind::Native => WindowsTebWrapper::native(vmi, va, root),
            WindowsWow64Kind::X86 => WindowsTebWrapper::w32(vmi, va, root),
        };

        Self { inner }
    }

    /// Returns the process environment block (PEB) associated with the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.ProcessEnvironmentBlock`.
    pub fn peb(&self) -> Result<Option<WindowsPeb<'a, Driver>>, VmiError> {
        self.inner.peb()
    }

    /// Returns the last error value for the thread.
    ///
    /// The equivalent of `GetLastError()` in the Windows API.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.LastErrorValue`.
    pub fn last_error_value(&self) -> Result<u32, VmiError> {
        self.inner.last_error_value()
    }

    /// Returns the last status value for the current thread.
    ///
    /// `LastStatusValue` is an `NTSTATUS` value, whereas `LastError` is a
    /// Win32 error code. You can obtain the Win32 error code by calling
    /// [`last_error_value`](Self::last_error_value).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.LastStatusValue`.
    pub fn last_status_value(&self) -> Result<u32, VmiError> {
        self.inner.last_status_value()
    }

    /// Returns the value of the specified thread-local storage (TLS) slot.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TEB.TlsSlots[index]`.
    pub fn tls_slot(&self, index: usize) -> Result<u64, VmiError> {
        self.inner.tls_slot(index)
    }
}
