use vmi_core::{Pa, Registers as _, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{
    LdrDataTableEntry, LdrDataTableEntryLayout, PebLdrData, PebLdrDataLayout, WindowsPebLdrData,
    WindowsPebLdrDataBase, WindowsProcessParameters, WindowsProcessParametersBase,
    WindowsWow64Kind,
    process_parameters::{
        CurDir, CurDirLayout, RtlUserProcessParameters, RtlUserProcessParametersLayout,
    },
};
use crate::{
    ListEntry, WindowsOs,
    arch::{ArchAdapter, StructLayout, StructLayout32, StructLayout64},
    iter::ListEntryLayout,
};

/// Field offsets for a `_PEB` structure.
pub trait Peb<Layout>
where
    Layout: StructLayout,
{
    /// Offset of the `Ldr` field.
    const OFFSET_LDR: u64;

    /// Offset of the `ProcessParameters` field.
    const OFFSET_PROCESS_PARAMETERS: u64;
}

/// `_PEB` structure layout.
pub struct PebLayout;

impl Peb<StructLayout32> for PebLayout {
    const OFFSET_LDR: u64 = 0x0c;
    const OFFSET_PROCESS_PARAMETERS: u64 = 0x10;
}

impl Peb<StructLayout64> for PebLayout {
    const OFFSET_LDR: u64 = 0x18;
    const OFFSET_PROCESS_PARAMETERS: u64 = 0x20;
}

/// PEB accessor with a compile-time pointer width.
///
/// # Implementation Details
///
/// Corresponds to `_PEB`.
pub struct WindowsPebBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    PebLayout: Peb<Layout>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_PEB` structure.
    va: Va,

    /// The translation root.
    root: Pa,

    _marker: std::marker::PhantomData<Layout>,
}

impl<'a, Driver, Layout> WindowsPebBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    PebLayout: Peb<Layout>,
{
    /// Creates a new PEB accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self {
            vmi,
            va,
            root,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the PEB loader data.
    pub fn ldr(&self) -> Result<WindowsPebLdrDataBase<'a, Driver, Layout>, VmiError>
    where
        ListEntryLayout: ListEntry<Layout>,
        PebLdrDataLayout: PebLdrData<Layout>,
        LdrDataTableEntryLayout: LdrDataTableEntry<Layout>,
    {
        let va = Layout::read_va(self.vmi, (self.va + PebLayout::OFFSET_LDR, self.root))?;
        Ok(WindowsPebLdrDataBase::new(self.vmi, va, self.root))
    }

    /// Returns the process parameters.
    pub fn process_parameters(
        &self,
    ) -> Result<WindowsProcessParametersBase<'a, Driver, Layout>, VmiError>
    where
        RtlUserProcessParametersLayout: RtlUserProcessParameters<Layout>,
        CurDirLayout: CurDir<Layout>,
    {
        let va = Layout::read_va(
            self.vmi,
            (self.va + PebLayout::OFFSET_PROCESS_PARAMETERS, self.root),
        )?;
        Ok(WindowsProcessParametersBase::new(self.vmi, va, self.root))
    }
}

enum WindowsPebWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    W32(WindowsPebBase<'a, Driver, StructLayout32>),
    W64(WindowsPebBase<'a, Driver, StructLayout64>),
}

impl<'a, Driver> WindowsPebWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn w32(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W32(WindowsPebBase::new(vmi, va, root))
    }

    fn w64(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W64(WindowsPebBase::new(vmi, va, root))
    }

    fn native(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        match vmi.registers().address_width() {
            4 => Self::w32(vmi, va, root),
            8 => Self::w64(vmi, va, root),
            _ => panic!("Unsupported address width"),
        }
    }

    fn ldr(&self) -> Result<WindowsPebLdrData<'a, Driver>, VmiError> {
        match self {
            Self::W32(inner) => Ok(WindowsPebLdrData::from(inner.ldr()?)),
            Self::W64(inner) => Ok(WindowsPebLdrData::from(inner.ldr()?)),
        }
    }

    fn process_parameters(&self) -> Result<WindowsProcessParameters<'a, Driver>, VmiError> {
        match self {
            Self::W32(inner) => Ok(WindowsProcessParameters::from(inner.process_parameters()?)),
            Self::W64(inner) => Ok(WindowsProcessParameters::from(inner.process_parameters()?)),
        }
    }
}

/// PEB accessor with a runtime pointer width.
///
/// The PEB is a user-mode structure that stores process-wide information,
/// such as loaded modules, heap data, and environment settings.
///
/// # Implementation Details
///
/// Corresponds to `_PEB`.
pub struct WindowsPeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    inner: WindowsPebWrapper<'a, Driver>,
}

impl<Driver> VmiVa for WindowsPeb<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        match &self.inner {
            WindowsPebWrapper::W32(inner) => inner.va,
            WindowsPebWrapper::W64(inner) => inner.va,
        }
    }
}

impl<'a, Driver> From<WindowsPebBase<'a, Driver, StructLayout32>> for WindowsPeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsPebBase<'a, Driver, StructLayout32>) -> Self {
        Self {
            inner: WindowsPebWrapper::W32(value),
        }
    }
}

impl<'a, Driver> From<WindowsPebBase<'a, Driver, StructLayout64>> for WindowsPeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsPebBase<'a, Driver, StructLayout64>) -> Self {
        Self {
            inner: WindowsPebWrapper::W64(value),
        }
    }
}

impl<Driver> std::fmt::Debug for WindowsPeb<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let process_parameters = self.process_parameters();

        f.debug_struct("WindowsPeb")
            .field("process_parameters", &process_parameters)
            .finish()
    }
}

impl<'a, Driver> WindowsPeb<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new PEB accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self::with_kind(vmi, va, vmi.translation_root(va), WindowsWow64Kind::Native)
    }

    /// Creates a new PEB accessor with an explicit address space root and
    /// pointer width.
    pub fn with_kind(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        let inner = match kind {
            WindowsWow64Kind::Native => WindowsPebWrapper::native(vmi, va, root),
            WindowsWow64Kind::X86 => WindowsPebWrapper::w32(vmi, va, root),
        };

        Self { inner }
    }

    /// Returns the PEB loader data.
    ///
    /// The loader data contains the three module lists maintained
    /// by the Windows loader.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB.Ldr`.
    pub fn ldr(&self) -> Result<WindowsPebLdrData<'a, Driver>, VmiError> {
        self.inner.ldr()
    }

    /// Returns the process parameters of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB.ProcessParameters`.
    pub fn process_parameters(&self) -> Result<WindowsProcessParameters<'a, Driver>, VmiError> {
        self.inner.process_parameters()
    }

    /// Returns the current directory.
    ///
    /// Shortcut for [`self.process_parameters()?.current_directory()`].
    ///
    /// [`self.process_parameters()?.current_directory()`]: WindowsProcessParameters::current_directory
    pub fn current_directory(&self) -> Result<String, VmiError> {
        self.process_parameters()?.current_directory()
    }

    /// Returns the DLL search path.
    ///
    /// Shortcut for [`self.process_parameters()?.dll_path()`].
    ///
    /// [`self.process_parameters()?.dll_path()`]: WindowsProcessParameters::dll_path
    pub fn dll_path(&self) -> Result<String, VmiError> {
        self.process_parameters()?.dll_path()
    }

    /// Returns the full path of the executable image.
    ///
    /// Shortcut for [`self.process_parameters()?.image_path_name()`].
    ///
    /// [`self.process_parameters()?.image_path_name()`]: WindowsProcessParameters::image_path_name
    pub fn image_path_name(&self) -> Result<String, VmiError> {
        self.process_parameters()?.image_path_name()
    }

    /// Returns the command line used to launch the process.
    ///
    /// Shortcut for [`self.process_parameters()?.command_line()`].
    ///
    /// [`self.process_parameters()?.command_line()`]: WindowsProcessParameters::command_line
    pub fn command_line(&self) -> Result<String, VmiError> {
        self.process_parameters()?.command_line()
    }
}
