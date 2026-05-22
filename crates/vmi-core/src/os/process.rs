use super::{RegionPredicate, VmiOs, VmiOsImageArchitecture, impl_ops, impl_predicate};
use crate::{Pa, Va, VmiDriver, VmiError, VmiVa};

impl_ops! {
    /// A process ID within a system.
    ProcessId, u32
}

impl_ops! {
    /// A process object within a system.
    ///
    /// Equivalent to `EPROCESS*` on Windows or `task_struct*` on Linux.
    ProcessObject, Va
}

impl VmiVa for ProcessObject {
    fn va(&self) -> Va {
        self.0
    }
}

impl ProcessObject {
    /// Checks if the process object is a null reference.
    pub fn is_null(&self) -> bool {
        self.0.0 == 0
    }

    /// Converts the process object to a 64-bit unsigned integer.
    pub fn to_u64(&self) -> u64 {
        self.0.0
    }
}

impl_predicate! {
    /// Predicate used by [`VmiOsExt::find_process`].
    ///
    /// [`VmiOsExt::find_process`]: super::VmiOsExt::find_process
    pub trait ProcessPredicate & impl for &str {
        fn matches(&self, process: &Os::Process<'_>) -> Result<bool, VmiError> {
            Ok(process.name()?.eq_ignore_ascii_case(self))
        }
    }

    #[any]
    pub struct AnyProcess;
}

impl<Os> ProcessPredicate<Os> for ProcessId
where
    Os: VmiOs,
{
    fn matches(&self, process: &Os::Process<'_>) -> Result<bool, VmiError> {
        Ok(process.id()? == *self)
    }
}

/// A trait for process objects.
///
/// This trait provides an abstraction over processes within a guest OS.
pub trait VmiOsProcess<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver = Driver, Process<'a> = Self>;

    /// Returns the process ID.
    fn id(&self) -> Result<ProcessId, VmiError>;

    /// Returns the process object.
    fn object(&self) -> Result<ProcessObject, VmiError>;

    /// Returns the name of the process.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `_EPROCESS.ImageFileName` (limited to 16 characters).
    /// - **Linux**: `_task_struct.comm` (limited to 16 characters).
    fn name(&self) -> Result<String, VmiError>;

    /// Returns the parent process ID.
    fn parent_id(&self) -> Result<ProcessId, VmiError>;

    /// Returns the architecture of the process.
    fn architecture(&self) -> Result<VmiOsImageArchitecture, VmiError>;

    /// Returns the process's page table translation root.
    fn translation_root(&self) -> Result<Pa, VmiError>;

    /// Returns the user-mode page table translation root.
    ///
    /// If KPTI is disabled, this function will return the same value as
    /// [`translation_root`](Self::translation_root).
    fn user_translation_root(&self) -> Result<Pa, VmiError>;

    /// Returns the base address of the process image.
    fn image_base(&self) -> Result<Va, VmiError>;

    /// Returns an iterator over the process's memory regions.
    fn regions(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs>::Region<'a>, VmiError>> + use<'a, Driver, Self>,
        VmiError,
    >;

    /// Returns the memory region containing the given address.
    fn lookup_region(
        &self,
        address: Va,
    ) -> Result<Option<<Self::Os as VmiOs>::Region<'a>>, VmiError>;

    /// Returns an iterator over the threads in the process.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `_EPROCESS.ThreadListHead`.
    fn threads(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs>::Thread<'a>, VmiError>> + use<'a, Driver, Self>,
        VmiError,
    >;

    /// Checks whether the given virtual address is valid in the process.
    ///
    /// This method checks if page-faulting on the address would result in
    /// a successful access.
    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError>;
}

/// Extension methods on [`VmiOsProcess`].
///
/// The blanket impl is the only impl of this trait, so implementors of
/// [`VmiOsProcess`] cannot override the default bodies.
pub trait VmiOsProcessExt<'a, Driver>: VmiOsProcess<'a, Driver>
where
    Driver: VmiDriver,
{
    /// Returns the first memory region matching `predicate`, or
    /// `Ok(None)` if no region in the process matches.
    fn find_region(
        &self,
        predicate: impl RegionPredicate<Self::Os>,
    ) -> Result<Option<<Self::Os as VmiOs>::Region<'a>>, VmiError> {
        for region in self.regions()? {
            let region = region?;

            if predicate.matches(&region)? {
                return Ok(Some(region));
            }
        }

        Ok(None)
    }

    /// Returns an iterator over the memory regions matching `predicate`.
    fn filter_regions(
        &self,
        predicate: impl RegionPredicate<Self::Os>,
    ) -> Result<impl Iterator<Item = Result<<Self::Os as VmiOs>::Region<'a>, VmiError>>, VmiError>
    {
        let mut regions = self.regions()?;

        Ok(std::iter::from_fn(move || {
            for region in regions.by_ref() {
                let region = match region {
                    Ok(region) => region,
                    Err(err) => return Some(Err(err)),
                };

                match predicate.matches(&region) {
                    Ok(true) => return Some(Ok(region)),
                    Ok(false) => continue,
                    Err(err) => return Some(Err(err)),
                }
            }

            None
        }))
    }
}

impl<'a, Driver, T> VmiOsProcessExt<'a, Driver> for T
where
    Driver: VmiDriver,
    T: VmiOsProcess<'a, Driver>,
{
}
