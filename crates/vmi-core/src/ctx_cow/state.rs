use std::borrow::Cow;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::session::VmiSession;
use crate::{os::VmiOs, Architecture, Pa, Registers as _, Va, VmiCore, VmiDriver, VmiError};

/// A VMI context.
///
/// `VmiState` combines access to a [`VmiSession`] with [`VmiEvent`] to
/// provide unified access to VMI operations in the context of a specific event.
///
/// This structure is created inside the [`VmiSession::handle`] method and
/// passed to the [`VmiHandler::handle_event`] method to handle VMI events.
///
/// [`VmiHandler::handle_event`]: crate::VmiHandler::handle_event
pub struct VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI session.
    session: Cow<'a, VmiSession<'a, Driver, Os>>,

    /// The VMI event.
    registers: &'a <Driver::Architecture as Architecture>::Registers,
}

impl<'a, Driver, Os> Clone for VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            registers: self.registers,
        }
    }
}

impl<'a, Driver, Os> From<VmiState<'a, Driver, Os>> for Cow<'a, VmiState<'a, Driver, Os>>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn from(value: VmiState<'a, Driver, Os>) -> Self {
        Cow::Owned(value)
    }
}

impl<'a, Driver, Os> From<&'a VmiState<'a, Driver, Os>> for Cow<'a, VmiState<'a, Driver, Os>>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn from(value: &'a VmiState<'a, Driver, Os>) -> Self {
        Cow::Borrowed(value)
    }
}

impl<'a, Driver, Os> std::ops::Deref for VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    type Target = VmiSession<'a, Driver, Os>;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl<'a, Driver, Os> VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new VMI context.
    pub fn new(
        session: impl Into<Cow<'a, VmiSession<'a, Driver, Os>>>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
    ) -> Self {
        Self {
            session: session.into(),
            registers,
        }
    }

    // Note that `core()` and `underlying_os()` are delegated to the `VmiSession`.

    /// Returns the VMI session.
    pub fn session(&self) -> &VmiSession<Driver, Os> {
        &self.session
    }

    /// Returns the CPU registers associated with the current event.
    pub fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers {
        self.registers
    }

    /// Returns a wrapper providing access to OS-specific operations.
    pub fn os(&self) -> VmiOsState<Driver, Os> {
        VmiOsState {
            session: &self.session,
            registers: self.registers,
        }
    }

    /// Returns the return address from the current stack frame.
    pub fn return_address(&self) -> Result<Va, VmiError> {
        self.registers().return_address(self.core())
    }

    /// Reads memory from the virtual machine.
    pub fn read(&self, address: Va, buffer: &mut [u8]) -> Result<(), VmiError> {
        self.core().read(self.access_context(address), buffer)
    }

    /// Writes memory to the virtual machine.
    pub fn write(&self, address: Va, buffer: &[u8]) -> Result<(), VmiError> {
        self.core().write(self.access_context(address), buffer)
    }

    /// Reads a single byte from the virtual machine.
    pub fn read_u8(&self, address: Va) -> Result<u8, VmiError> {
        self.core().read_u8(self.access_context(address))
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    pub fn read_u16(&self, address: Va) -> Result<u16, VmiError> {
        self.core().read_u16(self.access_context(address))
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    pub fn read_u32(&self, address: Va) -> Result<u32, VmiError> {
        self.core().read_u32(self.access_context(address))
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    pub fn read_u64(&self, address: Va) -> Result<u64, VmiError> {
        self.core().read_u64(self.access_context(address))
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va(&self, address: Va) -> Result<Va, VmiError> {
        self.core().read_va(
            self.access_context(address),
            self.registers().effective_address_width(),
        )
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    pub fn read_va32(&self, address: Va) -> Result<Va, VmiError> {
        self.core().read_va32(self.access_context(address))
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    pub fn read_va64(&self, address: Va) -> Result<Va, VmiError> {
        self.core().read_va64(self.access_context(address))
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    pub fn read_string_bytes(&self, address: Va) -> Result<Vec<u8>, VmiError> {
        self.core().read_string_bytes(self.access_context(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring_bytes(&self, address: Va) -> Result<Vec<u16>, VmiError> {
        self.core().read_wstring_bytes(self.access_context(address))
    }

    /// Reads a null-terminated string from the virtual machine.
    pub fn read_string(&self, address: Va) -> Result<String, VmiError> {
        self.core().read_string(self.access_context(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring(&self, address: Va) -> Result<String, VmiError> {
        self.core().read_wstring(self.access_context(address))
    }

    /// Reads a struct from the virtual machine.
    pub fn read_struct<T>(&self, address: Va) -> Result<T, VmiError>
    where
        T: IntoBytes + FromBytes,
    {
        self.core().read_struct(self.access_context(address))
    }

    /// Writes a single byte to the virtual machine.
    pub fn write_u8(&self, address: Va, value: u8) -> Result<(), VmiError> {
        self.core().write_u8(self.access_context(address), value)
    }

    /// Writes a 16-bit unsigned integer to the virtual machine.
    pub fn write_u16(&self, address: Va, value: u16) -> Result<(), VmiError> {
        self.core().write_u16(self.access_context(address), value)
    }

    /// Writes a 32-bit unsigned integer to the virtual machine.
    pub fn write_u32(&self, address: Va, value: u32) -> Result<(), VmiError> {
        self.core().write_u32(self.access_context(address), value)
    }

    /// Writes a 64-bit unsigned integer to the virtual machine.
    pub fn write_u64(&self, address: Va, value: u64) -> Result<(), VmiError> {
        self.core().write_u64(self.access_context(address), value)
    }

    /// Writes a struct to the virtual machine.
    pub fn write_struct<T>(&self, address: Va, value: T) -> Result<(), VmiError>
    where
        T: FromBytes + IntoBytes + Immutable,
    {
        self.core()
            .write_struct(self.access_context(address), value)
    }

    /// Translates a virtual address to a physical address.
    pub fn translate_address(&self, va: Va) -> Result<Pa, VmiError> {
        self.core()
            .translate_address((va, self.translation_root(va)))
    }

    /// Returns the physical address of the root of the current page table
    /// hierarchy for a given virtual address.
    fn translation_root(&self, va: Va) -> Pa {
        self.registers().translation_root(va)
    }

    /// Creates an address context for a given virtual address.
    fn access_context(&self, address: Va) -> (Va, Pa) {
        (address, self.translation_root(address))
    }
}

/// Wrapper providing access to OS-specific operations.
pub struct VmiOsState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI session.
    session: &'a VmiSession<'a, Driver, Os>,

    /// The VMI event.
    registers: &'a <Driver::Architecture as Architecture>::Registers,
}

impl<'a, Driver, Os> VmiOsState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Returns the VMI core.
    pub fn core(&self) -> &VmiCore<Driver> {
        self.session.core()
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &Os {
        self.session.underlying_os()
    }

    /// Returns the VMI session.
    pub fn session(&self) -> &VmiSession<'a, Driver, Os> {
        self.session
    }

    /// Returns the CPU registers associated with the current event.
    pub fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers {
        self.registers
    }

    //    /// Retrieves a specific function argument according to the calling
    //    /// convention of the operating system.
    //    pub fn function_argument_for_registers(
    //        &self,
    //        registers: &<Driver::Architecture as Architecture>::Registers,
    //        index: u64,
    //    ) -> Result<u64, VmiError> {
    //        self.underlying_os()
    //            .function_argument(self.core(), registers, index)
    //    }
    //
    //    /// Retrieves the return value of a function.
    //    pub fn function_return_value_for_registers(
    //        &self,
    //        registers: &<Driver::Architecture as Architecture>::Registers,
    //    ) -> Result<u64, VmiError> {
    //        self.underlying_os()
    //            .function_return_value(self.core(), registers)
    //    }
}

/*

/// Prober for safely handling page faults during memory access operations.
pub struct VmiStateProber<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI context.
    pub(super) state: &'a VmiState<'a, Driver, Os>,

    /// The set of restricted page faults that are allowed to occur.
    pub(super) restricted: Rc<IndexSet<PageFault>>,

    /// The set of page faults that have occurred.
    pub(super) page_faults: Rc<RefCell<IndexSet<PageFault>>>,
}

impl<'a, Driver, Os> VmiStateProber<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new VMI context prober.
    pub fn new(state: &'a VmiState<Driver, Os>, restricted: &IndexSet<PageFault>) -> Self {
        Self {
            state,
            restricted: Rc::new(restricted.clone()),
            page_faults: Rc::new(RefCell::new(IndexSet::new())),
        }
    }

    /// Returns the VMI context prober.
    pub fn core(&self) -> &'a VmiCore<Driver> {
        self.state.core()
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &'a Os {
        self.state.underlying_os()
    }

    /// Returns the VMI session prober.
    pub fn session(&self) -> VmiSessionProber<'a, Driver, Os> {
        VmiSessionProber {
            session: self.state.session,
            restricted: self.restricted.clone(),
            page_faults: self.page_faults.clone(),
        }
    }

    /// Returns the CPU registers associated with the current event.
    pub fn registers(&self) -> &'a <Driver::Architecture as Architecture>::Registers {
        self.state.registers()
    }

    /// Returns a wrapper providing access to OS-specific operations.
    pub fn os(&self) -> VmiOsStateProber<Driver, Os> {
        VmiOsStateProber(self)
    }

    /// Handles a result that may contain page faults, returning the value if successful.
    pub fn check_result<T>(&self, result: Result<T, VmiError>) -> Result<Option<T>, VmiError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(VmiError::PageFault(pfs)) => {
                self.check_restricted(pfs);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Records any page faults that are not in the restricted set.
    fn check_restricted(&self, pfs: PageFaults) {
        let mut page_faults = self.page_faults.borrow_mut();
        for pf in pfs {
            if !self.restricted.contains(&pf) {
                tracing::trace!(va = %pf.address, "page fault");
                page_faults.insert(pf);
            }
            else {
                tracing::trace!(va = %pf.address, "restricted page fault");
            }
        }
    }

    /// Checks for any unexpected page faults that have occurred and returns an error if any are present.
    #[tracing::instrument(skip_all)]
    pub fn error_for_page_faults(&self) -> Result<(), VmiError> {
        let pfs = self.page_faults.borrow();
        let new_pfs = &*pfs - &self.restricted;
        if !new_pfs.is_empty() {
            tracing::trace!(?new_pfs);
            return Err(VmiError::page_faults(new_pfs));
        }

        Ok(())
    }

    /*
    /// Returns the return address from the current stack frame.
    pub fn return_address(&self) -> Result<Option<Va>, VmiError> {
        self.check_result(self.state.return_address())
    }

    /// Reads memory from the virtual machine.
    pub fn read(&self, address: Va, buffer: &mut [u8]) -> Result<Option<()>, VmiError> {
        self.check_result(self.state.read(address, buffer))
    }

    /// Reads a single byte from the virtual machine.
    pub fn read_u8(&self, address: Va) -> Result<Option<u8>, VmiError> {
        self.check_result(self.state.read_u8(address))
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    pub fn read_u16(&self, address: Va) -> Result<Option<u16>, VmiError> {
        self.check_result(self.state.read_u16(address))
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    pub fn read_u32(&self, address: Va) -> Result<Option<u32>, VmiError> {
        self.check_result(self.state.read_u32(address))
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    pub fn read_u64(&self, address: Va) -> Result<Option<u64>, VmiError> {
        self.check_result(self.state.read_u64(address))
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va(&self, address: Va) -> Result<Option<Va>, VmiError> {
        self.check_result(self.state.read_va(address))
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    pub fn read_va32(&self, address: Va) -> Result<Option<Va>, VmiError> {
        self.check_result(self.state.read_va32(address))
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    pub fn read_va64(&self, address: Va) -> Result<Option<Va>, VmiError> {
        self.check_result(self.state.read_va64(address))
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    pub fn read_string_bytes(&self, address: Va) -> Result<Option<Vec<u8>>, VmiError> {
        self.check_result(self.state.read_string_bytes(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring_bytes(&self, address: Va) -> Result<Option<Vec<u16>>, VmiError> {
        self.check_result(self.state.read_wstring_bytes(address))
    }

    /// Reads a null-terminated string from the virtual machine.
    pub fn read_string(&self, address: Va) -> Result<Option<String>, VmiError> {
        self.check_result(self.state.read_string(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring(&self, address: Va) -> Result<Option<String>, VmiError> {
        self.check_result(self.state.read_wstring(address))
    }

    /// Reads a struct from the virtual machine.
    pub fn read_struct<T>(&self, address: Va) -> Result<Option<T>, VmiError>
    where
        T: IntoBytes + FromBytes,
    {
        self.check_result(self.state.read_struct(address))
    }
    */
}

/// Wrapper providing access to OS-specific operations with page fault handling.
pub struct VmiOsStateProber<'a, Driver, Os>(&'a VmiStateProber<'a, Driver, Os>)
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>;

impl<'a, Driver, Os> VmiOsStateProber<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Returns the VMI context prober.
    pub fn core(&self) -> &'a VmiCore<Driver> {
        self.0.core()
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &'a Os {
        self.0.underlying_os()
    }

    /// Returns the CPU registers associated with the current event.
    pub fn registers(&self) -> &'a <Driver::Architecture as Architecture>::Registers {
        self.0.registers()
    }

    /// Handles a result that may contain page faults, returning the value if successful.
    pub fn check_result<T>(&self, result: Result<T, VmiError>) -> Result<Option<T>, VmiError> {
        self.0.check_result(result)
    }

    /// Retrieves a specific function argument according to the calling
    /// convention of the operating system.
    pub fn function_argument_for_registers(
        &self,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<Option<u64>, VmiError> {
        self.0.check_result(
            self.0
                .underlying_os()
                .function_argument(self.core(), registers, index),
        )
    }

    /// Retrieves the return value of a function.
    pub fn function_return_value_for_registers(
        &self,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<u64>, VmiError> {
        self.0.check_result(
            self.0
                .underlying_os()
                .function_return_value(self.core(), registers),
        )
    }
}
*/
