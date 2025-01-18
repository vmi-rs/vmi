use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::{cow::VmiCow, session::VmiSession};
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
    session: VmiCow<'a, VmiSession<'a, Driver, Os>>,

    /// The VMI event.
    registers: &'a <Driver::Architecture as Architecture>::Registers,
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
        session: impl Into<VmiCow<'a, VmiSession<'a, Driver, Os>>>,
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
    pub fn session(&self) -> &VmiSession<Driver, Os> {
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
