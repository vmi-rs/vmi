use isr_macros::Field;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::session::VmiSession;
use crate::{
    os::VmiOs, AccessContext, AddressContext, Architecture, Pa, Registers as _, Va, VmiCore,
    VmiDriver, VmiError,
};

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
    session: &'a VmiSession<'a, Driver, Os>,

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
            session: self.session,
            registers: self.registers,
        }
    }
}

impl<'a, Driver, Os> Copy for VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
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
        session: &'a VmiSession<'a, Driver, Os>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
    ) -> Self {
        Self { session, registers }
    }

    /// Creates a new VMI context with the specified registers.
    pub fn with_registers(
        &'a self,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
    ) -> Self {
        Self {
            session: self.session,
            registers,
        }
    }

    // Note that `core()` and `underlying_os()` are delegated to the `VmiSession`.

    /// Returns the VMI session.
    pub fn session(&self) -> &'a VmiSession<'a, Driver, Os> {
        self.session
    }

    /// Returns the CPU registers associated with the current event.
    pub fn registers(&self) -> &'a <Driver::Architecture as Architecture>::Registers {
        self.registers
    }

    /// Returns a wrapper providing access to OS-specific operations.
    pub fn os(&self) -> VmiOsState<'a, Driver, Os> {
        VmiOsState(*self)
    }

    /// Creates an address context for a given virtual address.
    pub fn access_context(&self, address: Va) -> AccessContext {
        self.registers().access_context(address)
    }

    /// Creates an address context for a given virtual address.
    pub fn address_context(&self, address: Va) -> AddressContext {
        self.registers().address_context(address)
    }

    /// Returns the physical address of the root of the current page table
    /// hierarchy for a given virtual address.
    pub fn translation_root(&self, va: Va) -> Pa {
        self.registers().translation_root(va)
    }

    /// Returns the return address from the current stack frame.
    pub fn return_address(&self) -> Result<Va, VmiError> {
        self.registers().return_address(self.core())
    }

    /// Translates a virtual address to a physical address.
    pub fn translate_address(&self, va: Va) -> Result<Pa, VmiError> {
        self.core().translate_address(self.address_context(va))
    }

    // region: Read

    /// Reads memory from the virtual machine.
    pub fn read(&self, address: Va, buffer: &mut [u8]) -> Result<(), VmiError> {
        self.read_in(self.access_context(address), buffer)
    }

    /// Writes memory to the virtual machine.
    pub fn write(&self, address: Va, buffer: &[u8]) -> Result<(), VmiError> {
        self.write_in(self.access_context(address), buffer)
    }

    /// Reads a single byte from the virtual machine.
    pub fn read_u8(&self, address: Va) -> Result<u8, VmiError> {
        self.read_u8_in(self.access_context(address))
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    pub fn read_u16(&self, address: Va) -> Result<u16, VmiError> {
        self.read_u16_in(self.access_context(address))
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    pub fn read_u32(&self, address: Va) -> Result<u32, VmiError> {
        self.read_u32_in(self.access_context(address))
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    pub fn read_u64(&self, address: Va) -> Result<u64, VmiError> {
        self.read_u64_in(self.access_context(address))
    }

    /// Reads an unsigned integer of the specified size from the virtual machine.
    ///
    /// This method reads an unsigned integer of the specified size (in bytes)
    /// from the given access context. Note that the size must be 1, 2, 4, or 8.
    /// The result is returned as a `u64` to accommodate the widest possible
    /// integer size.
    pub fn read_uint(&self, address: Va, size: usize) -> Result<u64, VmiError> {
        self.read_uint_in(self.access_context(address), size)
    }

    /// TODO: xxx
    pub fn read_field(&self, base_address: Va, field: &Field) -> Result<u64, VmiError> {
        self.read_field_in(self.access_context(base_address), field)
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    pub fn read_address(&self, address: Va) -> Result<u64, VmiError> {
        self.read_address_in(self.access_context(address))
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    pub fn read_address_native(&self, address: Va) -> Result<u64, VmiError> {
        self.read_address_native_in(self.access_context(address))
    }

    /// Reads a 32-bit address from the virtual machine.
    pub fn read_address32(&self, address: Va) -> Result<u64, VmiError> {
        self.read_address32_in(self.access_context(address))
    }

    /// Reads a 64-bit address from the virtual machine.
    pub fn read_address64(&self, address: Va) -> Result<u64, VmiError> {
        self.read_address64_in(self.access_context(address))
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va(&self, address: Va) -> Result<Va, VmiError> {
        self.read_va_in(self.access_context(address))
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va_native(&self, address: Va) -> Result<Va, VmiError> {
        self.read_va_native_in(self.access_context(address))
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    pub fn read_va32(&self, address: Va) -> Result<Va, VmiError> {
        self.read_va32_in(self.access_context(address))
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    pub fn read_va64(&self, address: Va) -> Result<Va, VmiError> {
        self.read_va64_in(self.access_context(address))
    }

    /// Reads a null-terminated string of bytes from the virtual machine with a
    /// specified limit.
    pub fn read_string_bytes_limited(
        &self,
        address: Va,
        limit: usize,
    ) -> Result<Vec<u8>, VmiError> {
        self.read_string_bytes_limited_in(self.access_context(address), limit)
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    pub fn read_string_bytes(&self, address: Va) -> Result<Vec<u8>, VmiError> {
        self.read_string_bytes_in(self.access_context(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine
    /// with a specified limit.
    pub fn read_wstring_bytes_limited(
        &self,
        address: Va,
        limit: usize,
    ) -> Result<Vec<u16>, VmiError> {
        self.read_wstring_bytes_limited_in(self.access_context(address), limit)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring_bytes(&self, address: Va) -> Result<Vec<u16>, VmiError> {
        self.read_wstring_bytes_in(self.access_context(address))
    }

    /// Reads a null-terminated string from the virtual machine with a specified
    /// limit.
    pub fn read_string_limited(&self, address: Va, limit: usize) -> Result<String, VmiError> {
        self.read_string_limited_in(self.access_context(address), limit)
    }

    /// Reads a null-terminated string from the virtual machine.
    pub fn read_string(&self, address: Va) -> Result<String, VmiError> {
        self.read_string_in(self.access_context(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine
    /// with a specified limit.
    pub fn read_wstring_limited(&self, address: Va, limit: usize) -> Result<String, VmiError> {
        self.read_wstring_limited_in(self.access_context(address), limit)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring(&self, address: Va) -> Result<String, VmiError> {
        self.read_wstring_in(self.access_context(address))
    }

    /// Reads a struct from the virtual machine.
    pub fn read_struct<T>(&self, address: Va) -> Result<T, VmiError>
    where
        T: IntoBytes + FromBytes,
    {
        self.read_struct_in(self.access_context(address))
    }

    // endregion: Read

    // region: Read in

    /// Reads memory from the virtual machine.
    pub fn read_in(
        &self,
        ctx: impl Into<AccessContext>,
        buffer: &mut [u8],
    ) -> Result<(), VmiError> {
        self.core().read(ctx, buffer)
    }

    /// Writes memory to the virtual machine.
    pub fn write_in(&self, ctx: impl Into<AccessContext>, buffer: &[u8]) -> Result<(), VmiError> {
        self.core().write(ctx, buffer)
    }

    /// Reads a single byte from the virtual machine.
    pub fn read_u8_in(&self, ctx: impl Into<AccessContext>) -> Result<u8, VmiError> {
        self.core().read_u8(ctx)
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    pub fn read_u16_in(&self, ctx: impl Into<AccessContext>) -> Result<u16, VmiError> {
        self.core().read_u16(ctx)
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    pub fn read_u32_in(&self, ctx: impl Into<AccessContext>) -> Result<u32, VmiError> {
        self.core().read_u32(ctx)
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    pub fn read_u64_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core().read_u64(ctx)
    }

    /// Reads an unsigned integer of the specified size from the virtual machine.
    ///
    /// This method reads an unsigned integer of the specified size (in bytes)
    /// from the given access context. Note that the size must be 1, 2, 4, or 8.
    /// The result is returned as a `u64` to accommodate the widest possible
    /// integer size.
    pub fn read_uint_in(
        &self,
        ctx: impl Into<AccessContext>,
        size: usize,
    ) -> Result<u64, VmiError> {
        self.core().read_uint(ctx, size)
    }

    /// TODO: xxx
    pub fn read_field_in(
        &self,
        ctx: impl Into<AccessContext>,
        field: &Field,
    ) -> Result<u64, VmiError> {
        self.core().read_field(ctx, field)
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    pub fn read_address_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core()
            .read_address(ctx, self.registers().effective_address_width())
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    pub fn read_address_native_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core()
            .read_address(ctx, self.registers().address_width())
    }

    /// Reads a 32-bit address from the virtual machine.
    pub fn read_address32_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core().read_address32(ctx)
    }

    /// Reads a 64-bit address from the virtual machine.
    pub fn read_address64_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core().read_address64(ctx)
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core()
            .read_va(ctx, self.registers().effective_address_width())
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va_native_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core().read_va(ctx, self.registers().address_width())
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    pub fn read_va32_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core().read_va32(ctx)
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    pub fn read_va64_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core().read_va64(ctx)
    }

    /// Reads a null-terminated string of bytes from the virtual machine with a
    /// specified limit.
    pub fn read_string_bytes_limited_in(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<Vec<u8>, VmiError> {
        self.core().read_string_bytes_limited(ctx, limit)
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    pub fn read_string_bytes_in(&self, ctx: impl Into<AccessContext>) -> Result<Vec<u8>, VmiError> {
        self.core().read_string_bytes(ctx)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine
    /// with a specified limit.
    pub fn read_wstring_bytes_limited_in(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<Vec<u16>, VmiError> {
        self.core().read_wstring_bytes_limited(ctx, limit)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring_bytes_in(
        &self,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u16>, VmiError> {
        self.core().read_wstring_bytes(ctx)
    }

    /// Reads a null-terminated string from the virtual machine with a specified
    /// limit.
    pub fn read_string_limited_in(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<String, VmiError> {
        self.core().read_string_limited(ctx, limit)
    }

    /// Reads a null-terminated string from the virtual machine.
    pub fn read_string_in(&self, ctx: impl Into<AccessContext>) -> Result<String, VmiError> {
        self.core().read_string(ctx)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine
    /// with a specified limit.
    pub fn read_wstring_limited_in(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<String, VmiError> {
        self.core().read_wstring_limited(ctx, limit)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring_in(&self, ctx: impl Into<AccessContext>) -> Result<String, VmiError> {
        self.core().read_wstring(ctx)
    }

    /// Reads a struct from the virtual machine.
    pub fn read_struct_in<T>(&self, ctx: impl Into<AccessContext>) -> Result<T, VmiError>
    where
        T: IntoBytes + FromBytes,
    {
        self.core().read_struct(ctx)
    }

    // endregion: Read in

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
}

/// Wrapper providing access to OS-specific operations.
pub struct VmiOsState<'a, Driver, Os>(VmiState<'a, Driver, Os>)
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>;

impl<'a, Driver, Os> VmiOsState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Returns the VMI core.
    pub fn core(&self) -> &'a VmiCore<Driver> {
        self.0.core()
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &'a Os {
        self.0.underlying_os()
    }

    /// Returns the VMI session.
    pub fn session(&self) -> &'a VmiSession<'a, Driver, Os> {
        self.0.session()
    }

    /// Returns the VMI state.
    pub fn state(&self) -> VmiState<'a, Driver, Os> {
        self.0
    }

    /// Returns the CPU registers associated with the current event.
    pub fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers {
        self.0.registers()
    }

    /// Retrieves a specific function argument according to the calling
    /// convention of the operating system.
    pub fn function_argument_for_registers(
        &self,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError> {
        self.underlying_os()
            .function_argument(self.0.with_registers(registers), index)
    }

    /// Retrieves the return value of a function.
    pub fn function_return_value_for_registers(
        &self,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<u64, VmiError> {
        self.underlying_os()
            .function_return_value(self.0.with_registers(registers))
    }
}
