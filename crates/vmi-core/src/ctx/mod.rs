mod context;
mod cow;
mod prober;
mod session;
mod state;

pub use self::{
    context::{VmiContext, VmiOsContext},
    prober::VmiProber,
    session::VmiSession,
    state::{VmiOsState, VmiState},
};

/*
pub trait VmiWithCore<Driver>
where
    Driver: VmiDriver,
{
    fn core(&self) -> &VmiCore<Driver>;
}
pub trait VmiWithOs<Driver, Os>: VmiWithCore<Driver>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn os(&self) -> &Os;
}
pub trait VmiWithRegisters<Driver>: VmiWithCore<Driver>
where
    Driver: VmiDriver,
{
    /// Returns the CPU registers associated with the current event.
    fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers;

    /// Returns the return address from the current stack frame.
    fn return_address(&self) -> Result<Va, VmiError> {
        self.registers().return_address(self.core())
    }

    // region: Read

    /// Reads memory from the virtual machine.
    fn read(&self, address: Va, buffer: &mut [u8]) -> Result<(), VmiError> {
        self.core().read(self.access_context(address), buffer)
    }

    /// Writes memory to the virtual machine.
    fn write(&self, address: Va, buffer: &[u8]) -> Result<(), VmiError> {
        self.core().write(self.access_context(address), buffer)
    }

    /// Reads a single byte from the virtual machine.
    fn read_u8(&self, address: Va) -> Result<u8, VmiError> {
        self.core().read_u8(self.access_context(address))
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    fn read_u16(&self, address: Va) -> Result<u16, VmiError> {
        self.core().read_u16(self.access_context(address))
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    fn read_u32(&self, address: Va) -> Result<u32, VmiError> {
        self.core().read_u32(self.access_context(address))
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    fn read_u64(&self, address: Va) -> Result<u64, VmiError> {
        self.core().read_u64(self.access_context(address))
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    fn read_address(&self, address: Va) -> Result<u64, VmiError> {
        self.core().read_address(
            self.access_context(address),
            self.registers().effective_address_width(),
        )
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    fn read_address_native(&self, address: Va) -> Result<u64, VmiError> {
        self.core().read_address(
            self.access_context(address),
            self.registers().address_width(),
        )
    }

    /// Reads a 32-bit address from the virtual machine.
    fn read_address32(&self, address: Va) -> Result<u64, VmiError> {
        self.core().read_address32(self.access_context(address))
    }

    /// Reads a 64-bit address from the virtual machine.
    fn read_address64(&self, address: Va) -> Result<u64, VmiError> {
        self.core().read_address64(self.access_context(address))
    }

    /// Reads a virtual address from the virtual machine.
    fn read_va(&self, address: Va) -> Result<Va, VmiError> {
        self.core().read_va(
            self.access_context(address),
            self.registers().effective_address_width(),
        )
    }

    /// Reads a virtual address from the virtual machine.
    fn read_va_native(&self, address: Va) -> Result<Va, VmiError> {
        self.core().read_va(
            self.access_context(address),
            self.registers().address_width(),
        )
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    fn read_va32(&self, address: Va) -> Result<Va, VmiError> {
        self.core().read_va32(self.access_context(address))
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    fn read_va64(&self, address: Va) -> Result<Va, VmiError> {
        self.core().read_va64(self.access_context(address))
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    fn read_string_bytes(&self, address: Va) -> Result<Vec<u8>, VmiError> {
        self.core().read_string_bytes(self.access_context(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    fn read_wstring_bytes(&self, address: Va) -> Result<Vec<u16>, VmiError> {
        self.core().read_wstring_bytes(self.access_context(address))
    }

    /// Reads a null-terminated string from the virtual machine.
    fn read_string(&self, address: Va) -> Result<String, VmiError> {
        self.core().read_string(self.access_context(address))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    fn read_wstring(&self, address: Va) -> Result<String, VmiError> {
        self.core().read_wstring(self.access_context(address))
    }

    /// Reads a struct from the virtual machine.
    fn read_struct<T>(&self, address: Va) -> Result<T, VmiError>
    where
        T: IntoBytes + FromBytes,
    {
        self.core().read_struct(self.access_context(address))
    }

    // endregion: Read

    // region: Read in

    /// Reads memory from the virtual machine.
    fn read_in(&self, ctx: impl Into<AccessContext>, buffer: &mut [u8]) -> Result<(), VmiError> {
        self.core().read(ctx, buffer)
    }

    /// Writes memory to the virtual machine.
    fn write_in(&self, ctx: impl Into<AccessContext>, buffer: &[u8]) -> Result<(), VmiError> {
        self.core().write(ctx, buffer)
    }

    /// Reads a single byte from the virtual machine.
    fn read_u8_in(&self, ctx: impl Into<AccessContext>) -> Result<u8, VmiError> {
        self.core().read_u8(ctx)
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    fn read_u16_in(&self, ctx: impl Into<AccessContext>) -> Result<u16, VmiError> {
        self.core().read_u16(ctx)
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    fn read_u32_in(&self, ctx: impl Into<AccessContext>) -> Result<u32, VmiError> {
        self.core().read_u32(ctx)
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    fn read_u64_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core().read_u64(ctx)
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    fn read_address_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core()
            .read_address(ctx, self.registers().effective_address_width())
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    fn read_address_native_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core()
            .read_address(ctx, self.registers().address_width())
    }

    /// Reads a 32-bit address from the virtual machine.
    fn read_address32_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core().read_address32(ctx)
    }

    /// Reads a 64-bit address from the virtual machine.
    fn read_address64_in(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.core().read_address64(ctx)
    }

    /// Reads a virtual address from the virtual machine.
    fn read_va_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core()
            .read_va(ctx, self.registers().effective_address_width())
    }

    /// Reads a virtual address from the virtual machine.
    fn read_va_native_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core().read_va(ctx, self.registers().address_width())
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    fn read_va32_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core().read_va32(ctx)
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    fn read_va64_in(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        self.core().read_va64(ctx)
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    fn read_string_bytes_in(&self, ctx: impl Into<AccessContext>) -> Result<Vec<u8>, VmiError> {
        self.core().read_string_bytes(ctx)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    fn read_wstring_bytes_in(&self, ctx: impl Into<AccessContext>) -> Result<Vec<u16>, VmiError> {
        self.core().read_wstring_bytes(ctx)
    }

    /// Reads a null-terminated string from the virtual machine.
    fn read_string_in(&self, ctx: impl Into<AccessContext>) -> Result<String, VmiError> {
        self.core().read_string(ctx)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    fn read_wstring_in(&self, ctx: impl Into<AccessContext>) -> Result<String, VmiError> {
        self.core().read_wstring(ctx)
    }

    /// Reads a struct from the virtual machine.
    fn read_struct_in<T>(&self, ctx: impl Into<AccessContext>) -> Result<T, VmiError>
    where
        T: IntoBytes + FromBytes,
    {
        self.core().read_struct(ctx)
    }

    // endregion: Read in

    /// Writes a single byte to the virtual machine.
    fn write_u8(&self, address: Va, value: u8) -> Result<(), VmiError> {
        self.core().write_u8(self.access_context(address), value)
    }

    /// Writes a 16-bit unsigned integer to the virtual machine.
    fn write_u16(&self, address: Va, value: u16) -> Result<(), VmiError> {
        self.core().write_u16(self.access_context(address), value)
    }

    /// Writes a 32-bit unsigned integer to the virtual machine.
    fn write_u32(&self, address: Va, value: u32) -> Result<(), VmiError> {
        self.core().write_u32(self.access_context(address), value)
    }

    /// Writes a 64-bit unsigned integer to the virtual machine.
    fn write_u64(&self, address: Va, value: u64) -> Result<(), VmiError> {
        self.core().write_u64(self.access_context(address), value)
    }

    /// Writes a struct to the virtual machine.
    fn write_struct<T>(&self, address: Va, value: T) -> Result<(), VmiError>
    where
        T: FromBytes + IntoBytes + Immutable,
    {
        self.core()
            .write_struct(self.access_context(address), value)
    }

    /// Translates a virtual address to a physical address.
    fn translate_address(&self, va: Va) -> Result<Pa, VmiError> {
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

pub trait VmiWithEvent<Driver>: VmiWithCore<Driver>
where
    Driver: VmiDriver,
{
    fn event(&self) -> &VmiEvent<Driver::Architecture>;
}

//
// VmiWithCore
//

impl<'a, Driver, Os> VmiWithCore<Driver> for VmiSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn core(&self) -> &VmiCore<Driver> {
        self.core()
    }
}

impl<'a, Driver, Os> VmiWithCore<Driver> for VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn core(&self) -> &VmiCore<Driver> {
        self.session().core()
    }
}

impl<'a, Driver, Os> VmiWithCore<Driver> for VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn core(&self) -> &VmiCore<Driver> {
        self.session().core()
    }
}

impl<'a, Driver, Os> VmiWithCore<Driver> for VmiOsState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn core(&self) -> &VmiCore<Driver> {
        self.session().core()
    }
}

impl<'a, Driver, Os> VmiWithCore<Driver> for VmiOsContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn core(&self) -> &VmiCore<Driver> {
        self.session().core()
    }
}

//
// VmiWithOs
//

impl<'a, Driver, Os> VmiWithOs<Driver, Os> for VmiSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn os(&self) -> &Os {
        self.underlying_os()
    }
}

impl<'a, Driver, Os> VmiWithOs<Driver, Os> for VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn os(&self) -> &Os {
        self.underlying_os()
    }
}

impl<'a, Driver, Os> VmiWithOs<Driver, Os> for VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn os(&self) -> &Os {
        self.underlying_os()
    }
}

//
// VmiWithRegisters
//

impl<'a, Driver, Os> VmiWithRegisters<Driver> for VmiState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers {
        self.registers()
    }
}

impl<'a, Driver, Os> VmiWithRegisters<Driver> for VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers {
        self.event().registers()
    }
}

impl<'a, Driver, Os> VmiWithRegisters<Driver> for VmiOsState<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers {
        self.registers()
    }
}

impl<'a, Driver, Os> VmiWithRegisters<Driver> for VmiOsContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn registers(&self) -> &<Driver::Architecture as Architecture>::Registers {
        self.event().registers()
    }
}

//
// VmiWithEvent
//

impl<'a, Driver, Os> VmiWithEvent<Driver> for VmiContext<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    fn event(&self) -> &VmiEvent<Driver::Architecture> {
        self.event()
    }
}

/*
impl<'a, Driver, T> VmiWithCoreAndRegisters<Driver> for T
where
    Driver: VmiDriver,
    T: VmiWithCore<Driver> + VmiWithRegisters<Driver>,
{
}
*/
 */
