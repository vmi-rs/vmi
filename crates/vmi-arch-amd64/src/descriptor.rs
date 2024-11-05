/// Global Descriptor Table Register (GDTR).
///
/// The GDTR is a special register that holds the base address and size of the
/// Global Descriptor Table (GDT). The GDT contains entries telling the CPU
/// about memory segments.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Gdtr {
    /// The linear address of the Global Descriptor Table (GDT).
    pub base: u64,

    /// The size of the GDT.
    pub limit: u32,
}

/// Interrupt Descriptor Table Register (IDTR).
///
/// The IDTR is a special register that holds the base address and size of the
/// Interrupt Descriptor Table (IDT). The IDT contains entry points for
/// interrupt and exception handlers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Idtr {
    /// The linear address of the Interrupt Descriptor Table (IDT).
    pub base: u64,

    /// The size of the IDT.
    pub limit: u32,
}
