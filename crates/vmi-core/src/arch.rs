#![doc = include_str!("../docs/arch.md")]

use std::fmt::Debug;

use crate::{AddressContext, Gfn, MemoryAccess, Pa, Va, VmiCore, VmiDriver, VmiError};

/// Defines an interface for CPU architecture-specific operations and constants.
///
/// The `Architecture` trait provides generic abstraction for interacting with
/// different CPU architectures in the context of virtual machine introspection.
///
/// This trait encapsulates the key characteristics and operations that vary
/// across different CPU architectures, allowing for the implementation of
/// architecture-agnostic tools and libraries.
pub trait Architecture {
    /// The size of a memory page in bytes for the given architecture.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `0x1000` (4096 bytes)
    const PAGE_SIZE: u64;

    /// The number of bits to shift when converting between page numbers and
    /// physical addresses.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `12` (2^12 = 4096)
    const PAGE_SHIFT: u64;

    /// A bitmask used to isolate the page number from a full address.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `0xFFFFFFFFFFFFF000`
    const PAGE_MASK: u64;

    /// The machine code for a breakpoint instruction in the given architecture.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `&[0xcc]` (`INT3` instruction)
    const BREAKPOINT: &'static [u8];

    /// The complete set of CPU registers for the architecture.
    ///
    /// This type should include general-purpose registers, and all control and
    /// special registers.
    type Registers: Registers;

    /// An enumeration representing the levels of page tables in the
    /// architecture's paging structure.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: PML5, PML4, PDPT, PD, PT
    type PageTableLevel: Debug + Clone + Copy;

    /// Various types of interrupts that can occur in the architecture.
    type Interrupt: Debug + Clone + Copy;

    /// Represents special-purpose registers in the architecture.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: May represent control registers like `CR0`, `CR2`, `CR3`,
    ///   `CR4`
    type SpecialRegister: Debug + Clone + Copy;

    /// Options for monitoring.
    type EventMonitor;

    /// Architecture-specific event details.
    type EventReason: EventReason;

    /// Converts a guest physical address (GPA) to a guest frame number (GFN).
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `gfn = pa >> 12`
    fn gfn_from_pa(pa: Pa) -> Gfn;

    /// Converts a guest frame number (GFN) to a guest physical address (GPA).
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `pa = gfn << 12`
    fn pa_from_gfn(gfn: Gfn) -> Pa;

    /// Extracts the offset within a page from a physical address.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `offset = pa & 0xfff`
    fn pa_offset(pa: Pa) -> u64;

    /// Extracts the offset within a page from a virtual address.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `offset = va & 0xfff`
    fn va_offset(va: Va) -> u64;

    /// Calculates the offset within a page for a given virtual address and
    /// page table level.
    fn va_offset_for(va: Va, level: Self::PageTableLevel) -> u64;

    /// Calculates the index into the lowest level page table for a given
    /// virtual address.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `index = va & 0x1ff`
    fn va_index(va: Va) -> u64;

    /// Calculates the index into the specified level of the page table
    /// hierarchy for a given virtual address.
    fn va_index_for(va: Va, level: Self::PageTableLevel) -> u64;

    /// Performs a full page table walk to translate a virtual address to a
    /// physical address.
    fn translate_address<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> Result<Pa, VmiError>
    where
        Driver: VmiDriver<Architecture = Self>;
}

/// Complete set of CPU registers for a specific architecture.
///
/// Provides methods to access and modify key registers and register sets.
pub trait Registers
where
    Self: Debug + Default + Clone + Copy,
{
    /// The specific CPU architecture implementation.
    type Architecture: Architecture + ?Sized;

    /// General-purpose registers of the architecture.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `RSP`, `RBP`,
    ///   `R8`-`R15`, `RIP` and `RFLAGS`.
    type GpRegisters: Debug + Default + Clone + Copy;

    /// Returns the current value of the instruction pointer.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RIP`
    fn instruction_pointer(&self) -> u64;

    /// Sets the value of the instruction pointer.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RIP`
    fn set_instruction_pointer(&mut self, ip: u64);

    /// Returns the current value of the stack pointer.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RSP`
    fn stack_pointer(&self) -> u64;

    /// Sets the value of the stack pointer.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RSP`
    fn set_stack_pointer(&mut self, sp: u64);

    /// Returns the current value of the result register.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RAX`
    fn result(&self) -> u64;

    /// Sets the value of the result register.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RAX`
    fn set_result(&mut self, result: u64);

    /// Returns a copy of all general-purpose registers.
    fn gp_registers(&self) -> Self::GpRegisters;

    /// Sets all general-purpose registers.
    fn set_gp_registers(&mut self, gp: &Self::GpRegisters);

    /// Returns the native address width (i.e. pointer size) of the architecture
    /// in bytes.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: 8 bytes
    fn address_width(&self) -> usize;

    /// Returns the effective address width, which may differ from the native
    /// width (e.g., in compatibility modes).
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: 8 bytes if the `CS.L` bit is set, otherwise 4 bytes
    fn effective_address_width(&self) -> usize;

    /// Creates an address context for a given virtual address.
    fn address_context(&self, va: Va) -> AddressContext;

    /// Returns the physical address of the root of the current page table
    /// hierarchy for a given virtual address.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `CR3 & 0x0000FFFFFFFFF000`
    fn translation_root(&self, va: Va) -> Pa;

    /// Attempts to determine the return address of the current function call.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: Value at the top of the stack (i.e. `RSP`)
    fn return_address<Driver>(&self, vmi: &VmiCore<Driver>) -> Result<Va, VmiError>
    where
        Driver: VmiDriver;
}

/// A memory access event, providing details about the accessed memory.
pub trait EventMemoryAccess
where
    Self: Debug + Clone + Copy,
{
    /// The specific CPU architecture implementation.
    type Architecture: Architecture + ?Sized;

    /// Returns the physical address of the memory access.
    fn pa(&self) -> Pa;

    /// Returns the virtual address of the memory access.
    fn va(&self) -> Va;

    /// Returns the type of memory access (e.g., read, write, execute).
    fn access(&self) -> MemoryAccess;
}

/// An interrupt event, providing details about the interrupt.
pub trait EventInterrupt
where
    Self: Debug + Clone + Copy,
{
    /// The specific CPU architecture implementation.
    type Architecture: Architecture + ?Sized;

    /// Returns the guest frame number where the interrupt occurred.
    /// Effectively, this is GFN of the current instruction pointer.
    fn gfn(&self) -> Gfn;
}

/// The reason for a VM exit or similar event, allowing for type-safe access
/// to specific event details.
pub trait EventReason
where
    Self: Debug + Clone + Copy,
{
    /// The specific CPU architecture implementation.
    type Architecture: Architecture + ?Sized;

    /// If the event was caused by a memory access, returns the details
    /// of that access.
    fn as_memory_access(
        &self,
    ) -> Option<&impl EventMemoryAccess<Architecture = Self::Architecture>>;

    /// If the event was caused by an interrupt, returns the details
    /// of that interrupt.
    fn as_interrupt(&self) -> Option<&impl EventInterrupt<Architecture = Self::Architecture>>;

    /// If the event was caused by a software breakpoint, returns the details
    /// of that breakpoint.
    fn as_software_breakpoint(
        &self,
    ) -> Option<&impl EventInterrupt<Architecture = Self::Architecture>>;
}
