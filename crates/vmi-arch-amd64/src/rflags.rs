/// The RFLAGS register.
///
/// The 64-bit RFLAGS register contains a group of status flags, a control flag,
/// and a group of system flags in 64-bit mode. The upper 32 bits of RFLAGS
/// register is reserved. The lower 32 bits of RFLAGS contains a group of status
/// flags, a control flag, and a group of system flags. The status flags (bits
/// 0, 2, 4, 6, 7, and 11) of the RFLAGS register indicate the results of
/// arithmetic instructions, such as the ADD, SUB, MUL, and DIV instructions.
///
/// The system flags and IOPL field in the RFLAGS register control
/// operating-system or executive operations.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Rflags(pub u64);

impl Rflags {
    /// Reserved bits that should not be modified.
    pub const RESERVED_BITS: u64 = 0xffc38028;

    /// Bits that are fixed to 1 ("read_as_1" field).
    pub const FIXED_BITS: u64 = 0x00000002;

    /// Checks if the Carry Flag (CF) is set.
    ///
    /// Set if an arithmetic operation generates a carry or a borrow out of the
    /// mostsignificant bit of the result; cleared otherwise. This flag
    /// indicates an overflow condition for unsigned-integer arithmetic. It
    /// is also used in multiple-precision arithmetic.
    pub fn carry(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if the Parity Flag (PF) is set.
    ///
    /// Set if the least-significant byte of the result contains an even number
    /// of 1 bits; cleared otherwise.
    pub fn parity(self) -> bool {
        (self.0 >> 2) & 1 != 0
    }

    /// Checks if the Auxiliary Carry Flag (AF) is set.
    ///
    /// Set if an arithmetic operation generates a carry or a borrow out of bit
    /// 3 of the result; cleared otherwise. This flag is used in binary-coded
    /// decimal (BCD) arithmetic.
    pub fn auxiliary_carry(self) -> bool {
        (self.0 >> 4) & 1 != 0
    }

    /// Checks if the Zero Flag (ZF) is set.
    ///
    /// Set if the result is zero; cleared otherwise.
    pub fn zero(self) -> bool {
        (self.0 >> 6) & 1 != 0
    }

    /// Checks if the Sign Flag (SF) is set.
    ///
    /// Set equal to the most-significant bit of the result, which is the sign
    /// bit of a signed integer. (0 indicates a positive value and 1
    /// indicates a negative value.)
    pub fn sign(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    /// Checks if the Trap Flag (TF) is set.
    ///
    /// Set to enable single-step mode for debugging; clear to disable
    /// single-step mode.
    pub fn trap(self) -> bool {
        (self.0 >> 8) & 1 != 0
    }

    /// Checks if the Interrupt Enable Flag (IF) is set.
    ///
    /// Controls the response of the processor to maskable interrupt
    /// requests. Set to respond to maskable interrupts; cleared to inhibit
    /// maskable interrupts.
    pub fn interrupt_enable(self) -> bool {
        (self.0 >> 9) & 1 != 0
    }

    /// Checks if the Direction Flag (DF) is set.
    ///
    /// Controls string instructions (MOVS, CMPS, SCAS, LODS, and STOS). Setting
    /// the DF flag causes the string instructions to auto-decrement (to
    /// process strings from high addresses to low addresses). Clearing the
    /// DF flag causes the string instructions to auto-increment (process
    /// strings from low addresses to high addresses).
    pub fn direction(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Checks if the Overflow Flag (OF) is set.
    ///
    /// Set if the integer result is too large a positive number or too small a
    /// negative number (excluding the sign-bit) to fit in the destination
    /// operand; cleared otherwise. This flag indicates an overflow
    /// condition for signed-integer (two’s complement) arithmetic.
    pub fn overflow(self) -> bool {
        (self.0 >> 11) & 1 != 0
    }

    /// Returns the I/O Privilege Level (IOPL).
    ///
    /// Indicates the I/O privilege level of the currently running program
    /// or task. The current privilege level (CPL) of the currently running
    /// program or task must be less than or equal to the I/O privilege
    /// level to access the I/O address space. The POPF and IRET
    /// instructions can modify this field only when operating at a CPL of 0.
    ///
    /// # Returns
    ///
    /// A value between 0 and 3, representing the current I/O privilege level.
    pub fn io_privilege_level(self) -> u8 {
        ((self.0 >> 12) & 0b11) as _
    }

    /// Checks if the Nested Task (NT) flag is set.
    ///
    /// Controls the chaining of interrupted and called tasks. Set when the
    /// current task is linked to the previously executed task; cleared when the
    /// current task is not linked to another task.
    pub fn nested_task(self) -> bool {
        (self.0 >> 14) & 1 != 0
    }

    /// Checks if the Resume Flag (RF) is set.
    ///
    /// Controls the processor’s response to debug exceptions.
    pub fn resume(self) -> bool {
        (self.0 >> 16) & 1 != 0
    }

    /// Checks if Virtual 8086 Mode (VM) is active.
    ///
    /// Set to enable virtual-8086 mode; clear to return to protected
    /// mode without virtual-8086 mode semantics.
    pub fn virtual_8086_mode(self) -> bool {
        (self.0 >> 17) & 1 != 0
    }

    /// Checks if the Alignment Check (AC) flag is set.
    ///
    /// If the AM bit is set in the CR0 register, alignment
    /// checking of user-mode data accesses is enabled if and only if this flag
    /// is 1. If the SMAP bit is set in the CR4 register, explicit
    /// supervisor-mode data accesses to user-mode pages are allowed if and
    /// only if this bit is 1.
    pub fn alignment_check(self) -> bool {
        (self.0 >> 18) & 1 != 0
    }

    /// Checks if the Virtual Interrupt Flag (VIF) is set.
    ///
    /// Virtual image of the IF flag. Used in conjunction with the VIP flag.
    /// (To use this flag and the VIP flag the virtual mode extensions are
    /// enabled by setting the VME flag in control register CR4.)
    pub fn virtual_interrupt(self) -> bool {
        (self.0 >> 19) & 1 != 0
    }

    /// Checks if the Virtual Interrupt Pending (VIP) flag is set.
    ///
    /// Set to indicate that an interrupt is pending; clear when no
    /// interrupt is pending. (Software sets and clears this flag; the processor
    /// only reads it.) Used in conjunction with the VIF flag.
    pub fn virtual_interrupt_pending(self) -> bool {
        (self.0 >> 20) & 1 != 0
    }

    /// Checks if the Identification Flag (ID) is set.
    ///
    /// The ability of a program to set or clear this flag indicates support for
    /// the CPUID instruction.
    pub fn identification(self) -> bool {
        (self.0 >> 21) & 1 != 0
    }
}

impl std::fmt::Debug for Rflags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Rflags")
            .field("carry", &self.carry())
            .field("parity", &self.parity())
            .field("auxiliary_carry", &self.auxiliary_carry())
            .field("zero", &self.zero())
            .field("sign", &self.sign())
            .field("trap", &self.trap())
            .field("interrupt_enable", &self.interrupt_enable())
            .field("direction", &self.direction())
            .field("overflow", &self.overflow())
            .field("io_privilege_level", &self.io_privilege_level())
            .field("nested_task", &self.nested_task())
            .field("resume", &self.resume())
            .field("virtual_8086_mode", &self.virtual_8086_mode())
            .field("alignment_check", &self.alignment_check())
            .field("virtual_interrupt", &self.virtual_interrupt())
            .field(
                "virtual_interrupt_pending",
                &self.virtual_interrupt_pending(),
            )
            .field("identification", &self.identification())
            .finish()
    }
}

impl From<u64> for Rflags {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Rflags> for u64 {
    fn from(value: Rflags) -> Self {
        value.0
    }
}
