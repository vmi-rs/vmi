mod efer;

pub use self::efer::MsrEfer;

/// Model-specific register (MSR) identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msr(pub u32);

impl Msr {
    /// The lower 16 bits of this MSR are the segment selector for the
    /// privilege level 0 code segment. This value is also used to determine
    /// the segment selector of the privilege level 0 stack segment.
    /// This value cannot indicate a null selector.
    pub const SYSENTER_CS: Self = Self(0x00000174);

    /// The value of this MSR is loaded into RSP (thus, this value contains
    /// the stack pointer for the privilege level 0 stack). This value cannot
    /// represent a non-canonical address. In protected mode, only bits 31:0
    /// are loaded.
    pub const SYSENTER_ESP: Self = Self(0x00000175);

    /// The value of this MSR is loaded into RIP (thus, this value references
    /// the first instruction of the selected operating procedure or routine).
    /// In protected mode, only bits 31:0 are loaded.
    pub const SYSENTER_EIP: Self = Self(0x00000176);

    /// Extended Feature Enable Register (EFER).
    ///
    /// # Remarks
    ///
    /// If `CPUID.06H:EAX.[13] = 1`
    ///
    /// # See also
    ///
    /// - [`MsrEfer`] for the bitfields of this MSR.
    pub const EFER: Self = Self(0xc0000080);

    /// System Call Target Address (STAR).
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001:EDX.[29] = 1`
    pub const STAR: Self = Self(0xc0000081);

    /// IA-32e Mode System Call Target Address (LSTAR).
    ///
    /// Target RIP for the called procedure when SYSCALL is executed in 64-bit
    /// mode.
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001:EDX.[29] = 1`
    pub const LSTAR: Self = Self(0xc0000082);

    /// IA-32e Mode System Call Target Address (CSTAR).
    ///
    /// Not used, as the SYSCALL instruction is not recognized in compatibility mode.
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001:EDX.[29] = 1`
    pub const CSTAR: Self = Self(0xc0000083);

    /// System Call Flag Mask (FMASK).
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001:EDX.[29] = 1`
    pub const FMASK: Self = Self(0xc0000084);

    /// Map of BASE Address of FS.
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001:EDX.[29] = 1`
    pub const FS_BASE: Self = Self(0xc0000100);

    /// Map of BASE Address of GS.
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001:EDX.[29] = 1`
    pub const GS_BASE: Self = Self(0xc0000101);

    /// Swap Target of BASE Address of GS.
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001:EDX.[29] = 1`
    pub const KERNEL_GS_BASE: Self = Self(0xc0000102);

    /// Auxiliary TSC.
    ///
    /// # Remarks
    ///
    /// If `CPUID.80000001H: EDX[27] = 1` or `CPUID.(EAX=7,ECX=0):ECX[bit 22] = 1`
    pub const TSC_AUX: Self = Self(0xc0000103);
}

impl From<u32> for Msr {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Msr> for u32 {
    fn from(value: Msr) -> Self {
        value.0
    }
}
