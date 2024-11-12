/// `CR4` control register.
///
/// Contains various architectural feature enable bits.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Cr4(pub u64);

impl Cr4 {
    /// Checks if the CR4.VME flag is set.
    ///
    /// Enables interrupt- and exception-handling extensions
    /// in virtual-8086 mode when set; disables the extensions when clear.
    pub fn virtual_mode_extensions(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if the CR4.PVI flag is set.
    ///
    /// Enables hardware support for a virtual interrupt
    /// flag (VIF) in protected mode when set; disables the VIF flag in
    /// protected mode when clear.
    pub fn protected_mode_virtual_interrupts(self) -> bool {
        (self.0 >> 1) & 1 != 0
    }

    /// Checks if the CR4.TSD flag is set.
    ///
    /// Restricts the execution of the RDTSC instruction to procedures
    /// running at privilege level 0 when set; allows RDTSC instruction to be
    /// executed at any privilege level when clear. This bit also applies to
    /// the RDTSCP instruction if supported (if CPUID.80000001H:EDX\[27\] = 1).
    pub fn timestamp_disable(self) -> bool {
        (self.0 >> 2) & 1 != 0
    }

    /// Checks if the CR4.DE flag is set.
    ///
    /// References to debug registers DR4 and DR5 cause an undefined
    /// opcode (#UD) exception to be generated when set; when clear, processor
    /// aliases references to registers DR4 and DR5 for compatibility with
    /// software written to run on earlier IA-32 processors.
    pub fn debugging_extensions(self) -> bool {
        (self.0 >> 3) & 1 != 0
    }

    /// Checks if the CR4.PSE flag is set.
    ///
    /// Enables 4-MByte pages with 32-bit paging when set; restricts
    /// 32-bit paging to pages of 4 KBytes when clear.
    pub fn page_size_extension(self) -> bool {
        (self.0 >> 4) & 1 != 0
    }

    /// Checks if the CR4.PAE flag is set.
    ///
    /// When set, enables paging to produce physical addresses
    /// with more than 32 bits. When clear, restricts physical addresses to 32
    /// bits. PAE must be set before entering IA-32e mode.
    pub fn physical_address_extension(self) -> bool {
        (self.0 >> 5) & 1 != 0
    }

    /// Checks if the CR4.MCE flag is set.
    ///
    /// Enables the machine-check exception when set; disables the
    /// machine-check exception when clear.
    pub fn machine_check_enable(self) -> bool {
        (self.0 >> 6) & 1 != 0
    }

    /// Checks if the CR4.PGE flag is set.
    ///
    /// Enables the global page
    /// feature when set; disables the global page feature when clear. The
    /// global page feature allows frequently used or shared pages to be
    /// marked as global to all users (done with the global flag, bit 8, in a
    /// page-directory or page-table entry). Global pages are not flushed
    /// from the translation-lookaside buffer (TLB) on a task switch or a
    /// write to register CR3.
    ///
    /// When enabling the global page feature, paging must be enabled (by
    /// setting the PG flag in control register CR0) before the PGE flag is
    /// set. Reversing this sequence may affect program correctness, and
    /// processor performance will be impacted.
    pub fn page_global_enable(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    /// Checks if the CR4.PCE flag is set.
    ///
    /// Enables execution of the RDPMC instruction
    /// for programs or procedures running at any protection level when set;
    /// RDPMC instruction can be executed only at protection level 0 when
    /// clear.
    pub fn performance_monitoring_counter_enable(self) -> bool {
        (self.0 >> 8) & 1 != 0
    }

    /// Checks if the CR4.OSFXSR flag is set.
    ///
    /// When set, this flag:
    /// - indicates to software that the operating system supports the use of
    ///   the FXSAVE and FXRSTOR instructions,
    /// - enables the FXSAVE and FXRSTOR instructions to save and restore the
    ///   contents of the XMM and MXCSR registers along with the contents of the
    ///   x87 FPU and MMX registers, and
    /// - enables the processor to execute SSE/SSE2/SSE3/SSSE3/SSE4
    ///   instructions, with the exception of the PAUSE, PREFETCHh, SFENCE,
    ///   LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
    ///
    /// If this flag is clear, the FXSAVE and FXRSTOR instructions will save and
    /// restore the contents of the x87 FPU and MMX registers, but they may
    /// not save and restore the contents of the XMM and MXCSR registers. Also,
    /// the processor will generate an invalid opcode exception (#UD) if it
    /// attempts to execute any SSE/SSE2/SSE3 instruction, with the
    /// exception of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE,
    /// MOVNTI, CLFLUSH, CRC32, and POPCNT. The operating system or executive
    /// must explicitly set this flag.
    pub fn os_fxsr_support(self) -> bool {
        (self.0 >> 9) & 1 != 0
    }

    /// Checks if the CR4.OSXMMEXCPT flag is set.
    ///
    /// Operating System Support for Unmasked SIMD Floating-Point Exceptions —
    /// When set, indicates that the operating system supports the handling of
    /// unmasked SIMD floating-point exceptions through an exception handler
    /// that is invoked when a SIMD floating-point exception (#XM) is
    /// generated. SIMD floating-point exceptions are only generated by
    /// SSE/SSE2/SSE3/SSE4.1 SIMD floating-point instructions.
    ///
    /// The operating system or executive must explicitly set this flag. If this
    /// flag is not set, the processor will generate an invalid opcode
    /// exception (#UD) whenever it detects an unmasked SIMD floating-point
    /// exception.
    pub fn os_xmm_exception_support(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Checks if the CR4.UMIP flag is set.
    ///
    /// When set, the following instructions cannot be
    /// executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt at such
    /// execution causes a general-protection exception (#GP).
    pub fn usermode_instruction_prevention(self) -> bool {
        (self.0 >> 11) & 1 != 0
    }

    /// Checks if the CR4.LA57 flag is set.
    ///
    /// When set in IA-32e mode, the processor uses 5-level paging to translate
    /// 57-bit linear addresses. When clear in IA-32e mode, the processor
    /// uses 4-level paging to translate 48-bit linear addresses.
    /// This bit cannot be modified in IA-32e mode.
    pub fn linear_address_57_bit(self) -> bool {
        (self.0 >> 12) & 1 != 0
    }

    /// Checks if the CR4.VMXE flag is set.
    ///
    /// Enables VMX operation when set.
    pub fn vmx_enable(self) -> bool {
        (self.0 >> 13) & 1 != 0
    }

    /// Checks if the CR4.SMXE flag is set.
    ///
    /// Enables SMX operation when set.
    pub fn smx_enable(self) -> bool {
        (self.0 >> 14) & 1 != 0
    }

    /// Checks if the CR4.FSGSBASE flag is set.
    ///
    /// Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE,
    /// and WRGSBASE.
    pub fn fsgsbase_enable(self) -> bool {
        (self.0 >> 16) & 1 != 0
    }

    /// Checks if the CR4.PCIDE flag is set.
    ///
    /// Enables process-context identifiers (PCIDs) when set.
    /// Can be set only in IA-32e mode (if IA32_EFER.LMA = 1).
    pub fn pcid_enable(self) -> bool {
        (self.0 >> 17) & 1 != 0
    }

    /// Checks if the CR4.OSXSAVE flag is set.
    ///
    /// When set, this flag:
    /// - indicates (via CPUID.01H:ECX.OSXSAVE[bit 27]) that the operating
    ///   system supports the use of the XGETBV, XSAVE and XRSTOR instructions
    ///   by general software;
    /// - enables the XSAVE and XRSTOR instructions to save and restore the x87
    ///   FPU state (including MMX registers), the SSE state (XMM registers and
    ///   MXCSR), along with other processor extended states enabled in XCR0;
    /// - enables the processor to execute XGETBV and XSETBV instructions in
    ///   order to read and write XCR0.
    pub fn os_xsave(self) -> bool {
        (self.0 >> 18) & 1 != 0
    }

    /// Checks if the CR4.KL flag is set.
    ///
    /// When set, the LOADIWKEY instruction is enabled; in addition, if support
    /// for the AES Key Locker instructions has been activated by system
    /// firmware, CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 1 and the AES
    /// Key Locker instructions are enabled. When clear,
    /// CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 0 and execution of any
    /// Key Locker instruction causes an invalid-opcode exception (#UD).
    pub fn key_locker_enable(self) -> bool {
        (self.0 >> 19) & 1 != 0
    }

    /// Checks if the CR4.SMEP flag is set.
    ///
    /// Enables supervisor-mode execution prevention (SMEP) when set.
    pub fn smep_enable(self) -> bool {
        (self.0 >> 20) & 1 != 0
    }

    /// Checks if the CR4.SMAP flag is set.
    ///
    /// Enables supervisor-mode access prevention (SMAP) when set.
    pub fn smap_enable(self) -> bool {
        (self.0 >> 21) & 1 != 0
    }

    /// Checks if the CR4.PKE flag is set.
    ///
    /// Enables 4-level paging and 5-level paging associate each user-mode
    /// linear address with a protection key. When set, this flag indicates (via
    /// CPUID.(EAX=07H,ECX=0H):ECX.OSPKE [bit 4]) that the operating system
    /// supports use of the PKRU register to specify, for each protection
    /// key, whether user-mode linear addresses with that protection key can
    /// be read or written. This bit also enables access to the PKRU register
    /// using the RDPKRU and WRPKRU instructions.
    pub fn protection_key_for_user_mode_enable(self) -> bool {
        (self.0 >> 22) & 1 != 0
    }

    /// Checks if the CR4.CET flag is set.
    ///
    /// Enables control-flow enforcement technology when set. This flag can be
    /// set only if CR0.WP is set, and it must be clear before CR0.WP can be
    /// cleared.
    pub fn control_flow_enforcement(self) -> bool {
        (self.0 >> 23) & 1 != 0
    }

    /// Checks if the CR4.PKS flag is set.
    ///
    /// 4-level paging and 5-level paging associate each supervisor-mode linear
    /// address with a protection key. When set, this flag allows use of the
    /// IA32_PKRS MSR to specify, for each protection key,
    /// whether supervisor-mode linear addresses with that protection key can be
    /// read or written.
    pub fn protection_key_for_supervisor_mode_enable(self) -> bool {
        (self.0 >> 24) & 1 != 0
    }

    /// Checks if the CR4.UINTR flag is set.
    ///
    /// Enables user interrupts when set, including user-interrupt
    /// delivery, user-interrupt notification identification, and the
    /// user-interrupt instructions.
    pub fn user_interrupts_enable(self) -> bool {
        (self.0 >> 25) & 1 != 0
    }

    /// Checks if the CR4.LAM_SUP flag is set.
    ///
    /// When set, enables LAM (linear-address masking) for supervisor pointers.
    pub fn supervisor_lam_enable(self) -> bool {
        (self.0 >> 28) & 1 != 0
    }
}

impl std::fmt::Debug for Cr4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Cr4")
            .field("virtual_mode_extensions", &self.virtual_mode_extensions())
            .field(
                "protected_mode_virtual_interrupts",
                &self.protected_mode_virtual_interrupts(),
            )
            .field("timestamp_disable", &self.timestamp_disable())
            .field("debugging_extensions", &self.debugging_extensions())
            .field("page_size_extension", &self.page_size_extension())
            .field(
                "physical_address_extension",
                &self.physical_address_extension(),
            )
            .field("machine_check_enable", &self.machine_check_enable())
            .field("page_global_enable", &self.page_global_enable())
            .field(
                "performance_monitoring_counter_enable",
                &self.performance_monitoring_counter_enable(),
            )
            .field("os_fxsr_support", &self.os_fxsr_support())
            .field("os_xmm_exception_support", &self.os_xmm_exception_support())
            .field(
                "usermode_instruction_prevention",
                &self.usermode_instruction_prevention(),
            )
            .field("linear_address_57_bit", &self.linear_address_57_bit())
            .field("vmx_enable", &self.vmx_enable())
            .field("smx_enable", &self.smx_enable())
            .field("fsgsbase_enable", &self.fsgsbase_enable())
            .field("pcid_enable", &self.pcid_enable())
            .field("os_xsave", &self.os_xsave())
            .field("key_locker_enable", &self.key_locker_enable())
            .field("smep_enable", &self.smep_enable())
            .field("smap_enable", &self.smap_enable())
            .field(
                "protection_key_for_user_mode_enable",
                &self.protection_key_for_user_mode_enable(),
            )
            .field("control_flow_enforcement", &self.control_flow_enforcement())
            .field(
                "protection_key_for_supervisor_mode_enable",
                &self.protection_key_for_supervisor_mode_enable(),
            )
            .field("user_interrupts_enable", &self.user_interrupts_enable())
            .finish()
    }
}

impl From<u64> for Cr4 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Cr4> for u64 {
    fn from(value: Cr4) -> Self {
        value.0
    }
}
