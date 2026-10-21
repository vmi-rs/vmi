bitflags::bitflags! {
    /// Page-fault error code.
    ///
    /// The error code that the processor provides on delivery of a page-fault
    /// exception (#PF; exception 14). An access to a linear address may cause
    /// a page-fault exception for either of two reasons: (1) there is no
    /// translation for the linear address; or (2) there is a translation for
    /// the linear address, but its access rights do not permit the access.
    ///
    /// See the Intel SDM, Vol. 3A, section 5.7 and Figure 5-12.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct PageFaultErrorCode: u32 {
        /// P flag (bit 0).
        ///
        /// This flag is 0 if there is no translation for the linear address
        /// because the P flag was 0 in one of the paging-structure entries
        /// used to translate that address.
        ///
        /// - 0: The fault was caused by a non-present page.
        /// - 1: The fault was caused by a page-level protection violation.
        const PROTECTION = 1 << 0;

        /// W/R (bit 1).
        ///
        /// If the access causing the page-fault exception was a write, this
        /// flag is 1; otherwise, it is 0. This flag describes the access
        /// causing the page-fault exception, not the access rights specified
        /// by paging.
        const WRITE = 1 << 1;

        /// U/S (bit 2).
        ///
        /// If a user-mode access caused the page-fault exception, this flag is
        /// 1; it is 0 if a supervisor-mode access did so. This flag describes
        /// the access causing the page-fault exception, not the access rights
        /// specified by paging. User-mode and supervisor-mode accesses are
        /// defined in Section 5.6.
        const USER = 1 << 2;

        /// RSVD flag (bit 3).
        ///
        /// This flag is 1 if there is no translation for the linear address
        /// because a reserved bit was set in one of the paging-structure
        /// entries used to translate that address. (Because reserved bits are
        /// not checked in a paging-structure entry whose P flag is 0, bit 3 of
        /// the error code can be set only if bit 0 is also set.)
        ///
        /// Bits reserved in the paging-structure entries are reserved for
        /// future functionality. Software developers should be aware that such
        /// bits may be used in the future and that a paging-structure entry
        /// that causes a page-fault exception on one processor might not do so
        /// in the future.
        const RESERVED_BIT = 1 << 3;

        /// I/D flag (bit 4).
        ///
        /// This flag is 1 if (1) the access causing the page-fault exception
        /// was an instruction fetch; and (2) either (a) CR4.SMEP = 1; or (b)
        /// both (i) CR4.PAE = 1 (either PAE paging, 4-level paging, or 5-level
        /// paging is in use); and (ii) IA32_EFER.NXE = 1. Otherwise, the flag
        /// is 0. This flag describes the access causing the page-fault
        /// exception, not the access rights specified by paging.
        const INSTRUCTION_FETCH = 1 << 4;

        /// PK flag (bit 5).
        ///
        /// This flag is 1 only for data accesses and only with 4-level paging
        /// and 5-level paging. In these cases, the setting depends on the mode
        /// of the address being accessed:
        ///
        /// - For accesses to supervisor-mode addresses, the flag is set if (1)
        ///   CR4.PKS = 1; (2) the linear address has protection key i; and (3)
        ///   the IA32_PKRS MSR (see Section 5.6.2) is such that either (a)
        ///   ADi = 1; or (b) the following all hold: (i) WDi = 1; (ii) the
        ///   access is a write access; and (iii) either CR0.WP = 1 or the
        ///   access causing the page-fault exception was a user-mode access.
        ///   (Note that this flag may be set on page faults due to user-mode
        ///   accesses to supervisor-mode addresses.)
        /// - For accesses to user-mode addresses, the flag is set if (1)
        ///   CR4.PKE = 1; (2) the linear address has protection key i; and (3)
        ///   the PKRU register (see Section 5.6.2) is such that either (a)
        ///   ADi = 1; or (b) the following all hold: (i) WDi = 1; (ii) the
        ///   access is a write access; and (iii) either CR0.WP = 1 or the
        ///   access causing the page-fault exception was a user-mode access.
        const PROTECTION_KEY = 1 << 5;

        /// SS (bit 6).
        ///
        /// If the access causing the page-fault exception was a shadow-stack
        /// access (including shadow-stack accesses in enclave mode), this flag
        /// is 1; otherwise, it is 0. This flag describes the access causing the
        /// page-fault exception, not the access rights specified by paging.
        const SHADOW_STACK = 1 << 6;

        /// HLAT (bit 7).
        ///
        /// This flag is 1 if there is no translation for the linear address
        /// using HLAT paging because, in one of the paging-structure entries
        /// used to translate that address, either the P flag was 0 or a
        /// reserved bit was set. An error code will set this flag only if it
        /// clears bit 0 or sets bit 3. This flag will not be set by a page
        /// fault resulting from a violation of access rights, nor for one
        /// encountered during ordinary paging, including the case in which
        /// there has been a restart of HLAT paging.
        const HLAT = 1 << 7;

        /// SGX flag (bit 15).
        ///
        /// This flag is 1 if the exception is unrelated to paging and resulted
        /// from violation of SGX-specific access-control requirements. Because
        /// such a violation can occur only if there is no ordinary page fault,
        /// this flag is set only if the P flag (bit 0) is 1 and the RSVD flag
        /// (bit 3) and the PK flag (bit 5) are both 0.
        const SGX = 1 << 15;
    }
}
