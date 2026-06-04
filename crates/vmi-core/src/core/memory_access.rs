use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// Memory access permission flags.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub struct MemoryAccess: u8 {
        /// Read permission.
        const R = 0b00000001;

        /// Write permission.
        const W = 0b00000010;

        /// Execute permission.
        const X = 0b00000100;

        /// Combined Read and Write permissions.
        const RW = Self::R.bits() | Self::W.bits();

        /// Combined Write and Execute permissions.
        const WX = Self::W.bits() | Self::X.bits();

        /// Combined Read and Execute permissions.
        const RX = Self::R.bits() | Self::X.bits();

        /// Full access: Read, Write, and Execute permissions.
        const RWX = Self::R.bits() | Self::W.bits() | Self::X.bits();
    }
}

bitflags::bitflags! {
    /// Options for controlling memory access monitoring.
    ///
    /// These options can be used to fine-tune the behavior of memory access
    /// monitoring, allowing you to ignore certain types of memory accesses
    /// and improve performance.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub struct MemoryAccessOptions: u8 {
        /// Ignore page-walk updates caused by the CPU.
        ///
        /// When this flag is set, memory accesses that are solely the result of
        /// CPU-initiated page-table walks will not trigger an [`EventMemoryAccess`].
        /// This is useful for filtering out irrelevant events when monitoring
        /// page-table modifications.
        ///
        /// # Notes
        ///
        /// This option is only effective when the [`MemoryAccess:W`] is not set.
        ///
        /// [`EventMemoryAccess`]: ../vmi_arch_amd64/struct.EventMemoryAccess.html
        const IGNORE_PAGE_WALK_UPDATES = 0b00000001;

        /// Single-step neighbor guest pages in the kernel instead of delivering
        /// a mem-access event.
        ///
        /// On a host whose page size exceeds the guest granule, one stage-2
        /// leaf protects several fused guest pages at once. With this flag the
        /// driver marks every guest page fused into the target's host page,
        /// except the target itself, for in-kernel single-stepping, so a data
        /// access to a neighbor is retired in the kernel rather than storming
        /// the agent with an event per access. Accesses to the target page
        /// still deliver normally. This has no effect when the host and guest
        /// page sizes match.
        const AUTO_STEP_NEIGHBORS = 0b00000010;
    }
}

impl std::fmt::Display for MemoryAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut result = [b'-'; 3];

        if self.contains(MemoryAccess::R) {
            result[0] = b'r';
        }
        if self.contains(MemoryAccess::W) {
            result[1] = b'w';
        }
        if self.contains(MemoryAccess::X) {
            result[2] = b'x';
        }

        // SAFETY: The `result` array is always valid UTF-8.
        f.write_str(unsafe { std::str::from_utf8_unchecked(&result) })
    }
}
