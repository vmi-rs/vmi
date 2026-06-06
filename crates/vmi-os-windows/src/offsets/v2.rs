use isr_macros::{Bitfield, Field, offsets};

offsets! {
    /// Windows 10+ kernel offsets used by the [`WindowsOs`] implementation.
    ///
    /// [`WindowsOs`]: crate::WindowsOs
    #[derive(Debug)]
    pub struct Offsets {

        struct _SECTION {
            StartingVpn: Field,
            EndingVpn: Field,
            ControlArea: Field,
            Flags: Field,
            SizeOfSection: Field,
        }

        struct _HANDLE_TABLE_ENTRY {
            Attributes: Bitfield,
            ObjectPointerBits: Bitfield,
            GrantedAccessBits: Bitfield,
        }

        struct _EWOW64PROCESS {
            Peb: Field,                     // PVOID
        }

        struct _RTL_AVL_TREE {
            Root: Field,                    // _RTL_BALANCED_NODE*
        }

        struct _RTL_BALANCED_NODE {
            Left: Field,                    // _RTL_BALANCED_NODE*
            Right: Field,                   // _RTL_BALANCED_NODE*
            ParentValue: Field,             // ULONG_PTR
        }

        // Windows 8 through early Windows 10. Recent Windows 10/11 dissolved this
        // type: CommitCharge became the direct field _MMVAD_SHORT.CommitCharge and
        // MemCommit moved into _MM_PRIVATE_VAD_FLAGS, so it is optional here.
        #[isr(optional)]
        struct _MMVAD_FLAGS1 {
            CommitCharge: Bitfield,         // ULONG : 31
            MemCommit: Bitfield,            // ULONG : 1
        }

        // Recent Windows 10/11. Overlays the _MMVAD_SHORT.u5 longflags union and
        // carries MemCommit (the commit charge is the direct _MMVAD_SHORT.CommitCharge
        // field). Absent on Windows 8 / early Windows 10, so optional.
        #[isr(optional)]
        struct _MM_PRIVATE_VAD_FLAGS {
            MemCommit: Bitfield,            // ULONG : 1
        }

    }
}
