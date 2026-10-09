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

        //
        // Up to Windows 11 23H2, the commit charge and the MemCommit bit
        // of a VAD are in _MMVAD_SHORT.u1.VadFlags1 (_MMVAD_FLAGS1).
        //
        // Windows 11 24H2 removed _MMVAD_FLAGS1. The commit charge is a
        // plain ULONG _MMVAD_SHORT.CommitCharge, and the MemCommit bit
        // moved into _MMVAD_SHORT.u.PrivateVadFlags (_MM_PRIVATE_VAD_FLAGS).
        // The shared VAD flags have no MemCommit bit.
        //

        #[isr(optional)]
        struct _MMVAD_FLAGS1 {
            CommitCharge: Bitfield,         // ULONG : 31
            MemCommit: Bitfield,            // ULONG : 1
        }

        struct _MMVAD_SHORT {
            //
            // NOTE: Declared as a bitfield, because before Windows 11 24H2
            //       the nested field lookup resolves this name to the
            //       u1.VadFlags1.CommitCharge bitfield. On Windows 11 24H2+
            //       it is a plain ULONG, read as a bitfield over all 32 bits.
            //       Read it only if _MMVAD_FLAGS1 is absent.
            //
            CommitCharge: Option<Bitfield>, // ULONG (Windows 11 24H2+)
        }

        #[isr(optional)]
        struct _MM_PRIVATE_VAD_FLAGS {
            MemCommit: Option<Bitfield>,    // ULONG : 1 (Windows 11 24H2+)
        }

    }
}
