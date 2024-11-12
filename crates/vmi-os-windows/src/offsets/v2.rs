use isr_macros::{offsets, Bitfield, Field};

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

        struct _MMVAD_FLAGS1 {
            MemCommit: Bitfield,            // ULONG bitfield (1 bit, might be in _MMVAD_FLAGS1)
        }

    }
}
