use isr_macros::{offsets, Field};

offsets! {
    /// Windows 7 kernel offsets used by the [`WindowsOs`] implementation.
    ///
    /// [`WindowsOs`]: crate::WindowsOs
    #[derive(Debug)]
    pub struct Offsets {

        struct _SECTION_OBJECT {
            StartingVa: Field,
            EndingVa: Field,
            Segment: Field,
        }

        struct _SEGMENT_OBJECT {
            BaseAddress: Field,
            SizeOfSegment: Field,
            ControlArea: Field,
            MmSectionFlags: Field,
        }

        struct _HANDLE_TABLE_ENTRY {
            Object: Field,
            ObAttributes: Field,
            GrantedAccess: Field,
        }

        struct _MM_AVL_TABLE {
            BalancedRoot: Field,            // _MMADDRESS_NODE
            NodeHint: Field,                // PVOID
        }

        struct _MMADDRESS_NODE {
            LeftChild: Field,
            RightChild: Field,
        }

    }
}