/// `CR3` control register.
///
/// Contains the physical address of the page directory base and controls page
/// directory caching.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Cr3(pub u64);

impl Cr3 {
    /// Returns the Process Context Identifier (PCID).
    pub fn pcid(self) -> u16 {
        (self.0 & 0xfff) as _
    }

    /// Returns the page table base physical address.
    pub fn page_frame_number(self) -> u64 {
        self.0 >> 12 & 0x000f_ffff_ffff_ffff
    }

    /// Returns true if the PCID should be invalidated.
    pub fn pcid_invalidate(self) -> bool {
        self.0 >> 63 & 1 != 0
    }
}

impl std::fmt::Debug for Cr3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Cr3")
            .field("pcid", &self.pcid())
            .field("page_frame_number", &self.page_frame_number())
            .field("pcid_invalidate", &self.pcid_invalidate())
            .finish()
    }
}

impl From<u64> for Cr3 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Cr3> for u64 {
    fn from(value: Cr3) -> Self {
        value.0
    }
}
