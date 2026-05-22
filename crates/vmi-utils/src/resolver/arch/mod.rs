#[cfg(feature = "arch-amd64")]
mod amd64;

use vmi_core::{Architecture, Pa, VmiDriver, VmiOs, VmiSession, VmiState};

/// Architecture-specific functionality used by the resolver.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiDriver<Architecture = Self>,
{
    /// Returns a [`VmiState`] whose memory reads translate through `root`.
    ///
    /// Used to switch into another process's address space when reading
    /// its memory.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: Writes `root` to `CR3`.
    fn with_translation_root<'a, Os>(
        vmi: &'a VmiSession<Os>,
        registers: &'a mut Self::Registers,
        root: Pa,
    ) -> VmiState<'a, Os>
    where
        Os: VmiOs<Architecture = Self>;
}
