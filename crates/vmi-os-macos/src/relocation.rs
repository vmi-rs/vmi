//! Relocation of profile symbols to their runtime addresses.
//!
//! The kernel collection moves each segment of the kernel independently, so
//! a single slide does not fit all symbols. Each symbol is relocated by the
//! segment that contains it in the profile, to the in-memory segment with
//! the same name.

use vmi_core::Va;

use crate::{MacOsError, MacOsSegment};

/// A profile segment paired with the base of its in-memory counterpart.
#[derive(Debug, Clone)]
struct SegmentRelocation {
    /// Address of the segment in the profile.
    profile_address: u64,

    /// Size of the segment in the profile, in bytes.
    size: u64,

    /// Address of the segment in memory.
    runtime_address: u64,
}

/// Per-segment relocation table of the kernel.
#[derive(Debug, Clone)]
pub(crate) struct KernelRelocations(Vec<SegmentRelocation>);

impl KernelRelocations {
    /// Pairs every non-empty profile segment with the in-memory segment of
    /// the same name.
    ///
    /// `profile_segments` yields `(name, address, size)` triples. A profile
    /// segment without an in-memory counterpart is an error.
    pub fn new<'a>(
        profile_segments: impl IntoIterator<Item = (&'a str, u64, u64)>,
        runtime_segments: &[MacOsSegment],
    ) -> Result<Self, MacOsError> {
        let mut result = Vec::new();

        for (name, profile_address, size) in profile_segments {
            if size == 0 {
                continue;
            }

            let runtime = match runtime_segments.iter().find(|segment| segment.name == name) {
                Some(runtime) => runtime,
                None => return Err(MacOsError::MissingSegment(String::from(name))),
            };

            result.push(SegmentRelocation {
                profile_address,
                size,
                runtime_address: runtime.address.0,
            });
        }

        Ok(Self(result))
    }

    /// Returns the runtime address of the profile address `address`.
    pub fn relocate(&self, address: u64) -> Result<Va, MacOsError> {
        for segment in &self.0 {
            let offset = match address.checked_sub(segment.profile_address) {
                Some(offset) if offset < segment.size => offset,
                _ => continue,
            };

            return Ok(Va(segment.runtime_address + offset));
        }

        Err(MacOsError::SymbolOutsideSegment(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an in-memory segment.
    fn runtime(name: &str, address: u64, size: u64) -> MacOsSegment {
        MacOsSegment {
            name: String::from(name),
            address: Va(address),
            size,
        }
    }

    /// Returns a relocation table with two segments that moved by different
    /// distances.
    fn relocations() -> KernelRelocations {
        KernelRelocations::new(
            [
                ("__TEXT", 0xfffffe0007004000, 0x11c000),
                ("__DATA_CONST", 0xfffffe0007120000, 0x1e0000),
                ("__EMPTY", 0xfffffe0007000000, 0),
            ],
            &[
                runtime("__DATA_CONST", 0xfffffe0029f7c000, 0x1e0000),
                runtime("__TEXT", 0xfffffe0029770000, 0x11c000),
            ],
        )
        .unwrap()
    }

    #[test]
    fn relocates_by_containing_segment() {
        let relocations = relocations();

        assert_eq!(
            relocations.relocate(0xfffffe0007004000).unwrap(),
            Va(0xfffffe0029770000)
        );
        assert_eq!(
            relocations.relocate(0xfffffe000711ffff).unwrap(),
            Va(0xfffffe002988bfff)
        );
        assert_eq!(
            relocations.relocate(0xfffffe0007120000).unwrap(),
            Va(0xfffffe0029f7c000)
        );
        assert_eq!(
            relocations.relocate(0xfffffe00072c5b88).unwrap(),
            Va(0xfffffe002a121b88)
        );
    }

    #[test]
    fn rejects_addresses_outside_segments() {
        let relocations = relocations();

        assert!(relocations.relocate(0xfffffe0007003fff).is_err());
        assert!(relocations.relocate(0xfffffe0007300000).is_err());
    }

    #[test]
    fn rejects_missing_runtime_segment() {
        let result = KernelRelocations::new(
            [
                ("__TEXT", 0xfffffe0007004000, 0x4000),
                ("__DATA", 0xfffffe0007cac000, 0x4000),
            ],
            &[runtime("__TEXT", 0xfffffe0029770000, 0x4000)],
        );

        assert!(matches!(result, Err(MacOsError::MissingSegment(name)) if name == "__DATA"));
    }
}
