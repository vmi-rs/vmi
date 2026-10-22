//! ELF notes and the GNU build-id.

use vmi_core::{Va, VmiError};

use super::{
    ELF_NOTE_GNU, ElfReader, NT_GNU_BUILD_ID, NoteHeader64, checked_size, parse, read_bytes,
};
use crate::LinuxError;

/// Upper limit for the size of a notes region.
const NOTES_MAX: usize = 1 << 16;

/// A GNU build-id.
///
/// The linker hashes an image and writes the hash into a note with the type
/// `NT_GNU_BUILD_ID`. Debug files and debuginfod servers are indexed by it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BuildId(Vec<u8>);

impl BuildId {
    /// Returns the build-id's bytes, which are the descriptor in its note.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Formats the build-id as lowercase hex, as `readelf -n` prints it.
impl std::fmt::Display for BuildId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

/// Returns the alignment of the notes in a `PT_NOTE` segment.
///
/// A segment with `p_align` 8 holds notes aligned to 8 bytes, such as
/// `.note.gnu.property`. Every other segment holds notes aligned to 4 bytes.
pub(crate) fn segment_alignment(p_align: u64) -> usize {
    if p_align == 8 { 8 } else { 4 }
}

/// Reads a region of notes and returns its first GNU build-id.
///
/// `va` and `length` give the region, and `align` is the alignment of its
/// notes. A region larger than 64 KiB is an error.
pub(crate) fn read_build_id(
    reader: &impl ElfReader,
    va: Va,
    length: u64,
    align: usize,
) -> Result<Option<BuildId>, VmiError> {
    let length = checked_size(length, NOTES_MAX, "ELF notes")?;
    let notes = read_bytes(reader, va, length)?;
    find_build_id(&notes, align)
}

/// Returns the first GNU build-id in a region of notes.
///
/// Each note is an `Elf64_Nhdr` followed by its name and its descriptor. The
/// name and the descriptor are each padded to `align` bytes, counted from the
/// start of the region. A build-id note has the name `GNU` and the type
/// `NT_GNU_BUILD_ID`, and its descriptor holds the build-id. A build-id note
/// with an empty descriptor is skipped. A note that runs past the end of the
/// region is an error.
fn find_build_id(notes: &[u8], align: usize) -> Result<Option<BuildId>, VmiError> {
    let mut offset = 0;

    while offset < notes.len() {
        let header = parse::<NoteHeader64>(&notes[offset..], "ELF note header")?;
        let name_start = offset + size_of::<NoteHeader64>();

        let note = name_start
            .checked_add(header.n_namesz as usize)
            .and_then(|name_end| {
                let descriptor_start = name_end.checked_next_multiple_of(align)?;
                let descriptor_end = descriptor_start.checked_add(header.n_descsz as usize)?;
                Some((
                    notes.get(name_start..name_end)?,
                    notes.get(descriptor_start..descriptor_end)?,
                    descriptor_end.checked_next_multiple_of(align)?,
                ))
            });

        let (name, descriptor, next) = match note {
            Some(note) => note,
            None => return Err(LinuxError::CorruptedImage("ELF note").into()),
        };

        if header.n_type == NT_GNU_BUILD_ID
            && name.strip_suffix(b"\0") == Some(ELF_NOTE_GNU)
            && !descriptor.is_empty()
        {
            return Ok(Some(BuildId(descriptor.to_vec())));
        }

        offset = next;
    }

    Ok(None)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Appends a note with its padding to a region of notes.
    pub(crate) fn push_note(
        notes: &mut Vec<u8>,
        name: &[u8],
        kind: u32,
        descriptor: &[u8],
        align: usize,
    ) {
        notes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        notes.extend_from_slice(&(descriptor.len() as u32).to_le_bytes());
        notes.extend_from_slice(&kind.to_le_bytes());
        notes.extend_from_slice(name);
        notes.resize(notes.len().next_multiple_of(align), 0);
        notes.extend_from_slice(descriptor);
        notes.resize(notes.len().next_multiple_of(align), 0);
    }

    /// A build-id of 20 bytes, as `ld --build-id=sha1` writes it.
    pub(crate) const BUILD_ID: [u8; 20] = [
        0x2b, 0x6e, 0x3c, 0x8a, 0x91, 0x07, 0x5d, 0xf4, 0x10, 0xaa, 0x00, 0x43, 0x9e, 0x5c, 0x77,
        0x01, 0xfe, 0x28, 0xb6, 0x0d,
    ];

    #[test]
    fn build_id_after_another_note() -> Result<(), VmiError> {
        // The kernel puts a `Linux` note before its build-id.
        let mut notes = Vec::new();
        push_note(&mut notes, b"Linux\0", 6, b"6.8.0\0", 4);
        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, 4);

        assert_eq!(find_build_id(&notes, 4)?, Some(BuildId(BUILD_ID.to_vec())));
        Ok(())
    }

    #[test]
    fn build_id_after_padding_to_eight_bytes() -> Result<(), VmiError> {
        // A property note with 12 bytes needs 4 padding bytes before the next
        // note at 8 bytes.
        let mut notes = Vec::new();
        push_note(&mut notes, b"GNU\0", 5, &[0xaa; 12], 8);
        assert_eq!(notes.len(), 16 + 16);
        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, 8);

        assert_eq!(find_build_id(&notes, 8)?, Some(BuildId(BUILD_ID.to_vec())));
        Ok(())
    }

    #[test]
    fn type_three_with_another_name_is_no_build_id() -> Result<(), VmiError> {
        let mut notes = Vec::new();
        push_note(&mut notes, b"Xen\0", NT_GNU_BUILD_ID, &[0x11; 8], 4);
        push_note(&mut notes, b"GNUX\0", NT_GNU_BUILD_ID, &[0x22; 8], 4);
        assert_eq!(find_build_id(&notes, 4)?, None);

        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, 4);
        assert_eq!(find_build_id(&notes, 4)?, Some(BuildId(BUILD_ID.to_vec())));
        Ok(())
    }

    #[test]
    fn empty_descriptor_is_skipped() -> Result<(), VmiError> {
        let mut notes = Vec::new();
        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &[], 4);
        assert_eq!(find_build_id(&notes, 4)?, None);

        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, 4);
        assert_eq!(find_build_id(&notes, 4)?, Some(BuildId(BUILD_ID.to_vec())));
        Ok(())
    }

    #[test]
    fn truncated_note_is_an_error() {
        let mut notes = Vec::new();
        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, 4);

        // The descriptor runs past the region.
        assert!(find_build_id(&notes[..notes.len() - 1], 4).is_err());

        // The region ends inside the header.
        assert!(find_build_id(&notes[..8], 4).is_err());

        // The name length runs past the region.
        let mut notes = Vec::new();
        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, 4);
        notes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(find_build_id(&notes, 4).is_err());
    }

    #[test]
    fn empty_region_has_no_build_id() -> Result<(), VmiError> {
        assert_eq!(find_build_id(&[], 4)?, None);
        Ok(())
    }

    #[test]
    fn build_id_prints_as_lowercase_hex() -> Result<(), VmiError> {
        let mut notes = Vec::new();
        push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, 4);

        let build_id = find_build_id(&notes, 4)?.map(|build_id| build_id.to_string());
        assert_eq!(
            build_id.as_deref(),
            Some("2b6e3c8a91075df410aa00439e5c7701fe28b60d")
        );
        Ok(())
    }

    #[test]
    fn segment_alignment_is_eight_only_for_eight() {
        assert_eq!(segment_alignment(8), 8);
        assert_eq!(segment_alignment(4), 4);
        assert_eq!(segment_alignment(0), 4);
        assert_eq!(segment_alignment(16), 4);
    }
}
