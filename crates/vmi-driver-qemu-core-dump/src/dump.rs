use std::{ops::Deref, rc::Rc};

use elf::{
    ElfBytes,
    abi::{ET_CORE, NT_PRSTATUS, PT_LOAD, PT_NOTE},
    endian::LittleEndian,
    file::Class,
    note::{Note, NoteIterator},
};
use memmap2::Mmap;

use crate::Error;

/// Offset of `pr_pid` within a 64-bit `NT_PRSTATUS` descriptor.
const PRSTATUS_PID_OFFSET: usize = 32;

/// Guest physical memory backed by one `PT_LOAD` segment.
#[derive(Debug, Clone, Copy)]
struct Segment {
    /// First guest physical address of the segment (`p_paddr`).
    start: u64,

    /// End of the guest physical range of the segment (`p_paddr + p_memsz`).
    end: u64,

    /// End of the file-backed part (`p_paddr + p_filesz`). Memory between
    /// this address and `end` reads as zero.
    file_end: u64,

    /// File offset of `start` (`p_offset`).
    offset: u64,
}

/// A borrowed range of the memory-mapped dump.
///
/// Keeps the mapping alive so the range can back a page without copying.
pub(crate) struct MappedRange {
    /// Shared mapping of the dump file.
    mmap: Rc<Mmap>,

    /// Start of the range within the file.
    start: usize,

    /// End of the range within the file.
    end: usize,
}

impl Deref for MappedRange {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mmap[self.start..self.end]
    }
}

/// A page read from the dump.
pub(crate) enum Page {
    /// The page lies within one file-backed segment and borrows the mapping.
    Mapped(MappedRange),

    /// The page spans several segments or holes and was assembled into an
    /// owned buffer.
    Assembled(Vec<u8>),
}

/// Parsed layout of a QEMU ELF core dump.
pub(crate) struct Dump {
    /// Shared mapping of the dump file.
    mmap: Rc<Mmap>,

    /// `PT_LOAD` segments sorted by guest physical address.
    segments: Vec<Segment>,
}

/// Contents of a dump that borrow the mapping before it is shared.
pub(crate) struct DumpNotes<'a> {
    /// Descriptors of the `NT_PRSTATUS` notes, in note order.
    pub prstatus: Vec<&'a [u8]>,
}

impl Dump {
    /// Parses the ELF headers of `mmap`, validating the file type and the
    /// machine, and passes the `NT_PRSTATUS` notes to `notes`.
    ///
    /// The callback runs while the notes still borrow the mapping, before the
    /// mapping is moved into shared ownership.
    pub fn new<T>(
        mmap: Mmap,
        machine: u16,
        notes: impl FnOnce(DumpNotes) -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        let elf = ElfBytes::<LittleEndian>::minimal_parse(&mmap)?;

        if elf.ehdr.e_type != ET_CORE || elf.ehdr.class != Class::ELF64 {
            return Err(Error::NotCoreDump {
                e_type: elf.ehdr.e_type,
                class: match elf.ehdr.class {
                    Class::ELF32 => "ELF32",
                    Class::ELF64 => "ELF64",
                },
            });
        }

        if elf.ehdr.e_machine != machine {
            return Err(Error::MachineMismatch {
                expected: machine,
                found: elf.ehdr.e_machine,
            });
        }

        let phdrs = match elf.segments() {
            Some(phdrs) => phdrs,
            None => return Err(Error::NoProgramHeaders),
        };

        let mut segments = Vec::new();
        let mut prstatus = Vec::new();

        for phdr in phdrs.iter() {
            match phdr.p_type {
                PT_LOAD if phdr.p_memsz != 0 => {
                    let file_end = phdr.p_offset.checked_add(phdr.p_filesz);
                    if file_end.is_none_or(|file_end| file_end > mmap.len() as u64)
                        || phdr.p_filesz > phdr.p_memsz
                    {
                        return Err(Error::TruncatedSegment {
                            address: phdr.p_paddr,
                        });
                    }

                    segments.push(Segment {
                        start: phdr.p_paddr,
                        end: phdr.p_paddr + phdr.p_memsz,
                        file_end: phdr.p_paddr + phdr.p_filesz,
                        offset: phdr.p_offset,
                    });
                }
                PT_NOTE => {
                    // QEMU pads note names and descriptors to 4 bytes,
                    // regardless of `p_align`.
                    let data = elf.segment_data(&phdr)?;
                    let iter = NoteIterator::new(LittleEndian, Class::ELF64, 4, data);

                    for note in iter {
                        if let Note::Unknown(note) = note
                            && note.n_type == NT_PRSTATUS
                            && note.name_str()? == "CORE"
                        {
                            prstatus.push(note.desc);
                        }
                    }
                }
                _ => (),
            }
        }

        segments.sort_by_key(|segment| segment.start);
        for pair in segments.windows(2) {
            if pair[1].start < pair[0].end {
                return Err(Error::OverlappingSegments {
                    address: pair[1].start,
                });
            }
        }

        if prstatus.is_empty() {
            return Err(Error::NoVcpus);
        }

        if prstatus.len() > u16::MAX as usize {
            return Err(Error::TooManyVcpus {
                count: prstatus.len(),
            });
        }

        for (vcpu, desc) in prstatus.iter().enumerate() {
            let pid = match desc.get(PRSTATUS_PID_OFFSET..PRSTATUS_PID_OFFSET + 4) {
                Some(pid) => u32::from_le_bytes([pid[0], pid[1], pid[2], pid[3]]),
                None => {
                    return Err(Error::InvalidPrstatus {
                        vcpu: vcpu as u16,
                        size: desc.len(),
                        expected: PRSTATUS_PID_OFFSET + 4,
                    });
                }
            };

            if pid as usize != vcpu + 1 {
                return Err(Error::UnexpectedPid {
                    vcpu: vcpu as u16,
                    pid,
                });
            }
        }

        let result = notes(DumpNotes { prstatus })?;

        Ok((
            Self {
                mmap: Rc::new(mmap),
                segments,
            },
            result,
        ))
    }

    /// Returns the end of the highest `PT_LOAD` segment.
    pub fn end(&self) -> u64 {
        match self.segments.last() {
            Some(segment) => segment.end,
            None => 0,
        }
    }

    /// Reads `size` bytes of guest physical memory at `address`.
    ///
    /// Returns a borrowed range when one segment backs the whole range from
    /// the file. Otherwise assembles the bytes, filling holes with zeros.
    /// Returns `None` when no segment overlaps the range.
    pub fn read(&self, address: u64, size: u64) -> Option<Page> {
        let end = address.checked_add(size)?;

        // Index of the first segment that ends after `address`.
        let first = self
            .segments
            .partition_point(|segment| segment.end <= address);

        let segment = self.segments.get(first)?;
        if segment.start <= address && end <= segment.file_end {
            let start = (segment.offset + (address - segment.start)) as usize;
            return Some(Page::Mapped(MappedRange {
                mmap: self.mmap.clone(),
                start,
                end: start + size as usize,
            }));
        }

        let mut buffer = vec![0; size as usize];
        let mut overlapped = false;

        for segment in &self.segments[first..] {
            if segment.start >= end {
                break;
            }

            overlapped = true;

            // Copy the file-backed intersection. The rest stays zero.
            let copy_start = segment.start.max(address);
            let copy_end = segment.file_end.min(end);
            if copy_start >= copy_end {
                continue;
            }

            let file_start = (segment.offset + (copy_start - segment.start)) as usize;
            let file_end = file_start + (copy_end - copy_start) as usize;
            let buffer_start = (copy_start - address) as usize;
            let buffer_end = (copy_end - address) as usize;
            buffer[buffer_start..buffer_end].copy_from_slice(&self.mmap[file_start..file_end]);
        }

        if !overlapped {
            return None;
        }

        Some(Page::Assembled(buffer))
    }
}
