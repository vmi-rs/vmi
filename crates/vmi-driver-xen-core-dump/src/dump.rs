use std::{fs::File, path::Path};

use elf::{endian::AnyEndian, note::Note, section::SectionHeader, ElfBytes, ParseError};
use memmap2::Mmap;
use xen::sys::vcpu_guest_context;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::Error;

pub struct Dump {
    mmap: Mmap,
    xen_pfn_shdr: SectionHeader,
    xen_pages_shdr: SectionHeader,
    xen_prstatus_shdr: SectionHeader,
    nr_vcpus: u64,
    nr_pages: u64,
    page_size: u64,
}

impl Dump {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        let elf = ElfBytes::<AnyEndian>::minimal_parse(&mmap)?;

        let xen_note = parse_xen_dumpcore_elfnote_header_desc(&elf)?.expect("xen note not found");

        let xen_pfn_shdr = elf
            .section_header_by_name(".xen_pfn")?
            .expect("xen_pfn section not found");

        if xen_pfn_shdr.sh_size != xen_note.xch_nr_pages * size_of::<u64>() as u64 {
            panic!("xen_pfn section size does not match the number of pages");
        }

        let xen_pages_shdr = elf
            .section_header_by_name(".xen_pages")?
            .expect("xen_pages section not found");

        if xen_pages_shdr.sh_size != xen_note.xch_nr_pages * xen_note.xch_page_size {
            panic!("xen_pages section size does not match the number of pages");
        }

        let xen_prstatus_shdr = elf
            .section_header_by_name(".xen_prstatus")?
            .expect("xen_prstatus section not found");

        if xen_prstatus_shdr.sh_size
            != xen_note.xch_nr_vcpus * size_of::<vcpu_guest_context>() as u64
        {
            panic!("xen_prstatus section size does not match the number of vcpus");
        }

        Ok(Self {
            mmap,
            xen_pfn_shdr,
            xen_pages_shdr,
            xen_prstatus_shdr,
            nr_vcpus: xen_note.xch_nr_vcpus,
            nr_pages: xen_note.xch_nr_pages,
            page_size: xen_note.xch_page_size,
        })
    }

    pub fn xen_pfn(&self) -> Result<&[u64], ParseError> {
        let data = self.data(&self.xen_pfn_shdr)?;

        let ptr = data.as_ptr() as *const u64;
        let len = data.len() / size_of::<u64>();

        // SAFETY: The data is guaranteed to be correctly aligned and sized.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    pub fn xen_pages(&self) -> Result<&[u8], ParseError> {
        self.data(&self.xen_pages_shdr)
    }

    pub fn xen_prstatus(&self) -> Result<&[vcpu_guest_context], ParseError> {
        let data = self.data(&self.xen_prstatus_shdr)?;

        let ptr = data.as_ptr() as *const vcpu_guest_context;
        let len = data.len() / size_of::<vcpu_guest_context>();

        // SAFETY: The data is guaranteed to be correctly aligned and sized.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    #[expect(unused)]
    pub fn nr_vcpus(&self) -> u64 {
        self.nr_vcpus
    }

    #[expect(unused)]
    pub fn nr_pages(&self) -> u64 {
        self.nr_pages
    }

    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    fn data(&self, shdr: &SectionHeader) -> Result<&[u8], ParseError> {
        let start = usize::try_from(shdr.sh_offset)?;
        let size = usize::try_from(shdr.sh_size)?;
        let end = start.checked_add(size).ok_or(ParseError::IntegerOverflow)?;

        self.mmap
            .get(start..end)
            .ok_or(ParseError::SliceReadError((start, end)))
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[allow(non_camel_case_types)]
struct xen_dumpcore_elfnote_header_desc {
    xch_magic: u64,
    xch_nr_vcpus: u64,
    xch_nr_pages: u64,
    xch_page_size: u64,
}

fn parse_xen_dumpcore_elfnote_header_desc(
    elf: &ElfBytes<AnyEndian>,
) -> Result<Option<xen_dumpcore_elfnote_header_desc>, ParseError> {
    let mut xen_notes = elf
        .section_header_by_name(".note.Xen")?
        .expect("xen notes not found");

    // Xen stores the notes in a section with alignment 0, which is not
    // allowed by the ELF specification. We set the alignment to 1 to
    // work around this.
    if xen_notes.sh_addralign == 0 {
        xen_notes.sh_addralign = 1;
    }

    for note in elf.section_data_as_notes(&xen_notes)? {
        if let Note::Unknown(note) = note {
            const XEN_ELFNOTE_DUMPCORE_HEADER: u64 = 0x2000001;

            // const XC_CORE_MAGIC: u64 = 0xF00FEBED; // for paravirtualized domain
            // const XC_CORE_MAGIC_HVM: u64 = 0xF00FEBEE; // for full virtualized domain

            if note.n_type != XEN_ELFNOTE_DUMPCORE_HEADER
                || note.desc.len() != size_of::<xen_dumpcore_elfnote_header_desc>()
            {
                continue;
            }

            // SAFETY: The note.desc is guaranteed to be the correct size.
            return Ok(Some(
                xen_dumpcore_elfnote_header_desc::ref_from_bytes(note.desc)
                    .copied()
                    .unwrap(),
            ));
        }
    }

    Ok(None)
}
