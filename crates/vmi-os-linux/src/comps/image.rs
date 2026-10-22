use once_cell::unsync::OnceCell;
use vmi_core::{
    Architecture as _, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsImage, VmiOsImageArchitecture, VmiOsImageSymbol, VmiOsModule as _},
};

use crate::{
    ArchAdapter, BuildId, LinuxError, LinuxOs,
    elf::{self, ElfImage, GuestElfReader},
    offset,
    offsets::ModuleNotesLayout,
    symbol,
};

/// Size of a `struct kernel_symbol`, three 32-bit offsets with
/// `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS`, which x86-64 sets.
const KERNEL_SYMBOL_SIZE: usize = 12;

/// Upper limit of the entries in an export table.
const KERNEL_SYMBOLS_MAX: usize = 1 << 20;

/// Upper limit for the span that the names in a symbol table cover.
const KERNEL_NAMES_MAX: u64 = 1 << 24;

/// Maximum length of a kernel symbol name (`KSYM_NAME_LEN`).
pub(super) const KSYM_NAME_LEN: usize = 512;

/// The notes of the kernel and its modules are aligned to this many bytes.
const NOTE_ALIGN: usize = 4;

/// Name of the notes section that holds a module's build-id.
const BUILD_ID_SECTION: &[u8] = b".note.gnu.build-id";

/// Upper limit of the notes sections in a module.
const MODULE_NOTES_MAX: u64 = 256;

/// What the base address of an image names.
#[derive(Debug, Clone, Copy)]
enum ImageKind {
    /// An ELF image in user space.
    User,

    /// The kernel.
    Kernel,

    /// A kernel module, with the address of its `struct module`.
    Module(Va),
}

/// A Linux image: an ELF executable or shared object in user space, the
/// kernel, or a kernel module.
///
/// An ELF image is read from its headers and its dynamic section, through
/// the state's address space. The kernel and its modules have no ELF header
/// in memory, and their exports come from their export tables.
pub struct LinuxImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Base address of the image.
    va: Va,

    /// What the base address names, decided on first use.
    kind: OnceCell<ImageKind>,

    /// The parsed ELF image, for an image in user space.
    elf: OnceCell<ElfImage>,
}

impl<Driver> VmiVa for LinuxImage<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new image at a base address. Nothing is read until a
    /// method needs it.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            kind: OnceCell::new(),
            elf: OnceCell::new(),
        }
    }

    /// Returns the parsed ELF headers and dynamic section of an image in user
    /// space.
    ///
    /// Only 64-bit images are read. 32-bit ones give `VmiError::NotSupported`,
    /// as do the kernel and its modules, which have no ELF header in memory.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    pub fn elf(&self) -> Result<&ElfImage, VmiError> {
        match self.kind()? {
            ImageKind::User => self
                .elf
                .get_or_try_init(|| ElfImage::parse(&GuestElfReader::new(self.vmi, None), self.va)),
            ImageKind::Kernel | ImageKind::Module(_) => Err(VmiError::NotSupported),
        }
    }

    /// Returns the GNU build-id, if the image has one.
    ///
    /// The build-id is a hash that the linker writes into a note of type
    /// `NT_GNU_BUILD_ID`. Debug files and debuginfod servers are indexed by
    /// it.
    ///
    /// # Implementation Details
    ///
    /// For an ELF image, corresponds to the notes in its `PT_NOTE` segments.
    /// Only 64-bit images are read. 32-bit ones give `VmiError::NotSupported`.
    ///
    /// For the kernel, corresponds to the notes from `__start_notes` to
    /// `__stop_notes`. For a module, corresponds to the section
    /// `.note.gnu.build-id` in `module.notes_attrs`. This table backs the
    /// files in `/sys/module/<name>/notes`.
    pub fn build_id(&self) -> Result<Option<BuildId>, VmiError> {
        match self.kind()? {
            ImageKind::User => self.elf()?.build_id(&GuestElfReader::new(self.vmi, None)),
            ImageKind::Kernel => self.kernel_build_id(),
            ImageKind::Module(module) => self.module_build_id(module),
        }
    }

    /// Returns what the base address names.
    ///
    /// A user address names an ELF image. A kernel address names the kernel
    /// at its image base, or a module at the base of its code. Any other
    /// kernel address gives `VmiError::NotSupported`.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    fn kind(&self) -> Result<ImageKind, VmiError> {
        self.kind
            .get_or_try_init(|| {
                if !Driver::Architecture::is_kernel_address(self.va) {
                    return Ok(ImageKind::User);
                }

                if self.vmi.os().kernel_image_base()? == self.va {
                    return Ok(ImageKind::Kernel);
                }

                for module in self.vmi.os().modules()? {
                    let module = module?;
                    if module.base_address()? == self.va {
                        return Ok(ImageKind::Module(module.va()));
                    }
                }

                Err(VmiError::NotSupported)
            })
            .copied()
    }

    /// Returns the exports of the kernel, from its export tables.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the entries from `__start___ksymtab` to
    /// `__stop___ksymtab`, and from `__start___ksymtab_gpl` to
    /// `__stop___ksymtab_gpl`.
    fn kernel_exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        let tables = [
            (
                symbol!(self.vmi, __start___ksymtab),
                symbol!(self.vmi, __stop___ksymtab),
            ),
            (
                symbol!(self.vmi, __start___ksymtab_gpl),
                symbol!(self.vmi, __stop___ksymtab_gpl),
            ),
        ];

        let mut exports = Vec::new();

        for (start, stop) in tables {
            let start = LinuxOs::symbol_address(self.vmi, start)?;
            let stop = LinuxOs::symbol_address(self.vmi, stop)?;
            exports.extend(read_kernel_exports(
                self.vmi,
                start,
                table_length(start, stop)?,
            )?);
        }

        Ok(exports)
    }

    /// Returns the exports of a module, from its export tables.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.syms` with `module.num_syms` entries, and
    /// `module.gpl_syms` with `module.num_gpl_syms` entries.
    fn module_exports(&self, module: Va) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        let MODULE = offset!(self.vmi, module);

        let syms = self.vmi.read_va_native(module + MODULE.syms.offset())?;
        let num_syms = self.vmi.read_u32(module + MODULE.num_syms.offset())?;
        let gpl_syms = self.vmi.read_va_native(module + MODULE.gpl_syms.offset())?;
        let num_gpl_syms = self.vmi.read_u32(module + MODULE.num_gpl_syms.offset())?;

        let mut exports = read_kernel_exports(self.vmi, syms, num_syms as usize)?;
        exports.extend(read_kernel_exports(
            self.vmi,
            gpl_syms,
            num_gpl_syms as usize,
        )?);

        Ok(exports)
    }

    /// Returns the build-id of the kernel.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the notes from `__start_notes` to `__stop_notes`, which
    /// `/sys/kernel/notes` shows.
    fn kernel_build_id(&self) -> Result<Option<BuildId>, VmiError> {
        let start = LinuxOs::symbol_address(self.vmi, symbol!(self.vmi, __start_notes))?;
        let stop = LinuxOs::symbol_address(self.vmi, symbol!(self.vmi, __stop_notes))?;

        let length = match stop.0.checked_sub(start.0) {
            Some(length) => length,
            None => return Err(LinuxError::CorruptedStruct("kernel notes").into()),
        };

        elf::read_build_id(
            &GuestElfReader::new(self.vmi, None),
            start,
            length,
            NOTE_ALIGN,
        )
    }

    /// Returns the build-id of a module.
    ///
    /// A module without notes sections has no `module_notes_attrs` and no
    /// build-id.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the entry of `module.notes_attrs` whose `attr.name` is
    /// `.note.gnu.build-id`. The entry's `private` holds the section's
    /// address, and its `size` holds the section's length.
    fn module_build_id(&self, module: Va) -> Result<Option<BuildId>, VmiError> {
        let MODULE = offset!(self.vmi, module);
        let BIN_ATTRIBUTE = offset!(self.vmi, bin_attribute);
        let ATTRIBUTE = offset!(self.vmi, attribute);

        let notes_attrs = self
            .vmi
            .read_va_native(module + MODULE.notes_attrs.offset())?;

        if notes_attrs.is_null() {
            return Ok(None);
        }

        for entry in self.module_notes_entries(notes_attrs)? {
            let name = self
                .vmi
                .read_va_native(entry + BIN_ATTRIBUTE.attr.offset() + ATTRIBUTE.name.offset())?;

            let name = self
                .vmi
                .read_string_bytes_limited(name, BUILD_ID_SECTION.len() + 1)?;

            if name != BUILD_ID_SECTION {
                continue;
            }

            let section = self
                .vmi
                .read_va_native(entry + BIN_ATTRIBUTE.private.offset())?;

            let size = self.vmi.read_u64(entry + BIN_ATTRIBUTE.size.offset())?;

            return elf::read_build_id(
                &GuestElfReader::new(self.vmi, None),
                section,
                size,
                NOTE_ALIGN,
            );
        }

        Ok(None)
    }

    /// Returns the addresses of the `bin_attribute` entries in a
    /// `module_notes_attrs`. Each notes section in the module has one entry.
    ///
    /// # Implementation Details
    ///
    /// In the layout of Linux 6.8 to 6.13, corresponds to the array `attrs`
    /// with `notes` entries. In the layout of Linux 6.14 and later,
    /// corresponds to the pointers in `grp.bin_attrs` before the first
    /// `NULL`.
    fn module_notes_entries(&self, notes_attrs: Va) -> Result<Vec<Va>, VmiError> {
        let ATTRIBUTE_GROUP = offset!(self.vmi, attribute_group);
        let BIN_ATTRIBUTE = offset!(self.vmi, bin_attribute);

        match ModuleNotesLayout::new(LinuxOs::offsets(self.vmi))? {
            ModuleNotesLayout::Counted { notes, attrs } => {
                let count = u64::from(self.vmi.read_u32(notes_attrs + notes)?);
                if count > MODULE_NOTES_MAX {
                    return Err(LinuxError::CorruptedStruct("module_notes_attrs.notes").into());
                }

                let stride = BIN_ATTRIBUTE.len() as u64;
                Ok((0..count)
                    .map(|index| notes_attrs + attrs + index * stride)
                    .collect())
            }
            ModuleNotesLayout::Grouped { bin_attrs } => {
                let pointers = self.vmi.read_va_native(notes_attrs + bin_attrs)?;
                let stride = ATTRIBUTE_GROUP.bin_attrs.size();

                let mut entries = Vec::new();
                for index in 0..=MODULE_NOTES_MAX {
                    let entry = self.vmi.read_va_native(pointers + index * stride)?;
                    if entry.is_null() {
                        return Ok(entries);
                    }

                    entries.push(entry);
                }

                Err(LinuxError::CorruptedStruct("attribute_group.bin_attrs").into())
            }
        }
    }
}

impl<'a, Driver> VmiOsImage<'a, Driver> for LinuxImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    fn base_address(&self) -> Va {
        self.va
    }

    /// Returns the target architecture of the image.
    ///
    /// # Implementation Details
    ///
    /// For an ELF image, corresponds to `e_ident[EI_CLASS]` and `e_machine`
    /// of its header. `EM_X86_64` gives `Amd64`, `EM_386` gives `X86`, and
    /// any other machine gives `None`. The kernel and its modules give
    /// `Amd64`, the only architecture that the crate supports.
    fn architecture(&self) -> Result<Option<VmiOsImageArchitecture>, VmiError> {
        match self.kind()? {
            ImageKind::User => elf::architecture(&GuestElfReader::new(self.vmi, None), self.va),
            ImageKind::Kernel | ImageKind::Module(_) => Ok(Some(VmiOsImageArchitecture::Amd64)),
        }
    }

    /// Returns the exported symbols, with their addresses in memory.
    ///
    /// # Implementation Details
    ///
    /// For an ELF image, the exports are the functions and data objects in
    /// its dynamic symbol table that it defines and other objects can see,
    /// in their default versions. Only 64-bit images are read. 32-bit ones
    /// give `VmiError::NotSupported`.
    ///
    /// For the kernel, corresponds to the entries of `__ksymtab` and
    /// `__ksymtab_gpl`. For a module, corresponds to `module.syms` and
    /// `module.gpl_syms`.
    fn exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        match self.kind()? {
            ImageKind::User => self.elf()?.exports(&GuestElfReader::new(self.vmi, None)),
            ImageKind::Kernel => self.kernel_exports(),
            ImageKind::Module(module) => self.module_exports(module),
        }
    }
}

/// Returns how many entries lie between the bounds of an export table.
fn table_length(start: Va, stop: Va) -> Result<usize, VmiError> {
    match stop.0.checked_sub(start.0) {
        Some(size) if size as usize / KERNEL_SYMBOL_SIZE <= KERNEL_SYMBOLS_MAX => {
            Ok(size as usize / KERNEL_SYMBOL_SIZE)
        }
        _ => Err(LinuxError::CorruptedStruct("kernel symbol table").into()),
    }
}

/// Returns, for export table entries, the addresses of their values and
/// names.
///
/// Each field of an entry holds an offset from its own address
/// (`offset_to_ptr`).
fn kernel_symbol_addresses(table: Va, bytes: &[u8]) -> Vec<(Va, Va)> {
    let (entries, _) = bytes.as_chunks::<KERNEL_SYMBOL_SIZE>();

    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let entry_address = table.0 + (index * KERNEL_SYMBOL_SIZE) as u64;
            let (fields, _) = entry.as_chunks::<4>();
            let value_offset = i32::from_le_bytes(fields[0]);
            let name_offset = i32::from_le_bytes(fields[1]);

            (
                Va(entry_address.wrapping_add_signed(i64::from(value_offset))),
                Va((entry_address + 4).wrapping_add_signed(i64::from(name_offset))),
            )
        })
        .collect()
}

/// Reads the exports of an export table with `count` entries.
///
/// The names lie in `__ksymtab_strings`.
fn read_kernel_exports<Driver>(
    vmi: VmiState<LinuxOs<Driver>>,
    table: Va,
    count: usize,
) -> Result<Vec<VmiOsImageSymbol>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    if count == 0 {
        return Ok(Vec::new());
    }

    if count > KERNEL_SYMBOLS_MAX {
        return Err(LinuxError::CorruptedStruct("kernel symbol table").into());
    }

    let mut bytes = vec![0; count * KERNEL_SYMBOL_SIZE];
    vmi.read(table, &mut bytes)?;
    let entries = kernel_symbol_addresses(table, &bytes);

    let (first, last) = match (
        entries.iter().map(|(_, name)| name.0).min(),
        entries.iter().map(|(_, name)| name.0).max(),
    ) {
        (Some(first), Some(last)) => (first, last),
        _ => return Err(LinuxError::CorruptedStruct("kernel symbol names").into()),
    };

    let names = read_symbol_names(vmi, Va(first), Va(last), "kernel symbol names")?;

    let mut exports = Vec::with_capacity(entries.len());

    for (value, name) in entries {
        let start = (name.0 - first) as usize;
        let length = match memchr::memchr(0, &names[start..]) {
            Some(length) => length,
            None => return Err(LinuxError::CorruptedStruct("kernel symbol name").into()),
        };

        exports.push(VmiOsImageSymbol {
            name: String::from_utf8_lossy(&names[start..start + length]).into_owned(),
            address: value,
        });
    }

    Ok(exports)
}

/// Reads the names in a symbol table, from the lowest name to the end of
/// the highest.
///
/// `first` and `last` are the addresses of the lowest and the highest name.
/// One read covers all names but the highest, and a string read finds the
/// end of the highest. The returned bytes end with a null byte. A span
/// larger than `KERNEL_NAMES_MAX` is an error.
pub(super) fn read_symbol_names<Driver>(
    vmi: VmiState<LinuxOs<Driver>>,
    first: Va,
    last: Va,
    what: &'static str,
) -> Result<Vec<u8>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    let length = match last.0.checked_sub(first.0) {
        Some(length) if length <= KERNEL_NAMES_MAX => length as usize,
        _ => return Err(LinuxError::CorruptedStruct(what).into()),
    };

    let mut names = vec![0; length];
    vmi.read(first, &mut names)?;
    names.extend(vmi.read_string_bytes_limited(last, KSYM_NAME_LEN)?);
    names.push(0);

    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_symbol_fields_count_from_their_own_addresses() {
        let table = Va(0xffff_ffff_8310_0000);

        // Two entries: the first points forward, the second backward.
        let mut bytes = Vec::new();
        for (value_offset, name_offset, namespace_offset) in
            [(0x1000i32, 0x2000i32, 0x3000i32), (-0x10, -0x20, 0)]
        {
            bytes.extend_from_slice(&value_offset.to_le_bytes());
            bytes.extend_from_slice(&name_offset.to_le_bytes());
            bytes.extend_from_slice(&namespace_offset.to_le_bytes());
        }

        assert_eq!(
            kernel_symbol_addresses(table, &bytes),
            vec![
                (Va(0xffff_ffff_8310_1000), Va(0xffff_ffff_8310_2004)),
                (
                    Va(0xffff_ffff_8310_000c - 0x10),
                    Va(0xffff_ffff_8310_0010 - 0x20)
                ),
            ]
        );
    }

    #[test]
    fn table_length_counts_whole_entries() -> Result<(), VmiError> {
        assert_eq!(table_length(Va(0x1000), Va(0x1000 + 12 * 3))?, 3);
        assert_eq!(table_length(Va(0x1000), Va(0x1000))?, 0);
        assert!(table_length(Va(0x2000), Va(0x1000)).is_err());
        Ok(())
    }
}
