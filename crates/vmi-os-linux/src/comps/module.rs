use vmi_core::{
    Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsImageSymbol, VmiOsModule},
};
use zerocopy::FromBytes as _;

use super::image::{KSYM_NAME_LEN, read_symbol_names};
use crate::{ArchAdapter, LinuxError, LinuxOs, elf::Sym64, offset};

/// The module is still being loaded (`MODULE_STATE_UNFORMED`).
const MODULE_STATE_UNFORMED: u32 = 3;

/// Index of the memory area with the module's code in `module.mem`
/// (`MOD_TEXT`).
const MOD_TEXT: u64 = 0;

/// Upper limit of the symbols in a module's kallsyms.
const KALLSYMS_MAX: usize = 1 << 20;

/// A Linux kernel module.
///
/// A module is code and data that the kernel loads at runtime, such as a
/// driver.
///
/// # Implementation Details
///
/// Corresponds to `module`.
pub struct LinuxModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `module` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux kernel module.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the state of the module (`MODULE_STATE_*`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.state`.
    pub fn state(&self) -> Result<u32, VmiError> {
        let MODULE = offset!(self.vmi, module);

        self.vmi.read_u32(self.va + MODULE.state.offset())
    }

    /// Checks if the module is still being loaded.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `MODULE_STATE_UNFORMED` in `module.state`.
    pub fn is_unformed(&self) -> Result<bool, VmiError> {
        Ok(self.state()? == MODULE_STATE_UNFORMED)
    }

    /// Returns the symbols of the module, with their addresses in memory.
    ///
    /// The symbols come from the module's kallsyms. The kallsyms are the
    /// symbol table that the kernel keeps for each loaded module, static
    /// functions included, and `/proc/kallsyms` lists them. When the kernel
    /// loads a module, it adds the address of each symbol's section to the
    /// symbol's value. The value is therefore the address in memory. The
    /// null symbol at index 0 and the symbols without a name are skipped.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.kallsyms`, with `num_symtab` entries of
    /// `Elf64_Sym` at `symtab` and their names in `strtab`. After the
    /// module's init code returns, the kernel points `module.kallsyms` to
    /// `core_kallsyms`, which keeps only the symbols outside the init
    /// sections.
    pub fn symbols(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        let MODULE = offset!(self.vmi, module);
        let MOD_KALLSYMS = offset!(self.vmi, mod_kallsyms);

        let kallsyms = self
            .vmi
            .read_va_native(self.va + MODULE.kallsyms.offset())?;

        if kallsyms.is_null() {
            return Ok(Vec::new());
        }

        let symtab = self
            .vmi
            .read_va_native(kallsyms + MOD_KALLSYMS.symtab.offset())?;

        let num_symtab =
            self.vmi
                .read_u32(kallsyms + MOD_KALLSYMS.num_symtab.offset())? as usize;

        let strtab = self
            .vmi
            .read_va_native(kallsyms + MOD_KALLSYMS.strtab.offset())?;

        if num_symtab > KALLSYMS_MAX {
            return Err(LinuxError::CorruptedStruct("mod_kallsyms.num_symtab").into());
        }

        let mut bytes = vec![0; num_symtab * size_of::<Sym64>()];
        self.vmi.read(symtab, &mut bytes)?;
        let table = match <[Sym64]>::ref_from_bytes(&bytes) {
            Ok(table) => table,
            Err(_) => return Err(LinuxError::CorruptedStruct("mod_kallsyms.symtab").into()),
        };

        let (first, last) = match name_bounds(table) {
            Some(bounds) => bounds,
            None => return Ok(Vec::new()),
        };

        let names = read_symbol_names(
            self.vmi,
            strtab + u64::from(first),
            strtab + u64::from(last),
            "mod_kallsyms.strtab",
        )?;

        decode_symbols(table, first, &names)
    }

    /// Returns the number of memory areas and the size of one.
    ///
    /// The kernel declares `module.mem` as an array of `MOD_MEM_NUM_TYPES`
    /// entries, a count that the profile gives only through the sizes.
    fn memory_layout(&self) -> Result<(u64, u64), VmiError> {
        let MODULE = offset!(self.vmi, module);
        let MODULE_MEMORY = offset!(self.vmi, module_memory);

        let stride = MODULE_MEMORY.len() as u64;
        if stride == 0 {
            return Err(LinuxError::UnsupportedProfile("module_memory has no size").into());
        }

        Ok((MODULE.mem.size() / stride, stride))
    }

    /// Returns the address of a memory area of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.mem[index]`.
    fn memory(&self, index: u64) -> Result<Va, VmiError> {
        let MODULE = offset!(self.vmi, module);

        let (count, stride) = self.memory_layout()?;
        if index >= count {
            return Err(VmiError::OutOfBounds);
        }

        Ok(self.va + MODULE.mem.offset() + index * stride)
    }
}

impl<'a, Driver> VmiOsModule<'a, Driver> for LinuxModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the base address of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.mem[MOD_TEXT].base`.
    fn base_address(&self) -> Result<Va, VmiError> {
        let MODULE_MEMORY = offset!(self.vmi, module_memory);

        let text = self.memory(MOD_TEXT)?;
        self.vmi.read_va_native(text + MODULE_MEMORY.base.offset())
    }

    /// Returns the size of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the sum of `module.mem[].size`, as
    /// `module_total_size` computes it for `/proc/modules`.
    fn size(&self) -> Result<u64, VmiError> {
        let MODULE_MEMORY = offset!(self.vmi, module_memory);

        let (count, _stride) = self.memory_layout()?;

        let mut size = 0;
        for index in 0..count {
            let memory = self.memory(index)?;
            size += self.vmi.read_u32(memory + MODULE_MEMORY.size.offset())? as u64;
        }

        Ok(size)
    }

    /// Returns the name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.name`.
    fn name(&self) -> Result<String, VmiError> {
        let MODULE = offset!(self.vmi, module);

        self.vmi
            .read_string_limited(self.va + MODULE.name.offset(), MODULE.name.size() as usize)
    }
}

/// Returns the lowest and the highest name offset in a symbol table, or
/// `None` for a table without symbols after the null symbol.
fn name_bounds(table: &[Sym64]) -> Option<(u32, u32)> {
    let offsets = table.iter().skip(1).map(|symbol| symbol.st_name);
    Some((offsets.clone().min()?, offsets.max()?))
}

/// Decodes the symbols of a module's kallsyms.
///
/// `table` holds the `Elf64_Sym` entries. `names` holds the string table
/// from the offset `first` on, and it covers every name in the table. A name
/// without a null byte within `KSYM_NAME_LEN` bytes is an error. The null
/// symbol at index 0 and the symbols without a name are skipped.
fn decode_symbols(
    table: &[Sym64],
    first: u32,
    names: &[u8],
) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
    let mut symbols = Vec::with_capacity(table.len().saturating_sub(1));

    for symbol in table.iter().skip(1) {
        let name = symbol
            .st_name
            .checked_sub(first)
            .and_then(|start| names.get(start as usize..))
            .and_then(|name| {
                let name = &name[..name.len().min(KSYM_NAME_LEN)];
                Some(&name[..memchr::memchr(0, name)?])
            });

        let name = match name {
            Some(name) => name,
            None => return Err(LinuxError::CorruptedStruct("module symbol name").into()),
        };

        if name.is_empty() {
            continue;
        }

        symbols.push(VmiOsImageSymbol {
            name: String::from_utf8_lossy(name).into_owned(),
            address: Va(symbol.st_value),
        });
    }

    Ok(symbols)
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes as _;

    use super::*;

    /// Returns a symbol with a name offset and a value.
    fn symbol(st_name: u32, st_value: u64) -> Sym64 {
        Sym64 {
            st_name,
            st_info: 0x02,
            st_other: 0,
            st_shndx: 1,
            st_value,
            st_size: 0,
        }
    }

    /// Returns the names and addresses of decoded symbols.
    fn decode(table: &[Sym64], first: u32, names: &[u8]) -> Result<Vec<(String, u64)>, VmiError> {
        Ok(decode_symbols(table, first, names)?
            .into_iter()
            .map(|symbol| (symbol.name, symbol.address.0))
            .collect())
    }

    #[test]
    fn symbols_carry_their_values_as_addresses() -> Result<(), VmiError> {
        // The null symbol names an offset below the names, which the
        // decoder never reads. Symbol 2 has an empty name.
        let table = [
            symbol(0, 0),
            symbol(0x101, 0xffff_ffff_c0a0_1000),
            symbol(0x100, 0xffff_ffff_c0a0_1100),
            symbol(0x10f, 0xffff_ffff_c0a0_2000),
        ];
        let names = b"\0fq_codel_dump\0fq_codel_init\0";

        assert_eq!(name_bounds(&table), Some((0x100, 0x10f)));
        assert_eq!(
            decode(&table, 0x100, names)?,
            vec![
                (String::from("fq_codel_dump"), 0xffff_ffff_c0a0_1000),
                (String::from("fq_codel_init"), 0xffff_ffff_c0a0_2000),
            ]
        );
        Ok(())
    }

    #[test]
    fn table_with_only_the_null_symbol_has_no_names() {
        assert_eq!(name_bounds(&[symbol(0, 0)]), None);
        assert_eq!(name_bounds(&[]), None);
    }

    #[test]
    fn symbol_table_decodes_from_bytes() -> Result<(), VmiError> {
        let table = [symbol(0, 0), symbol(1, 0xffff_ffff_c0a0_1000)];
        let bytes = table.as_bytes();
        assert_eq!(bytes.len(), 2 * 24);

        let table = match <[Sym64]>::ref_from_bytes(bytes) {
            Ok(table) => table,
            Err(_) => return Err(VmiError::Other("symbol table")),
        };
        assert_eq!(
            decode(table, 1, b"init_module\0")?,
            vec![(String::from("init_module"), 0xffff_ffff_c0a0_1000)]
        );
        Ok(())
    }

    #[test]
    fn name_outside_the_names_is_an_error() {
        let table = [symbol(0, 0), symbol(0x10, 0x1000)];

        // The name lies below the first offset in the first call, and past
        // the end in the second.
        assert!(decode_symbols(&table, 0x11, b"name\0").is_err());
        assert!(decode_symbols(&table, 0, b"name\0").is_err());
    }

    #[test]
    fn name_needs_a_null_byte_within_the_limit() -> Result<(), VmiError> {
        let table = [symbol(0, 0), symbol(0, 0x1000)];

        let mut names = vec![b'a'; KSYM_NAME_LEN - 1];
        names.push(0);
        assert_eq!(decode(&table, 0, &names)?[0].0.len(), KSYM_NAME_LEN - 1);

        let mut names = vec![b'a'; KSYM_NAME_LEN];
        names.push(0);
        assert!(decode_symbols(&table, 0, &names).is_err());

        assert!(decode_symbols(&table, 0, b"unterminated").is_err());
        Ok(())
    }
}
