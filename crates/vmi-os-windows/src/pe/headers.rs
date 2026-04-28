//! On-disk PE header layouts.
//!
//! Mirrors the relevant `IMAGE_*` types from `object::pe` as
//! `#[repr(C, packed)]` zerocopy structs and re-exports the PE constants.
//! This is the only module in the crate that imports from the `object`
//! crate. Everything else goes through [`crate::pe`].

use object::ReadRef as _;
pub use object::{
    pe::{
        IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
        IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_DEBUG,
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_GLOBALPTR, IMAGE_DIRECTORY_ENTRY_IAT,
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
        IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_TLS,
        IMAGE_DOS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        IMAGE_NT_SIGNATURE, IMAGE_NUMBEROF_DIRECTORY_ENTRIES, IMAGE_SIZEOF_SHORT_NAME,
    },
    // Intentional re-export: `Export`, `ExportTable` and `ExportTarget` are good as they are.
    read::pe::{Export, ExportTable, ExportTarget},
};

use super::error::PeError;

/// Reads an `object`-crate struct field as a native scalar.
///
/// `impl_struct!` calls `to_endian(LE)` on every source field. The trait
/// covers both `object`'s endian wrappers (`U16<E>`, `U32<E>`, `U64<E>`,
/// and arrays of those) and the raw types `object` stores natively because
/// no `U8<E>` wrapper exists (`u8` and byte arrays).
trait ToEndian<E: ::object::Endian> {
    /// Native counterpart of `Self`.
    type Output;

    /// Returns `self` decoded with `endian`.
    fn to_endian(&self, endian: E) -> Self::Output;
}

impl<E: ::object::Endian> ToEndian<E> for ::object::U16<E> {
    type Output = u16;

    fn to_endian(&self, endian: E) -> Self::Output {
        self.get(endian)
    }
}

impl<E: ::object::Endian> ToEndian<E> for ::object::U32<E> {
    type Output = u32;

    fn to_endian(&self, endian: E) -> Self::Output {
        self.get(endian)
    }
}

impl<E: ::object::Endian> ToEndian<E> for ::object::U64<E> {
    type Output = u64;

    fn to_endian(&self, endian: E) -> Self::Output {
        self.get(endian)
    }
}

impl<E: ::object::Endian> ToEndian<E> for u8 {
    type Output = u8;

    fn to_endian(&self, _endian: E) -> Self::Output {
        *self
    }
}

impl<E: ::object::Endian, const N: usize> ToEndian<E> for [u8; N] {
    type Output = [u8; N];

    fn to_endian(&self, _endian: E) -> Self::Output {
        *self
    }
}

impl<E: ::object::Endian, const N: usize> ToEndian<E> for [::object::U16<E>; N] {
    type Output = [u16; N];

    fn to_endian(&self, endian: E) -> Self::Output {
        std::array::from_fn(|i| self[i].get(endian))
    }
}

/// Defines a `#[repr(C, packed)]` PE struct that mirrors an `object`-crate
/// type and verifies the layout match at compile time.
///
/// Each invocation expands to:
///
/// - A struct with the requested fields, `#[repr(C, packed)]`, and the
///   `zerocopy` derives needed for byte-level reads.
/// - `impl From<SourceType> for $name` that decodes every field through
///   [`ToEndian`].
/// - Static asserts that `$name` and `SourceType` agree on size,
///   alignment, and the offset of every field.
///
/// `#[from(SourceType)]` is required and must appear once. `#[derive(...)]`
/// blocks are merged with the macro's own derives. Any other attributes
/// pass through to the generated struct.
///
/// # Usage
///
/// ```ignore
/// impl_struct! {
///     /// Field descriptor for an export entry.
///     #[derive(Debug, Clone, Copy)]
///     #[from(::object::pe::ImageDataDirectory)]
///     pub struct ImageDataDirectory {
///         pub virtual_address: u32,
///         pub size: u32,
///     }
/// }
/// ```
macro_rules! impl_struct {
    //
    // @parse - tokenize the attribute list before the struct body.
    //
    // Each arm matches one leading `#[...]`, appends it to the matching
    // accumulator, and recurses with the rest. Specialized arms come
    // before the catch-all so that `#[from]`, `#[doc]`, and `#[derive]`
    // are recognized rather than forwarded blindly.
    //

    // Capture `#[from(SourceType)]`. Allowed once.
    (@parse
        from   = []
        doc    = [$($doc:tt)*]
        derive = [$($derive:tt)*]
        attrs  = [$($attrs:tt)*]
        rest   = [#[from($from:ty)] $($rest:tt)*]
    ) => {
        impl_struct!(@parse
            from   = [$from]
            doc    = [$($doc)*]
            derive = [$($derive)*]
            attrs  = [$($attrs)*]
            rest   = [$($rest)*]
        );
    };

    // Reject a duplicate `#[from(...)]`.
    (@parse
        from   = [$_first:ty]
        doc    = [$($doc:tt)*]
        derive = [$($derive:tt)*]
        attrs  = [$($attrs:tt)*]
        rest   = [#[from($_dup:ty)] $($rest:tt)*]
    ) => {
        compile_error!("impl_struct!: duplicate `#[from(...)]` attribute");
    };

    // Append a doc comment.
    (@parse
        from   = [$($from:tt)*]
        doc    = [$($doc:tt)*]
        derive = [$($derive:tt)*]
        attrs  = [$($attrs:tt)*]
        rest   = [#[doc = $d:literal] $($rest:tt)*]
    ) => {
        impl_struct!(@parse
            from   = [$($from)*]
            doc    = [$($doc)* #[doc = $d]]
            derive = [$($derive)*]
            attrs  = [$($attrs)*]
            rest   = [$($rest)*]
        );
    };

    // Merge a `#[derive(...)]` block into the running derive list.
    (@parse
        from   = [$($from:tt)*]
        doc    = [$($doc:tt)*]
        derive = [$($derive:tt)*]
        attrs  = [$($attrs:tt)*]
        rest   = [#[derive($($d:path),* $(,)?)] $($rest:tt)*]
    ) => {
        impl_struct!(@parse
            from   = [$($from)*]
            doc    = [$($doc)*]
            derive = [$($derive)* $($d,)*]
            attrs  = [$($attrs)*]
            rest   = [$($rest)*]
        );
    };

    // Forward any other `#[...]` to the generated struct verbatim.
    (@parse
        from   = [$($from:tt)*]
        doc    = [$($doc:tt)*]
        derive = [$($derive:tt)*]
        attrs  = [$($attrs:tt)*]
        rest   = [#[$attr:meta] $($rest:tt)*]
    ) => {
        impl_struct!(@parse
            from   = [$($from)*]
            doc    = [$($doc)*]
            derive = [$($derive)*]
            attrs  = [$($attrs)* #[$attr]]
            rest   = [$($rest)*]
        );
    };

    //
    // @parse - terminal arms.
    //
    // Hit when `rest` consists of just `pub struct ...`. The first emits
    // the struct, the `From` impl, and the layout asserts. The second
    // errors out if `#[from(...)]` was never supplied.
    //

    (@parse
        from   = [$from_ty:ty]
        doc    = [$($doc:tt)*]
        derive = [$($derive:tt)*]
        attrs  = [$($attrs:tt)*]
        rest   = [
            $vis:vis struct $name:ident {
                $(
                    $(#[$field_attr:meta])*
                    $field_vis:vis $field:ident : $field_ty:ty
                ),* $(,)?
            }
        ]
    ) => {
        $($doc)*
        #[derive(
            $($derive)*
            ::zerocopy::FromBytes,
            ::zerocopy::IntoBytes,
            ::zerocopy::Immutable,
            ::zerocopy::KnownLayout,
        )]
        #[repr(C, packed)]
        $($attrs)*
        $vis struct $name {
            $(
                $(#[$field_attr])*
                $field_vis $field: $field_ty,
            )*
        }

        impl ::core::convert::From<$from_ty> for $name {
            fn from(value: $from_ty) -> Self {
                Self {
                    $(
                        $field: value.$field.to_endian(::object::LittleEndian),
                    )*
                }
            }
        }

        const _: () = {
            use ::core::mem::{align_of, size_of};

            assert!(
                size_of::<$name>() == size_of::<$from_ty>(),
                concat!(stringify!($name), " size mismatch"),
            );

            assert!(
                align_of::<$name>() == align_of::<$from_ty>(),
                concat!(stringify!($name), " alignment mismatch"),
            );
        };

        $(
            const _: () = {
                use ::core::mem::offset_of;

                assert!(
                    offset_of!($name, $field) == offset_of!($from_ty, $field),
                    concat!(stringify!($name), " field offset mismatch: ", stringify!($field)),
                );
            };
        )*
    };

    (@parse
        from   = []
        doc    = [$($doc:tt)*]
        derive = [$($derive:tt)*]
        attrs  = [$($attrs:tt)*]
        rest   = [$vis:vis struct $name:ident { $($body:tt)* }]
    ) => {
        compile_error!(concat!(
            "impl_struct!: missing `#[from(SourceType)]` attribute on `",
            stringify!($name),
            "`",
        ));
    };

    //
    // Entry arm.
    //
    // Placed last so any recursive call starting with `@parse` matches one
    // of the arms above instead of falling through here. Seeds the muncher
    // with empty accumulators so the user-facing call doesn't thread any
    // bookkeeping arguments.
    //

    ($($input:tt)*) => {
        impl_struct!(@parse
            from   = []
            doc    = []
            derive = []
            attrs  = []
            rest   = [$($input)*]
        );
    };
}

impl_struct! {
    /// MS-DOS executable header at the start of every PE file.
    ///
    /// Of the original DOS layout, only `e_magic` (must be `MZ`) and
    /// `e_lfanew` (file offset of the NT headers) are used by the PE loader.
    /// The rest is preserved for compatibility with the legacy format.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_DOS_HEADER`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageDosHeader)]
    pub struct ImageDosHeader {
        /// DOS magic, must be `MZ` (`0x5A4D`).
        pub e_magic: u16,

        /// Bytes on the last page of the file.
        pub e_cblp: u16,

        /// Pages in the file.
        pub e_cp: u16,

        /// Relocation count.
        pub e_crlc: u16,

        /// Header size in 16-byte paragraphs.
        pub e_cparhdr: u16,

        /// Minimum extra paragraphs needed.
        pub e_minalloc: u16,

        /// Maximum extra paragraphs needed.
        pub e_maxalloc: u16,

        /// Initial relative SS value.
        pub e_ss: u16,

        /// Initial SP value.
        pub e_sp: u16,

        /// Header checksum.
        pub e_csum: u16,

        /// Initial IP value.
        pub e_ip: u16,

        /// Initial relative CS value.
        pub e_cs: u16,

        /// File offset of the relocation table.
        pub e_lfarlc: u16,

        /// Overlay number.
        pub e_ovno: u16,

        /// Reserved words.
        pub e_res: [u16; 4],

        /// OEM identifier qualifying `e_oeminfo`.
        pub e_oemid: u16,

        /// OEM information specific to `e_oemid`.
        pub e_oeminfo: u16,

        /// Reserved words.
        pub e_res2: [u16; 10],

        /// File offset of the NT headers.
        pub e_lfanew: u32,
    }
}

impl ImageDosHeader {
    /// Parses the DOS header.
    pub fn parse(data: &[u8], offset: &mut u64) -> Result<Self, PeError> {
        let dos_header = data
            .read_at::<::object::pe::ImageDosHeader>(0)
            .copied()
            .map_err(|_| PeError::InvalidDosHeader)?;

        if dos_header.e_magic.get(::object::LittleEndian) != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosMagic);
        }

        *offset = dos_header.nt_headers_offset() as u64;

        Ok(dos_header.into())
    }

    /// Returns the file offset of the NT headers.
    pub fn nt_headers_offset(&self) -> u32 {
        self.e_lfanew
    }
}

/// Top-level PE header pointed to by [`ImageDosHeader::e_lfanew`].
///
/// Identifies whether the image is 32-bit or 64-bit through the optional
/// header magic.
///
/// # Implementation Details
///
/// Corresponds to `_IMAGE_NT_HEADERS32` or `_IMAGE_NT_HEADERS64`.
#[derive(Debug, Clone, Copy)]
pub struct ImageNtHeaders {
    /// PE signature, `PE\0\0` (`0x00004550`).
    pub signature: u32,

    /// COFF file header.
    pub file_header: ImageFileHeader,

    /// PE32 or PE32+ optional header.
    pub optional_header: ImageOptionalHeader,
}

impl ImageNtHeaders {
    /// Parses the NT headers.
    pub fn parse(data: &[u8], offset: &mut u64) -> Result<Self, PeError> {
        let magic =
            ::object::read::pe::optional_header_magic(data).map_err(|_| PeError::InvalidPeMagic)?;

        match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                Self::parse_inner::<::object::pe::ImageNtHeaders32>(data, offset)
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                Self::parse_inner::<::object::pe::ImageNtHeaders64>(data, offset)
            }
            _ => Err(PeError::InvalidPeMagic),
        }
    }

    fn parse_inner<Pe>(data: &[u8], offset: &mut u64) -> Result<Self, PeError>
    where
        Self: From<Pe>,
        Pe: ::object::read::pe::ImageNtHeaders,
    {
        let nt_headers = data
            .read::<Pe>(offset)
            .copied()
            .map_err(|_| PeError::InvalidNtHeaders)?;

        if nt_headers.signature() != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidPeMagic);
        }

        if !nt_headers.is_valid_optional_magic() {
            return Err(PeError::InvalidOptionalHeaderMagic);
        }

        Ok(nt_headers.into())
    }
}

impl From<::object::pe::ImageNtHeaders32> for ImageNtHeaders {
    fn from(value: ::object::pe::ImageNtHeaders32) -> Self {
        Self {
            signature: value.signature.get(::object::LittleEndian),
            file_header: value.file_header.into(),
            optional_header: value.optional_header.into(),
        }
    }
}

impl From<::object::pe::ImageNtHeaders64> for ImageNtHeaders {
    fn from(value: ::object::pe::ImageNtHeaders64) -> Self {
        Self {
            signature: value.signature.get(::object::LittleEndian),
            file_header: value.file_header.into(),
            optional_header: value.optional_header.into(),
        }
    }
}

impl_struct! {
    /// COFF file header that follows the PE signature in [`ImageNtHeaders`].
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_FILE_HEADER`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageFileHeader)]
    pub struct ImageFileHeader {
        /// Target machine architecture, `IMAGE_FILE_MACHINE_*`.
        pub machine: u16,

        /// Number of entries in the section table.
        pub number_of_sections: u16,

        /// Build timestamp, in Unix epoch seconds.
        pub time_date_stamp: u32,

        /// File offset of the COFF symbol table. Deprecated, zero in modern images.
        pub pointer_to_symbol_table: u32,

        /// Symbol table entry count. Deprecated, zero in modern images.
        pub number_of_symbols: u32,

        /// Size in bytes of the optional header that follows.
        pub size_of_optional_header: u16,

        /// `IMAGE_FILE_*` characteristic flags.
        pub characteristics: u16,
    }
}

impl_struct! {
    /// PE32 optional header for 32-bit images.
    ///
    /// Layout differs from [`ImageOptionalHeader64`] in `image_base` and the
    /// stack/heap size fields, which are 32-bit here, and in the presence
    /// of `base_of_data`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_OPTIONAL_HEADER`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageOptionalHeader32)]
    pub struct ImageOptionalHeader32 {
        /// PE32 magic, `0x10b`.
        pub magic: u16,

        /// Linker version, major part.
        pub major_linker_version: u8,

        /// Linker version, minor part.
        pub minor_linker_version: u8,

        /// Combined size of all code sections, in bytes.
        pub size_of_code: u32,

        /// Combined size of all initialized data sections, in bytes.
        pub size_of_initialized_data: u32,

        /// Combined size of all uninitialized data sections, in bytes.
        pub size_of_uninitialized_data: u32,

        /// RVA of the entry point.
        pub address_of_entry_point: u32,

        /// RVA of the start of the code section.
        pub base_of_code: u32,

        /// RVA of the start of the data section.
        pub base_of_data: u32,

        /// Preferred load address.
        pub image_base: u32,

        /// Section alignment when loaded into memory, in bytes.
        pub section_alignment: u32,

        /// Section alignment within the file, in bytes.
        pub file_alignment: u32,

        /// Required OS version, major part.
        pub major_operating_system_version: u16,

        /// Required OS version, minor part.
        pub minor_operating_system_version: u16,

        /// Image version, major part.
        pub major_image_version: u16,

        /// Image version, minor part.
        pub minor_image_version: u16,

        /// Required subsystem version, major part.
        pub major_subsystem_version: u16,

        /// Required subsystem version, minor part.
        pub minor_subsystem_version: u16,

        /// Reserved, must be zero.
        pub win32_version_value: u32,

        /// Total size of the image when loaded, including headers.
        pub size_of_image: u32,

        /// Combined size of the DOS, NT, and section headers, file-aligned.
        pub size_of_headers: u32,

        /// Image checksum. Often zero outside system images.
        pub check_sum: u32,

        /// `IMAGE_SUBSYSTEM_*` value identifying the runtime environment.
        pub subsystem: u16,

        /// `IMAGE_DLLCHARACTERISTICS_*` flags.
        pub dll_characteristics: u16,

        /// Reserved stack size.
        pub size_of_stack_reserve: u32,

        /// Initial committed stack size.
        pub size_of_stack_commit: u32,

        /// Reserved heap size.
        pub size_of_heap_reserve: u32,

        /// Initial committed heap size.
        pub size_of_heap_commit: u32,

        /// Reserved, must be zero.
        pub loader_flags: u32,

        /// Length of the data directory array that follows the optional header.
        pub number_of_rva_and_sizes: u32,
    }
}

impl_struct! {
    /// PE32+ optional header for 64-bit images.
    ///
    /// Layout differs from [`ImageOptionalHeader32`] in `image_base` and the
    /// stack/heap size fields, which are 64-bit here, and in the absence
    /// of `base_of_data`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_OPTIONAL_HEADER64`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageOptionalHeader64)]
    pub struct ImageOptionalHeader64 {
        /// PE32+ magic, `0x20b`.
        pub magic: u16,

        /// Linker version, major part.
        pub major_linker_version: u8,

        /// Linker version, minor part.
        pub minor_linker_version: u8,

        /// Combined size of all code sections, in bytes.
        pub size_of_code: u32,

        /// Combined size of all initialized data sections, in bytes.
        pub size_of_initialized_data: u32,

        /// Combined size of all uninitialized data sections, in bytes.
        pub size_of_uninitialized_data: u32,

        /// RVA of the entry point.
        pub address_of_entry_point: u32,

        /// RVA of the start of the code section.
        pub base_of_code: u32,

        /// Preferred load address.
        pub image_base: u64,

        /// Section alignment when loaded into memory, in bytes.
        pub section_alignment: u32,

        /// Section alignment within the file, in bytes.
        pub file_alignment: u32,

        /// Required OS version, major part.
        pub major_operating_system_version: u16,

        /// Required OS version, minor part.
        pub minor_operating_system_version: u16,

        /// Image version, major part.
        pub major_image_version: u16,

        /// Image version, minor part.
        pub minor_image_version: u16,

        /// Required subsystem version, major part.
        pub major_subsystem_version: u16,

        /// Required subsystem version, minor part.
        pub minor_subsystem_version: u16,

        /// Reserved, must be zero.
        pub win32_version_value: u32,

        /// Total size of the image when loaded, including headers.
        pub size_of_image: u32,

        /// Combined size of the DOS, NT, and section headers, file-aligned.
        pub size_of_headers: u32,

        /// Image checksum. Often zero outside system images.
        pub check_sum: u32,

        /// `IMAGE_SUBSYSTEM_*` value identifying the runtime environment.
        pub subsystem: u16,

        /// `IMAGE_DLLCHARACTERISTICS_*` flags.
        pub dll_characteristics: u16,

        /// Reserved stack size.
        pub size_of_stack_reserve: u64,

        /// Initial committed stack size.
        pub size_of_stack_commit: u64,

        /// Reserved heap size.
        pub size_of_heap_reserve: u64,

        /// Initial committed heap size.
        pub size_of_heap_commit: u64,

        /// Reserved, must be zero.
        pub loader_flags: u32,

        /// Length of the data directory array that follows the optional header.
        pub number_of_rva_and_sizes: u32,
    }
}

/// Optional header in either PE32 or PE32+ form.
///
/// Discriminated by the magic in [`ImageOptionalHeader::magic`].
///
/// # Implementation Details
///
/// Corresponds to `_IMAGE_OPTIONAL_HEADER` or `_IMAGE_OPTIONAL_HEADER64`.
#[derive(Debug, Clone, Copy)]
pub enum ImageOptionalHeader {
    /// PE32 optional header (32-bit image).
    ImageOptionalHeader32(ImageOptionalHeader32),

    /// PE32+ optional header (64-bit image).
    ImageOptionalHeader64(ImageOptionalHeader64),
}

impl From<::object::pe::ImageOptionalHeader32> for ImageOptionalHeader {
    fn from(value: ::object::pe::ImageOptionalHeader32) -> Self {
        Self::ImageOptionalHeader32(value.into())
    }
}

impl From<::object::pe::ImageOptionalHeader64> for ImageOptionalHeader {
    fn from(value: ::object::pe::ImageOptionalHeader64) -> Self {
        Self::ImageOptionalHeader64(value.into())
    }
}

impl ImageOptionalHeader {
    /// Returns the magic identifying PE32 (`0x10b`) or PE32+ (`0x20b`).
    pub fn magic(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.magic,
            Self::ImageOptionalHeader64(hdr64) => hdr64.magic,
        }
    }

    /// Returns the major linker version.
    pub fn major_linker_version(&self) -> u8 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.major_linker_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.major_linker_version,
        }
    }

    /// Returns the minor linker version.
    pub fn minor_linker_version(&self) -> u8 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.minor_linker_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.minor_linker_version,
        }
    }

    /// Returns the combined size of all code sections, in bytes.
    pub fn size_of_code(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_code,
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_code,
        }
    }

    /// Returns the combined size of all initialized data sections, in bytes.
    pub fn size_of_initialized_data(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_initialized_data,
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_initialized_data,
        }
    }

    /// Returns the combined size of all uninitialized data sections, in bytes.
    pub fn size_of_uninitialized_data(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_uninitialized_data,
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_uninitialized_data,
        }
    }

    /// Returns the RVA of the entry point.
    ///
    /// When the image is loaded, this is the actual memory address.
    pub fn address_of_entry_point(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.address_of_entry_point,
            Self::ImageOptionalHeader64(hdr64) => hdr64.address_of_entry_point,
        }
    }

    /// Returns the RVA of the start of the code section.
    pub fn base_of_code(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.base_of_code,
            Self::ImageOptionalHeader64(hdr64) => hdr64.base_of_code,
        }
    }

    /// Returns the RVA of the start of the data section (PE32 only).
    pub fn base_of_data(&self) -> Option<u32> {
        match self {
            Self::ImageOptionalHeader32(hdr32) => Some(hdr32.base_of_data),
            Self::ImageOptionalHeader64(_) => None,
        }
    }

    /// Returns the preferred load address in memory.
    ///
    /// The actual base address may change due to ASLR or conflicts.
    pub fn image_base(&self) -> u64 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.image_base.into(),
            Self::ImageOptionalHeader64(hdr64) => hdr64.image_base,
        }
    }

    /// Returns the section alignment in memory, in bytes.
    ///
    /// This may change when the image is loaded by the OS.
    pub fn section_alignment(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.section_alignment,
            Self::ImageOptionalHeader64(hdr64) => hdr64.section_alignment,
        }
    }

    /// Returns the section alignment on disk, in bytes.
    pub fn file_alignment(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.file_alignment,
            Self::ImageOptionalHeader64(hdr64) => hdr64.file_alignment,
        }
    }

    /// Returns the major operating system version required.
    pub fn major_operating_system_version(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.major_operating_system_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.major_operating_system_version,
        }
    }

    /// Returns the minor operating system version required.
    pub fn minor_operating_system_version(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.minor_operating_system_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.minor_operating_system_version,
        }
    }

    /// Returns the major image version.
    pub fn major_image_version(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.major_image_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.major_image_version,
        }
    }

    /// Returns the minor image version.
    pub fn minor_image_version(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.minor_image_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.minor_image_version,
        }
    }

    /// Returns the major subsystem version.
    pub fn major_subsystem_version(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.major_subsystem_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.major_subsystem_version,
        }
    }

    /// Returns the minor subsystem version.
    pub fn minor_subsystem_version(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.minor_subsystem_version,
            Self::ImageOptionalHeader64(hdr64) => hdr64.minor_subsystem_version,
        }
    }

    /// Returns the reserved Windows version value (should be zero).
    pub fn win32_version_value(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.win32_version_value,
            Self::ImageOptionalHeader64(hdr64) => hdr64.win32_version_value,
        }
    }

    /// Returns the total size of the image in memory, including headers.
    pub fn size_of_image(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_image,
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_image,
        }
    }

    /// Returns the size of all headers (DOS header, PE header, section table).
    pub fn size_of_headers(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_headers,
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_headers,
        }
    }

    /// Returns the checksum of the image.
    pub fn check_sum(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.check_sum,
            Self::ImageOptionalHeader64(hdr64) => hdr64.check_sum,
        }
    }

    /// Returns the `IMAGE_SUBSYSTEM_*` value identifying the runtime environment.
    pub fn subsystem(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.subsystem,
            Self::ImageOptionalHeader64(hdr64) => hdr64.subsystem,
        }
    }

    /// Returns the `IMAGE_DLLCHARACTERISTICS_*` flags.
    pub fn dll_characteristics(&self) -> u16 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.dll_characteristics,
            Self::ImageOptionalHeader64(hdr64) => hdr64.dll_characteristics,
        }
    }

    /// Returns the reserved stack size.
    pub fn size_of_stack_reserve(&self) -> u64 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_stack_reserve.into(),
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_stack_reserve,
        }
    }

    /// Returns the committed stack size.
    pub fn size_of_stack_commit(&self) -> u64 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_stack_commit.into(),
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_stack_commit,
        }
    }

    /// Returns the reserved heap size.
    pub fn size_of_heap_reserve(&self) -> u64 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_heap_reserve.into(),
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_heap_reserve,
        }
    }

    /// Returns the committed heap size.
    pub fn size_of_heap_commit(&self) -> u64 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.size_of_heap_commit.into(),
            Self::ImageOptionalHeader64(hdr64) => hdr64.size_of_heap_commit,
        }
    }

    /// Returns the reserved loader flags (should be zero).
    pub fn loader_flags(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.loader_flags,
            Self::ImageOptionalHeader64(hdr64) => hdr64.loader_flags,
        }
    }

    /// Returns the number of data directories in the optional header.
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        match self {
            Self::ImageOptionalHeader32(hdr32) => hdr32.number_of_rva_and_sizes,
            Self::ImageOptionalHeader64(hdr64) => hdr64.number_of_rva_and_sizes,
        }
    }

    /// Returns the size of the optional header.
    pub fn size(&self) -> usize {
        match self {
            Self::ImageOptionalHeader32(_) => size_of::<ImageOptionalHeader32>(),
            Self::ImageOptionalHeader64(_) => size_of::<ImageOptionalHeader64>(),
        }
    }
}

impl_struct! {
    /// Single entry in the PE section table.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_SECTION_HEADER`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageSectionHeader)]
    pub struct ImageSectionHeader {
        /// Section name, null-padded to 8 bytes.
        pub name: [u8; IMAGE_SIZEOF_SHORT_NAME],

        /// Section size in memory before alignment.
        pub virtual_size: u32,

        /// RVA of the section when loaded.
        pub virtual_address: u32,

        /// Size of the section's raw data in the file, file-aligned.
        pub size_of_raw_data: u32,

        /// File offset of the section's raw data.
        pub pointer_to_raw_data: u32,

        /// File offset of the relocation table. Zero for executables.
        pub pointer_to_relocations: u32,

        /// File offset of the COFF line numbers. Zero in modern images.
        pub pointer_to_linenumbers: u32,

        /// Relocation entry count. Zero for executables.
        pub number_of_relocations: u16,

        /// Line-number entry count. Zero in modern images.
        pub number_of_linenumbers: u16,

        /// `IMAGE_SCN_*` flags.
        pub characteristics: u32,
    }
}

//
// The methods on `ImageSectionHeader` in this impl block (including their
// documentation) are copied from the `object` crate v0.39.1, Copyright (c)
// 2015 The Gimli Developers, used under the MIT license. See NOTICES at the
// repo root for the full license text.
//

impl ImageSectionHeader {
    /// Returns the offset and size of the section in a PE file.
    ///
    /// The size of the range will be the minimum of the file size and virtual
    /// size.
    pub fn pe_file_range(&self) -> (u32, u32) {
        // Pointer and size will be zero for uninitialized data.
        // We don't need to validate this.
        let offset = self.pointer_to_raw_data;
        let size = std::cmp::min(self.virtual_size, self.size_of_raw_data);
        (offset, size)
    }

    /// Returns the file offset of the given virtual address, and the remaining
    /// size up to the end of the section.
    ///
    /// Returns `None` if the section does not contain the address.
    pub fn pe_file_range_at(&self, va: u32) -> Option<(u32, u32)> {
        let section_va = self.virtual_address;
        let offset = va.checked_sub(section_va)?;
        let (section_offset, section_size) = self.pe_file_range();

        // Address must be within section (and not at its end).
        if offset < section_size {
            Some((section_offset.checked_add(offset)?, section_size - offset))
        }
        else {
            None
        }
    }

    /// Returns the section data in a PE file.
    ///
    /// The length of the data will be the minimum of the file size and virtual size.
    pub fn pe_data<'data>(&self, data: &'data [u8]) -> Option<&'data [u8]> {
        let (offset, size) = self.pe_file_range();
        data.read_bytes_at(offset.into(), size.into()).ok()
    }

    /// Returns the data starting at the given virtual address, up to the end
    /// of the section.
    ///
    /// Ignores sections with invalid data.
    ///
    /// Returns `None` if the section does not contain the address.
    pub fn pe_data_at<'data>(&self, data: &'data [u8], va: u32) -> Option<&'data [u8]> {
        let (offset, size) = self.pe_file_range_at(va)?;
        data.read_bytes_at(offset.into(), size.into()).ok()
    }
}

impl_struct! {
    /// Single entry in the data directory array of the optional header.
    ///
    /// Locates a standard PE table such as the export, import, or exception
    /// directory by RVA and size.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_DATA_DIRECTORY`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageDataDirectory)]
    pub struct ImageDataDirectory {
        /// RVA of the table.
        pub virtual_address: u32,

        /// Table size in bytes.
        pub size: u32,
    }
}

impl_struct! {
    /// Single entry in the debug directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_DEBUG_DIRECTORY`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageDebugDirectory)]
    pub struct ImageDebugDirectory {
        /// Reserved, must be zero.
        pub characteristics: u32,

        /// Build timestamp, in Unix epoch seconds.
        pub time_date_stamp: u32,

        /// Debug data format version, major part.
        pub major_version: u16,

        /// Debug data format version, minor part.
        pub minor_version: u16,

        /// `IMAGE_DEBUG_TYPE_*` identifying the debug data format.
        pub typ: u32,

        /// Size of the debug data, in bytes.
        pub size_of_data: u32,

        /// RVA of the debug data when loaded.
        pub address_of_raw_data: u32,

        /// File offset of the debug data.
        pub pointer_to_raw_data: u32,
    }
}

impl_struct! {
    /// Single entry in the `.pdata` exception directory.
    ///
    /// Maps a function's RVA range to its `UNWIND_INFO`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_RUNTIME_FUNCTION_ENTRY`.
    #[derive(Debug, Clone, Copy)]
    #[from(::object::pe::ImageRuntimeFunctionEntry)]
    pub struct ImageRuntimeFunctionEntry {
        /// Function start RVA.
        pub begin_address: u32,

        /// Function end RVA, exclusive.
        pub end_address: u32,

        /// RVA of the function's `UNWIND_INFO`.
        pub unwind_info_address_or_data: u32,
    }
}
