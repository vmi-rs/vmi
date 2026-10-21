//! Procedural macros for the `vmi` crate.

mod common;
mod derive_os_impl;
mod derive_os_trait;
mod method;
mod object_mirror;
mod transform;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn derive_os_wrapper(args: TokenStream, item: TokenStream) -> TokenStream {
    derive_os_trait::derive_os_wrapper(args, item)
}

#[proc_macro_attribute]
pub fn derive_trait_from_impl(args: TokenStream, item: TokenStream) -> TokenStream {
    derive_os_impl::derive_trait_from_impl(args, item)
}

/// Mirrors a struct of the `object` crate as a packed struct with native
/// fields.
///
/// The attribute takes the `object` type, such as
/// `::object::pe::ImageFileHeader` or
/// `::object::elf::Sym64<::object::LittleEndian>`, and the struct names the
/// same fields. The attribute adds `#[repr(C, packed)]` and the `zerocopy`
/// derives that byte-level reads need, and implements `From<SourceType>`.
/// Each field converts by its type in the mirror:
///
/// - `u8` and `i8` take the byte, and unwrap `object`'s byte newtypes.
/// - `u16` to `i64` decode `object`'s little-endian wrappers, and unwrap the
///   newtypes inside them.
/// - Arrays decode each element the same way.
/// - Any other type, such as another mirror, converts through `From`.
///
/// Compile-time assertions check that both structs agree on size, alignment
/// and the offset of every field. The crate that uses the attribute depends
/// on `object` and `zerocopy`.
///
/// # Examples
///
/// ```ignore
/// #[vmi_macros::object_mirror(::object::pe::ImageDataDirectory)]
/// #[derive(Debug, Clone, Copy)]
/// pub struct ImageDataDirectory {
///     pub virtual_address: u32,
///     pub size: u32,
/// }
/// ```
#[proc_macro_attribute]
pub fn object_mirror(args: TokenStream, item: TokenStream) -> TokenStream {
    object_mirror::object_mirror(args, item)
}
