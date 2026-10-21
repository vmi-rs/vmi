//! The `#[object_mirror]` attribute.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Fields, Ident, ItemStruct, Type, parse_macro_input};

/// How `object` stores an integer field.
enum Encoding {
    /// A single byte, plain or wrapped in a newtype.
    Byte,

    /// A little-endian wrapper such as `U32<E>`, possibly around a newtype.
    Wide,
}

/// Expands `#[object_mirror(SourceType)]` on a struct.
pub fn object_mirror(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let source = parse_macro_input!(args as Type);
    let item = parse_macro_input!(item as ItemStruct);

    match expand(&source, &item) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Returns the mirror struct, its `From` impl and the layout assertions.
fn expand(source: &Type, item: &ItemStruct) -> Result<TokenStream, syn::Error> {
    let fields = match &item.fields {
        Fields::Named(fields) => fields,
        _ => {
            return Err(syn::Error::new_spanned(
                &item.ident,
                "`object_mirror` needs a struct with named fields",
            ));
        }
    };

    if !item.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &item.generics,
            "`object_mirror` does not support generic structs",
        ));
    }

    let name = &item.ident;
    let mut conversions = Vec::new();
    let mut offset_checks = Vec::new();

    for field in &fields.named {
        let ident = match &field.ident {
            Some(ident) => ident,
            None => {
                return Err(syn::Error::new_spanned(field, "a named field needs a name"));
            }
        };

        let value = conversion(ident, &field.ty);
        conversions.push(quote! { #ident: #value });

        let message = format!("{name} field offset mismatch: {ident}");
        offset_checks.push(quote! {
            assert!(
                ::core::mem::offset_of!(#name, #ident) == ::core::mem::offset_of!(#source, #ident),
                #message,
            );
        });
    }

    let size_message = format!("{name} size mismatch");
    let align_message = format!("{name} alignment mismatch");

    let attrs = &item.attrs;
    let vis = &item.vis;
    let struct_token = &item.struct_token;

    Ok(quote! {
        #(#attrs)*
        #[derive(
            ::zerocopy::FromBytes,
            ::zerocopy::IntoBytes,
            ::zerocopy::Immutable,
            ::zerocopy::KnownLayout,
        )]
        #[repr(C, packed)]
        #vis #struct_token #name #fields

        impl ::core::convert::From<#source> for #name {
            fn from(value: #source) -> Self {
                Self {
                    #(#conversions,)*
                }
            }
        }

        const _: () = {
            assert!(
                ::core::mem::size_of::<#name>() == ::core::mem::size_of::<#source>(),
                #size_message,
            );
            assert!(
                ::core::mem::align_of::<#name>() == ::core::mem::align_of::<#source>(),
                #align_message,
            );
            #(#offset_checks)*
        };
    })
}

/// Returns the expression that converts the source field `ident` into the
/// mirror's field type `ty`.
fn conversion(ident: &Ident, ty: &Type) -> TokenStream {
    if let Type::Array(array) = ty {
        return match encoding(&array.elem) {
            Some(Encoding::Byte) => quote! { value.#ident.map(::object::Wrap::into_inner) },
            Some(Encoding::Wide) => quote! {
                value.#ident.map(|element| {
                    ::object::Wrap::into_inner(element.get(::object::LittleEndian))
                })
            },
            None => quote! { value.#ident.map(::core::convert::From::from) },
        };
    }

    match encoding(ty) {
        Some(Encoding::Byte) => quote! { ::object::Wrap::into_inner(value.#ident) },
        Some(Encoding::Wide) => quote! {
            ::object::Wrap::into_inner(value.#ident.get(::object::LittleEndian))
        },
        None => quote! { ::core::convert::From::from(value.#ident) },
    }
}

/// Returns how `object` stores a field whose mirror type is `ty`, or `None`
/// for a type that is no integer.
fn encoding(ty: &Type) -> Option<Encoding> {
    let path = match ty {
        Type::Path(path) if path.qself.is_none() => &path.path,
        _ => return None,
    };

    let ident = path.get_ident()?;
    match ident.to_string().as_str() {
        "u8" | "i8" => Some(Encoding::Byte),
        "u16" | "i16" | "u32" | "i32" | "u64" | "i64" => Some(Encoding::Wide),
        _ => None,
    }
}
