//! Procedural macros for the `vmi` crate.

mod common;
mod derive_os_impl;
mod derive_os_trait;
mod method;
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
