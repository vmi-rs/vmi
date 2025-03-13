use proc_macro2::TokenStream;
use quote::quote;
use syn::{Ident, ItemTrait, parse_macro_input};

use crate::{
    common::{self, __vmi_lifetime},
    method::{FnArgExt, ItemExt, ItemFnExt},
    transform,
};

struct TraitFn {
    os_context_fn: TokenStream,
}

fn generate_impl_fns(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let ident = &sig.ident;
    let generics = &sig.generics;
    let return_type = &sig.output;
    //let receiver = sig.receiver()?;

    let (args, arg_names) = common::build_args(sig)?;
    let where_clause = common::build_where_clause(sig);

    // Replace `Self` with `Os` in the return type.
    let mut return_type = return_type.clone();
    transform::replace_self_with_os(&mut return_type);

    // Generate the implementation for `VmiOsContext`.
    let doc = item_fn.doc();
    let os_context_fn = quote! {
        #(#doc)*
        pub fn #ident #generics(&self, #(#args),*) #return_type
            #where_clause
        {
            Os::#ident(self.state(), #(#arg_names),*)
        }
    };

    Some(TraitFn { os_context_fn })
}

fn transform_fn_to_trait_fn(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let mut inputs = sig.inputs.iter();

    // First argument must be a receiver (`self`).
    // inputs.next()?.receiver()?;

    // Second argument must be of type `Vmi*`.
    if !inputs.next()?.contains("VmiState") {
        return None;
    }

    // Generate the implementations.
    generate_impl_fns(item_fn)
}

pub fn derive_os_wrapper(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let os_context_name = parse_macro_input!(args as Ident);
    let input = parse_macro_input!(item as ItemTrait);
    let trait_name = &input.ident;
    let trait_methods = input
        .items
        .iter()
        .filter_map(ItemExt::as_fn)
        .filter_map(transform_fn_to_trait_fn);

    let os_context_methods = trait_methods.clone().map(|m| m.os_context_fn);

    let vmi_lifetime = __vmi_lifetime();

    // Generate the wrapper struct and its implementation
    let expanded = quote! {
        #input

        //
        // OS Context
        //

        impl<#vmi_lifetime, Driver, Os> #os_context_name<#vmi_lifetime, Driver, Os>
        where
            Driver: crate::VmiDriver,
            Os: #trait_name<Driver>,
        {
            #(#os_context_methods)*
        }
    };

    proc_macro::TokenStream::from(expanded)
}
