use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Error, FnArg, Ident, ItemTrait, Pat, PatType, Path, Result, Token,
};

use crate::method::{FnArgExt, ItemExt, ItemFnExt};

struct Args {
    os_context_name: Path,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut os_context_name = None;

        while !input.is_empty() {
            let ident = input.parse::<Ident>()?;
            let _ = input.parse::<syn::Token![=]>()?;
            let value = input.parse::<Path>()?;

            match ident.to_string().as_str() {
                "os_context_name" => os_context_name = Some(value),
                _ => return Err(Error::new(ident.span(), "unknown argument")),
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        let os_context_name = os_context_name
            .ok_or_else(|| Error::new(Span::call_site(), "missing `os_context_name` argument"))?;

        Ok(Self {
            os_context_name,
        })
    }
}

struct TraitFn {
    os_context_fn: TokenStream,
}

fn generate_impl_fns(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let ident = &sig.ident;
    let generics = &sig.generics;
    let return_type = &sig.output;

    let mut context_args = Vec::new();
    let mut context_arg_names = Vec::new();

    // Skip the first two arguments (`self` and `&impl Vmi*`).
    for arg in sig.inputs.iter().skip(2) {
        match arg {
            FnArg::Typed(PatType { pat, ty, .. }) => {
                let pat_ident = match &**pat {
                    Pat::Ident(pat_ident) => pat_ident,
                    _ => {
                        eprintln!("`{ident}`: argument is not an identifier, skipping");
                        return None;
                    }
                };

                context_args.push(quote! { #pat_ident: #ty });
                context_arg_names.push(quote! { #pat_ident });
            }
            _ => {
                eprintln!("`{ident}`: argument is not typed, skipping");
                return None;
            }
        }
    }

    // Generate the implementation for `VmiOsContext`.
    let doc = item_fn.doc();
    let os_context_fn = quote! {
        #(#doc)*
        pub fn #ident #generics(&self, #(#context_args),*) #return_type {
            self.underlying_os()
                .#ident(self, #(#context_arg_names),*)
        }
    };

    Some(TraitFn {
        os_context_fn,
    })
}

fn transform_fn_to_trait_fn(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let mut inputs = sig.inputs.iter();

    // First argument must be a receiver (`self`).
    inputs.next()?.receiver()?;

    // Second argument must be of type `& impl Vmi*`.
    if !inputs.next()?.contains("Vmi") {
        return None;
    }

    // Generate the implementations.
    generate_impl_fns(item_fn)
}

pub fn derive_os_wrapper(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let Args {
        os_context_name,
    } = parse_macro_input!(args as Args);
    let input = parse_macro_input!(item as ItemTrait);
    let trait_name = &input.ident;
    let trait_methods = input
        .items
        .iter()
        .filter_map(ItemExt::as_fn)
        .filter_map(transform_fn_to_trait_fn);

    let os_context_methods = trait_methods.clone().map(|m| m.os_context_fn);

    // Generate the wrapper struct and its implementation
    let expanded = quote! {
        #input

        //
        // OS Context
        //

        impl<Driver, Os> #os_context_name<'_, Driver, Os>
        where
            Driver: crate::VmiDriver,
            Os: #trait_name<Driver>,
        {
            #(#os_context_methods)*
        }
    };

    proc_macro::TokenStream::from(expanded)
}
