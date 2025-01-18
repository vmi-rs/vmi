use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Error, FnArg, GenericParam, Generics, Ident, ItemImpl, Lifetime, Pat,
    PatType, Path, Result, Token, Visibility,
};

use crate::{
    lifetime,
    method::{FnArgExt, ItemExt, ItemFnExt},
};

const VMI_LIFETIME: &str = "__vmi";

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

        Ok(Self { os_context_name })
    }
}

struct TraitFn {
    os_context_sig: TokenStream,
    os_context_fn: TokenStream,
}

fn generate_trait_fn(item_fn: impl ItemFnExt, skip: usize) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let ident = &sig.ident;
    let mut generics = sig.generics.clone();
    let mut return_type = sig.output.clone();
    let mut receiver = sig.receiver()?.clone();

    let lifetime_of_self = receiver
        .lifetime()
        .map(|lifetime| lifetime.ident.to_string());

    let maybe_vmi = match skip {
        // Skip the first argument (`self`).
        1 => quote! {},

        // Skip the first two arguments (`self` and `&impl Vmi*`).
        2 => quote! { self, },

        // This should never happen.
        _ => panic!("unexpected number of arguments to skip"),
    };

    let mut context_args = Vec::new();
    let mut context_arg_names = Vec::new();

    // Skip the first two arguments (`self` and `&impl Vmi*`).
    for arg in sig.inputs.clone().iter_mut().skip(2) {
        // If a lifetime has been applied to `self`, then we need to
        // replace that lifetime in the arguments.
        if let Some(lifetime_of_self) = &lifetime_of_self {
            lifetime::replace_in_fn_arg(arg, lifetime_of_self, VMI_LIFETIME);
        }

        let PatType { pat, ty, .. } = match arg {
            FnArg::Typed(pat_type) => pat_type,
            _ => panic!("`{ident}`: argument is not typed, skipping"),
        };

        let pat_ident = match &**pat {
            Pat::Ident(pat_ident) => pat_ident,
            _ => return None,
        };

        context_args.push(quote! { #pat_ident: #ty });
        context_arg_names.push(quote! { #pat_ident });
    }

    // If a lifetime has been applied to `self`, then we need to:
    //   1. remove the lifetime from the generics,
    //   2. replace the lifetime in the receiver (`self`), and
    //   3. replace the lifetime in the return type.
    if let Some(lifetime_of_self) = &lifetime_of_self {
        lifetime::remove_in_generics(&mut generics, lifetime_of_self);
        lifetime::replace_in_receiver(&mut receiver, lifetime_of_self, VMI_LIFETIME);
        lifetime::replace_in_return_type(&mut return_type, lifetime_of_self, VMI_LIFETIME);
    }

    // Generate the implementation for `VmiOsContext`.
    let doc = item_fn.doc();
    let os_context_sig = quote! {
        #(#doc)*
        fn #ident #generics(#receiver, #(#context_args),*) #return_type;
    };

    let doc = item_fn.doc();
    let os_context_fn = quote! {
        #(#doc)*
        fn #ident #generics(#receiver, #(#context_args),*) #return_type {
            self.underlying_os()
                .#ident(
                    #maybe_vmi
                    #(#context_arg_names),*
                )
        }
    };

    Some(TraitFn {
        os_context_sig,
        os_context_fn,
    })
}

fn filter_pub(item: impl ItemFnExt) -> Option<impl ItemFnExt> {
    match item.vis() {
        Some(Visibility::Public(_)) => Some(item),
        _ => None,
    }
}

fn transform_fn_to_trait_fn(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let mut inputs = sig.inputs.iter();

    // First argument must be a receiver (`self`).
    inputs.next()?.receiver()?;

    // Second argument _might_ be of type `&VmiCore<Driver>`.
    if !inputs
        .next()
        .map(|fn_arg| fn_arg.contains("Vmi"))
        .unwrap_or(false)
    {
        return generate_trait_fn(item_fn, 1);
    }

    generate_trait_fn(item_fn, 2)
}

fn verify_generics(generics: &Generics) -> Result<()> {
    let mut params = generics.params.iter();
    let param = match params.next() {
        Some(param) => param,
        None => {
            return Err(Error::new(
                Span::call_site(),
                "missing generic `Driver` parameter",
            ))
        }
    };

    let ident = match param {
        GenericParam::Type(ty) => &ty.ident,
        _ => return Err(Error::new(Span::call_site(), "expected type parameter")),
    };

    if ident != "Driver" {
        return Err(Error::new(
            Span::call_site(),
            "expected `Driver` type parameter",
        ));
    }

    Ok(())
}

pub fn derive_trait_from_impl(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let Args { os_context_name } = parse_macro_input!(args as Args);
    let input = parse_macro_input!(item as ItemImpl);

    match verify_generics(&input.generics) {
        Ok(_) => {}
        Err(err) => return proc_macro::TokenStream::from(err.to_compile_error()),
    }

    let struct_type = &input.self_ty;
    let struct_type_raw = quote! { #struct_type }.to_string();
    let struct_type_raw = match struct_type_raw.find(' ') {
        Some(index) => &struct_type_raw[..index],
        None => &struct_type_raw,
    };
    let where_clause = input.generics.where_clause.as_ref();
    let fns = input
        .items
        .iter()
        .filter_map(ItemExt::as_fn)
        .filter_map(filter_pub)
        .filter_map(transform_fn_to_trait_fn);

    let os_context_sigs = fns.clone().map(|m| m.os_context_sig);
    let os_context_fns = fns.clone().map(|m| m.os_context_fn);

    let lt = syn::parse_str::<Lifetime>(&format!("'{VMI_LIFETIME}")).unwrap();

    let expanded = quote! {
        #input

        //
        // OS Context
        //

        #[doc = concat!("[`", #struct_type_raw, "`] extensions for the [`VmiContext`].")]
        #[doc = ""]
        #[doc = "[`VmiContext`]: vmi_core::VmiContext"]
        pub trait #os_context_name <#lt, Driver>
            #where_clause
        {
            #(#os_context_sigs)*
        }

        impl<#lt, Driver> #os_context_name <#lt, Driver> for vmi_core::VmiOsState<#lt, Driver, #struct_type>
            #where_clause
        {
            #(#os_context_fns)*
        }
    };

    proc_macro::TokenStream::from(expanded)
}
