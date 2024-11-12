use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Error, FnArg, GenericParam, Generics, Ident, ItemImpl, Lifetime, Pat,
    PatType, Path, Receiver, Result, Token, Visibility,
};

use crate::{
    lifetime,
    method::{FnArgExt, ItemExt, ItemFnExt},
    transform,
};

const VMI_LIFETIME: &str = "__vmi";

struct Args {
    os_session_name: Path,
    os_context_name: Path,
    os_session_prober_name: Path,
    os_context_prober_name: Path,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut os_session_name = None;
        let mut os_context_name = None;
        let mut os_session_prober_name = None;
        let mut os_context_prober_name = None;

        while !input.is_empty() {
            let ident = input.parse::<Ident>()?;
            let _ = input.parse::<syn::Token![=]>()?;
            let value = input.parse::<Path>()?;

            match ident.to_string().as_str() {
                "os_session_name" => os_session_name = Some(value),
                "os_context_name" => os_context_name = Some(value),
                "os_session_prober_name" => os_session_prober_name = Some(value),
                "os_context_prober_name" => os_context_prober_name = Some(value),
                _ => return Err(Error::new(ident.span(), "unknown argument")),
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        let os_session_name = os_session_name
            .ok_or_else(|| Error::new(Span::call_site(), "missing `os_session_name` argument"))?;

        let os_context_name = os_context_name
            .ok_or_else(|| Error::new(Span::call_site(), "missing `os_context_name` argument"))?;

        let os_session_prober_name = os_session_prober_name.ok_or_else(|| {
            Error::new(
                Span::call_site(),
                "missing `os_session_prober_name` argument",
            )
        })?;

        let os_context_prober_name = os_context_prober_name.ok_or_else(|| {
            Error::new(
                Span::call_site(),
                "missing `os_context_prober_name` argument",
            )
        })?;

        Ok(Self {
            os_session_name,
            os_context_name,
            os_session_prober_name,
            os_context_prober_name,
        })
    }
}

struct TraitFn {
    os_session_sig: TokenStream,
    os_session_fn: TokenStream,

    os_context_sig: TokenStream,
    os_context_fn: TokenStream,

    os_session_prober_sig: TokenStream,
    os_session_prober_fn: TokenStream,

    os_context_prober_sig: TokenStream,
    os_context_prober_fn: TokenStream,
}

fn generate_trait_fn(item_fn: impl ItemFnExt, skip: usize) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let ident = &sig.ident;
    let lifetime_of_self = sig
        .receiver()
        .and_then(Receiver::lifetime)
        .map(|lifetime| lifetime.ident.to_string());
    let mut generics = sig.generics.clone();

    if let Some(lifetime_of_self) = &lifetime_of_self {
        lifetime::remove_in_generics(&mut generics, lifetime_of_self);
    }

    let (maybe_core, maybe_registers) = match skip {
        // Skip the first argument (`self`).
        1 => (quote! {}, quote! {}),

        // Skip the first two arguments (`self` and `&VmiCore<Driver>`).
        2 => (quote! { self.core(), }, quote! {}),

        // Skip the first three arguments (`self`, `&VmiCore<Driver>`, and
        // `&<Driver::Architecture as Architecture>::Registers`).
        3 => (
            quote! { self.core(), },
            quote! { self.event().registers(), },
        ),

        // This should never happen.
        _ => panic!("unexpected number of arguments to skip"),
    };

    let mut session_args = Vec::new();
    let mut session_arg_names = Vec::new();

    for arg in sig.inputs.clone().iter_mut().skip(skip.min(2)) {
        // If a lifetime has been applied to `self`, and the argument
        // is a reference type, then we need to check if the reference
        // type has a lifetime that matches the lifetime applied to `self`.
        //
        // If it does, then we need to replace that lifetime with a `__vmi`
        // lifetime instead.
        if let Some(lifetime_of_self) = &lifetime_of_self {
            lifetime::replace_in_fn_arg(arg, lifetime_of_self, VMI_LIFETIME);
        }

        match arg {
            FnArg::Typed(PatType { pat, ty, .. }) => {
                let pat_ident = match &**pat {
                    Pat::Ident(pat_ident) => pat_ident,
                    _ => return None,
                };

                session_args.push(quote! { #pat_ident: #ty });
                session_arg_names.push(quote! { #pat_ident });
            }
            _ => panic!("`{ident}`: argument is not typed, skipping"),
        }
    }

    let (context_args, context_arg_names) = match skip {
        3 => (&session_args[1..], &session_arg_names[1..]),
        _ => (&session_args[..], &session_arg_names[..]),
    };

    let mut return_type = sig.output.clone();

    // If a lifetime has been applied to `self`, and the return type
    // is an `impl Trait` type, then we need to check if the `impl Trait`
    // type has a lifetime that matches the lifetime applied to `self`.
    //
    // If it does, then we need to replace that lifetime with a `__vmi`
    // lifetime instead.
    if let Some(lifetime_of_self) = &lifetime_of_self {
        lifetime::replace_in_return_type(&mut return_type, lifetime_of_self, VMI_LIFETIME);
    }

    let prober_return_type = transform::result_to_result_option(&return_type);

    // Generate the implementation for `VmiOsSession`.
    let doc = item_fn.doc();
    let os_session_sig = quote! {
        #(#doc)*
        fn #ident #generics(&self, #(#session_args),*) #return_type;
    };

    let doc = item_fn.doc();
    let os_session_fn = quote! {
        #(#doc)*
        fn #ident #generics(&self, #(#session_args),*) #return_type {
            self.underlying_os().#ident(
                #maybe_core
                #(#session_arg_names),*
            )
        }
    };

    // Generate the implementation for `VmiOsContext`.
    let doc = item_fn.doc();
    let os_context_sig = quote! {
        #(#doc)*
        fn #ident #generics(&self, #(#context_args),*) #return_type;
    };

    let doc = item_fn.doc();
    let os_context_fn = quote! {
        #(#doc)*
        fn #ident #generics(&self, #(#context_args),*) #return_type {
            self.underlying_os().#ident(
                #maybe_core
                #maybe_registers
                #(#context_arg_names),*
            )
        }
    };

    // Generate the implementation for `VmiOsSessionProber`.
    let (os_session_prober_sig, os_session_prober_fn) = match &prober_return_type {
        Some(prober_return_type) => {
            let doc = item_fn.doc();
            let os_session_prober_sig = quote! {
                #(#doc)*
                fn #ident #generics(&self, #(#session_args),*) #prober_return_type;
            };

            let doc = item_fn.doc();
            let os_session_prober_fn = quote! {
                #(#doc)*
                fn #ident #generics(&self, #(#session_args),*) #prober_return_type {
                    self.core().check_result(
                        self.core()             // -> &VmiSessionProber
                            .underlying_os()    // -> &Os
                            .#ident(
                                #maybe_core
                                #(#session_arg_names),*
                            ),
                    )
                }
            };

            (os_session_prober_sig, os_session_prober_fn)
        }

        None => (os_session_sig.clone(), os_session_fn.clone()),
    };

    // Generate the implementation for `VmiOsContextProber`.
    let (os_context_prober_sig, os_context_prober_fn) = match &prober_return_type {
        Some(prober_return_type) => {
            let doc = item_fn.doc();
            let os_context_prober_sig = quote! {
                #(#doc)*
                fn #ident #generics(&self, #(#context_args),*) #prober_return_type;
            };

            let doc = item_fn.doc();
            let os_context_prober_fn = quote! {
                #(#doc)*
                fn #ident #generics(&self, #(#context_args),*) #prober_return_type {
                    self.core().check_result(
                        self.core()             // -> &VmiContextProber
                            .underlying_os()    // -> &Os
                            .#ident(
                                #maybe_core
                                #maybe_registers
                                #(#context_arg_names),*
                            ),
                    )
                }
            };

            (os_context_prober_sig, os_context_prober_fn)
        }

        None => (os_context_sig.clone(), os_context_fn.clone()),
    };

    Some(TraitFn {
        os_session_sig,
        os_session_fn,
        os_context_sig,
        os_context_fn,
        os_session_prober_sig,
        os_session_prober_fn,
        os_context_prober_sig,
        os_context_prober_fn,
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
        .map(|fn_arg| fn_arg.contains("VmiCore"))
        .unwrap_or(false)
    {
        return generate_trait_fn(item_fn, 1);
    }

    // Third argument _might_ be of type `&<Driver::Architecture as Architecture>::Registers`.
    // If it is, include it in the trait method signature.
    if !inputs
        .next()
        .map(|fn_arg| fn_arg.contains("Registers"))
        .unwrap_or(false)
    {
        return generate_trait_fn(item_fn, 2);
    }

    generate_trait_fn(item_fn, 3)
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
    let Args {
        os_session_name,
        os_context_name,
        os_session_prober_name,
        os_context_prober_name,
    } = parse_macro_input!(args as Args);
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

    let os_session_sigs = fns.clone().map(|m| m.os_session_sig);
    let os_session_fns = fns.clone().map(|m| m.os_session_fn);
    let os_context_sigs = fns.clone().map(|m| m.os_context_sig);
    let os_context_fns = fns.clone().map(|m| m.os_context_fn);
    let os_session_prober_sigs = fns.clone().map(|m| m.os_session_prober_sig);
    let os_session_prober_fns = fns.clone().map(|m| m.os_session_prober_fn);
    let os_context_prober_sigs = fns.clone().map(|m| m.os_context_prober_sig);
    let os_context_prober_fns = fns.clone().map(|m| m.os_context_prober_fn);

    let lt = syn::parse_str::<Lifetime>(&format!("'{VMI_LIFETIME}")).unwrap();

    let expanded = quote! {
        #input

        //
        // OS Session
        //

        #[doc = concat!("[`", #struct_type_raw, "`] extensions for the [`VmiSession`].")]
        #[doc = ""]
        #[doc = "[`VmiSession`]: vmi_core::VmiSession"]
        pub trait #os_session_name <#lt, Driver>
            #where_clause
        {
            #(#os_session_sigs)*
        }

        impl<#lt, Driver> #os_session_name <#lt, Driver> for vmi_core::VmiOsSession<#lt, Driver, #struct_type>
            #where_clause
        {
            #(#os_session_fns)*
        }

        //
        // OS Session Prober
        //

        #[doc = concat!("[`", #struct_type_raw, "`] extensions for the [`VmiSessionProber`].")]
        #[doc = ""]
        #[doc = "[`VmiSessionProber`]: vmi_core::VmiSessionProber"]
        pub trait #os_session_prober_name <#lt, Driver>
            #where_clause
        {
            #(#os_session_prober_sigs)*
        }

        impl<#lt, Driver> #os_session_prober_name <#lt, Driver> for vmi_core::VmiOsSessionProber<#lt, Driver, #struct_type>
            #where_clause
        {
            #(#os_session_prober_fns)*
        }

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

        impl<#lt, Driver> #os_context_name <#lt, Driver> for vmi_core::VmiOsContext<#lt, Driver, #struct_type>
            #where_clause
        {
            #(#os_context_fns)*
        }

        //
        // OS Context Prober
        //

        #[doc = concat!("[`", #struct_type_raw, "`] extensions for the [`VmiContextProber`].")]
        #[doc = ""]
        #[doc = "[`VmiContextProber`]: vmi_core::VmiContextProber"]
        pub trait #os_context_prober_name <#lt, Driver>
            #where_clause
        {
            #(#os_context_prober_sigs)*
        }

        impl<#lt, Driver> #os_context_prober_name <#lt, Driver> for vmi_core::VmiOsContextProber<#lt, Driver, #struct_type>
            #where_clause
        {
            #(#os_context_prober_fns)*
        }
    };

    proc_macro::TokenStream::from(expanded)
}
