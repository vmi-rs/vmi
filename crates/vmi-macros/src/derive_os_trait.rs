use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned as _,
    Error, FnArg, Ident, ItemTrait, Pat, PatType, Path, PathArguments, Result, ReturnType, Token,
    Type,
};

use crate::method::{FnArgExt, ItemExt, ItemFnExt};

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
    os_session_fn: TokenStream,
    os_context_fn: TokenStream,
    os_session_prober_fn: TokenStream,
    os_context_prober_fn: TokenStream,
}

/// Transform the return type from `Result<T, VmiError>` to
/// `Result<Option<T>, VmiError>`.
fn transform_return_type(return_type: &ReturnType) -> TokenStream {
    let ty = match &return_type {
        ReturnType::Type(_, ty) => ty,
        ReturnType::Default => {
            return quote_spanned! {
                return_type.span() =>
                    compile_error!("expected return type `Result<T, VmiError>`")
            }
        }
    };

    let type_path = match &**ty {
        Type::Path(type_path) => type_path,
        _ => {
            return quote_spanned! {
                ty.span() => compile_error!("expected path type")
            }
        }
    };

    let segment = match type_path.path.segments.last() {
        Some(segment) => segment,
        None => {
            return quote_spanned! {
                ty.span() => compile_error!("expected path segment")
            }
        }
    };

    if segment.ident != "Result" {
        return quote_spanned! {
            ty.span() => compile_error!("expected `Result` type");
        };
    }

    let args = match &segment.arguments {
        PathArguments::AngleBracketed(args) => args,
        _ => {
            return quote_spanned! {
                ty.span() => compile_error!("expected angle-bracketed arguments in `Result` type");
            }
        }
    };

    if args.args.len() != 2 {
        return quote_spanned! {
            args.span() => compile_error!("expected two arguments in `Result` type");
        };
    }

    let t = &args.args[0];
    quote! { -> Result<Option<#t>, VmiError> }
}

fn generate_impl_fns(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let ident = &sig.ident;

    let mut session_args = Vec::new();
    let mut session_arg_names = Vec::new();

    // Skip the first two arguments (`self` and `&VmiCore<Driver>`).
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

                session_args.push(quote! { #pat_ident: #ty });
                session_arg_names.push(quote! { #pat_ident });
            }
            _ => {
                eprintln!("`{ident}`: argument is not typed, skipping");
                return None;
            }
        }
    }

    // For the context functions, we need to skip the
    // `&<Driver::Architecture as Architecture>::Registers`,
    // since they are provided by the `event` in the `VmiContext`.
    let context_args = &session_args[1..];
    let context_arg_names = &session_arg_names[1..];

    // Transform the return type from `Result<T, VmiError>` to
    // `Result<Option<T>, VmiError>`.
    let return_type = &sig.output;
    let prober_return_type = transform_return_type(return_type);

    // Generate the implementation for `VmiOsSession`.
    let doc = item_fn.doc();
    let os_session_fn = quote! {
        #(#doc)*
        pub fn #ident(&self, #(#session_args),*) #return_type {
            self.0.os.#ident(&self.0.core, #(#session_arg_names),*)
        }
    };

    // Generate the implementation for `VmiOsContext`.
    let doc = item_fn.doc();
    let os_context_fn = quote! {
        #(#doc)*
        pub fn #ident(&self, #(#context_args),*) #return_type {
            self.0.session.os.#ident(
                &self.0.session,
                self.0.event.registers(),
                #(#context_arg_names),*
            )
        }
    };

    // Generate the implementation for `VmiOsSessionProber`.
    let doc = item_fn.doc();
    let os_session_prober_fn = quote! {
        #(#doc)*
        pub fn #ident(&self, #(#session_args),*) #prober_return_type {
            self.0.check_result(
                self.0
                    .session
                    .os()
                    .#ident(#(#session_arg_names),*),
            )
        }
    };

    // Generate the implementation for `VmiOsContextProber`.
    let doc = item_fn.doc();
    let os_context_prober_fn = quote! {
        #(#doc)*
        pub fn #ident(&self, #(#context_args),*) #prober_return_type {
            self.0.check_result(
                self.0
                    .context
                    .os()
                    .#ident(#(#context_arg_names),*),
            )
        }
    };

    Some(TraitFn {
        os_session_fn,
        os_context_fn,
        os_session_prober_fn,
        os_context_prober_fn,
    })
}

fn transform_fn_to_trait_fn(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let mut inputs = sig.inputs.iter();

    // First argument must be a receiver (`self`).
    inputs.next()?.receiver()?;

    // Second argument must be of type `&VmiCore<Driver>`.
    if !inputs.next()?.contains("VmiCore") {
        return None;
    }

    // Third argument must be of type `&<Driver::Architecture as Architecture>::Registers`.
    if !inputs.next()?.contains("Registers") {
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
        os_session_name,
        os_context_name,
        os_session_prober_name,
        os_context_prober_name,
    } = parse_macro_input!(args as Args);
    let input = parse_macro_input!(item as ItemTrait);
    let trait_name = &input.ident;
    let trait_methods = input
        .items
        .iter()
        .filter_map(ItemExt::as_fn)
        .filter_map(transform_fn_to_trait_fn);

    let os_session_methods = trait_methods.clone().map(|m| m.os_session_fn);
    let os_context_methods = trait_methods.clone().map(|m| m.os_context_fn);
    let os_session_prober_methods = trait_methods.clone().map(|m| m.os_session_prober_fn);
    let os_context_prober_methods = trait_methods.clone().map(|m| m.os_context_prober_fn);

    // Generate the wrapper struct and its implementation
    let expanded = quote! {
        #input

        //
        // OS Session
        //

        impl<Driver, Os> #os_session_name<'_, Driver, Os>
        where
            Driver: crate::VmiDriver,
            Os: #trait_name<Driver>,
        {
            #(#os_session_methods)*
        }

        //
        // OS Session Prober
        //

        impl<Driver, Os> #os_session_prober_name<'_, Driver, Os>
        where
            Driver: crate::VmiDriver,
            Os: #trait_name<Driver>,
        {
            #(#os_session_prober_methods)*
        }

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

        //
        // OS Context Prober
        //

        impl<Driver, Os> #os_context_prober_name<'_, Driver, Os>
        where
            Driver: crate::VmiDriver,
            Os: #trait_name<Driver>,
        {
            #(#os_context_prober_methods)*
        }
    };

    proc_macro::TokenStream::from(expanded)
}
