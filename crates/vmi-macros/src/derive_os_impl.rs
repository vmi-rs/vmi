use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Error, GenericParam, Generics, Ident, ItemImpl, Result, Visibility};

use crate::{
    common::{self, __vmi_lifetime},
    method::{FnArgExt, ItemExt, ItemFnExt},
};

struct TraitFn {
    os_context_sig: TokenStream,
    os_context_fn: TokenStream,
}

fn generate_trait_fn(item_fn: impl ItemFnExt) -> Option<TraitFn> {
    let sig = item_fn.sig();
    let ident = &sig.ident;
    let generics = &sig.generics;
    let return_type = &sig.output;
    //let receiver = sig.receiver()?;

    let (args, arg_names) = common::build_args(sig)?;
    let where_clause = common::build_where_clause(sig);

    // Generate the implementation for `VmiOsContext`.
    let doc = item_fn.doc();
    let os_context_sig = quote! {
        #(#doc)*
        fn #ident #generics(&self, #(#args),*) #return_type
            #where_clause;
    };

    let doc = item_fn.doc();
    let os_context_fn = quote! {
        #(#doc)*
        fn #ident #generics(&self, #(#args),*) #return_type
            #where_clause
        {
            <<Self as VmiOsStateExt>::Os>::#ident(self.state(), #(#arg_names),*)
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
    //inputs.next()?.receiver()?;

    // Second argument _might_ be of type `&VmiCore<Driver>`.
    if !inputs
        .next()
        .map(|fn_arg| fn_arg.contains("VmiState"))
        .unwrap_or(false)
    {
        return None;
    }

    generate_trait_fn(item_fn)
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
    let os_context_name = parse_macro_input!(args as Ident);
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

    let vmi_lifetime = __vmi_lifetime();

    let expanded = quote! {
        #input

        // A helper trait to expose the Os type from VmiOsState
        trait VmiOsStateExt {
            type Os;
        }

        impl<'__vmi, TDriver, TOs> VmiOsStateExt for vmi_core::VmiOsState<'__vmi, TDriver, TOs>
        where
            TDriver: VmiDriver,
            TOs: VmiOs<TDriver>,
        {
            type Os = TOs;
        }

        //
        // OS Context
        //

        #[doc = concat!("[`", #struct_type_raw, "`] extensions for the [`VmiContext`].")]
        #[doc = ""]
        #[doc = "[`VmiContext`]: vmi_core::VmiContext"]
        pub trait #os_context_name <#vmi_lifetime, Driver>
            #where_clause
        {
            #(#os_context_sigs)*
        }

        impl<#vmi_lifetime, Driver> #os_context_name <#vmi_lifetime, Driver>
            for vmi_core::VmiOsState<#vmi_lifetime, Driver, #struct_type>
            #where_clause
        {
            #(#os_context_fns)*
        }
    };

    proc_macro::TokenStream::from(expanded)
}
