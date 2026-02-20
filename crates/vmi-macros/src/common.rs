use proc_macro2::TokenStream;
use quote::quote;
use syn::{FnArg, GenericParam, Lifetime, Pat, PatType, Signature};

pub const VMI_LIFETIME: &str = "__vmi";

pub fn __vmi_lifetime() -> Lifetime {
    syn::parse_str::<Lifetime>(&format!("'{VMI_LIFETIME}")).unwrap()
}

pub fn build_args(sig: &Signature) -> Option<(Vec<TokenStream>, Vec<TokenStream>)> {
    let ident = &sig.ident;

    let mut args = Vec::new();
    let mut arg_names = Vec::new();

    // Skip the first two arguments (`self` and `Vmi*`).
    for arg in sig.inputs.iter().skip(1) {
        let PatType { pat, ty, .. } = match arg {
            FnArg::Typed(pat_type) => pat_type,
            _ => panic!("`{ident}`: argument is not typed, skipping"),
        };

        let pat_ident = match &**pat {
            Pat::Ident(pat_ident) => pat_ident,
            _ => return None,
        };

        args.push(quote! { #pat_ident: #ty });
        arg_names.push(quote! { #pat_ident });
    }

    Some((args, arg_names))
}

pub fn build_where_clause(sig: &Signature) -> Option<TokenStream> {
    let mut predicates = Vec::new();
    let vmi_lifetime = __vmi_lifetime();

    for param in &sig.generics.params {
        let lifetime = match param {
            GenericParam::Lifetime(lifetime) => lifetime,
            _ => continue,
        };

        let lifetime = &lifetime.lifetime;
        predicates.push(quote! { #vmi_lifetime: #lifetime });
    }

    if let Some(where_clause) = &sig.generics.where_clause {
        for predicate in &where_clause.predicates {
            predicates.push(quote! { #predicate });
        }
    }

    if predicates.is_empty() {
        return None;
    }

    Some(quote! { where #(#predicates),* })
}
