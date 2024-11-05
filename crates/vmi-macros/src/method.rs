use quote::quote;
use syn::{
    Attribute, FnArg, ImplItem, ImplItemFn, PatType, Receiver, Signature, TraitItem, TraitItemFn,
    Type, TypeReference, Visibility,
};

/// Trait for items.
pub trait ItemExt {
    /// Returns the function item if the item is a function.
    fn as_fn(&self) -> Option<impl ItemFnExt>;
}

/// Trait for function items.
pub trait ItemFnExt {
    /// Returns the visibility of the function.
    fn vis(&self) -> Option<&Visibility>;

    /// Returns the documentation attributes of the function.
    fn doc(&self) -> impl Iterator<Item = &Attribute>;

    /// Returns the signature of the function.
    fn sig(&self) -> &Signature;
}

impl ItemExt for ImplItem {
    fn as_fn(&self) -> Option<impl ItemFnExt> {
        match self {
            ImplItem::Fn(item_fn) => Some(item_fn),
            _ => None,
        }
    }
}

impl ItemFnExt for &ImplItemFn {
    fn vis(&self) -> Option<&Visibility> {
        Some(&self.vis)
    }

    fn doc(&self) -> impl Iterator<Item = &Attribute> {
        self.attrs.iter().filter(|attr| attr.path().is_ident("doc"))
    }

    fn sig(&self) -> &Signature {
        &self.sig
    }
}

impl ItemExt for TraitItem {
    fn as_fn(&self) -> Option<impl ItemFnExt> {
        match self {
            TraitItem::Fn(item_fn) => Some(item_fn),
            _ => None,
        }
    }
}

impl ItemFnExt for &TraitItemFn {
    fn vis(&self) -> Option<&Visibility> {
        None
    }

    fn doc(&self) -> impl Iterator<Item = &Attribute> {
        self.attrs.iter().filter(|attr| attr.path().is_ident("doc"))
    }

    fn sig(&self) -> &Signature {
        &self.sig
    }
}

pub trait FnArgExt {
    fn receiver(&self) -> Option<&Receiver>;
    fn typed(&self) -> Option<&PatType>;
    fn contains(&self, needle: &str) -> bool;
}

pub trait TypeExt {
    fn reference(&self) -> Option<&TypeReference>;
    fn contains(&self, needle: &str) -> bool;
}

impl FnArgExt for FnArg {
    fn receiver(&self) -> Option<&Receiver> {
        match self {
            FnArg::Receiver(receiver) => Some(receiver),
            _ => None,
        }
    }

    fn typed(&self) -> Option<&PatType> {
        match self {
            FnArg::Typed(typed) => Some(typed),
            _ => None,
        }
    }

    fn contains(&self, needle: &str) -> bool {
        let PatType { ty, .. } = match self.typed() {
            Some(ty) => ty,
            None => return false,
        };

        let ty_ref = match ty.reference() {
            Some(ty_ref) => ty_ref,
            None => return false,
        };

        ty_ref.elem.contains(needle)
    }
}

impl TypeExt for Type {
    fn reference(&self) -> Option<&TypeReference> {
        match self {
            Type::Reference(reference) => Some(reference),
            _ => None,
        }
    }

    fn contains(&self, needle: &str) -> bool {
        quote! { #self }.to_string().contains(needle)
    }
}
/*

pub fn check_for_self(arg: Option<&FnArg>) -> Option<()> {
    match arg {
        Some(FnArg::Receiver(_)) => Some(()),
        // Skip if the first argument is not `self`.
        Some(FnArg::Typed(_)) => None,
        // Skip if there are no arguments.
        None => None,
    }
}

pub fn check_fn_arg_for_typed(arg: Option<&FnArg>) -> Option<&Type> {
    match arg {
        Some(FnArg::Typed(PatType { ty, .. })) => Some(ty),
        // Skip if the argument is not typed.
        _ => None,
    }
}

pub fn check_type_for_reference(ty: &Type) -> Option<&TypeReference> {
    match ty {
        // TODO: reject if the reference is mutable?
        Type::Reference(reference) => Some(reference),
        // Skip if the argument is not a reference.
        _ => None,
    }
}

pub fn check_type_for_substring(ty: &Type, needle: &str) -> Option<()> {
    if !quote! { #ty }.to_string().contains(needle) {
        // Skip if the argument is not of the expected type.
        return None;
    }

    Some(())
}

pub fn check_for_arg(arg: Option<&FnArg>, needle: &str) -> Option<()> {
    let ty = check_fn_arg_for_typed(arg)?;
    let ty_ref = check_type_for_reference(ty)?;
    check_type_for_substring(&ty_ref.elem, needle)
}
*/
