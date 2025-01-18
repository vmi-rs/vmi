use syn::{
    AngleBracketedGenericArguments, FnArg, GenericArgument, GenericParam, Generics, Ident,
    Lifetime, Path, PathArguments, Receiver, ReturnType, TraitBound, Type, TypeImplTrait,
    TypeParamBound, TypePath, TypeReference,
};

pub fn remove_in_generics(generics: &mut Generics, lifetime: &str) {
    generics.params = generics
        .params
        .iter()
        .filter(|&param| match param {
            GenericParam::Lifetime(lt) => lt.lifetime.ident != lifetime,
            _ => true,
        })
        .cloned()
        .collect();
}

/// Replace the lifetime `'from` with `'to` in the given lifetime.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// 'from
/// ```
///
/// After:
///
/// ```rust,ignore
/// 'to
/// ```
pub fn replace_in_lifetime(lifetime: &mut Lifetime, from: &str, to: &str) {
    if lifetime.ident != from {
        return;
    }

    lifetime.ident = Ident::new(to, lifetime.ident.span());
}

/// Replace the lifetime `'from` with `'to` in the given trait bound.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// 'from: 'a
/// 'a: 'from
/// T: 'from
/// ```
///
/// After:
///
/// ```rust,ignore
/// 'to: 'a
/// 'a: 'to
/// T: 'to
/// ```
pub fn replace_in_trait_bound(trait_bound: &mut TraitBound, from: &str, to: &str) {
    if let Some(lifetimes) = &mut trait_bound.lifetimes {
        for param in lifetimes.lifetimes.iter_mut() {
            replace_in_generic_param(param, from, to);
        }
    }

    replace_in_path(&mut trait_bound.path, from, to);
}

/// Replace the lifetime `'from` with `'to` in the given path.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// Foo<'from, T>
/// ```
///
/// After:
///
/// ```rust,ignore
/// Foo<'to, T>
/// ```
pub fn replace_in_path(path: &mut Path, from: &str, to: &str) {
    for segment in &mut path.segments {
        // TODO: Handle `PathArguments::Parenthesized`
        if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
            replace_in_angle_bracketed_generic_arguments(args, from, to);
        }
    }
}

/// Replace the lifetime `'from` with `'to` in the given angle-bracketed generic arguments.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// <'from, T>
/// <Output = &'from T>
/// ```
///
/// After:
///
/// ```rust,ignore
/// <'to, T>
/// <Output = &'to T>
/// ```
pub fn replace_in_angle_bracketed_generic_arguments(
    args: &mut AngleBracketedGenericArguments,
    from: &str,
    to: &str,
) {
    for arg in &mut args.args {
        match arg {
            GenericArgument::Lifetime(lifetime) => {
                replace_in_lifetime(lifetime, from, to);
            }
            GenericArgument::Type(ty) => replace_in_type(ty, from, to),
            GenericArgument::Const(_) => {}
            GenericArgument::AssocType(assoc_type) => {
                if let Some(generics) = &mut assoc_type.generics {
                    replace_in_angle_bracketed_generic_arguments(generics, from, to);
                }
                replace_in_type(&mut assoc_type.ty, from, to);
            }
            GenericArgument::AssocConst(_) => {}
            GenericArgument::Constraint(constraint) => {
                if let Some(generics) = &mut constraint.generics {
                    replace_in_angle_bracketed_generic_arguments(generics, from, to);
                }

                for bound in &mut constraint.bounds {
                    replace_in_type_param_bound(bound, from, to);
                }
            }
            _ => panic!("unexpected generic argument"),
        }
    }
}

/// Replace the lifetime `'from` with `'to` in the given generic parameter.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// 'a: 'from
/// 'from: 'b
/// T: 'from
/// ```
///
/// After:
///
/// ```rust,ignore
/// 'a: 'to
/// 'to: 'b
/// T: 'to
/// ```
pub fn replace_in_generic_param(param: &mut GenericParam, from: &str, to: &str) {
    match param {
        GenericParam::Lifetime(lifetime) => {
            replace_in_lifetime(&mut lifetime.lifetime, from, to);

            for bound in &mut lifetime.bounds {
                replace_in_lifetime(bound, from, to);
            }
        }
        GenericParam::Type(ty) => {
            for bound in &mut ty.bounds {
                replace_in_type_param_bound(bound, from, to);
            }

            if let Some(default) = &mut ty.default {
                replace_in_type(default, from, to);
            }
        }
        _ => {}
    }
}

/// Replace the lifetime `'from` with `'to` in the given type parameter bound.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
///
pub fn replace_in_type_param_bound(bound: &mut TypeParamBound, from: &str, to: &str) {
    match bound {
        TypeParamBound::Trait(trait_bound) => {
            if let Some(lifetimes) = &mut trait_bound.lifetimes {
                for param in lifetimes.lifetimes.iter_mut() {
                    replace_in_generic_param(param, from, to);
                }
            }
        }
        TypeParamBound::Lifetime(lifetime) => replace_in_lifetime(lifetime, from, to),
        _ => panic!("unexpected type parameter bound"),
    }
}

/// Replace the lifetime `'from` with `'to` in the given type path.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// Foo<'from, T>
/// ```
///
/// After:
///
/// ```rust,ignore
/// Foo<'to, T>
/// ```
pub fn replace_in_type_path(type_path: &mut TypePath, from: &str, to: &str) {
    replace_in_path(&mut type_path.path, from, to);
}

/// Replace the lifetime `'from` with `'to` in the given type reference.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// &'from T<'from>
/// ```
///
/// After:
///
/// ```rust,ignore
/// &'to T<'to>
/// ```
pub fn replace_in_type_reference(ty_ref: &mut TypeReference, from: &str, to: &str) {
    replace_in_type(&mut ty_ref.elem, from, to);

    if let Some(lifetime) = &mut ty_ref.lifetime {
        replace_in_lifetime(lifetime, from, to);
    }
}

/// Replace the lifetime `'from` with `'to` in the given function argument.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// arg: &'from T
/// ```
///
/// After:
///
/// ```rust,ignore
/// arg: &'to T
/// ```
pub fn replace_in_fn_arg(arg: &mut FnArg, from: &str, to: &str) {
    match arg {
        FnArg::Receiver(receiver) => replace_in_receiver(receiver, from, to),
        FnArg::Typed(pat_type) => replace_in_type(&mut pat_type.ty, from, to),
    };
}

/// Replace the lifetime `'from` with `'to` in the given type impl trait.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// impl Trait + 'from
/// impl Trait<Output = &'from T>
/// ```
///
/// After:
///
/// ```rust,ignore
/// impl Trait + 'to
/// impl Trait<Output = &'to T>
/// ```
pub fn replace_in_type_impl_trait(impl_trait: &mut TypeImplTrait, from: &str, to: &str) {
    for bound in &mut impl_trait.bounds {
        match bound {
            TypeParamBound::Lifetime(lifetime) => replace_in_lifetime(lifetime, from, to),
            TypeParamBound::Trait(trait_bound) => replace_in_trait_bound(trait_bound, from, to),
            _ => {}
        }
    }
}

/// Replace the lifetime `'from` with `'to` in the given receiver (self).
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// &'from self
/// ```
///
/// After:
///
/// ```rust,ignore
/// &'to self
/// ```
pub fn replace_in_receiver(receiver: &mut Receiver, from: &str, to: &str) {
    if let Some(reference) = &mut receiver.reference {
        if let Some(lifetime) = &mut reference.1 {
            replace_in_lifetime(lifetime, from, to);
        }
    }
}

/// Replace the lifetime `'from` with `'to` in the given type.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// Foo<'from, T>
/// impl Trait + 'from
/// // impl Trait<Output = &'from T> // TODO: Handle this case
/// ```
///
/// After:
///
/// ```rust,ignore
/// Foo<'to, T>
/// impl Trait + 'to
/// // impl Trait<Output = &'to T> // TODO: Handle this case
/// ```
pub fn replace_in_type(ty: &mut Type, from: &str, to: &str) {
    match ty {
        Type::Reference(ty_ref) => replace_in_type_reference(ty_ref, from, to),
        Type::ImplTrait(impl_trait) => replace_in_type_impl_trait(impl_trait, from, to),
        Type::Path(type_path) => replace_in_type_path(type_path, from, to),
        _ => {}
    };
}

/// Replace the lifetime `'from` with `'to` in the given return type.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// -> &'from T
/// -> Result<&'from T, VmiError>
/// -> Result<T<'from>, VmiError>
/// -> impl Trait + 'from
/// -> Result<impl Trait + 'from, VmiError>
/// ```
///
/// After:
///
/// ```rust,ignore
/// -> &'to T
/// -> Result<&'to T, VmiError>
/// -> Result<T<'to>, VmiError>
/// -> impl Trait + 'to
/// -> Result<impl Trait + 'to, VmiError>
/// ```
pub fn replace_in_return_type(return_type: &mut ReturnType, from: &str, to: &str) {
    match return_type {
        ReturnType::Type(_, ty) => replace_in_type(ty, from, to),
        ReturnType::Default => {}
    }
}
