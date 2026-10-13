use syn::{
    AngleBracketedGenericArguments, CapturedParam, FnArg, GenericArgument, GenericParam, Ident,
    Lifetime, Path, PathArguments, PreciseCapture, ReturnType, Signature, TraitBound, Type,
    TypeImplTrait, TypeParamBound, TypePath, TypeReference, WherePredicate,
};

/// Rewrites every occurrence of `Self` in `sig` to `Os`, both as a path
/// segment (for example `Self::Module<'a>` -> `Os::Module<'a>`) and as an
/// identifier in `use<...>` precise-capture bounds.
///
/// Walks typed arguments, generic-parameter bounds, where-clause
/// predicates, and the return type. The receiver (`self` / `&self`) is
/// left alone, since in the generated wrapper it refers to the wrapper
/// type, not to the OS.
///
/// Used when copying a trait method signature into an inherent-style
/// wrapper impl where `Self` would be an alias for the concrete wrapper
/// type and `Os` is the in-scope generic parameter carrying the original
/// trait type.
pub fn replace_self_with_os(sig: &mut Signature) {
    for input in &mut sig.inputs {
        if let FnArg::Typed(pat_type) = input {
            replace_in_type(&mut pat_type.ty);
        }
    }

    for param in &mut sig.generics.params {
        if let GenericParam::Type(type_param) = param {
            for bound in &mut type_param.bounds {
                replace_in_type_param_bound(bound);
            }
        }
    }

    if let Some(where_clause) = &mut sig.generics.where_clause {
        for predicate in &mut where_clause.predicates {
            if let WherePredicate::Type(predicate_type) = predicate {
                replace_in_type(&mut predicate_type.bounded_ty);

                for bound in &mut predicate_type.bounds {
                    replace_in_type_param_bound(bound);
                }
            }
        }
    }

    replace_in_return_type(&mut sig.output);
}

fn replace_in_return_type(return_type: &mut ReturnType) {
    match return_type {
        ReturnType::Type(_, ty) => replace_in_type(ty),
        ReturnType::Default => {}
    }
}

fn replace_in_path(path: &mut Path) {
    for segment in &mut path.segments {
        // TODO: Handle `PathArguments::Parenthesized`
        if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
            replace_in_angle_bracketed_generic_arguments(args);
        }
    }

    let segment = match path.segments.first_mut() {
        Some(segment) => segment,
        None => return,
    };

    if segment.ident != "Self" {
        return;
    }

    segment.ident = Ident::new("Os", segment.ident.span());
}

fn replace_in_angle_bracketed_generic_arguments(args: &mut AngleBracketedGenericArguments) {
    for arg in &mut args.args {
        match arg {
            GenericArgument::Lifetime(_) => {}
            GenericArgument::Type(ty) => replace_in_type(ty),
            GenericArgument::Const(_) => {}
            GenericArgument::AssocType(assoc_type) => {
                if let Some(generics) = &mut assoc_type.generics {
                    replace_in_angle_bracketed_generic_arguments(generics);
                }
                replace_in_type(&mut assoc_type.ty);
            }
            GenericArgument::AssocConst(_) => {}
            GenericArgument::Constraint(constraint) => {
                if let Some(generics) = &mut constraint.generics {
                    replace_in_angle_bracketed_generic_arguments(generics);
                }

                for bound in &mut constraint.bounds {
                    replace_in_type_param_bound(bound);
                }
            }
            _ => panic!("unexpected generic argument"),
        }
    }
}

fn replace_in_type(ty: &mut Type) {
    match ty {
        Type::Reference(ty_ref) => replace_in_type_reference(ty_ref),
        Type::ImplTrait(impl_trait) => replace_in_type_impl_trait(impl_trait),
        Type::Path(type_path) => replace_in_type_path(type_path),
        _ => {}
    };
}

fn replace_in_type_param_bound(bound: &mut TypeParamBound) {
    match bound {
        TypeParamBound::Trait(trait_bound) => replace_in_trait_bound(trait_bound),
        TypeParamBound::Lifetime(_) => {}
        TypeParamBound::PreciseCapture(capture) => replace_in_precise_capture(capture),
        _ => panic!("unexpected type parameter bound"),
    }
}

fn replace_in_type_reference(ty_ref: &mut TypeReference) {
    replace_in_type(&mut ty_ref.elem);
}

fn replace_in_type_path(type_path: &mut TypePath) {
    replace_in_path(&mut type_path.path);
}

fn replace_in_trait_bound(trait_bound: &mut TraitBound) {
    replace_in_path(&mut trait_bound.path);
}

fn replace_in_type_impl_trait(impl_trait: &mut TypeImplTrait) {
    for bound in &mut impl_trait.bounds {
        match bound {
            TypeParamBound::Trait(trait_bound) => replace_in_trait_bound(trait_bound),
            TypeParamBound::PreciseCapture(capture) => replace_in_precise_capture(capture),
            _ => {}
        }
    }
}

fn replace_in_precise_capture(capture: &mut PreciseCapture) {
    for param in &mut capture.params {
        if let CapturedParam::Ident(ident) = param
            && *ident == "Self"
        {
            *ident = Ident::new("Os", ident.span());
        }
    }
}

/// Replaces every elided lifetime in `return_type` with `lifetime`. That
/// covers a reference without a lifetime (`&T`) and `'_` in generic arguments
/// and bounds, but not `use<...>` precise-capture bounds.
///
/// A source method takes `VmiState<'_, Self>` as its only argument with a
/// lifetime, so an elided lifetime in its return type is the state's lifetime.
/// The generated wrapper method takes `&self`, where the same elision would
/// tie the result to the borrow of the wrapper. A caller then could not keep
/// a result taken from a temporary wrapper, such as `vmi.os().symbols()`, in a
/// variable. Naming the state's lifetime keeps the meaning of the source
/// signature.
pub fn replace_elided_lifetimes(return_type: &mut ReturnType, lifetime: &Lifetime) {
    match return_type {
        ReturnType::Type(_, ty) => replace_elided_in_type(ty, lifetime),
        ReturnType::Default => {}
    }
}

fn replace_elided_in_type(ty: &mut Type, lifetime: &Lifetime) {
    match ty {
        Type::Reference(ty_ref) => {
            match &mut ty_ref.lifetime {
                Some(ty_lifetime) => replace_elided_lifetime(ty_lifetime, lifetime),
                None => ty_ref.lifetime = Some(lifetime.clone()),
            }

            replace_elided_in_type(&mut ty_ref.elem, lifetime);
        }
        Type::ImplTrait(impl_trait) => {
            for bound in &mut impl_trait.bounds {
                replace_elided_in_type_param_bound(bound, lifetime);
            }
        }
        Type::Path(type_path) => replace_elided_in_path(&mut type_path.path, lifetime),
        _ => {}
    }
}

fn replace_elided_in_type_param_bound(bound: &mut TypeParamBound, lifetime: &Lifetime) {
    match bound {
        TypeParamBound::Trait(trait_bound) => {
            replace_elided_in_path(&mut trait_bound.path, lifetime)
        }
        TypeParamBound::Lifetime(bound_lifetime) => {
            replace_elided_lifetime(bound_lifetime, lifetime)
        }
        _ => {}
    }
}

fn replace_elided_in_path(path: &mut Path, lifetime: &Lifetime) {
    for segment in &mut path.segments {
        let args = match &mut segment.arguments {
            PathArguments::AngleBracketed(args) => args,
            _ => continue,
        };

        for arg in &mut args.args {
            match arg {
                GenericArgument::Lifetime(arg_lifetime) => {
                    replace_elided_lifetime(arg_lifetime, lifetime)
                }
                GenericArgument::Type(ty) => replace_elided_in_type(ty, lifetime),
                GenericArgument::AssocType(assoc_type) => {
                    replace_elided_in_type(&mut assoc_type.ty, lifetime)
                }
                _ => {}
            }
        }
    }
}

fn replace_elided_lifetime(target: &mut Lifetime, lifetime: &Lifetime) {
    if target.ident == "_" {
        *target = lifetime.clone();
    }
}

/// Appends the given parameters to every `use<...>` precise-capture bound
/// found in `return_type`. Used when copying a method signature into a
/// generated trait or trait impl that introduces additional in-scope
/// generics beyond the source method (for example the trait's implicit
/// `Self` and the macro-introduced `'__vmi` lifetime), all of which must
/// be listed in `use<...>` on pain of E0796 / E0797.
///
/// No-op on return types that don't contain an `impl Trait` with an
/// existing `use<...>` bound.
pub fn extend_precise_captures(return_type: &mut ReturnType, extras: &[CapturedParam]) {
    if extras.is_empty() {
        return;
    }

    extend_in_return_type(return_type, extras);
}

fn extend_in_return_type(return_type: &mut ReturnType, extras: &[CapturedParam]) {
    match return_type {
        ReturnType::Type(_, ty) => extend_in_type(ty, extras),
        ReturnType::Default => {}
    }
}

fn extend_in_type(ty: &mut Type, extras: &[CapturedParam]) {
    match ty {
        Type::Reference(ty_ref) => extend_in_type_reference(ty_ref, extras),
        Type::ImplTrait(impl_trait) => extend_in_type_impl_trait(impl_trait, extras),
        Type::Path(type_path) => extend_in_type_path(type_path, extras),
        _ => {}
    }
}

fn extend_in_type_reference(ty_ref: &mut TypeReference, extras: &[CapturedParam]) {
    extend_in_type(&mut ty_ref.elem, extras);
}

fn extend_in_type_impl_trait(impl_trait: &mut TypeImplTrait, extras: &[CapturedParam]) {
    for bound in &mut impl_trait.bounds {
        if let TypeParamBound::PreciseCapture(capture) = bound {
            extend_precise_capture(capture, extras);
        }
    }
}

fn extend_in_type_path(type_path: &mut TypePath, extras: &[CapturedParam]) {
    extend_in_path(&mut type_path.path, extras);
}

fn extend_in_path(path: &mut Path, extras: &[CapturedParam]) {
    for segment in &mut path.segments {
        if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
            extend_in_angle_bracketed_generic_arguments(args, extras);
        }
    }
}

fn extend_in_angle_bracketed_generic_arguments(
    args: &mut AngleBracketedGenericArguments,
    extras: &[CapturedParam],
) {
    for arg in &mut args.args {
        if let GenericArgument::Type(ty) = arg {
            extend_in_type(ty, extras);
        }
    }
}

fn extend_precise_capture(capture: &mut PreciseCapture, extras: &[CapturedParam]) {
    for extra in extras {
        capture.params.push(extra.clone());
    }
}
