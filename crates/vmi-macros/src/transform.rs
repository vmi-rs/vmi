use syn::{
    AngleBracketedGenericArguments, CapturedParam, GenericArgument, Ident, Path, PathArguments,
    PreciseCapture, ReturnType, TraitBound, Type, TypeImplTrait, TypeParamBound, TypePath,
    TypeReference,
};

/// Rewrites every occurrence of `Self` in `return_type` to `Os`, both as a
/// path segment (for example `Self::Module<'a>` -> `Os::Module<'a>`) and
/// as an identifier in `use<...>` precise-capture bounds.
///
/// Used when copying a trait method signature into an inherent-style
/// wrapper impl where `Self` would be an alias for the concrete wrapper
/// type and `Os` is the in-scope generic parameter carrying the original
/// trait type.
pub fn replace_self_with_os(return_type: &mut ReturnType) {
    replace_in_return_type(return_type);
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
