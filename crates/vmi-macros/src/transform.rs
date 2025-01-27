use syn::{
    AngleBracketedGenericArguments, GenericArgument, Ident, Path, PathArguments, ReturnType,
    TraitBound, Type, TypeImplTrait, TypeParamBound, TypePath, TypeReference,
};

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
            _ => {}
        }
    }
}
