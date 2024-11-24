use syn::{GenericArgument, PathArguments, ReturnType, Type};

/// Transform the return type from `Result<T, VmiError>` to
/// `Result<Option<T>, VmiError>`.
///
/// # Example
///
/// Before:
///
/// ```rust,ignore
/// -> Result<T, VmiError>
/// -> Result<impl Trait, VmiError>
/// -> Result<impl Trait<T> + 'a, VmiError>
/// ```
///
/// After:
///
/// ```rust,ignore
/// -> Result<Option<T>, VmiError>
/// -> Result<Option<impl Trait>, VmiError>
/// -> Result<Option<impl Trait<T> + 'a>, VmiError>
/// ```
pub fn result_to_result_option(return_type: &ReturnType) -> Option<ReturnType> {
    let ty = match &return_type {
        ReturnType::Type(_, ty) => ty,
        ReturnType::Default => return None,
    };

    let type_path = match &**ty {
        Type::Path(type_path) => type_path,
        _ => return None,
    };

    let segment = type_path.path.segments.last()?;

    if segment.ident != "Result" {
        return None;
    }

    let args = match &segment.arguments {
        PathArguments::AngleBracketed(args) => args,
        _ => return None,
    };

    if args.args.len() != 2 {
        return None;
    }

    let arg_type = match &args.args[0] {
        GenericArgument::Type(arg_type) => arg_type,
        _ => return None,
    };

    Some(syn::parse_quote! { -> Result<Option<#arg_type>, VmiError> })
}
