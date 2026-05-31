/// Crate-local trait for conversion between types.
pub trait FromExt<T>: Sized {
    fn from_ext(value: T) -> Self;
}
