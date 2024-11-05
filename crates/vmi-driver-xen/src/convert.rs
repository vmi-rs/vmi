/// Crate-local trait for conversion between types.
pub trait FromExt<T>: Sized {
    fn from_ext(value: T) -> Self;
}

/// Crate-local trait for conversion between types.
pub trait IntoExt<T>: Sized {
    fn into_ext(self) -> T;
}

impl<T, U> IntoExt<U> for T
where
    U: FromExt<T>,
{
    fn into_ext(self) -> U {
        U::from_ext(self)
    }
}

/// Crate-local trait for conversion between types.
pub trait TryFromExt<T>: Sized {
    type Error;

    fn try_from_ext(value: T) -> Result<Self, Self::Error>;
}
