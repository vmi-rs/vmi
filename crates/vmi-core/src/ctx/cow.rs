pub enum VmiCow<'a, T: 'a> {
    /// Borrowed data.
    Borrowed(&'a T),

    /// Owned data.
    Owned(T),
}

impl<'a, T> AsRef<T> for VmiCow<'a, T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<'a, T> std::ops::Deref for VmiCow<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match *self {
            VmiCow::Borrowed(borrowed) => borrowed,
            VmiCow::Owned(ref owned) => owned,
        }
    }
}
