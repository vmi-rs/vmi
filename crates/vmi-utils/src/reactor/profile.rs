use isr_core::Profile;

/// A [`Profile`] that may be owned or borrowed.
///
/// This is used to allow both owned and borrowed profiles to be accessed
/// uniformly through [`Deref`].
///
/// [`Deref`]: std::ops::Deref
pub enum ProfileRef<'a> {
    /// Profile owned by the wrapper.
    Owned(Profile<'a>),

    /// Profile borrowed for `'a`.
    Borrowed(&'a Profile<'a>),
}

impl<'a> From<Profile<'a>> for ProfileRef<'a> {
    fn from(value: Profile<'a>) -> Self {
        Self::Owned(value)
    }
}

impl<'a> From<&'a Profile<'a>> for ProfileRef<'a> {
    fn from(value: &'a Profile<'a>) -> Self {
        Self::Borrowed(value)
    }
}

impl<'a> std::ops::Deref for ProfileRef<'a> {
    type Target = Profile<'a>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(profile) => profile,
            Self::Borrowed(profile) => profile,
        }
    }
}
