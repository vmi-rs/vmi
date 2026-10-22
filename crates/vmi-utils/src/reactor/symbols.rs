use isr_core::Profile;
use vmi_core::os::VmiOsImageSymbol;

use super::ProfileRef;

/// A module's symbols, which the reactor searches for event names.
///
/// A profile gives symbol values that [`OsAdapter::profile_symbol_offset`]
/// turns into offsets from the module base. An address list gives each
/// symbol's runtime address, as the exports of an image do.
///
/// [`OsAdapter::profile_symbol_offset`]: super::OsAdapter::profile_symbol_offset
pub enum ModuleSymbols<'a> {
    /// An isr profile.
    Profile(ProfileRef<'a>),

    /// Symbols with their runtime addresses.
    Addresses(Vec<VmiOsImageSymbol>),
}

impl<'a> From<Profile<'a>> for ModuleSymbols<'a> {
    fn from(value: Profile<'a>) -> Self {
        Self::Profile(value.into())
    }
}

impl<'a> From<&'a Profile<'a>> for ModuleSymbols<'a> {
    fn from(value: &'a Profile<'a>) -> Self {
        Self::Profile(value.into())
    }
}

impl<'a> From<ProfileRef<'a>> for ModuleSymbols<'a> {
    fn from(value: ProfileRef<'a>) -> Self {
        Self::Profile(value)
    }
}

impl From<Vec<VmiOsImageSymbol>> for ModuleSymbols<'_> {
    fn from(value: Vec<VmiOsImageSymbol>) -> Self {
        Self::Addresses(value)
    }
}
