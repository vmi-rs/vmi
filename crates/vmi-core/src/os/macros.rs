macro_rules! impl_ops {
    (
        $(#[$meta:meta])*
        $name:ident, $type:ty
    ) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Default,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        pub struct $name(pub $type);

        impl From<$type> for $name {
            fn from(value: $type) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $type {
            fn from(value: $name) -> $type {
                value.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl ::std::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl ::std::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::UpperHex::fmt(&self.0, f)
            }
        }
    };
}

macro_rules! impl_predicate {
    (
        $(#[$outer_meta:meta])*
        $vis:vis trait $name:ident & impl for &str {
            $(#[$inner_meta:meta])*
            fn matches(&$self:ident, $value:ident: &Os::$subtype:ident<'_>) -> Result<bool, VmiError> {
                $($rest:tt)*
            }
        }

        $(
            #[any]
            $any_vis:vis struct $any_name:ident;
        )?
    ) => {
        $(#[$outer_meta])*
        $vis trait $name<Os>
        where
            Os: VmiOs,
        {
            #[doc = concat!("Returns `Ok(true)` if `", stringify!($value), "` matches the predicate.")]
            fn matches(&self, $value: &Os::$subtype<'_>) -> Result<bool, VmiError>;
        }

        impl<Os> $name<Os> for &str
        where
            Os: VmiOs,
        {
            $(#[$inner_meta])*
            fn matches(&$self, $value: &Os::$subtype<'_>) -> Result<bool, VmiError> {
                $($rest)*
            }
        }

        impl<Os> $name<Os> for &String
        where
            Os: VmiOs,
        {
            $(#[$inner_meta])*
            fn matches(&self, $value: &Os::$subtype<'_>) -> Result<bool, VmiError> {
                $name::<Os>::matches(&self.as_str(), $value)
            }
        }

        impl<Os, F> $name<Os> for F
        where
            Os: VmiOs,
            F: Fn(&Os::$subtype<'_>) -> Result<bool, VmiError>,
        {
            fn matches(&self, $value: &Os::$subtype<'_>) -> Result<bool, VmiError> {
                self($value)
            }
        }

        $(
            #[doc = concat!(
                "A [`", stringify!($name), "`] that matches every `",
                stringify!($subtype), "`."
            )]
            $any_vis struct $any_name;

            impl<Os> $name<Os> for $any_name
            where
                Os: VmiOs,
            {
                fn matches(&self, _: &Os::$subtype<'_>) -> Result<bool, VmiError> {
                    Ok(true)
                }
            }
        )?
    };
}

pub(crate) use impl_ops;
pub(crate) use impl_predicate;
