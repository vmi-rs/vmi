macro_rules! impl_ops {
    ($name:ident, $type:ty, $doc:expr) => {
        #[doc = concat!("A ", $doc, ".")]
        #[derive(
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

        impl $name {
            #[doc = concat!("Creates a new instance of the `", stringify!($name), "` type.")]
            pub const fn new(value: $type) -> Self {
                Self(value)
            }
        }

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

        impl ::std::ops::Add<$type> for $name {
            type Output = $name;

            fn add(self, rhs: $type) -> Self::Output {
                Self(self.0 + rhs)
            }
        }

        impl ::std::ops::Add<$name> for $name {
            type Output = $name;

            fn add(self, rhs: $name) -> Self::Output {
                Self(self.0 + rhs.0)
            }
        }

        impl ::std::ops::AddAssign<$type> for $name {
            fn add_assign(&mut self, rhs: $type) {
                self.0 += rhs;
            }
        }

        impl ::std::ops::AddAssign<$name> for $name {
            fn add_assign(&mut self, rhs: $name) {
                self.0 += rhs.0;
            }
        }

        impl ::std::ops::Sub<$type> for $name {
            type Output = $name;

            fn sub(self, rhs: $type) -> Self::Output {
                Self(self.0 - rhs)
            }
        }

        impl ::std::ops::Sub<$name> for $name {
            type Output = $name;

            fn sub(self, rhs: $name) -> Self::Output {
                Self(self.0 - rhs.0)
            }
        }

        impl ::std::ops::SubAssign<$type> for $name {
            fn sub_assign(&mut self, rhs: $type) {
                self.0 -= rhs;
            }
        }

        impl ::std::ops::SubAssign<$name> for $name {
            fn sub_assign(&mut self, rhs: $name) {
                self.0 -= rhs.0;
            }
        }

        impl ::std::ops::Mul<$type> for $name {
            type Output = $name;

            fn mul(self, rhs: $type) -> Self::Output {
                Self(self.0 * rhs)
            }
        }

        impl ::std::ops::Mul<$name> for $name {
            type Output = $name;

            fn mul(self, rhs: $name) -> Self::Output {
                Self(self.0 * rhs.0)
            }
        }

        impl ::std::ops::MulAssign<$type> for $name {
            fn mul_assign(&mut self, rhs: $type) {
                self.0 *= rhs;
            }
        }

        impl ::std::ops::MulAssign<$name> for $name {
            fn mul_assign(&mut self, rhs: $name) {
                self.0 *= rhs.0;
            }
        }

        impl ::std::ops::Div<$type> for $name {
            type Output = $name;

            fn div(self, rhs: $type) -> Self::Output {
                Self(self.0 / rhs)
            }
        }

        impl ::std::ops::Div<$name> for $name {
            type Output = $name;

            fn div(self, rhs: $name) -> Self::Output {
                Self(self.0 / rhs.0)
            }
        }

        impl ::std::ops::DivAssign<$type> for $name {
            fn div_assign(&mut self, rhs: $type) {
                self.0 /= rhs;
            }
        }

        impl ::std::ops::DivAssign<$name> for $name {
            fn div_assign(&mut self, rhs: $name) {
                self.0 /= rhs.0;
            }
        }

        impl ::std::ops::BitAnd<$type> for $name {
            type Output = $name;

            fn bitand(self, rhs: $type) -> Self::Output {
                Self(self.0 & rhs)
            }
        }

        impl ::std::ops::BitAndAssign<$type> for $name {
            fn bitand_assign(&mut self, rhs: $type) {
                self.0 &= rhs;
            }
        }

        impl ::std::ops::BitOr<$type> for $name {
            type Output = $name;

            fn bitor(self, rhs: $type) -> Self::Output {
                Self(self.0 | rhs)
            }
        }

        impl ::std::ops::BitOrAssign<$type> for $name {
            fn bitor_assign(&mut self, rhs: $type) {
                self.0 |= rhs;
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match ::std::mem::size_of::<$type>() {
                    1 => write!(f, "0x{:02x}", self.0),
                    2 => write!(f, "0x{:04x}", self.0),
                    4 => write!(f, "0x{:08x}", self.0),
                    8 => write!(f, "0x{:016x}", self.0),
                    _ => write!(f, "{}", self.0),
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match ::std::mem::size_of::<$type>() {
                    1 => write!(f, "0x{:02x}", self.0),
                    2 => write!(f, "0x{:04x}", self.0),
                    4 => write!(f, "0x{:08x}", self.0),
                    8 => write!(f, "0x{:016x}", self.0),
                    _ => write!(f, "{}", self.0),
                }
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

pub(crate) use impl_ops;
