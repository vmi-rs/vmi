macro_rules! impl_ops {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($inner_vis:vis $inner:ty);
    ) => {
        $(#[$meta])*
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
        $vis struct $name($inner_vis $inner);

        impl $name {
            #[doc = concat!("Creates a new instance of the `", stringify!($name), "` type.")]
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> $inner {
                value.0
            }
        }

        impl ::std::ops::Add<$inner> for $name {
            type Output = $name;

            fn add(self, rhs: $inner) -> Self::Output {
                Self(self.0 + rhs)
            }
        }

        impl ::std::ops::Add<$name> for $name {
            type Output = $name;

            fn add(self, rhs: $name) -> Self::Output {
                Self(self.0 + rhs.0)
            }
        }

        impl ::std::ops::AddAssign<$inner> for $name {
            fn add_assign(&mut self, rhs: $inner) {
                self.0 += rhs;
            }
        }

        impl ::std::ops::AddAssign<$name> for $name {
            fn add_assign(&mut self, rhs: $name) {
                self.0 += rhs.0;
            }
        }

        impl ::std::ops::Sub<$inner> for $name {
            type Output = $name;

            fn sub(self, rhs: $inner) -> Self::Output {
                Self(self.0 - rhs)
            }
        }

        impl ::std::ops::Sub<$name> for $name {
            type Output = $name;

            fn sub(self, rhs: $name) -> Self::Output {
                Self(self.0 - rhs.0)
            }
        }

        impl ::std::ops::SubAssign<$inner> for $name {
            fn sub_assign(&mut self, rhs: $inner) {
                self.0 -= rhs;
            }
        }

        impl ::std::ops::SubAssign<$name> for $name {
            fn sub_assign(&mut self, rhs: $name) {
                self.0 -= rhs.0;
            }
        }

        impl ::std::ops::Mul<$inner> for $name {
            type Output = $name;

            fn mul(self, rhs: $inner) -> Self::Output {
                Self(self.0 * rhs)
            }
        }

        impl ::std::ops::Mul<$name> for $name {
            type Output = $name;

            fn mul(self, rhs: $name) -> Self::Output {
                Self(self.0 * rhs.0)
            }
        }

        impl ::std::ops::MulAssign<$inner> for $name {
            fn mul_assign(&mut self, rhs: $inner) {
                self.0 *= rhs;
            }
        }

        impl ::std::ops::MulAssign<$name> for $name {
            fn mul_assign(&mut self, rhs: $name) {
                self.0 *= rhs.0;
            }
        }

        impl ::std::ops::Div<$inner> for $name {
            type Output = $name;

            fn div(self, rhs: $inner) -> Self::Output {
                Self(self.0 / rhs)
            }
        }

        impl ::std::ops::Div<$name> for $name {
            type Output = $name;

            fn div(self, rhs: $name) -> Self::Output {
                Self(self.0 / rhs.0)
            }
        }

        impl ::std::ops::DivAssign<$inner> for $name {
            fn div_assign(&mut self, rhs: $inner) {
                self.0 /= rhs;
            }
        }

        impl ::std::ops::DivAssign<$name> for $name {
            fn div_assign(&mut self, rhs: $name) {
                self.0 /= rhs.0;
            }
        }

        impl ::std::ops::BitAnd<$inner> for $name {
            type Output = $name;

            fn bitand(self, rhs: $inner) -> Self::Output {
                Self(self.0 & rhs)
            }
        }

        impl ::std::ops::BitAndAssign<$inner> for $name {
            fn bitand_assign(&mut self, rhs: $inner) {
                self.0 &= rhs;
            }
        }

        impl ::std::ops::BitOr<$inner> for $name {
            type Output = $name;

            fn bitor(self, rhs: $inner) -> Self::Output {
                Self(self.0 | rhs)
            }
        }

        impl ::std::ops::BitOrAssign<$inner> for $name {
            fn bitor_assign(&mut self, rhs: $inner) {
                self.0 |= rhs;
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match ::std::mem::size_of::<$inner>() {
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
                match ::std::mem::size_of::<$inner>() {
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
