macro_rules! impl_base {
    ($name:ident, $type:ty) => {
        impl ::std::fmt::Debug for Hex<$type> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                impl_base_fmt(f, self.0)
            }
        }

        impl ::std::fmt::Display for Hex<$type> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                impl_base_fmt(f, self.0)
            }
        }
    };
}

fn impl_base_fmt<T>(f: &mut ::std::fmt::Formatter, data: T) -> ::std::fmt::Result
where
    T: Copy + ::std::fmt::LowerHex,
{
    match size_of::<T>() {
        1 => write!(f, "0x{:02x}", data),
        2 => write!(f, "0x{:04x}", data),
        4 => write!(f, "0x{:08x}", data),
        8 => write!(f, "0x{:016x}", data),
        _ => write!(f, "0x{:x}", data),
    }
}

macro_rules! impl_sequence {
    ($name:ident, $type:ty) => {
        impl ::std::fmt::Debug for Hex<$type> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                impl_base_sequence(f, &self.0)
            }
        }

        impl ::std::fmt::Display for Hex<$type> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                impl_base_sequence(f, &self.0)
            }
        }
    };
}

fn impl_base_sequence<T>(f: &mut ::std::fmt::Formatter, data: impl AsRef<[T]>) -> ::std::fmt::Result
where
    T: Copy + ::std::fmt::LowerHex,
{
    let data = data.as_ref();

    if data.is_empty() {
        return write!(f, "[]");
    }

    write!(f, "[")?;

    for (index, item) in data.iter().enumerate() {
        impl_base_fmt(f, *item)?;

        if index < data.len() - 1 {
            write!(f, ", ")?;
        }
    }

    write!(f, "]")
}

macro_rules! impl_ops {
    ($name:ident, $type:ty) => {
        impl_base!($name, $type);
        impl_sequence!($name, &Vec<$type>);
        impl_sequence!($name, &[$type]);
    };
}

/// A hexadecimal representation of a value.
///
/// This type is used to display values in hexadecimal format.
///
/// # Examples
///
/// ```
/// # use vmi_core::Hex;
/// assert_eq!(format!("{}", Hex(42u16)), "0x002a");
/// ```
pub struct Hex<T>(pub T);

impl_ops!(Hex, i8);
impl_ops!(Hex, i16);
impl_ops!(Hex, i32);
impl_ops!(Hex, i64);

impl_ops!(Hex, u8);
impl_ops!(Hex, u16);
impl_ops!(Hex, u32);
impl_ops!(Hex, u64);

impl_ops!(Hex, isize);
impl_ops!(Hex, usize);
