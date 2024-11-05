use vmi_core::Va;

/// A function argument that can be either a direct value or a reference to data.
pub struct Argument {
    /// The argument data - either a direct value or reference to bytes.
    pub(super) data: ArgumentData,

    /// Required memory alignment for the argument.
    pub(super) alignment: u64,
}

/// The data portion of a function argument.
pub enum ArgumentData {
    /// A direct integer value.
    Value(u64),

    /// A reference to bytes in memory.
    Reference(Vec<u8>),
}

macro_rules! impl_from_num {
    ($($t:ty),*) => {
        $(
            impl From<$t> for Argument {
                fn from(value: $t) -> Self {
                    Self::from(value as u64)
                }
            }

            impl From<&$t> for Argument {
                fn from(value: &$t) -> Self {
                    Self::from(*value)
                }
            }
        )*
    };
}

impl_from_num!(u8, u16, u32, usize, i8, i16, i32, i64, isize);

impl From<u64> for Argument {
    fn from(value: u64) -> Self {
        Self {
            data: ArgumentData::Value(value),
            alignment: 8,
        }
    }
}

impl From<&u64> for Argument {
    fn from(value: &u64) -> Self {
        Self::from(*value)
    }
}

impl From<Va> for Argument {
    fn from(value: Va) -> Self {
        Self::from(value.0)
    }
}

impl From<&Va> for Argument {
    fn from(value: &Va) -> Self {
        Self::from(*value)
    }
}

impl From<&str> for Argument {
    fn from(value: &str) -> Self {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);

        Self {
            data: ArgumentData::Reference(bytes),
            alignment: 32,
        }
    }
}

impl From<&&str> for Argument {
    fn from(value: &&str) -> Self {
        Self::from(*value)
    }
}

impl From<&String> for Argument {
    fn from(value: &String) -> Self {
        Self::from(value.as_str())
    }
}

impl From<&&String> for Argument {
    fn from(value: &&String) -> Self {
        Self::from(*value)
    }
}

impl From<&[u8]> for Argument {
    fn from(value: &[u8]) -> Self {
        Self {
            data: ArgumentData::Reference(value.to_vec()),
            alignment: 16,
        }
    }
}

impl From<&&[u8]> for Argument {
    fn from(value: &&[u8]) -> Self {
        Self::from(*value)
    }
}

impl From<&Vec<u8>> for Argument {
    fn from(value: &Vec<u8>) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<&&Vec<u8>> for Argument {
    fn from(value: &&Vec<u8>) -> Self {
        Self::from(*value)
    }
}
