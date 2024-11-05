/// `DR0` debug register.
///
/// Contains the linear address of the first local breakpoint.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Dr0(pub u64);

impl From<u64> for Dr0 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Dr0> for u64 {
    fn from(value: Dr0) -> Self {
        value.0
    }
}
