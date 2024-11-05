/// `DR3` debug register.
///
/// Contains the linear address of the fourth local breakpoint.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Dr3(pub u64);

impl From<u64> for Dr3 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Dr3> for u64 {
    fn from(value: Dr3) -> Self {
        value.0
    }
}
