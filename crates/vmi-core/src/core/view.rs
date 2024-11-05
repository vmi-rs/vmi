/// A physical memory view identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct View(pub u16);

impl std::fmt::Display for View {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
