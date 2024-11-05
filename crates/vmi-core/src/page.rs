use std::{ops::Deref, rc::Rc};

/// A page of memory that has been mapped from the guest virtual machine.
#[derive(Clone)]
pub struct VmiMappedPage(Rc<Box<dyn Deref<Target = [u8]>>>);

impl VmiMappedPage {
    /// Creates a new mapped page.
    pub fn new<T>(inner: T) -> Self
    where
        T: Deref<Target = [u8]> + 'static,
    {
        Self(Rc::new(Box::new(inner)))
    }
}

impl Deref for VmiMappedPage {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for VmiMappedPage {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}
