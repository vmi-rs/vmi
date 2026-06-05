use std::{ops::Deref, rc::Rc};

/// A reference-counted mapped guest page, optionally narrowed to a sub-window
/// of the backing mapping.
#[derive(Clone)]
pub struct VmiMappedPage {
    inner: Rc<Box<dyn Deref<Target = [u8]>>>,
    offset: usize,
    len: usize,
}

impl VmiMappedPage {
    /// Wraps a mapping, exposing all of it.
    pub fn new<T>(inner: T) -> Self
    where
        T: Deref<Target = [u8]> + 'static,
    {
        let boxed: Box<dyn Deref<Target = [u8]>> = Box::new(inner);
        let len = boxed.len();
        Self {
            inner: Rc::new(boxed),
            offset: 0,
            len,
        }
    }

    /// Returns a cheap clone narrowed to `[offset, offset + len)` of the current
    /// window. Used to present a guest page inside a larger host-page mapping.
    pub fn window(&self, offset: usize, len: usize) -> Self {
        debug_assert!(offset + len <= self.len);
        Self {
            inner: self.inner.clone(),
            offset: self.offset + offset,
            len,
        }
    }
}

impl Deref for VmiMappedPage {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner[self.offset..self.offset + self.len]
    }
}

impl AsRef<[u8]> for VmiMappedPage {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
