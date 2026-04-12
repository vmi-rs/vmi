use std::iter::FusedIterator;

use vmi_core::{Pa, Registers as _, Va, VmiError, VmiState, driver::VmiRead};

use crate::{
    WindowsOs, WindowsWow64Kind,
    arch::{ArchAdapter, StructLayout, StructLayout32, StructLayout64},
};

/// Field offsets for a `LIST_ENTRY` structure.
pub trait ListEntry<Layout>
where
    Layout: StructLayout,
{
    /// Offset of the `LIST_ENTRY::Flink` field.
    const OFFSET_FLINK: u64;

    /// Offset of the `LIST_ENTRY::Blink` field.
    const OFFSET_BLINK: u64;
}

/// `LIST_ENTRY` structure layout.
pub struct ListEntryLayout;

impl ListEntry<StructLayout32> for ListEntryLayout {
    const OFFSET_FLINK: u64 = 0x00;
    const OFFSET_BLINK: u64 = 0x04;
}

impl ListEntry<StructLayout64> for ListEntryLayout {
    const OFFSET_FLINK: u64 = 0x00;
    const OFFSET_BLINK: u64 = 0x08;
}

/// Iterator over a `LIST_ENTRY` chain with a compile-time pointer width.
///
/// Generic over [`StructLayout`], so it is monomorphized for either
/// 32-bit or 64-bit structures. Prefer [`ListEntryIterator`] when the
/// pointer width is not known at compile time.
pub struct ListEntryIteratorBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    ListEntryLayout: ListEntry<Layout>,
{
    /// VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the list head.
    list_head: Va,

    /// Offset to the containing structure.
    ///
    /// The offset is subtracted from the entry address to get the containing
    /// structure, similar to the `CONTAINING_RECORD` macro in the Windows
    /// kernel.
    offset: u64,

    /// The translation root.
    root: Pa,

    /// Current entry.
    current: Option<Va>,

    /// Whether the iterator has been initialized.
    initialized: bool,

    _marker: std::marker::PhantomData<Layout>,
}

impl<'a, Driver, Layout> ListEntryIteratorBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    ListEntryLayout: ListEntry<Layout>,
{
    /// Creates a new list entry iterator.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, list_head: Va, offset: u64, root: Pa) -> Self {
        Self {
            vmi,
            list_head,
            offset,
            root,
            current: None,
            initialized: false,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the next entry in the list.
    ///
    /// Corresponds to the `LIST_ENTRY.Flink` pointer.
    fn next_entry(&self, entry: Va) -> Result<Va, VmiError> {
        Layout::read_va(
            self.vmi,
            (
                entry + <ListEntryLayout as ListEntry<Layout>>::OFFSET_FLINK,
                self.root,
            ),
        )
    }

    /// Returns the previous entry in the list.
    ///
    /// Corresponds to the `LIST_ENTRY.Blink` pointer.
    fn previous_entry(&self, entry: Va) -> Result<Va, VmiError> {
        Layout::read_va(
            self.vmi,
            (
                entry + <ListEntryLayout as ListEntry<Layout>>::OFFSET_BLINK,
                self.root,
            ),
        )
    }

    /// Returns the first entry in the list.
    ///
    /// Returns `None` if the `list_head` is `NULL`.
    fn first_entry(&self) -> Result<Option<Va>, VmiError> {
        if self.list_head.is_null() {
            return Ok(None);
        }

        Ok(Some(self.next_entry(self.list_head)?))
    }

    /// Returns the last entry in the list.
    ///
    /// Returns `None` if the `list_head` is `NULL`.
    fn last_entry(&self) -> Result<Option<Va>, VmiError> {
        if self.list_head.is_null() {
            return Ok(None);
        }

        Ok(Some(self.previous_entry(self.list_head)?))
    }

    /// Walks to the next entry in the list.
    fn walk_next(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => {
                // If `self.current` is `None`, we need to initialize the iterator.
                //
                // However, if the iterator has already been initialized, we should
                // return `None` to prevent infinite iteration.
                if self.initialized {
                    return Ok(None);
                }

                self.initialized = true;

                match self.first_entry() {
                    Ok(Some(first)) => first,
                    Ok(None) => return Ok(None),
                    Err(err) => return Err(err),
                }
            }
        };

        if entry == self.list_head {
            return Ok(None);
        }

        match self.next_entry(entry) {
            Ok(next) => self.current = Some(next),
            Err(err) => {
                // Terminate iteration so that callers who `continue` on
                // errors do not spin forever on the same failing entry.
                self.current = None;
                return Err(err);
            }
        }

        Ok(Some(entry - self.offset))
    }

    /// Walks to the previous entry in the list.
    fn walk_next_back(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => {
                // If `self.current` is `None`, we need to initialize the iterator.
                //
                // However, if the iterator has already been initialized, we should
                // return `None` to prevent infinite iteration.
                if self.initialized {
                    return Ok(None);
                }

                self.initialized = true;

                match self.last_entry() {
                    Ok(Some(last)) => last,
                    Ok(None) => return Ok(None),
                    Err(err) => return Err(err),
                }
            }
        };

        if entry == self.list_head {
            return Ok(None);
        }

        match self.previous_entry(entry) {
            Ok(prev) => self.current = Some(prev),
            Err(err) => {
                self.current = None;
                return Err(err);
            }
        }

        Ok(Some(entry - self.offset))
    }
}

impl<Driver, Layout> Iterator for ListEntryIteratorBase<'_, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    ListEntryLayout: ListEntry<Layout>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver, Layout> DoubleEndedIterator for ListEntryIteratorBase<'_, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    ListEntryLayout: ListEntry<Layout>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.walk_next_back().transpose()
    }
}

impl<Driver, Layout> FusedIterator for ListEntryIteratorBase<'_, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    ListEntryLayout: ListEntry<Layout>,
{
}

enum ListEntryWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    W32(ListEntryIteratorBase<'a, Driver, StructLayout32>),
    W64(ListEntryIteratorBase<'a, Driver, StructLayout64>),
}

impl<'a, Driver> ListEntryWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn w32(vmi: VmiState<'a, WindowsOs<Driver>>, list_head: Va, offset: u64, root: Pa) -> Self {
        Self::W32(ListEntryIteratorBase::new(vmi, list_head, offset, root))
    }

    fn w64(vmi: VmiState<'a, WindowsOs<Driver>>, list_head: Va, offset: u64, root: Pa) -> Self {
        Self::W64(ListEntryIteratorBase::new(vmi, list_head, offset, root))
    }

    fn native(vmi: VmiState<'a, WindowsOs<Driver>>, list_head: Va, offset: u64, root: Pa) -> Self {
        match vmi.registers().address_width() {
            4 => Self::w32(vmi, list_head, offset, root),
            8 => Self::w64(vmi, list_head, offset, root),
            _ => panic!("Unsupported address width"),
        }
    }

    fn walk_next(&mut self) -> Result<Option<Va>, VmiError> {
        match self {
            Self::W32(inner) => inner.walk_next(),
            Self::W64(inner) => inner.walk_next(),
        }
    }

    fn walk_next_back(&mut self) -> Result<Option<Va>, VmiError> {
        match self {
            Self::W32(inner) => inner.walk_next_back(),
            Self::W64(inner) => inner.walk_next_back(),
        }
    }
}

/// Iterator over a `LIST_ENTRY` chain with a runtime pointer width.
///
/// Wraps [`ListEntryIteratorBase`] and erases the [`StructLayout`] type
/// parameter, dispatching between 32-bit and 64-bit layouts dynamically.
pub struct ListEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    inner: ListEntryWrapper<'a, Driver>,
}

impl<'a, Driver> From<ListEntryIteratorBase<'a, Driver, StructLayout32>>
    for ListEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: ListEntryIteratorBase<'a, Driver, StructLayout32>) -> Self {
        Self {
            inner: ListEntryWrapper::W32(value),
        }
    }
}

impl<'a, Driver> From<ListEntryIteratorBase<'a, Driver, StructLayout64>>
    for ListEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: ListEntryIteratorBase<'a, Driver, StructLayout64>) -> Self {
        Self {
            inner: ListEntryWrapper::W64(value),
        }
    }
}

impl<'a, Driver> ListEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new list entry iterator.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, list_head: Va, offset: u64) -> Self {
        Self::with_kind(
            vmi,
            list_head,
            offset,
            vmi.translation_root(list_head),
            WindowsWow64Kind::Native,
        )
    }

    /// Creates a new list entry iterator with an explicit address space
    /// root and pointer width.
    pub fn with_kind(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        list_head: Va,
        offset: u64,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        let inner = match kind {
            WindowsWow64Kind::Native => ListEntryWrapper::native(vmi, list_head, offset, root),
            WindowsWow64Kind::X86 => ListEntryWrapper::w32(vmi, list_head, offset, root),
        };

        Self { inner }
    }

    /// Walks to the next entry in the list.
    fn walk_next(&mut self) -> Result<Option<Va>, VmiError> {
        self.inner.walk_next()
    }

    /// Walks to the previous entry in the list.
    fn walk_next_back(&mut self) -> Result<Option<Va>, VmiError> {
        self.inner.walk_next_back()
    }
}

impl<Driver> Iterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> DoubleEndedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.walk_next_back().transpose()
    }
}

impl<Driver> FusedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
