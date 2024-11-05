use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

use vmi_core::{AddressContext, View};

/// Metadata key for breakpoints.
pub trait KeyType: Debug + Copy + Eq + Hash {}
impl<T> KeyType for T where T: Debug + Copy + Eq + Hash {}

/// Metadata tag for breakpoints.
///
/// Tags are used to associate metadata with breakpoints, allowing users to
/// easily track breakpoints during debugging.
pub trait TagType: Debug + Copy + Eq + Hash {}
impl<T> TagType for T where T: Debug + Copy + Eq + Hash {}

pub(super) type ActiveBreakpoints<Key, Tag> =
    HashMap<(Key, AddressContext), HashSet<Breakpoint<Key, Tag>>>;
pub(super) type PendingBreakpoints<Key, Tag> = HashSet<Breakpoint<Key, Tag>>;

/// A breakpoint definition.
///
/// A breakpoint is defined by its address context, view, and optional metadata
/// in the form of a key and tag.
///
/// If the breakpoint is global, it will be triggered regardless of the
/// translation root, e.g., only [`AddressContext::va`] will be considered
/// during breakpoint matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Breakpoint<Key, Tag>
where
    Key: KeyType,
    Tag: TagType,
{
    pub(super) ctx: AddressContext,
    pub(super) view: View,
    pub(super) global: bool,
    pub(super) key: Key,
    pub(super) tag: Tag,
}

impl<Key, Tag> Breakpoint<Key, Tag>
where
    Key: KeyType,
    Tag: TagType,
{
    /// Returns the address context of the breakpoint.
    ///
    /// If the breakpoint is global, only [`AddressContext::va`] will be
    /// considered during breakpoint matching.
    pub fn ctx(&self) -> AddressContext {
        self.ctx
    }

    /// Returns the view in which the breakpoint is defined.
    pub fn view(&self) -> View {
        self.view
    }

    /// Returns whether the breakpoint is global.
    ///
    /// A global breakpoint will be triggered regardless of the translation
    /// root, e.g., only [`AddressContext::va`] will be considered during
    /// breakpoint matching.
    pub fn global(&self) -> bool {
        self.global
    }

    /// Returns the key of the breakpoint.
    pub fn key(&self) -> Key {
        self.key
    }

    /// Returns the tag of the breakpoint.
    pub fn tag(&self) -> Tag {
        self.tag
    }
}

/// A builder for constructing breakpoint definitions.
///
/// This builder provides a fluent interface for creating [`Breakpoint`]
/// instances, allowing for flexible configuration of breakpoint properties
/// and metadata.
#[derive(Debug)]
pub struct BreakpointBuilder {
    ctx: AddressContext,
    view: View,
    global: bool,
}

#[doc(hidden)]
#[derive(Debug)]
pub struct BreakpointBuilderWithKey<Key>
where
    Key: KeyType,
{
    ctx: AddressContext,
    view: View,
    global: bool,
    key: Key,
}

#[doc(hidden)]
#[derive(Debug)]
pub struct BreakpointBuilderWithTag<Tag>
where
    Tag: TagType,
{
    ctx: AddressContext,
    view: View,
    global: bool,
    tag: Tag,
}

#[doc(hidden)]
#[derive(Debug)]
pub struct BreakpointBuilderWithKeyTag<Key, Tag>
where
    Key: KeyType,
    Tag: TagType,
{
    ctx: AddressContext,
    view: View,
    global: bool,
    key: Key,
    tag: Tag,
}

impl Breakpoint<(), ()> {
    /// Creates a new breakpoint builder.
    #[expect(clippy::new_ret_no_self)]
    pub fn new(ctx: impl Into<AddressContext>, view: View) -> BreakpointBuilder {
        BreakpointBuilder::new(ctx, view)
    }
}

impl BreakpointBuilder {
    /// Creates a new breakpoint builder.
    pub fn new(ctx: impl Into<AddressContext>, view: View) -> Self {
        Self {
            ctx: ctx.into(),
            view,
            global: false,
        }
    }

    /// Sets the breakpoint as global.
    ///
    /// A global breakpoint will be triggered regardless of the translation
    /// root, e.g., only [`AddressContext::va`] will be considered during
    /// breakpoint matching.
    pub fn global(self) -> Self {
        Self {
            global: true,
            ..self
        }
    }

    /// Sets the key of the breakpoint.
    pub fn with_key<Key>(self, key: Key) -> BreakpointBuilderWithKey<Key>
    where
        Key: KeyType,
    {
        BreakpointBuilderWithKey {
            ctx: self.ctx,
            view: self.view,
            global: self.global,
            key,
        }
    }

    /// Sets the tag of the breakpoint.
    pub fn with_tag<Tag>(self, tag: Tag) -> BreakpointBuilderWithTag<Tag>
    where
        Tag: TagType,
    {
        BreakpointBuilderWithTag {
            ctx: self.ctx,
            view: self.view,
            global: self.global,
            tag,
        }
    }
}

impl<Key> BreakpointBuilderWithKey<Key>
where
    Key: KeyType,
{
    /// Sets the tag of the breakpoint.
    pub fn with_tag<Tag>(self, tag: Tag) -> BreakpointBuilderWithKeyTag<Key, Tag>
    where
        Tag: TagType,
    {
        BreakpointBuilderWithKeyTag {
            ctx: self.ctx,
            view: self.view,
            global: self.global,
            key: self.key,
            tag,
        }
    }
}

impl<Tag> BreakpointBuilderWithTag<Tag>
where
    Tag: TagType,
{
    /// Sets the key of the breakpoint.
    pub fn with_key<Key>(self, key: Key) -> BreakpointBuilderWithKeyTag<Key, Tag>
    where
        Key: KeyType,
    {
        BreakpointBuilderWithKeyTag {
            ctx: self.ctx,
            view: self.view,
            global: self.global,
            key,
            tag: self.tag,
        }
    }
}

impl<Key, Tag> From<BreakpointBuilder> for Breakpoint<Key, Tag>
where
    Key: KeyType + Default,
    Tag: TagType + Default,
{
    fn from(value: BreakpointBuilder) -> Self {
        Self {
            ctx: value.ctx,
            view: value.view,
            global: value.global,
            key: Default::default(),
            tag: Default::default(),
        }
    }
}

impl<Key, Tag> From<BreakpointBuilderWithKey<Key>> for Breakpoint<Key, Tag>
where
    Key: KeyType,
    Tag: TagType + Default,
{
    fn from(value: BreakpointBuilderWithKey<Key>) -> Self {
        Self {
            ctx: value.ctx,
            view: value.view,
            global: value.global,
            key: value.key,
            tag: Default::default(),
        }
    }
}

impl<Key, Tag> From<BreakpointBuilderWithTag<Tag>> for Breakpoint<Key, Tag>
where
    Key: KeyType + Default,
    Tag: TagType,
{
    fn from(value: BreakpointBuilderWithTag<Tag>) -> Self {
        Self {
            ctx: value.ctx,
            view: value.view,
            global: value.global,
            key: Default::default(),
            tag: value.tag,
        }
    }
}

impl<Key, Tag> From<BreakpointBuilderWithKeyTag<Key, Tag>> for Breakpoint<Key, Tag>
where
    Key: KeyType,
    Tag: TagType,
{
    fn from(value: BreakpointBuilderWithKeyTag<Key, Tag>) -> Self {
        Self {
            ctx: value.ctx,
            view: value.view,
            global: value.global,
            key: value.key,
            tag: value.tag,
        }
    }
}
