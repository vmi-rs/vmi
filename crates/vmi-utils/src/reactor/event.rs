//! Event enum and metadata types emitted by [`define_events!`].
//!
//! [`define_events!`]: super::define_events

use std::fmt::Debug;

use vmi_core::{Va, os::ProcessObject};

use super::super::{bpm, ptm};

/// Event set monitored by a reactor.
///
/// Implemented by the enum that [`define_events!`] produces. The enum
/// variants name symbols to breakpoint, each tagged with the module
/// that owns it.
///
/// [`define_events!`]: super::define_events
pub trait ReactorEvent: bpm::TagType + ptm::TagType + 'static {
    /// Module enum that owns the symbols referenced by [`METADATA`].
    ///
    /// [`METADATA`]: Self::METADATA
    // Note: unfortunately, we cannot use `type Module: ReactorModule` here,
    //       because ReactorModule requires an Os type parameter, and we want
    //       to avoid making `ReactorEvent` generic. (Should we, though?)
    type Module: Debug + Copy + 'static;

    /// Per-variant event metadata.
    const METADATA: &'static [EventMetadata<Self>];
}

/// Compile-time descriptor that [`define_events!`] emits for each variant of
/// the event enum.
///
/// [`define_events!`]: super::define_events
pub struct EventMetadata<Event>
where
    Event: ReactorEvent,
{
    /// Primary symbol name.
    pub name: &'static str,

    /// Aliases tried when the primary name is not found in the profile.
    pub alias: &'static [&'static str],

    /// Module that owns the symbol, or `None` for the kernel image.
    pub module: Option<Event::Module>,

    /// Event tag delivered to the handler when the breakpoint hits.
    pub event: Event,

    /// Whether the event is allowed to be absent from the profile.
    pub optional: bool,
}

/// Successfully resolved entry for an event variant.
pub struct ResolvedEvent<Event>
where
    Event: ReactorEvent,
{
    /// Process whose page tables map this event's containing module.
    ///
    /// `None` for events in the kernel module, which share the global kernel
    /// mapping.
    pub process: Option<ProcessObject>,

    /// Resolved virtual address of the symbol.
    pub address: Va,

    /// Event tag delivered to the handler when the breakpoint hits.
    pub event: Event,
}
