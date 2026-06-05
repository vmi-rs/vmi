//! Simple software breakpoint management.
//!
//! Provides the fundamental mechanisms for inserting and removing breakpoint
//! instructions in guest memory using shadow pages. It serves as a building
//! block for higher-level breakpoint management systems like the
//! [`BreakpointController`].
//!
//! When a breakpoint is inserted, the `Interceptor`:
//! - Creates a shadow copy of the host page that backs the target
//! - Replaces the target instruction with a breakpoint instruction
//! - Remaps the guest's view to the shadow page
//!
//! The original page content is preserved, allowing the `Interceptor` to
//! restore the original state when breakpoints are removed.
//!
//! Shadows are keyed by host frame, so every breakpoint in one host page shares
//! a single shadow and a single stage-2 remap. On a host whose page exceeds the
//! guest coordinate page (a 16K arm64 host over a 4K guest) two breakpoints
//! that land in different guest pages but the same host page coexist instead of
//! colliding.
//!
//! [`BreakpointController`]: crate::bpm::BreakpointController

use std::collections::{HashMap, hash_map::Entry};

use vmi_core::{
    Hfn, Pa, Va, View, VmiCore, VmiError, VmiEvent,
    arch::{Architecture, EventInterrupt, EventReason, Registers as _},
    driver::{VmiRead, VmiViewControl, VmiVmControl, VmiWrite},
};

/// A single breakpoint within a host page.
///
/// Stores the original content that was replaced by the breakpoint instruction
/// and tracks the number of references to this breakpoint location.
struct Breakpoint {
    #[expect(unused)]
    offset: u16,
    original_content: Vec<u8>, // until [u8; Arch::BREAKPOINT.len()] is allowed
    references: u32,
}

/// A host page containing one or more breakpoints.
///
/// Maintains the mapping between original and shadow host frames, along with
/// all breakpoint locations within the page.
struct Page {
    /// Host frame being shadowed (the map key's frame).
    host_frame: Hfn,

    /// Shadow host frame returned by `allocate_gfn`.
    shadow: Hfn,

    view: View,

    /// Breakpoints keyed by their offset within the host page.
    breakpoints: HashMap<u16, Breakpoint>,
}

/// Core implementation of software breakpoint handling.
#[derive(Default)]
pub struct Interceptor<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    pages: HashMap<(View, Hfn), Page>,
    _marker: std::marker::PhantomData<Driver>,
}

impl<Driver> Interceptor<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    /// Creates a new `Interceptor`.
    pub fn new() -> Self {
        Self {
            pages: HashMap::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Inserts a breakpoint at the given address.
    pub fn insert_breakpoint(
        &mut self,
        vmi: &VmiCore<Driver>,
        address: Pa,
        view: View,
    ) -> Result<Hfn, VmiError> {
        let info = vmi.info()?;
        let host_shift = info.host_page_shift as u32;
        let host_page = info.host_page_size;

        let original_gfn = Driver::Architecture::gfn_from_pa(address);
        let guest_offset = Driver::Architecture::pa_offset(address) as usize;
        let host_frame = Driver::Architecture::hfn_from_gfn(original_gfn, host_shift);
        let host_offset = (u64::from(address) & (host_page - 1)) as usize;

        debug_assert!(guest_offset < Driver::Architecture::PAGE_SIZE as usize);

        // Check if the breakpoint doesn't cross a guest page boundary.
        if guest_offset + Driver::Architecture::BREAKPOINT.len()
            > Driver::Architecture::PAGE_SIZE as usize
        {
            return Err(VmiError::OutOfBounds);
        }

        // Check if the host page already has a shadow.
        let page = match self.pages.entry((view, host_frame)) {
            Entry::Occupied(entry) => {
                let page = entry.into_mut();

                if let Some(breakpoint) = page.breakpoints.get_mut(&(host_offset as u16)) {
                    breakpoint.references += 1;

                    tracing::debug!(
                        %address,
                        current_count = breakpoint.references,
                        "breakpoint already exists"
                    );

                    return Ok(page.shadow);
                }

                page
            }
            Entry::Vacant(entry) => {
                // Create a shadow page for the host page.
                let shadow = vmi.allocate_gfn()?;

                // Copy the whole host page into the shadow (the shadow is one
                // host frame). The guest read chunks correctly across the
                // consecutive guest gfns, but the shadow is written directly as
                // a single host frame through the driver.
                let base = u64::from(address) & !(host_page - 1);
                let mut content = vec![0u8; host_page as usize];
                vmi.read(Pa::new(base), &mut content)?;
                vmi.driver().write_page(shadow, 0, &content)?;

                // Change the view of the original host frame to the shadow.
                vmi.change_view_gfn(view, host_frame, shadow)?;

                tracing::debug!(
                    %address,
                    %host_frame,
                    %shadow,
                    %view,
                    "created shadow page"
                );

                entry.insert(Page {
                    host_frame,
                    shadow,
                    view,
                    breakpoints: HashMap::new(),
                })
            }
        };

        // Replace the original content with a breakpoint instruction, reading
        // and writing the host-page shadow frame directly at host_offset.
        let brk_len = Driver::Architecture::BREAKPOINT.len();
        let mut original_content = vec![0u8; brk_len];
        let shadow_page = vmi.driver().read_page(page.shadow)?;
        original_content.copy_from_slice(&shadow_page[host_offset..host_offset + brk_len]);
        drop(shadow_page);
        vmi.driver().write_page(
            page.shadow,
            host_offset as u64,
            Driver::Architecture::BREAKPOINT,
        )?;

        // Save the original content of the breakpoint.
        let host_offset = host_offset as u16;
        page.breakpoints.insert(
            host_offset,
            Breakpoint {
                offset: host_offset,
                original_content,
                references: 1,
            },
        );

        Ok(page.shadow)
    }

    /// Removes a breakpoint at the given address.
    pub fn remove_breakpoint(
        &mut self,
        vmi: &VmiCore<Driver>,
        address: Pa,
        view: View,
    ) -> Result<Option<bool>, VmiError> {
        self.remove_breakpoint_internal(vmi, address, view, false)
    }

    /// Removes a breakpoint at the given address by force.
    pub fn remove_breakpoint_by_force(
        &mut self,
        vmi: &VmiCore<Driver>,
        address: Pa,
        view: View,
    ) -> Result<Option<bool>, VmiError> {
        self.remove_breakpoint_internal(vmi, address, view, true)
    }

    fn remove_breakpoint_internal(
        &mut self,
        vmi: &VmiCore<Driver>,
        address: Pa,
        view: View,
        force: bool,
    ) -> Result<Option<bool>, VmiError> {
        let info = vmi.info()?;
        let host_shift = info.host_page_shift as u32;
        let host_page = info.host_page_size;

        let original_gfn = Driver::Architecture::gfn_from_pa(address);
        let host_frame = Driver::Architecture::hfn_from_gfn(original_gfn, host_shift);
        let host_offset = (u64::from(address) & (host_page - 1)) as u16;

        // Check if the host page has any breakpoints.
        let page = match self.pages.get_mut(&(view, host_frame)) {
            Some(page) => page,
            None => return Ok(None),
        };

        // Check if the breakpoint at the given offset exists.
        let breakpoint = match page.breakpoints.get_mut(&host_offset) {
            Some(breakpoint) => breakpoint,
            None => return Ok(None),
        };

        if !force && breakpoint.references > 1 {
            breakpoint.references -= 1;

            tracing::debug!(
                %address,
                current_count = breakpoint.references,
                "breakpoint still in use"
            );

            return Ok(Some(false));
        }

        // Restore the original content of the shadow page at the host offset.
        vmi.driver().write_page(
            page.shadow,
            host_offset as u64,
            &breakpoint.original_content,
        )?;

        // Remove the breakpoint from the page.
        page.breakpoints.remove(&host_offset);

        // If the host page has no more breakpoints, reset the view of the host
        // frame to its original mapping.
        if page.breakpoints.is_empty() {
            vmi.reset_view_gfn(view, page.host_frame)?;

            // Free the shadow page.
            // TODO: figure out why it's not working
            //self.vmi.free_gfn(page.shadow)?;
            //self.pages.remove(&(view, host_frame));
        }

        Ok(Some(true))
    }

    /// Checks if the given event was caused by a breakpoint managed by the
    /// [`Interceptor`].
    pub fn contains_breakpoint(
        &self,
        vmi: &VmiCore<Driver>,
        event: &VmiEvent<Driver::Architecture>,
    ) -> bool {
        let interrupt = match event.reason().as_software_breakpoint() {
            Some(interrupt) => interrupt,
            None => return false,
        };

        let view = match event.view() {
            Some(view) => view,
            None => return false,
        };

        let info = match vmi.info() {
            Ok(info) => info,
            Err(_) => return false,
        };
        let host_shift = info.host_page_shift as u32;

        let ip = Va(event.registers().instruction_pointer());
        let gfn = interrupt.gfn();
        let host_frame = Driver::Architecture::hfn_from_gfn(gfn, host_shift);
        let host_offset = ((Driver::Architecture::pa_from_gfn(gfn).0
            + Driver::Architecture::va_offset(ip))
            & (info.host_page_size - 1)) as u16;

        let page = match self.pages.get(&(view, host_frame)) {
            Some(page) => page,
            None => return false,
        };

        view == page.view && page.breakpoints.contains_key(&host_offset)
    }
}
