//! Simple software breakpoint management.
//!
//! Provides the fundamental mechanisms for inserting and removing breakpoint
//! instructions in guest memory using shadow pages. It serves as a building
//! block for higher-level breakpoint management systems like the
//! [`BreakpointController`].
//!
//! When a breakpoint is inserted, the `Interceptor`:
//! - Creates a shadow copy of the target page
//! - Replaces the target instruction with a breakpoint instruction
//! - Remaps the guest's view to the shadow page
//!
//! The original page content is preserved, allowing the `Interceptor` to
//! restore the original state when breakpoints are removed.
//!
//! [`BreakpointController`]: crate::bpm::BreakpointController

use std::collections::{hash_map::Entry, HashMap};

use vmi_core::{
    arch::{Architecture, EventInterrupt, EventReason, Registers as _},
    Gfn, Pa, Va, View, VmiCore, VmiDriver, VmiError, VmiEvent,
};

/// A single breakpoint within a page.
///
/// Stores the original content that was replaced by the breakpoint instruction
/// and tracks the number of references to this breakpoint location.
struct Breakpoint {
    #[expect(unused)]
    offset: u16,
    original_content: Vec<u8>, // until [u8; Arch::BREAKPOINT.len()] is allowed
    references: u32,
}

/// A memory page containing one or more breakpoints.
///
/// Maintains the mapping between original and shadow pages, along with all
/// breakpoint locations within the page.
struct Page {
    original_gfn: Gfn,
    shadow_gfn: Gfn,
    view: View,
    breakpoints: HashMap<u16, Breakpoint>,
}

/// Core implementation of software breakpoint handling.
#[derive(Default)]
pub struct Interceptor<Driver>
where
    Driver: VmiDriver,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    pages: HashMap<(View, Gfn), Page>,
    _marker: std::marker::PhantomData<Driver>,
}

impl<Driver> Interceptor<Driver>
where
    Driver: VmiDriver,
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
    ) -> Result<Gfn, VmiError> {
        let original_gfn = Driver::Architecture::gfn_from_pa(address);
        let offset = Driver::Architecture::pa_offset(address) as usize;

        debug_assert!(offset < Driver::Architecture::PAGE_SIZE as usize);

        // Check if the breakpoint doesn't cross a page boundary.
        if offset + Driver::Architecture::BREAKPOINT.len()
            > Driver::Architecture::PAGE_SIZE as usize
        {
            return Err(VmiError::OutOfBounds);
        }

        // Check if the page already has a breakpoint.
        let page = match self.pages.entry((view, original_gfn)) {
            Entry::Occupied(entry) => {
                let page = entry.into_mut();

                if let Some(breakpoint) = page.breakpoints.get_mut(&(offset as u16)) {
                    breakpoint.references += 1;

                    tracing::debug!(
                        %address,
                        current_count = breakpoint.references,
                        "breakpoint already exists"
                    );

                    return Ok(page.shadow_gfn);
                }

                page
            }
            Entry::Vacant(entry) => {
                let page = Page {
                    original_gfn,
                    shadow_gfn: vmi.allocate_next_available_gfn()?,
                    view,
                    breakpoints: HashMap::new(),
                };

                tracing::debug!(
                    %address,
                    %original_gfn,
                    shadow_gfn = %page.shadow_gfn,
                    %view,
                    "created shadow page"
                );

                entry.insert(page)
            }
        };

        // Read the content of the original page.
        let mut content = [0u8; 4096_usize]; // FIXME: Driver::Architecture::PAGE_SIZE
        vmi.read(
            Driver::Architecture::pa_from_gfn(original_gfn),
            &mut content,
        )?;

        // Carve out the fragment of the original page that will be replaced by the
        // breakpoint.
        let fragment = &mut content[offset..offset + Driver::Architecture::BREAKPOINT.len()];
        let original_content = fragment.to_vec();

        // Write the breakpoint to the shadow page.
        fragment.copy_from_slice(Driver::Architecture::BREAKPOINT);
        vmi.write(Driver::Architecture::pa_from_gfn(page.shadow_gfn), &content)?;

        // Change the view of the original page to the shadow page.
        vmi.change_view_gfn(view, original_gfn, page.shadow_gfn)?;

        // Save the original content of the breakpoint.
        let offset = offset as u16;
        page.breakpoints.insert(
            offset,
            Breakpoint {
                offset,
                original_content,
                references: 1,
            },
        );

        Ok(page.shadow_gfn)
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
        let gfn = Driver::Architecture::gfn_from_pa(address);
        let offset = Driver::Architecture::pa_offset(address) as u16;

        // Check if the page has any breakpoints.
        let page = match self.pages.get_mut(&(view, gfn)) {
            Some(page) => page,
            None => return Ok(None),
        };

        // Check if the breakpoint at the given offset exists.
        let breakpoint = match page.breakpoints.get_mut(&offset) {
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

        // Restore the original content of the shadow page at the given offset.
        let shadow_address = Driver::Architecture::pa_from_gfn(page.shadow_gfn) + offset as u64;
        vmi.write(shadow_address, &breakpoint.original_content)?;

        // Remove the breakpoint from the page.
        page.breakpoints.remove(&offset);

        // If the page has no more breakpoints, reset the view of the page to
        // the original page.
        if page.breakpoints.is_empty() {
            vmi.reset_view_gfn(view, page.original_gfn)?;

            // Free the shadow page.
            // TODO: figure out why it's not working
            //self.vmi.free_gfn(page.new_gfn)?;
            //self.pages.remove(&(view, gfn));
        }

        Ok(Some(true))
    }

    /// Checks if the given event was caused by a breakpoint managed by the
    /// [`Interceptor`].
    pub fn contains_breakpoint(&self, event: &VmiEvent<Driver::Architecture>) -> bool {
        let interrupt = match event.reason().as_software_breakpoint() {
            Some(interrupt) => interrupt,
            _ => return false,
        };

        let ip = Va(event.registers().instruction_pointer());

        let gfn = interrupt.gfn();
        let offset = Driver::Architecture::va_offset(ip) as u16;

        let view = match event.view() {
            Some(view) => view,
            None => return false,
        };

        let page = match self.pages.get(&(view, gfn)) {
            Some(page) => page,
            None => return false,
        };

        if view != page.view {
            return false;
        }

        page.breakpoints.contains_key(&offset)
    }
}
