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
//! # Consistency on error
//!
//! Inserting and removing a breakpoint each perform several distinct VMI
//! operations - allocating a shadow frame, copying the page, remapping the
//! guest view, and writing or restoring the breakpoint byte - and these are
//! not applied as a single transaction. If one step fails, the steps that
//! already succeeded are not undone. When a method returns an error, treat the
//! VM as being in an undefined state. The breakpoint may be partially installed
//! or partially removed, and the guest view may still point at the shadow page.
//! Callers must not assume a failed call had no effect.
//!
//! [`BreakpointController`]: crate::bpm::BreakpointController

use std::collections::{HashMap, hash_map::Entry};

use vmi_core::{
    Gfn, Pa, Va, View, VmiCore, VmiError, VmiEvent,
    arch::{Architecture, EventInterrupt, EventReason, Registers as _},
    driver::{VmiRead, VmiViewControl, VmiVmControl, VmiWrite},
};

/// A single software breakpoint installed at one offset within a page.
struct Breakpoint {
    /// In-page byte offset of the breakpoint.
    #[expect(unused)]
    offset: u16,

    /// Original bytes replaced by the breakpoint instruction, restored on
    /// removal.
    original_content: Vec<u8>, // until [u8; Arch::BREAKPOINT.len()] is allowed

    /// Outstanding insertions of this location. The breakpoint is torn down
    /// only when the last insertion is released.
    references: u32,
}

/// A shadowed guest page with the installed breakpoints.
struct Page {
    /// Guest frame being shadowed.
    original_gfn: Gfn,

    /// Patched copy that the view maps in place of the original frame.
    shadow_gfn: Gfn,

    /// View whose mapping is redirected from the original frame to the shadow.
    view: View,

    /// Breakpoints on this page, keyed by in-page offset.
    breakpoints: HashMap<u16, Breakpoint>,
}

/// Refreshes the shadow from the current original page and maps it into the
/// configured view.
fn activate_shadow_page<Driver>(vmi: &VmiCore<Driver>, page: &Page) -> Result<(), VmiError>
where
    Driver: VmiRead + VmiWrite + VmiViewControl,
{
    // Copy the content of the original page to the shadow page.
    let content = vmi.driver().read_page(page.original_gfn)?;
    vmi.driver().write_page(page.shadow_gfn, 0, &content)?;

    // Change the view of the original page to the shadow page.
    vmi.change_view_gfn(page.view, page.original_gfn, page.shadow_gfn)
}

/// Core implementation of software breakpoint handling.
#[derive(Default)]
pub struct Interceptor<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    pages: HashMap<(View, Gfn), Page>,
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

                if page.breakpoints.is_empty() {
                    // The view was reset when the last breakpoint was removed,
                    // but the shadow page is retained for reuse. Refresh it in
                    // case the original page changed, then reactivate its view
                    // mapping before inserting the new breakpoint.
                    activate_shadow_page(vmi, page)?;

                    tracing::debug!(
                        %address,
                        %original_gfn,
                        shadow_gfn = %page.shadow_gfn,
                        %view,
                        "reactivated shadow page"
                    );
                }

                page
            }
            Entry::Vacant(entry) => {
                // Create a shadow page for the original page.
                let page = Page {
                    original_gfn,
                    shadow_gfn: vmi.allocate_gfn()?,
                    view,
                    breakpoints: HashMap::new(),
                };

                activate_shadow_page(vmi, &page)?;

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

        // Replace the original content with a breakpoint instruction.
        let shadow = vmi.driver().read_page(page.shadow_gfn)?;
        let original_content =
            shadow[offset..offset + Driver::Architecture::BREAKPOINT.len()].to_vec();

        vmi.driver().write_page(
            page.shadow_gfn,
            offset as u64,
            Driver::Architecture::BREAKPOINT,
        )?;

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
        vmi.driver()
            .write_page(page.shadow_gfn, offset as u64, &breakpoint.original_content)?;

        // Remove the breakpoint from the page.
        page.breakpoints.remove(&offset);

        // If the page has no more breakpoints, reset the view of the page to
        // the original page.
        if page.breakpoints.is_empty() {
            vmi.reset_view_gfn(page.view, page.original_gfn)?;

            // Free the shadow page.
            // TODO: figure out why it's not working
            //vmi.free_gfn(page.shadow_gfn)?;
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

        debug_assert_eq!(page.view, view);
        debug_assert_eq!(page.original_gfn, gfn);

        page.breakpoints.contains_key(&offset)
    }
}
