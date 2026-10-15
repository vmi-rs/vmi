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
//! Callers must pause guest execution while modifying breakpoints. A shadow is
//! unmapped before it is edited and remapped only after all patches are
//! written. Failed operations retain their allocated frames, so a retry reuses
//! them. Errors must be handled before guest execution resumes.
//!
//! [`BreakpointController`]: crate::bpm::BreakpointController

use std::collections::{HashMap, hash_map::Entry};

use vmi_core::{
    Gfn, Pa, Va, View, VmiCore, VmiError, VmiEvent,
    arch::{Architecture, EventInterrupt, EventReason, Registers as _},
    driver::{VmiRead, VmiViewControl, VmiVmControl, VmiWrite},
};

#[cfg(test)]
mod tests;

/// A single software breakpoint installed at one offset within a page.
struct Breakpoint {
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

    /// Breakpoints on this page, indexed by in-page offset.
    breakpoints: HashMap<u16, Breakpoint>,

    /// Records whether the view may currently expose the shadow.
    mapped: bool,
}

/// Validates instruction alignment and containment before any guest mutation.
fn validate_breakpoint(offset: usize, length: usize, page_size: usize) -> Result<(), VmiError> {
    if length == 0
        || offset.checked_add(length).is_none_or(|end| end > page_size)
        || !offset.is_multiple_of(length)
        || offset > u16::MAX as usize
    {
        return Err(VmiError::OutOfBounds);
    }
    Ok(())
}

/// Unmaps an executable shadow before modifying or reclaiming its contents.
fn deactivate_shadow_page<Driver>(vmi: &VmiCore<Driver>, page: &mut Page) -> Result<(), VmiError>
where
    Driver: VmiRead + VmiViewControl,
{
    if page.mapped {
        match vmi.reset_view_gfn(page.view, page.original_gfn) {
            Ok(()) => {}
            Err(VmiError::ViewNotFound) => {}
            Err(err) => return Err(err),
        }
        page.mapped = false;
    }
    // Cached mappings must be dropped before a shadow is edited or freed.
    drop(vmi.flush_gfn_cache_entry(page.shadow_gfn));
    Ok(())
}

/// Publishes a fully patched shadow and synchronizes executable mappings.
fn activate_shadow_page<Driver>(vmi: &VmiCore<Driver>, page: &mut Page) -> Result<(), VmiError>
where
    Driver: VmiViewControl,
{
    page.mapped = true;
    vmi.change_view_gfn(page.view, page.original_gfn, page.shadow_gfn)
}

/// Core implementation of software breakpoint handling.
pub struct Interceptor<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    pages: HashMap<(View, Gfn), Page>,
    _marker: std::marker::PhantomData<Driver>,
}

impl<Driver> Default for Interceptor<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    fn default() -> Self {
        Self::new()
    }
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
        validate_breakpoint(
            offset,
            Driver::Architecture::BREAKPOINT.len(),
            Driver::Architecture::PAGE_SIZE as usize,
        )?;

        let page = match self.pages.entry((view, original_gfn)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Page {
                original_gfn,
                shadow_gfn: vmi.allocate_gfn()?,
                view,
                breakpoints: HashMap::new(),
                mapped: false,
            }),
        };
        if let Some(breakpoint) = page.breakpoints.get_mut(&(offset as u16)) {
            breakpoint.references = breakpoint
                .references
                .checked_add(1)
                .ok_or(VmiError::OutOfBounds)?;
            return Ok(page.shadow_gfn);
        }

        let original = vmi.driver().read_page(page.original_gfn)?;
        let mut content = original.to_vec();
        let original_content =
            content[offset..offset + Driver::Architecture::BREAKPOINT.len()].to_vec();
        for &patch_offset in page.breakpoints.keys() {
            let patch_offset = patch_offset as usize;
            content[patch_offset..patch_offset + Driver::Architecture::BREAKPOINT.len()]
                .copy_from_slice(Driver::Architecture::BREAKPOINT);
        }
        content[offset..offset + Driver::Architecture::BREAKPOINT.len()]
            .copy_from_slice(Driver::Architecture::BREAKPOINT);
        deactivate_shadow_page(vmi, page)?;
        vmi.driver().write_page(page.shadow_gfn, 0, &content)?;
        activate_shadow_page(vmi, page)?;
        for (&patch_offset, breakpoint) in &mut page.breakpoints {
            let patch_offset = patch_offset as usize;
            breakpoint.original_content.copy_from_slice(
                &original[patch_offset..patch_offset + Driver::Architecture::BREAKPOINT.len()],
            );
        }
        page.breakpoints.insert(
            offset as u16,
            Breakpoint {
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

    /// Releases an ownership reference and reclaims an empty shadow.
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

        if page.breakpoints.len() == 1 {
            deactivate_shadow_page(vmi, page)?;
            vmi.free_gfn(page.shadow_gfn)?;
            self.pages.remove(&(view, gfn));
        }
        else {
            deactivate_shadow_page(vmi, page)?;
            vmi.driver().write_page(
                page.shadow_gfn,
                offset as u64,
                &page.breakpoints[&offset].original_content,
            )?;
            activate_shadow_page(vmi, page)?;
            page.breakpoints.remove(&offset);
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
