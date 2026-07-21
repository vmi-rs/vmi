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

use std::collections::{HashMap, hash_map::Entry};

use vmi_core::{
    Gfn, Pa, Va, View, VmiCore, VmiError, VmiEvent,
    arch::{Architecture, EventInterrupt, EventReason, Registers as _},
    driver::{VmiRead, VmiViewControl, VmiVmControl, VmiWrite},
};

/// A single breakpoint within a page.
///
/// Stores the original content that was replaced by the breakpoint instruction
/// and tracks the number of references to this breakpoint location.
struct Breakpoint {
    /// Byte offset within the page.
    #[expect(unused)]
    offset: u16,

    /// Bytes replaced by the breakpoint instruction.
    original_content: Vec<u8>, // until [u8; Arch::BREAKPOINT.len()] is allowed

    /// Number of active users of this breakpoint.
    references: u32,
}

/// A memory page containing one or more breakpoints.
///
/// Maintains the mapping between original and shadow pages, along with all
/// breakpoint locations within the page.
struct Page {
    /// Guest frame containing the original page.
    original_gfn: Gfn,

    /// Guest frame containing the shadow page.
    shadow_gfn: Gfn,

    /// View that maps the original frame to the shadow frame.
    view: View,

    /// Breakpoints keyed by their byte offset within the page.
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
pub struct Interceptor<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    /// Pages keyed by view and original guest frame.
    pages: HashMap<(View, Gfn), Page>,

    /// Associates the interceptor with its driver type.
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

        debug_assert!(offset < Driver::Architecture::PAGE_SIZE as usize);

        // Check if the breakpoint doesn't cross a page boundary.
        if offset + Driver::Architecture::BREAKPOINT.len()
            > Driver::Architecture::PAGE_SIZE as usize
        {
            return Err(VmiError::OutOfBounds);
        }

        // Check if the page already has a breakpoint.
        let (page, deactivate_on_error) = match self.pages.entry((view, original_gfn)) {
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

                let deactivate_on_error = page.breakpoints.is_empty();
                if deactivate_on_error {
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

                (page, deactivate_on_error)
            }
            Entry::Vacant(entry) => {
                // Create a shadow page for the original page.
                let page = Page {
                    original_gfn,
                    shadow_gfn: vmi.allocate_gfn()?,
                    view,
                    breakpoints: HashMap::new(),
                };

                if let Err(err) = activate_shadow_page(vmi, &page) {
                    let _ = vmi.free_gfn(page.shadow_gfn).inspect_err(|err| {
                        tracing::error!(
                            shadow_gfn = %page.shadow_gfn,
                            %err,
                            "failed to free shadow page after activation failure"
                        );
                    });

                    return Err(err);
                }

                tracing::debug!(
                    %address,
                    %original_gfn,
                    shadow_gfn = %page.shadow_gfn,
                    %view,
                    "created shadow page"
                );

                (entry.insert(page), true)
            }
        };

        // Replace the original content with a breakpoint instruction.
        let install_result = (|| {
            let shadow = vmi.driver().read_page(page.shadow_gfn)?;
            let original_content =
                shadow[offset..offset + Driver::Architecture::BREAKPOINT.len()].to_vec();

            vmi.driver().write_page(
                page.shadow_gfn,
                offset as u64,
                Driver::Architecture::BREAKPOINT,
            )?;

            Ok(original_content)
        })();

        let original_content = match install_result {
            Ok(original_content) => original_content,
            Err(err) => {
                if deactivate_on_error {
                    let _ = vmi
                        .reset_view_gfn(page.view, page.original_gfn)
                        .inspect_err(|err| {
                            tracing::error!(
                                view = %page.view,
                                original_gfn = %page.original_gfn,
                                %err,
                                "failed to reset view after breakpoint installation failure"
                            );
                        });
                }

                return Err(err);
            }
        };

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

    /// Removes one reference or forcibly removes the entire breakpoint.
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

        let is_last_breakpoint = page.breakpoints.len() == 1;

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

        // Reset the mapping before removing the final bookkeeping entry. If
        // resetting fails, restore the breakpoint instruction so the physical
        // page and the in-memory state remain consistent and removal can be
        // retried.
        if is_last_breakpoint {
            let reset_result = vmi.reset_view_gfn(page.view, page.original_gfn);
            if let Err(err) = reset_result {
                let _ = vmi
                    .driver()
                    .write_page(
                        page.shadow_gfn,
                        offset as u64,
                        Driver::Architecture::BREAKPOINT,
                    )
                    .inspect_err(|err| {
                        tracing::error!(
                            shadow_gfn = %page.shadow_gfn,
                            %err,
                            "failed to restore breakpoint after view reset failure"
                        );
                    });

                return Err(err);
            }
        }

        // Remove the breakpoint from the page.
        page.breakpoints.remove(&offset);

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

/// Verifies interceptor behavior with deterministic mock drivers.
#[cfg(all(test, feature = "arch-amd64"))]
mod tests;
