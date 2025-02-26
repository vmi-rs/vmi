use std::cell::RefCell;

use indexmap::IndexSet;

use crate::{AddressContext, PageFaults, VmiError};

/// Prober for safely handling page faults during memory access operations.
pub struct VmiProber {
    /// The set of restricted page faults that are allowed to occur.
    restricted: IndexSet<AddressContext>,

    /// The set of page faults that have occurred.
    page_faults: RefCell<IndexSet<AddressContext>>,
}

impl VmiProber {
    /// Creates a new prober.
    pub fn new(restricted: &IndexSet<AddressContext>) -> Self {
        Self {
            restricted: restricted.clone(),
            page_faults: RefCell::new(IndexSet::new()),
        }
    }

    /// Probes for safely handling page faults during memory access operations.
    pub fn probe<T, F>(&self, f: F) -> Result<Option<T>, VmiError>
    where
        F: FnOnce() -> Result<T, VmiError>,
    {
        self.check_result(f())
    }

    /// Handles a result that may contain page faults, returning the value
    /// if successful.
    pub fn check_result<T>(&self, result: Result<T, VmiError>) -> Result<Option<T>, VmiError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(VmiError::Translation(pfs)) => {
                self.check_restricted(pfs);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /*
    /// Handles a result that may contain page faults over a memory range,
    /// returning the value if successful.
    fn check_result_range<T>(
        &self,
        result: Result<T, VmiError>,
        ctx: AccessContext,
        length: usize,
    ) -> Result<Option<T>, VmiError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(VmiError::Translation(pfs)) => {
                debug_assert_eq!(pfs.len(), 1);
                self.check_restricted_range(pfs[0], ctx, length);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }
    */

    /// Records any page faults that are not in the restricted set.
    fn check_restricted(&self, pfs: PageFaults) {
        let mut page_faults = self.page_faults.borrow_mut();
        for pf in pfs {
            if !self.restricted.contains(&pf) {
                tracing::trace!(va = %pf.va, "page fault");
                page_faults.insert(pf);
            }
            else {
                tracing::trace!(va = %pf.va, "page fault (restricted)");
            }
        }
    }

    /*
    /// Records any page faults that are not in the restricted set over
    /// a memory range.
    fn check_restricted_range(&self, pf: PageFault, ctx: AccessContext, mut length: usize) {
        let mut page_faults = self.page_faults.borrow_mut();

        if length == 0 {
            length = 1;
        }

        //
        // Generate page faults for the range of addresses that would be accessed by the read.
        // Start at the page containing the faulting address and end at the page containing the
        // last byte of the read.
        //

        let pf_page = pf.address.0 >> Driver::Architecture::PAGE_SHIFT;
        let last_page = (ctx.address + length as u64 - 1) >> Driver::Architecture::PAGE_SHIFT;
        let number_of_pages = last_page.saturating_sub(pf_page) + 1;

        let pf_address_aligned = Va(pf_page << Driver::Architecture::PAGE_SHIFT);
        let last_address_aligned = Va(last_page << Driver::Architecture::PAGE_SHIFT);

        if number_of_pages > 1 {
            tracing::debug!(
                from = %pf_address_aligned,
                to = %last_address_aligned,
                number_of_pages,
                "page fault (range)"
            );

            if number_of_pages >= 4096 {
                tracing::warn!(
                    from = %pf_address_aligned,
                    to = %last_address_aligned,
                    number_of_pages,
                    "page fault range too large"
                );
            }
        }

        for i in 0..number_of_pages {
            //
            // Ensure that the page fault is for the root that we are tracking.
            //

            debug_assert_eq!(
                pf.root,
                match ctx.mechanism {
                    TranslationMechanism::Paging { root: Some(root) } => root,
                    _ => panic!("page fault root doesn't match the context root"),
                }
            );

            let pf = PageFault {
                address: pf_address_aligned + i * Driver::Architecture::PAGE_SIZE,
                root: pf.root,
            };

            if !self.restricted.contains(&pf) {
                tracing::trace!(va = %pf.address, "page fault");
                page_faults.insert(pf);
            }
            else {
                tracing::trace!(va = %pf.address, "page fault (restricted)");
            }
        }
    }
    */

    /// Checks for any unexpected page faults that have occurred and returns
    /// an error if any are present.
    #[tracing::instrument(skip_all)]
    pub fn error_for_page_faults(&self) -> Result<(), VmiError> {
        let pfs = self.page_faults.borrow();
        let new_pfs = &*pfs - &self.restricted;
        if !new_pfs.is_empty() {
            tracing::trace!(?new_pfs);
            return Err(VmiError::page_faults(new_pfs));
        }

        Ok(())
    }
}

/// Probes for safely handling page faults during memory access operations.
#[macro_export]
macro_rules! vmi_probe {
    ($prober:expr, $expr:expr) => {
        $prober.check_result(|| -> Result<_, VmiError> { $expr }())
    };
}
