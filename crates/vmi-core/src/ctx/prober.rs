use std::cell::RefCell;

use indexmap::IndexSet;

use crate::{AddressContext, VmiError};

/// Batches the page faults raised by a sequence of memory reads so they can be
/// injected together, while skipping pages already known to be unserviceable.
///
/// A read that touches a non-resident page returns [`VmiError::Translation`].
/// Instead of aborting an operation on the first such fault, the prober lets
/// you run a sequence of reads: each probed read that faults yields `Ok(None)`
/// and its faulting address is recorded, unless that address is in the
/// `suppressed` set, in which case it is ignored.
///
/// # Protocol
///
/// 1. Construct a prober with [`new`], passing the set of pages already known
///    to be unserviceable (the `suppressed` set).
/// 2. Run one or more reads through [`probe`] or the [`vmi_probe!`] macro. Each
///    returns `Ok(Some(value))` when the read succeeded, or `Ok(None)` when it
///    faulted (the fault is recorded unless it is suppressed).
/// 3. Call [`error_for_page_faults`]. It returns `Err(VmiError::Translation)`
///    carrying every recorded, non-suppressed fault, or `Ok(())` if there were
///    none. Propagate that error to an event loop that injects page faults: for
///    example, returning it from a `vmi-utils` reactor handler makes the
///    reactor inject the fault so the guest pages the memory in, after which
///    the operation is retried.
/// 4. Faults that turn out to be permanently unserviceable are added to the
///    `suppressed` set by the caller (for instance from a `KiDispatchException`
///    handler), so a later attempt skips them instead of re-injecting forever.
///
/// [`new`]: Self::new
/// [`probe`]: Self::probe
/// [`error_for_page_faults`]: Self::error_for_page_faults
/// [`vmi_probe!`]: crate::vmi_probe
///
/// # Examples
///
/// ```ignore
/// // `suppressed` holds pages a previous round found unserviceable.
/// let prober = VmiProber::new(&suppressed);
///
/// // Each probed read is `Ok(Some(_))` if resident, `Ok(None)` if it faulted.
/// let header = vmi_probe!(prober, vmi.read_struct::<Header>(address))?;
/// let name = vmi_probe!(prober, vmi.read_string(name_address))?;
///
/// // Surface the accumulated, non-suppressed faults. Returning this error from
/// // a reactor handler injects the fault and retries the operation.
/// prober.error_for_page_faults()?;
///
/// // No faults pending: `header` and `name` are `Some` (or `None` for a
/// // suppressed page) and safe to use.
/// ```
pub struct VmiProber {
    /// Pages to suppress.
    ///
    /// Addresses already known to be unserviceable, so a probed read that
    /// faults on one is skipped instead of being reported for injection.
    suppressed: IndexSet<AddressContext>,

    /// Non-suppressed page faults recorded by the probed reads so far.
    page_faults: RefCell<IndexSet<AddressContext>>,
}

impl VmiProber {
    /// Creates a prober that suppresses faults on the given pages.
    ///
    /// `suppressed` is the set of pages already known to be unserviceable
    /// (typically discovered by an earlier round and recorded by an exception
    /// handler). Faults on them are ignored rather than reported by
    /// [`error_for_page_faults`].
    ///
    /// [`error_for_page_faults`]: Self::error_for_page_faults
    pub fn new(suppressed: &IndexSet<AddressContext>) -> Self {
        Self {
            suppressed: suppressed.clone(),
            page_faults: RefCell::new(IndexSet::new()),
        }
    }

    /// Runs `f` and records any page fault it raises, returning `Ok(None)` on a
    /// fault instead of propagating it.
    ///
    /// Equivalent to [`check_result`] applied to `f()`. See the type-level
    /// protocol for how to surface the recorded faults.
    ///
    /// [`check_result`]: Self::check_result
    pub fn probe<T, F>(&self, f: F) -> Result<Option<T>, VmiError>
    where
        F: FnOnce() -> Result<T, VmiError>,
    {
        self.check_result(f())
    }

    /// Records a page fault carried by `result` and returns `Ok(None)` instead
    /// of propagating it, so the caller can keep probing further reads.
    ///
    /// A successful `result` becomes `Ok(Some(value))`. A
    /// [`VmiError::Translation`] is recorded (unless its address is suppressed)
    /// and becomes `Ok(None)`. Any other error is propagated unchanged. Call
    /// [`error_for_page_faults`] afterwards to surface the recorded faults for
    /// injection.
    ///
    /// [`error_for_page_faults`]: Self::error_for_page_faults
    pub fn check_result<T>(&self, result: Result<T, VmiError>) -> Result<Option<T>, VmiError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(VmiError::Translation(pf)) => {
                self.record(pf);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Records the page faults that are not in the `suppressed` set.
    fn record(&self, pf: AddressContext) {
        let mut page_faults = self.page_faults.borrow_mut();
        if !self.suppressed.contains(&pf) {
            tracing::trace!(va = %pf.va, "page fault");
            page_faults.insert(pf);
        }
        else {
            tracing::trace!(va = %pf.va, "page fault (suppressed)");
        }
    }

    /// Returns the recorded page faults that are not in the `suppressed` set.
    pub fn page_faults(&self) -> IndexSet<AddressContext> {
        &*self.page_faults.borrow() - &self.suppressed
    }

    /// Returns `Err(VmiError::Translation)` carrying the recorded, non-suppressed
    /// page faults, or `Ok(())` if none occurred.
    ///
    /// The returned error is meant to be propagated to a page-fault-injecting
    /// event loop (such as the `vmi-utils` reactor). Injecting these faults
    /// pages the memory in so the probed operation can be retried.
    pub fn error_for_page_faults(&self) -> Result<(), VmiError> {
        let pfs = self.page_faults();
        if !pfs.is_empty() {
            tracing::trace!(?pfs);
            return Err(VmiError::Translation(pfs[0]));
        }

        Ok(())
    }
}

/// Probes a single read expression through a [`VmiProber`], returning
/// `Ok(None)` if it page-faults.
///
/// Shorthand for [`VmiProber::check_result`] over the expression's result.
///
/// [`VmiProber`]: crate::VmiProber
/// [`VmiProber::check_result`]: crate::VmiProber::check_result
#[macro_export]
macro_rules! vmi_probe {
    ($prober:expr, $expr:expr) => {
        $prober.check_result(|| -> Result<_, $crate::VmiError> { $expr }())
    };
}
