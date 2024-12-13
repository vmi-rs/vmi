use std::{cell::RefCell, io::ErrorKind, rc::Rc, time::Duration};

use indexmap::IndexSet;
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    context::VmiContext, os::VmiOs, AccessContext, Architecture, PageFault, PageFaults,
    TranslationMechanism, Va, VmiCore, VmiDriver, VmiError, VmiHandler,
};

/// A VMI session.
///
/// The session combines a [`VmiCore`] with an OS-specific [`VmiOs`]
/// implementation to provide unified access to both low-level VMI operations
/// and higher-level OS abstractions.
pub struct VmiSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI core providing low-level VM introspection capabilities.
    pub(crate) core: &'a VmiCore<Driver>,

    /// The OS-specific operations and abstractions.
    pub(crate) os: &'a Os,
}

impl<Driver, Os> std::ops::Deref for VmiSession<'_, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    type Target = VmiCore<Driver>;

    fn deref(&self) -> &Self::Target {
        self.core
    }
}

impl<'a, Driver, Os> VmiSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new VMI session.
    pub fn new(core: &'a VmiCore<Driver>, os: &'a Os) -> Self {
        Self { core, os }
    }

    /// Returns the VMI core.
    pub fn core(&self) -> &VmiCore<Driver> {
        self.core
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &Os {
        self.os
    }

    /// Returns a wrapper providing access to the OS-specific operations.
    pub fn os(&self) -> VmiOsSession<Driver, Os> {
        VmiOsSession {
            core: self.core,
            os: self.os,
        }
    }

    /// Creates a prober for safely handling page faults during memory access operations.
    pub fn prober(&'a self, restricted: &IndexSet<PageFault>) -> VmiSessionProber<'a, Driver, Os> {
        VmiSessionProber::new(self, restricted)
    }

    /// Waits for an event to occur and processes it with the provided handler.
    ///
    /// This method blocks until an event occurs or the specified timeout is
    /// reached. When an event occurs, it is passed to the provided callback
    /// function for processing.
    pub fn wait_for_event(
        &self,
        timeout: Duration,
        handler: &mut impl VmiHandler<Driver, Os>,
    ) -> Result<(), VmiError> {
        self.core.wait_for_event(timeout, |event| {
            handler.handle_event(VmiContext::new(self, event))
        })
    }

    /// Enters the main event handling loop that processes VMI events until
    /// finished.
    pub fn handle<Handler>(
        &self,
        handler_factory: impl FnOnce(&VmiSession<Driver, Os>) -> Result<Handler, VmiError>,
    ) -> Result<Option<Handler::Output>, VmiError>
    where
        Handler: VmiHandler<Driver, Os>,
    {
        self.handle_with_timeout(Duration::from_millis(5000), handler_factory)
    }

    /// Enters the main event handling loop that processes VMI events until
    /// finished, with a timeout for each event.
    pub fn handle_with_timeout<Handler>(
        &self,
        timeout: Duration,
        handler_factory: impl FnOnce(&VmiSession<Driver, Os>) -> Result<Handler, VmiError>,
    ) -> Result<Option<Handler::Output>, VmiError>
    where
        Handler: VmiHandler<Driver, Os>,
    {
        let mut result;
        let mut handler = handler_factory(self)?;

        loop {
            result = handler.check_completion();

            if result.is_some() {
                break;
            }

            match self.wait_for_event(timeout, &mut handler) {
                Err(VmiError::Timeout) => {
                    tracing::trace!("timeout");
                    handler.handle_timeout(self);
                }
                Err(VmiError::Io(err)) if err.kind() == ErrorKind::Interrupted => {
                    tracing::trace!("interrupted");
                    handler.handle_interrupted(self);
                    break;
                }
                Err(err) => return Err(err),
                Ok(_) => {}
            }
        }

        tracing::trace!("disabling monitor");
        self.core.reset_state()?;
        tracing::trace!(pending_events = self.events_pending());

        let _pause_guard = self.pause_guard()?;
        if self.events_pending() > 0 {
            match self.wait_for_event(Duration::from_millis(0), &mut handler) {
                Err(VmiError::Timeout) => {
                    tracing::trace!("timeout");
                }
                Err(err) => return Err(err),
                Ok(_) => {}
            }
        }

        Ok(result)
    }
}

/// Wrapper providing access to OS-specific operations.
pub struct VmiOsSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI core providing low-level VM introspection capabilities.
    pub(crate) core: &'a VmiCore<Driver>,

    /// The OS-specific operations and abstractions.
    pub(crate) os: &'a Os,
}

impl<'a, Driver, Os> VmiOsSession<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Returns the VMI session.
    pub fn core(&self) -> &'a VmiCore<Driver> {
        self.core
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &'a Os {
        self.os
    }
}

/// Prober for safely handling page faults during memory access operations.
pub struct VmiSessionProber<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// The VMI session.
    pub(crate) session: &'a VmiSession<'a, Driver, Os>,

    /// The set of restricted page faults that are allowed to occur.
    pub(crate) restricted: Rc<IndexSet<PageFault>>,

    /// The set of page faults that have occurred.
    pub(crate) page_faults: Rc<RefCell<IndexSet<PageFault>>>,
}

impl<'a, Driver, Os> std::ops::Deref for VmiSessionProber<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    type Target = VmiSession<'a, Driver, Os>;

    fn deref(&self) -> &Self::Target {
        self.session
    }
}

impl<'a, Driver, Os> VmiSessionProber<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Creates a new VMI session prober.
    pub fn new(session: &'a VmiSession<Driver, Os>, restricted: &IndexSet<PageFault>) -> Self {
        Self {
            session,
            restricted: Rc::new(restricted.clone()),
            page_faults: Rc::new(RefCell::new(IndexSet::new())),
        }
    }

    /// Checks for any unexpected page faults that have occurred and returns an error if any are present.
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

    /// Returns a wrapper providing access to OS-specific operations.
    pub fn os(&self) -> VmiOsSessionProber<Driver, Os> {
        VmiOsSessionProber(self)
    }

    /// Reads memory from the virtual machine.
    pub fn read(
        &self,
        ctx: impl Into<AccessContext>,
        buffer: &mut [u8],
    ) -> Result<Option<()>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read(ctx, buffer), ctx, buffer.len())
    }

    /// Reads a single byte from the virtual machine.
    pub fn read_u8(&self, ctx: impl Into<AccessContext>) -> Result<Option<u8>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_u8(ctx), ctx, size_of::<u8>())
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    pub fn read_u16(&self, ctx: impl Into<AccessContext>) -> Result<Option<u16>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_u16(ctx), ctx, size_of::<u16>())
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    pub fn read_u32(&self, ctx: impl Into<AccessContext>) -> Result<Option<u32>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_u32(ctx), ctx, size_of::<u32>())
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    pub fn read_u64(&self, ctx: impl Into<AccessContext>) -> Result<Option<u64>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_u64(ctx), ctx, size_of::<u64>())
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va(
        &self,
        ctx: impl Into<AccessContext>,
        address_width: usize,
    ) -> Result<Option<Va>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(
            self.session.core().read_va(ctx, address_width),
            ctx,
            address_width,
        )
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    pub fn read_va32(&self, ctx: impl Into<AccessContext>) -> Result<Option<Va>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_va32(ctx), ctx, size_of::<u32>())
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    pub fn read_va64(&self, ctx: impl Into<AccessContext>) -> Result<Option<Va>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_va64(ctx), ctx, size_of::<u64>())
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    pub fn read_string_bytes(
        &self,
        ctx: impl Into<AccessContext>,
    ) -> Result<Option<Vec<u8>>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_string_bytes(ctx), ctx, 1)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring_bytes(
        &self,
        ctx: impl Into<AccessContext>,
    ) -> Result<Option<Vec<u16>>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_wstring_bytes(ctx), ctx, 2)
    }

    /// Reads a null-terminated string from the virtual machine.
    pub fn read_string(&self, ctx: impl Into<AccessContext>) -> Result<Option<String>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_string(ctx), ctx, 1)
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring(&self, ctx: impl Into<AccessContext>) -> Result<Option<String>, VmiError> {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_wstring(ctx), ctx, 2)
    }

    /// Reads a struct from the virtual machine.
    pub fn read_struct<T>(&self, ctx: impl Into<AccessContext>) -> Result<Option<T>, VmiError>
    where
        T: IntoBytes + FromBytes,
    {
        let ctx = ctx.into();
        self.check_result_range(self.session.core().read_struct(ctx), ctx, size_of::<T>())
    }

    /// Handles a result that may contain page faults, returning the value if successful.
    pub fn check_result<T>(&self, result: Result<T, VmiError>) -> Result<Option<T>, VmiError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(VmiError::PageFault(pfs)) => {
                self.check_restricted(pfs);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Handles a result that may contain page faults over a memory range, returning the value if successful.
    fn check_result_range<T>(
        &self,
        result: Result<T, VmiError>,
        ctx: AccessContext,
        length: usize,
    ) -> Result<Option<T>, VmiError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(VmiError::PageFault(pfs)) => {
                debug_assert_eq!(pfs.len(), 1);
                self.check_restricted_range(pfs[0], ctx, length);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Records any page faults that are not in the restricted set.
    fn check_restricted(&self, pfs: PageFaults) {
        let mut page_faults = self.page_faults.borrow_mut();
        for pf in pfs {
            if !self.restricted.contains(&pf) {
                tracing::trace!(va = %pf.address, "page fault");
                page_faults.insert(pf);
            }
            else {
                tracing::trace!(va = %pf.address, "page fault (restricted)");
            }
        }
    }

    /// Records any page faults that are not in the restricted set over a memory range.
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
}

/// Wrapper providing access to OS-specific operations with page fault handling.
pub struct VmiOsSessionProber<'a, Driver, Os>(pub(crate) &'a VmiSessionProber<'a, Driver, Os>)
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>;

impl<'a, Driver, Os> VmiOsSessionProber<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
{
    /// Returns the VMI session prober.
    pub fn core(&self) -> &'a VmiSessionProber<'a, Driver, Os> {
        self.0
    }

    /// Returns the underlying OS-specific implementation.
    pub fn underlying_os(&self) -> &'a Os {
        self.0.os
    }

    /*
    pub fn function_argument_for_registers(
        &self,
        regs: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<Option<u64>, VmiError> {
        self.0
            .check_result(self.0.context.session().os().function_argument(regs, index))
    }

    pub fn function_return_value_for_registers(
        &self,
        regs: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<u64>, VmiError> {
        self.0
            .check_result(self.0.context.session.os().function_return_value(regs))
    }
     */
}
