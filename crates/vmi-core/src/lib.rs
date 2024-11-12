//! Core VMI functionality.

pub mod arch;
mod core;
mod ctx;
mod driver;
mod error;
mod event;
mod handler;
pub mod os;
mod page;

use std::{cell::RefCell, num::NonZeroUsize, time::Duration};

use isr_macros::Field;
use lru::LruCache;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use self::{
    arch::{Architecture, Registers},
    core::{
        AccessContext, AddressContext, Gfn, Hex, MemoryAccess, MemoryAccessOptions, Pa,
        TranslationMechanism, Va, VcpuId, View, VmiInfo, VmiVa,
    },
    ctx::{VmiContext, VmiOsContext, VmiOsState, VmiProber, VmiSession, VmiState},
    driver::VmiDriver,
    error::{PageFaults, VmiError},
    event::{VmiEvent, VmiEventFlags, VmiEventResponse, VmiEventResponseFlags},
    handler::VmiHandler,
    os::VmiOs,
    page::VmiMappedPage,
};

struct Cache {
    gfn: RefCell<LruCache<Gfn, VmiMappedPage>>,
    v2p: RefCell<LruCache<AccessContext, Pa>>,
}

impl Cache {
    const DEFAULT_SIZE: usize = 8192;

    pub fn new() -> Self {
        Self {
            gfn: RefCell::new(LruCache::new(
                NonZeroUsize::new(Self::DEFAULT_SIZE).unwrap(),
            )),
            v2p: RefCell::new(LruCache::new(
                NonZeroUsize::new(Self::DEFAULT_SIZE).unwrap(),
            )),
        }
    }
}

/// The core functionality for Virtual Machine Introspection (VMI).
pub struct VmiCore<Driver>
where
    Driver: VmiDriver,
{
    driver: Driver,
    cache: Cache,

    read_page_fn: fn(&Self, Gfn) -> Result<VmiMappedPage, VmiError>,
    translate_access_context_fn: fn(&Self, AccessContext) -> Result<Pa, VmiError>,

    read_string_length_limit: RefCell<Option<usize>>,
}

impl<Driver> VmiCore<Driver>
where
    Driver: VmiDriver,
{
    /// Creates a new `VmiCore` instance with the given driver.
    ///
    /// Both the GFN cache and the V2P cache are enabled by default,
    /// each with a capacity of 8192 entries.
    pub fn new(driver: Driver) -> Result<Self, VmiError> {
        Ok(Self {
            driver,
            cache: Cache::new(),
            read_page_fn: Self::read_page_cache,
            translate_access_context_fn: Self::translate_access_context_cache,
            read_string_length_limit: RefCell::new(None),
        })
    }

    /// Enables the Guest Frame Number (GFN) cache.
    ///
    /// The GFN cache stores the contents of recently accessed memory pages,
    /// indexed by their GFN. This can significantly improve performance when
    /// repeatedly accessing the same memory regions, as it avoids redundant
    /// reads from the virtual machine.
    ///
    /// When enabled, subsequent calls to [`read_page`] will first check
    /// the cache before querying the driver.
    ///
    /// # Panics
    ///
    /// Panics if `size` is zero.
    ///
    /// [`read_page`]: Self::read_page
    pub fn with_gfn_cache(self, size: usize) -> Self {
        Self {
            cache: Cache {
                gfn: RefCell::new(LruCache::new(NonZeroUsize::new(size).unwrap())),
                ..self.cache
            },
            read_page_fn: Self::read_page_cache,
            ..self
        }
    }

    /// Enables the GFN cache.
    ///
    /// See [`with_gfn_cache`] for more details.
    ///
    /// [`with_gfn_cache`]: Self::with_gfn_cache
    pub fn enable_gfn_cache(&mut self) {
        self.read_page_fn = Self::read_page_cache;
    }

    /// Disables the GFN cache.
    ///
    /// Subsequent calls to [`read_page`] will bypass the cache and read
    /// directly from the virtual machine.
    ///
    /// [`read_page`]: Self::read_page
    pub fn disable_gfn_cache(&mut self) {
        self.read_page_fn = Self::read_page_nocache;
    }

    /// Resizes the GFN cache.
    ///
    /// This allows you to adjust the cache size dynamically based on your
    /// performance needs. A larger cache can improve performance for
    /// workloads with high memory locality, but consumes more memory.
    ///
    /// # Panics
    ///
    /// Panics if `size` is zero.
    pub fn resize_gfn_cache(&mut self, size: usize) {
        self.cache
            .gfn
            .borrow_mut()
            .resize(NonZeroUsize::new(size).unwrap());
    }

    /// Removes a specific entry from the GFN cache.
    ///
    /// Returns the removed entry if it was present.
    /// This is useful for invalidating cached data that might have
    /// become stale.
    pub fn flush_gfn_cache_entry(&self, gfn: Gfn) -> Option<VmiMappedPage> {
        self.cache.gfn.borrow_mut().pop(&gfn)
    }

    /// Clears the entire GFN cache.
    pub fn flush_gfn_cache(&self) {
        self.cache.gfn.borrow_mut().clear();
    }

    ///// Retrieves metrics about the GFN cache.
    //pub fn gfn_cache_metrics(&self) -> CacheMetrics {
    //    let cache = self.cache.gfn.borrow();
    //    CacheMetrics {
    //        hits: ...,
    //        misses: ...,
    //    }
    //}

    /// Enables the virtual-to-physical (V2P) address translation cache.
    ///
    /// The V2P cache stores the results of recent address translations,
    /// mapping virtual addresses (represented by [`AccessContext`]) to their
    /// corresponding physical addresses ([`Pa`]). This can significantly
    /// speed up memory access operations, as address translation can be a
    /// relatively expensive operation.
    ///
    /// When enabled, [`translate_access_context`] will consult the cache
    /// before performing a full translation.
    ///
    /// # Panics
    ///
    /// Panics if `size` is zero.
    ///
    /// [`translate_access_context`]: Self::translate_access_context
    pub fn with_v2p_cache(self, size: usize) -> Self {
        Self {
            cache: Cache {
                v2p: RefCell::new(LruCache::new(NonZeroUsize::new(size).unwrap())),
                ..self.cache
            },
            translate_access_context_fn: Self::translate_access_context_cache,
            ..self
        }
    }

    /// Enables the V2P cache.
    ///
    /// See [`with_v2p_cache`] for more details.
    ///
    /// [`with_v2p_cache`]: Self::with_v2p_cache
    pub fn enable_v2p_cache(&mut self) {
        self.translate_access_context_fn = Self::translate_access_context_cache;
    }

    /// Disables the V2P cache.
    ///
    /// Subsequent calls to [`translate_access_context`] will bypass the cache
    /// and perform a full address translation every time.
    ///
    /// [`translate_access_context`]: Self::translate_access_context
    pub fn disable_v2p_cache(&mut self) {
        self.translate_access_context_fn = Self::translate_access_context_nocache;
    }

    /// Resizes the V2P cache.
    ///
    /// This allows dynamic adjustment of the cache size to balance
    /// performance and memory usage. A larger cache can lead to better
    /// performance if address translations are frequent and exhibit
    /// good locality.
    ///
    /// # Panics
    ///
    /// Panics if `size` is zero.
    pub fn resize_v2p_cache(&mut self, size: usize) {
        self.cache
            .v2p
            .borrow_mut()
            .resize(NonZeroUsize::new(size).unwrap());
    }

    /// Removes a specific entry from the V2P cache.
    ///
    /// Returns the removed entry if it was present.
    /// This can be used to invalidate cached translations that may have
    /// become stale due to changes in the guest's memory mapping.
    pub fn flush_v2p_cache_entry(&self, ctx: AccessContext) -> Option<Pa> {
        self.cache.v2p.borrow_mut().pop(&ctx)
    }

    /// Clears the entire V2P cache.
    ///
    /// This method is crucial for maintaining consistency when handling events.
    /// The guest operating system can modify page tables or other structures
    /// related to address translation between events. Using stale translations
    /// can lead to incorrect memory access and unexpected behavior.
    /// It is recommended to call this method at the beginning of each
    /// [`VmiHandler::handle_event`] loop to ensure that you are working with
    /// the most up-to-date address mappings.
    pub fn flush_v2p_cache(&self) {
        self.cache.v2p.borrow_mut().clear();
    }

    ///// Retrieves metrics about the V2P cache.
    //pub fn v2p_cache_metrics(&self) -> CacheMetrics {
    //    let cache = self.cache.v2p.borrow();
    //    CacheMetrics {
    //        hits: ...,
    //        misses: ...,
    //    }
    //}

    /// Sets a limit on the length of strings read by the `read_string` methods.
    /// If the limit is reached, the string will be truncated.
    pub fn with_read_string_length_limit(self, limit_in_bytes: usize) -> Self {
        Self {
            read_string_length_limit: RefCell::new(Some(limit_in_bytes)),
            ..self
        }
    }

    /// Returns the current limit on the length of strings read by the
    /// `read_string` methods.
    pub fn read_string_length_limit(&self) -> Option<usize> {
        *self.read_string_length_limit.borrow()
    }

    /// Sets a limit on the length of strings read by the `read_string` methods.
    ///
    /// This method allows you to set a maximum length (in bytes) for strings
    /// read from the virtual machine's memory. When set, string reading
    /// operations will truncate their results to this limit. This can be
    /// useful for preventing excessively long string reads, which might
    /// impact performance or consume too much memory.
    ///
    /// If the limit is reached during a string read operation, the resulting
    /// string will be truncated to the specified length.
    ///
    /// To remove the limit, call this method with `None`.
    pub fn set_read_string_length_limit(&self, limit: usize) {
        *self.read_string_length_limit.borrow_mut() = Some(limit);
    }

    /// Returns the driver used by this `VmiCore` instance.
    pub fn driver(&self) -> &Driver {
        &self.driver
    }

    /// Retrieves information about the virtual machine.
    pub fn info(&self) -> Result<VmiInfo, VmiError> {
        self.driver.info()
    }

    /// Pauses the virtual machine.
    pub fn pause(&self) -> Result<(), VmiError> {
        self.driver.pause()
    }

    /// Resumes the virtual machine.
    pub fn resume(&self) -> Result<(), VmiError> {
        self.driver.resume()
    }

    /// Pauses the virtual machine and returns a guard that will resume it when
    /// dropped.
    pub fn pause_guard(&self) -> Result<VmiPauseGuard<'_, Driver>, VmiError> {
        VmiPauseGuard::new(&self.driver)
    }

    /// Retrieves the current state of CPU registers for a specified virtual
    /// CPU.
    ///
    /// This method allows you to access the current values of CPU registers,
    /// which is crucial for understanding the state of the virtual machine
    /// at a given point in time.
    ///
    /// # Notes
    ///
    /// The exact structure and content of the returned registers depend on the
    /// specific architecture of the VM being introspected. Refer to the
    /// documentation of your [`Architecture`] implementation for details on
    /// how to interpret the register values.
    pub fn registers(
        &self,
        vcpu: VcpuId,
    ) -> Result<<Driver::Architecture as Architecture>::Registers, VmiError> {
        self.driver.registers(vcpu)
    }

    /// Sets the registers of a virtual CPU.
    pub fn set_registers(
        &self,
        vcpu: VcpuId,
        registers: <Driver::Architecture as Architecture>::Registers,
    ) -> Result<(), VmiError> {
        self.driver.set_registers(vcpu, registers)
    }

    /// Retrieves the memory access permissions for a specific guest frame
    /// number (GFN).
    ///
    /// The returned `MemoryAccess` indicates the current read, write, and
    /// execute permissions for the specified memory page in the given view.
    pub fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        self.driver.memory_access(gfn, view)
    }

    /// Sets the memory access permissions for a specific guest frame number
    /// (GFN).
    ///
    /// This method allows you to modify the read, write, and execute
    /// permissions for a given memory page in the specified view.
    pub fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        self.driver.set_memory_access(gfn, view, access)
    }

    /// Sets the memory access permissions for a specific guest frame number
    /// (GFN) with additional options.
    ///
    /// In addition to the basic read, write, and execute permissions, this
    /// method allows you to specify additional options for the memory access.
    pub fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        self.driver
            .set_memory_access_with_options(gfn, view, access, options)
    }

    /// Allocates the next available guest frame number (GFN).
    ///
    /// This method finds and allocates the next free GFN after the current
    /// maximum GFN. It's useful when you need to allocate new memory pages
    /// for the VM.
    pub fn allocate_next_available_gfn(&self) -> Result<Gfn, VmiError> {
        let info = self.info()?;

        let next_available_gfn = info.max_gfn + 1;
        self.allocate_gfn(next_available_gfn)?;
        Ok(next_available_gfn)
    }

    /// Allocates a specific guest frame number (GFN).
    ///
    /// This method allows you to allocate a particular GFN. It's useful when
    /// you need to allocate a specific memory page for the VM.
    pub fn allocate_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.driver.allocate_gfn(gfn)
    }

    /// Frees a previously allocated guest frame number (GFN).
    ///
    /// This method deallocates a GFN that was previously allocated. It's
    /// important to free GFNs when they're no longer needed to prevent
    /// memory leaks in the VM.
    pub fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.driver.free_gfn(gfn)
    }

    /// Returns the default view for the virtual machine.
    ///
    /// The default view typically represents the normal, unmodified state of
    /// the VM's memory.
    pub fn default_view(&self) -> View {
        self.driver.default_view()
    }

    /// Creates a new view with the specified default access permissions.
    ///
    /// Views allow for creating different perspectives of the VM's memory,
    /// which can be useful for analysis or isolation purposes. The default
    /// access permissions apply to memory pages not explicitly modified
    /// within this view.
    pub fn create_view(&self, default_access: MemoryAccess) -> Result<View, VmiError> {
        self.driver.create_view(default_access)
    }

    /// Destroys a previously created view.
    ///
    /// This method removes a view and frees associated resources. It should be
    /// called when a view is no longer needed to prevent resource leaks.
    pub fn destroy_view(&self, view: View) -> Result<(), VmiError> {
        self.driver.destroy_view(view)
    }

    /// Switches to a different view for all virtual CPUs.
    ///
    /// This method changes the current active view for all vCPUs, affecting
    /// subsequent memory operations across the entire VM. It allows for
    /// quick transitions between different memory perspectives globally.
    ///
    /// Note the difference between this method and
    /// [`VmiEventResponse::set_view()`]:
    /// - `switch_to_view()` changes the view for all vCPUs immediately.
    /// - `VmiEventResponse::set_view()` sets the view only for the specific
    ///   vCPU that received the event, and the change is applied when the event
    ///   handler returns.
    ///
    /// Use `switch_to_view()` for global view changes, and
    /// `VmiEventResponse::set_view()` for targeted, event-specific view
    /// modifications on individual vCPUs.
    pub fn switch_to_view(&self, view: View) -> Result<(), VmiError> {
        self.driver.switch_to_view(view)
    }

    /// Changes the mapping of a guest frame number (GFN) in a specific view.
    ///
    /// This method allows for remapping a GFN to a different physical frame
    /// within a view, enabling fine-grained control over memory layout in
    /// different views.
    ///
    /// A notable use case for this method is implementing "stealth hooks":
    /// 1. Create a new GFN and copy the contents of the original page to it.
    /// 2. Modify the new page by installing a breakpoint (e.g., 0xcc on AMD64)
    ///    at a strategic location.
    /// 3. Use this method to change the mapping of the original GFN to the new
    ///    one.
    /// 4. Set the memory access of the new GFN to non-readable.
    ///
    /// When a read access occurs:
    /// - The handler should enable single-stepping.
    /// - Switch to an unmodified view (e.g., `default_view`) to execute the
    ///   read instruction, which will read the original non-breakpoint byte.
    /// - Re-enable single-stepping afterwards.
    ///
    /// This technique allows for transparent breakpoints that are difficult to
    /// detect by the guest OS or applications.
    pub fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        self.driver.change_view_gfn(view, old_gfn, new_gfn)
    }

    /// Resets the mapping of a guest frame number (GFN) in a specific view to
    /// its original state.
    ///
    /// This method reverts any custom mapping for the specified GFN in the
    /// given view, restoring it to the default mapping.
    pub fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        self.driver.reset_view_gfn(view, gfn)
    }

    /// Enables monitoring of specific events.
    ///
    /// This method allows you to enable monitoring of specific events, such as
    /// control register writes, interrupts, or single-step execution.
    /// Monitoring events can be useful for tracking specific guest behavior or
    /// for implementing custom analysis tools.
    ///
    /// The type of event to monitor is defined by the architecture-specific
    /// [`Architecture::EventMonitor`] type.
    ///
    /// When an event occurs, it will be passed to the event callback function
    /// for processing.
    pub fn monitor_enable(
        &self,
        option: <Driver::Architecture as Architecture>::EventMonitor,
    ) -> Result<(), VmiError> {
        self.driver.monitor_enable(option)
    }

    /// Disables monitoring of specific events.
    ///
    /// This method allows you to disable monitoring of specific events that
    /// were previously enabled. It can be used to stop tracking certain
    /// hardware events or to reduce the overhead of event processing.
    ///
    /// The type of event to disable is defined by the architecture-specific
    /// [`Architecture::EventMonitor`] type.
    pub fn monitor_disable(
        &self,
        option: <Driver::Architecture as Architecture>::EventMonitor,
    ) -> Result<(), VmiError> {
        self.driver.monitor_disable(option)
    }

    /// Injects an interrupt into a specific virtual CPU.
    ///
    /// This method allows for the injection of architecture-specific interrupts
    /// into a given vCPU. It can be used to simulate hardware events or to
    /// manipulate the guest's execution flow for analysis purposes.
    ///
    /// The type of interrupt and its parameters are defined by the
    /// architecture-specific [`Architecture::Interrupt`] type.
    pub fn inject_interrupt(
        &self,
        vcpu: VcpuId,
        interrupt: <Driver::Architecture as Architecture>::Interrupt,
    ) -> Result<(), VmiError> {
        self.driver.inject_interrupt(vcpu, interrupt)
    }

    /// Returns the number of pending events.
    ///
    /// This method provides a count of events that have occurred but have not
    /// yet been processed.
    pub fn events_pending(&self) -> usize {
        self.driver.events_pending()
    }

    /// Returns the time spent processing events by the driver.
    ///
    /// This method provides a measure of the overhead introduced by event
    /// processing. It can be useful for performance tuning and
    /// understanding the impact of VMI operations on overall system
    /// performance.
    pub fn event_processing_overhead(&self) -> Duration {
        self.driver.event_processing_overhead()
    }

    /// Waits for an event to occur and processes it with the provided handler.
    ///
    /// This method blocks until an event occurs or the specified timeout is
    /// reached. When an event occurs, it is passed to the provided callback
    /// function for processing.
    pub fn wait_for_event(
        &self,
        timeout: Duration,
        handler: impl FnMut(&VmiEvent<Driver::Architecture>) -> VmiEventResponse<Driver::Architecture>,
    ) -> Result<(), VmiError> {
        self.driver.wait_for_event(timeout, handler)
    }

    /// Resets the state of the VMI system.
    ///
    /// This method clears all event monitors, caches, and any other stateful
    /// data maintained by the VMI system. It's useful for bringing the VMI
    /// system back to a known clean state, which can be necessary when
    /// switching between different analysis tasks or recovering from error
    /// conditions.
    pub fn reset_state(&self) -> Result<(), VmiError> {
        self.driver.reset_state()
    }

    /// Reads memory from the virtual machine.
    pub fn read(&self, ctx: impl Into<AccessContext>, buffer: &mut [u8]) -> Result<(), VmiError> {
        let ctx = ctx.into();
        let mut position = 0usize;
        let mut remaining = buffer.len();

        while remaining > 0 {
            let address = self.translate_access_context(ctx + position as u64)?;
            let gfn = Driver::Architecture::gfn_from_pa(address);
            let offset = Driver::Architecture::pa_offset(address) as usize;

            let page = self.read_page(gfn)?;
            let page = &page[offset..];

            let size = std::cmp::min(remaining, page.len());
            buffer[position..position + size].copy_from_slice(&page[..size]);

            position += size;
            remaining -= size;
        }

        Ok(())
    }

    /// Writes memory to the virtual machine.
    pub fn write(&self, ctx: impl Into<AccessContext>, buffer: &[u8]) -> Result<(), VmiError> {
        let ctx = ctx.into();
        let mut position = 0usize;
        let mut remaining = buffer.len();

        let page_size = self.info()?.page_size;

        while remaining > 0 {
            let address = self.translate_access_context(ctx + position as u64)?;
            let gfn = Driver::Architecture::gfn_from_pa(address);
            let offset = Driver::Architecture::pa_offset(address);

            let size = std::cmp::min(remaining, (page_size - offset) as usize);
            let content = &buffer[position..position + size];

            self.driver.write_page(gfn, offset, content)?;

            position += size;
            remaining -= size;
        }

        Ok(())
    }

    /// Reads a single byte from the virtual machine.
    pub fn read_u8(&self, ctx: impl Into<AccessContext>) -> Result<u8, VmiError> {
        let mut buffer = [0u8; 1];
        self.read(ctx, &mut buffer)?;
        Ok(buffer[0])
    }

    /// Reads a 16-bit unsigned integer from the virtual machine.
    pub fn read_u16(&self, ctx: impl Into<AccessContext>) -> Result<u16, VmiError> {
        let mut buffer = [0u8; 2];
        self.read(ctx, &mut buffer)?;
        Ok(u16::from_le_bytes(buffer))
    }

    /// Reads a 32-bit unsigned integer from the virtual machine.
    pub fn read_u32(&self, ctx: impl Into<AccessContext>) -> Result<u32, VmiError> {
        let mut buffer = [0u8; 4];
        self.read(ctx, &mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }

    /// Reads a 64-bit unsigned integer from the virtual machine.
    pub fn read_u64(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        let mut buffer = [0u8; 8];
        self.read(ctx, &mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }

    /// Reads an unsigned integer of the specified size from the virtual machine.
    ///
    /// This method reads an unsigned integer of the specified size (in bytes)
    /// from the virtual machine. Note that the size must be 1, 2, 4, or 8.
    ///
    /// The result is returned as a [`u64`] to accommodate the widest possible
    /// integer size.
    pub fn read_uint(&self, ctx: impl Into<AccessContext>, size: usize) -> Result<u64, VmiError> {
        match size {
            1 => self.read_u8(ctx).map(u64::from),
            2 => self.read_u16(ctx).map(u64::from),
            4 => self.read_u32(ctx).map(u64::from),
            8 => self.read_u64(ctx),
            _ => Err(VmiError::InvalidAddressWidth),
        }
    }

    /// Reads a field of a structure from the virtual machine.
    ///
    /// This method reads a field from the virtual machine. The field is
    /// defined by the provided [`Field`] structure, which specifies the
    /// offset and size of the field within the memory region.
    ///
    /// The result is returned as a [`u64`] to accommodate the widest possible
    /// integer size.
    pub fn read_field(
        &self,
        ctx: impl Into<AccessContext>,
        field: &Field,
    ) -> Result<u64, VmiError> {
        self.read_uint(ctx.into() + field.offset(), field.size() as usize)
    }

    /// Reads an address-sized unsigned integer from the virtual machine.
    ///
    /// This method reads an address of the specified width (in bytes) from
    /// the given access context. It's useful when dealing with architectures
    /// that can operate in different address modes.
    pub fn read_address(
        &self,
        ctx: impl Into<AccessContext>,
        address_width: usize,
    ) -> Result<u64, VmiError> {
        match address_width {
            4 => self.read_address32(ctx),
            8 => self.read_address64(ctx),
            _ => Err(VmiError::InvalidAddressWidth),
        }
    }

    /// Reads a 32-bit address from the virtual machine.
    pub fn read_address32(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        Ok(self.read_u32(ctx)? as u64)
    }

    /// Reads a 64-bit address from the virtual machine.
    pub fn read_address64(&self, ctx: impl Into<AccessContext>) -> Result<u64, VmiError> {
        self.read_u64(ctx)
    }

    /// Reads a virtual address from the virtual machine.
    pub fn read_va(
        &self,
        ctx: impl Into<AccessContext>,
        address_width: usize,
    ) -> Result<Va, VmiError> {
        Ok(Va(self.read_address(ctx, address_width)?))
    }

    /// Reads a 32-bit virtual address from the virtual machine.
    pub fn read_va32(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        Ok(Va(self.read_address32(ctx)?))
    }

    /// Reads a 64-bit virtual address from the virtual machine.
    pub fn read_va64(&self, ctx: impl Into<AccessContext>) -> Result<Va, VmiError> {
        Ok(Va(self.read_address64(ctx)?))
    }

    /// Reads a null-terminated string of bytes from the virtual machine with a
    /// specified limit.
    pub fn read_string_bytes_limited(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<Vec<u8>, VmiError> {
        let mut ctx = ctx.into();

        // read until the end of page
        let mut buffer = vec![
            0u8;
            (Driver::Architecture::PAGE_SIZE - (ctx.address & !Driver::Architecture::PAGE_MASK))
                as usize
        ];
        self.read(ctx, &mut buffer)?;

        // try to find the null terminator
        let position = buffer.iter().position(|&b| b == 0);

        if let Some(position) = position {
            buffer.truncate(limit.min(position));
            return Ok(buffer);
        }

        let mut page = [0u8; 4096_usize]; // FIXME: Driver::Architecture::PAGE_SIZE
        loop {
            ctx.address += buffer.len() as u64;
            self.read(ctx, &mut page)?;

            let position = page.iter().position(|&b| b == 0);

            if let Some(position) = position {
                buffer.extend_from_slice(&page[..position]);

                if buffer.len() >= limit {
                    buffer.truncate(limit);
                }

                break;
            }

            buffer.extend_from_slice(&page);

            if buffer.len() >= limit {
                buffer.truncate(limit);
                break;
            }
        }

        Ok(buffer)
    }

    /// Reads a null-terminated string of bytes from the virtual machine.
    pub fn read_string_bytes(&self, ctx: impl Into<AccessContext>) -> Result<Vec<u8>, VmiError> {
        self.read_string_bytes_limited(
            ctx,
            self.read_string_length_limit.borrow().unwrap_or(usize::MAX),
        )
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine
    /// with a specified limit.
    pub fn read_wstring_bytes_limited(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<Vec<u16>, VmiError> {
        let mut ctx = ctx.into();

        // read until the end of page
        let mut buffer = vec![
            0u8;
            (Driver::Architecture::PAGE_SIZE - (ctx.address & !Driver::Architecture::PAGE_MASK))
                as usize
        ];
        self.read(ctx, &mut buffer)?;

        // try to find the null terminator
        let position = buffer
            .chunks_exact(2)
            .position(|chunk| chunk[0] == 0 && chunk[1] == 0);

        if let Some(position) = position {
            buffer.truncate(limit.min(position * 2));
            return Ok(buffer
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect());
        }

        let mut page = [0u8; 4096_usize]; // FIXME: Driver::Architecture::PAGE_SIZE
        loop {
            ctx.address += buffer.len() as u64;
            self.read(ctx, &mut page)?;

            let position = page
                .chunks_exact(2)
                .position(|chunk| chunk[0] == 0 && chunk[1] == 0);

            if let Some(position) = position {
                buffer.extend_from_slice(&page[..position * 2]);

                if buffer.len() >= limit {
                    buffer.truncate(limit);
                }

                break;
            }

            buffer.extend_from_slice(&page);

            if buffer.len() >= limit {
                buffer.truncate(limit);
                break;
            }
        }

        Ok(buffer
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect())
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring_bytes(&self, ctx: impl Into<AccessContext>) -> Result<Vec<u16>, VmiError> {
        self.read_wstring_bytes_limited(
            ctx,
            self.read_string_length_limit.borrow().unwrap_or(usize::MAX),
        )
    }

    /// Reads a null-terminated string from the virtual machine with a specified
    /// limit.
    pub fn read_string_limited(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<String, VmiError> {
        Ok(String::from_utf8_lossy(&self.read_string_bytes_limited(ctx, limit)?).into())
    }

    /// Reads a null-terminated string from the virtual machine.
    pub fn read_string(&self, ctx: impl Into<AccessContext>) -> Result<String, VmiError> {
        self.read_string_limited(
            ctx,
            self.read_string_length_limit.borrow().unwrap_or(usize::MAX),
        )
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine
    /// with a specified limit.
    pub fn read_wstring_limited(
        &self,
        ctx: impl Into<AccessContext>,
        limit: usize,
    ) -> Result<String, VmiError> {
        Ok(String::from_utf16_lossy(
            &self.read_wstring_bytes_limited(ctx, limit)?,
        ))
    }

    /// Reads a null-terminated wide string (UTF-16) from the virtual machine.
    pub fn read_wstring(&self, ctx: impl Into<AccessContext>) -> Result<String, VmiError> {
        self.read_wstring_limited(
            ctx,
            self.read_string_length_limit.borrow().unwrap_or(usize::MAX),
        )
    }

    /// Reads a struct from the virtual machine.
    pub fn read_struct<T>(&self, ctx: impl Into<AccessContext>) -> Result<T, VmiError>
    where
        T: FromBytes + IntoBytes,
    {
        let mut result = T::new_zeroed();
        self.read(ctx, result.as_mut_bytes())?;
        Ok(result)
    }

    /// Writes a single byte to the virtual machine.
    pub fn write_u8(&self, ctx: impl Into<AccessContext>, value: u8) -> Result<(), VmiError> {
        self.write(ctx, &value.to_le_bytes())
    }

    /// Writes a 16-bit unsigned integer to the virtual machine.
    pub fn write_u16(&self, ctx: impl Into<AccessContext>, value: u16) -> Result<(), VmiError> {
        self.write(ctx, &value.to_le_bytes())
    }

    /// Writes a 32-bit unsigned integer to the virtual machine.
    pub fn write_u32(&self, ctx: impl Into<AccessContext>, value: u32) -> Result<(), VmiError> {
        self.write(ctx, &value.to_le_bytes())
    }

    /// Writes a 64-bit unsigned integer to the virtual machine.
    pub fn write_u64(&self, ctx: impl Into<AccessContext>, value: u64) -> Result<(), VmiError> {
        self.write(ctx, &value.to_le_bytes())
    }

    /// Writes a struct to the virtual machine.
    pub fn write_struct<T>(&self, ctx: impl Into<AccessContext>, value: T) -> Result<(), VmiError>
    where
        T: IntoBytes + Immutable,
    {
        self.write(ctx, value.as_bytes())
    }

    /// Translates a virtual address to a physical address.
    pub fn translate_address(&self, ctx: impl Into<AddressContext>) -> Result<Pa, VmiError> {
        self.translate_access_context(AccessContext::from(ctx.into()))
    }

    /// Translates an access context to a physical address.
    pub fn translate_access_context(&self, ctx: AccessContext) -> Result<Pa, VmiError> {
        (self.translate_access_context_fn)(self, ctx)
    }

    /// Reads a page of memory from the virtual machine.
    pub fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        (self.read_page_fn)(self, gfn)
    }

    /// Reads a page of memory from the virtual machine without using the cache.
    fn read_page_nocache(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        self.driver.read_page(gfn)
    }

    /// Reads a page of memory from the virtual machine, using the cache if
    /// enabled.
    fn read_page_cache(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        let mut cache = self.cache.gfn.borrow_mut();
        let value = cache.try_get_or_insert(gfn, || self.read_page_nocache(gfn))?;

        // Mapped pages are reference counted, so cloning it is cheap.
        Ok(value.clone())
    }

    /// Translates an access context to a physical address without using the
    /// cache.
    ///
    /// # Notes
    ///
    /// If [`TranslationMechanism::Paging`] is used, the `root` must be present.
    /// In case the root is not present, a [`VmiError::RootNotPresent`] error is
    /// returned.
    fn translate_access_context_nocache(&self, ctx: AccessContext) -> Result<Pa, VmiError> {
        Ok(match ctx.mechanism {
            TranslationMechanism::Direct => Pa(ctx.address),
            TranslationMechanism::Paging { root } => match root {
                Some(root) => <Driver::Architecture as Architecture>::translate_address(
                    self,
                    ctx.address.into(),
                    root,
                )?,
                None => return Err(VmiError::RootNotPresent),
            },
        })
    }

    /// Translates an access context to a physical address, using the cache if
    /// enabled.
    fn translate_access_context_cache(&self, ctx: AccessContext) -> Result<Pa, VmiError> {
        let mut cache = self.cache.v2p.borrow_mut();
        let value = cache.try_get_or_insert(ctx, || self.translate_access_context_nocache(ctx))?;
        Ok(*value)
    }
}

/// A guard that pauses the virtual machine on creation and resumes it on drop.
pub struct VmiPauseGuard<'a, Driver>
where
    Driver: VmiDriver,
{
    driver: &'a Driver,
}

impl<'a, Driver> VmiPauseGuard<'a, Driver>
where
    Driver: VmiDriver,
{
    /// Creates a new pause guard.
    pub fn new(driver: &'a Driver) -> Result<Self, VmiError> {
        driver.pause()?;
        Ok(Self { driver })
    }
}

impl<Driver> Drop for VmiPauseGuard<'_, Driver>
where
    Driver: VmiDriver,
{
    fn drop(&mut self) {
        if let Err(err) = self.driver.resume() {
            tracing::error!(?err, "Failed to resume the virtual machine");
        }
    }
}
