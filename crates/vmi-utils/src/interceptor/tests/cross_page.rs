//! Verifies breakpoint boundary handling with a multi-byte instruction.

use vmi_core::{
    AccessContext, AddressContext, Architecture, Gfn, MemoryAccess, Pa, Va, VcpuId, View, VmiCore,
    VmiDriver, VmiError, VmiInfo, VmiMappedPage, VmiRead, VmiViewControl, VmiVmControl, VmiWrite,
    arch::{
        EventInterrupt as EventInterruptTrait, EventMemoryAccess as EventMemoryAccessTrait,
        EventReason as EventReasonTrait, GpRegisters as GpRegistersTrait,
        Registers as RegistersTrait,
    },
};

use super::super::Interceptor;

/// Architecture with a two-byte software-breakpoint instruction.
#[derive(Debug)]
struct BoundaryArchitecture;

/// General-purpose registers required by the boundary architecture.
#[derive(Debug, Default, Clone, Copy)]
struct BoundaryGpRegisters {
    /// Instruction pointer.
    ip: u64,

    /// Stack pointer.
    sp: u64,

    /// Function result register.
    result: u64,
}

impl GpRegistersTrait for BoundaryGpRegisters {
    type Architecture = BoundaryArchitecture;

    fn instruction_pointer(&self) -> u64 {
        self.ip
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.ip = ip;
    }

    fn stack_pointer(&self) -> u64 {
        self.sp
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        self.sp = sp;
    }

    fn result(&self) -> u64 {
        self.result
    }

    fn set_result(&mut self, result: u64) {
        self.result = result;
    }
}

/// Complete register state required by the boundary architecture.
#[derive(Debug, Default, Clone, Copy)]
struct BoundaryRegisters {
    /// General-purpose register state.
    gp: BoundaryGpRegisters,

    /// Current translation root.
    root: Pa,
}

impl RegistersTrait for BoundaryRegisters {
    type Architecture = BoundaryArchitecture;
    type GpRegisters = BoundaryGpRegisters;

    fn instruction_pointer(&self) -> u64 {
        self.gp.instruction_pointer()
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.gp.set_instruction_pointer(ip);
    }

    fn stack_pointer(&self) -> u64 {
        self.gp.stack_pointer()
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        self.gp.set_stack_pointer(sp);
    }

    fn result(&self) -> u64 {
        self.gp.result()
    }

    fn set_result(&mut self, result: u64) {
        self.gp.set_result(result);
    }

    fn gp_registers(&self) -> Self::GpRegisters {
        self.gp
    }

    fn set_gp_registers(&mut self, gp: &Self::GpRegisters) {
        self.gp = *gp;
    }

    fn address_width(&self) -> usize {
        8
    }

    fn effective_address_width(&self) -> usize {
        8
    }

    fn access_context(&self, va: Va) -> AccessContext {
        AccessContext::paging(va, self.root)
    }

    fn address_context(&self, va: Va) -> AddressContext {
        AddressContext::new(va, self.root)
    }

    fn translation_root(&self, _va: Va) -> Pa {
        self.root
    }

    fn set_translation_root(&mut self, root: u64, _va: Va) {
        self.root = Pa(root);
    }

    fn return_address<Driver>(&self, _vmi: &VmiCore<Driver>) -> Result<Va, VmiError>
    where
        Driver: VmiRead<Architecture = Self::Architecture>,
    {
        Err(VmiError::NotSupported)
    }
}

/// Placeholder memory-access event required by the architecture trait.
#[derive(Debug, Clone, Copy)]
struct BoundaryMemoryAccess;

impl EventMemoryAccessTrait for BoundaryMemoryAccess {
    type Architecture = BoundaryArchitecture;

    fn pa(&self) -> Pa {
        Pa(0)
    }

    fn va(&self) -> Va {
        Va(0)
    }

    fn access(&self) -> MemoryAccess {
        MemoryAccess::RWX
    }
}

/// Placeholder interrupt event required by the architecture trait.
#[derive(Debug, Clone, Copy)]
struct BoundaryInterrupt;

impl EventInterruptTrait for BoundaryInterrupt {
    type Architecture = BoundaryArchitecture;

    fn gfn(&self) -> Gfn {
        Gfn(0)
    }
}

/// Placeholder event reason required by the architecture trait.
#[derive(Debug, Clone, Copy)]
struct BoundaryEventReason;

impl EventReasonTrait for BoundaryEventReason {
    type Architecture = BoundaryArchitecture;

    fn as_memory_access(
        &self,
    ) -> Option<&impl EventMemoryAccessTrait<Architecture = Self::Architecture>> {
        None::<&BoundaryMemoryAccess>
    }

    fn as_interrupt(&self) -> Option<&impl EventInterruptTrait<Architecture = Self::Architecture>> {
        None::<&BoundaryInterrupt>
    }

    fn as_software_breakpoint(
        &self,
    ) -> Option<&impl EventInterruptTrait<Architecture = Self::Architecture>> {
        None::<&BoundaryInterrupt>
    }
}

impl Architecture for BoundaryArchitecture {
    const PAGE_SIZE: u64 = 0x1000;
    const PAGE_SHIFT: u64 = 12;
    const PAGE_MASK: u64 = 0xffff_ffff_ffff_f000;
    const BREAKPOINT: &'static [u8] = &[0xcd, 0x03];

    type Registers = BoundaryRegisters;
    type PageTableLevel = ();
    type Interrupt = ();
    type SpecialRegister = ();
    type EventMonitor = ();
    type EventReason = BoundaryEventReason;

    fn gfn_from_pa(pa: Pa) -> Gfn {
        Gfn(pa.0 >> Self::PAGE_SHIFT)
    }

    fn pa_from_gfn(gfn: Gfn) -> Pa {
        Pa(gfn.0 << Self::PAGE_SHIFT)
    }

    fn pa_offset(pa: Pa) -> u64 {
        pa.0 & !Self::PAGE_MASK
    }

    fn va_align_down(va: Va) -> Va {
        Va(va.0 & Self::PAGE_MASK)
    }

    fn va_align_down_for(va: Va, _level: Self::PageTableLevel) -> Va {
        Self::va_align_down(va)
    }

    fn va_align_up(va: Va) -> Va {
        Va((va.0 + Self::PAGE_SIZE - 1) & Self::PAGE_MASK)
    }

    fn va_align_up_for(va: Va, _level: Self::PageTableLevel) -> Va {
        Self::va_align_up(va)
    }

    fn va_offset(va: Va) -> u64 {
        va.0 & !Self::PAGE_MASK
    }

    fn va_offset_for(va: Va, _level: Self::PageTableLevel) -> u64 {
        Self::va_offset(va)
    }

    fn va_index(va: Va) -> u64 {
        (va.0 >> Self::PAGE_SHIFT) & 0x1ff
    }

    fn va_index_for(va: Va, _level: Self::PageTableLevel) -> u64 {
        Self::va_index(va)
    }

    fn translate_address<Driver>(_vmi: &VmiCore<Driver>, _va: Va, _root: Pa) -> Result<Pa, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        Err(VmiError::NotSupported)
    }
}

/// Driver whose methods are unreachable after boundary validation.
struct BoundaryDriver;

impl VmiDriver for BoundaryDriver {
    type Architecture = BoundaryArchitecture;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: BoundaryArchitecture::PAGE_SIZE,
            page_shift: BoundaryArchitecture::PAGE_SHIFT,
            max_gfn: Gfn(0xffff),
            vcpus: 1,
        })
    }
}

impl VmiRead for BoundaryDriver {
    fn read_page(&self, _gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        Err(VmiError::NotSupported)
    }
}

impl VmiWrite for BoundaryDriver {
    fn write_page(
        &self,
        _gfn: Gfn,
        _offset: u64,
        _content: &[u8],
    ) -> Result<VmiMappedPage, VmiError> {
        Err(VmiError::NotSupported)
    }
}

impl VmiViewControl for BoundaryDriver {
    fn default_view(&self) -> View {
        View(0)
    }

    fn create_view(&self, _default_access: MemoryAccess) -> Result<View, VmiError> {
        Err(VmiError::NotSupported)
    }

    fn destroy_view(&self, _view: View) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn switch_to_view(&self, _view: View) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn change_view_gfn(&self, _view: View, _old_gfn: Gfn, _new_gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn reset_view_gfn(&self, _view: View, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }
}

impl VmiVmControl for BoundaryDriver {
    fn pause(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn resume(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        Err(VmiError::NotSupported)
    }

    fn allocate_gfn_at(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn free_gfn(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn inject_interrupt(&self, _vcpu: VcpuId, _interrupt: ()) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }
}

/// Rejects a multi-byte breakpoint that starts at the page's final byte.
#[test]
fn breakpoint_that_crosses_a_page_boundary_is_rejected() -> Result<(), VmiError> {
    let vmi = VmiCore::new(BoundaryDriver)?;
    let mut interceptor = Interceptor::<BoundaryDriver>::new();
    let last_byte = BoundaryArchitecture::PAGE_SIZE - 1;

    assert!(matches!(
        interceptor.insert_breakpoint(&vmi, Pa(last_byte), View(1)),
        Err(VmiError::OutOfBounds)
    ));

    Ok(())
}
