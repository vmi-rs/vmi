use vmi_core::{
    Architecture, Gfn, MemoryAccess, Pa, Registers as _, Va, View, VmiCore, VmiError, VmiEvent,
    arch::{EventInterrupt as _, EventReason},
    driver::{VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite},
};

use super::TapController;
use crate::interceptor::Interceptor;

#[doc = include_str!("breakpoint.md")]
pub struct BreakpointController<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    interceptor: Interceptor<Driver>,
}

impl<Driver> BreakpointController<Driver>
where
    Driver: VmiRead + VmiWrite + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    /// Checks if the given event was caused by a software breakpoint.
    pub fn is_breakpoint(
        vmi: &VmiCore<Driver>,
        event: &VmiEvent<Driver::Architecture>,
    ) -> Result<bool, VmiError> {
        let interrupt = match event.reason().as_software_breakpoint() {
            Some(interrupt) => interrupt,
            None => return Ok(false),
        };

        let va = Va(event.registers().instruction_pointer());
        let pa = Driver::Architecture::pa_from_gfn(interrupt.gfn())
            + Driver::Architecture::va_offset(va);

        let mut content = vec![0; Driver::Architecture::BREAKPOINT.len()];
        vmi.read(pa, &mut content)?;

        Ok(content == Driver::Architecture::BREAKPOINT)
    }
}

impl<Driver> TapController for BreakpointController<Driver>
where
    Driver: VmiRead + VmiWrite + VmiSetProtection + VmiViewControl + VmiVmControl,
    <Driver::Architecture as Architecture>::EventReason:
        EventReason<Architecture = Driver::Architecture>,
{
    type Driver = Driver;

    fn new() -> Self {
        Self {
            interceptor: Interceptor::new(),
        }
    }

    fn check_event(&self, event: &VmiEvent<Driver::Architecture>) -> Option<(View, Gfn)> {
        let interrupt = event.reason().as_software_breakpoint()?;
        let view = event.view()?;

        Some((view, interrupt.gfn()))
    }

    fn insert_breakpoint(
        &mut self,
        vmi: &VmiCore<Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        self.interceptor.insert_breakpoint(vmi, pa, view)?;
        Ok(())
    }

    fn remove_breakpoint(
        &mut self,
        vmi: &VmiCore<Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        let breakpoint_was_removed = self.interceptor.remove_breakpoint(vmi, pa, view)?;
        debug_assert!(
            breakpoint_was_removed.is_some(),
            "trying to remove a breakpoint that is not installed"
        );
        Ok(())
    }

    fn monitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        vmi.set_memory_access(gfn, view, MemoryAccess::X)
    }

    fn unmonitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        vmi.set_memory_access(gfn, view, MemoryAccess::RWX)
    }
}

#[cfg(all(test, feature = "arch-amd64"))]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
    };

    use vmi_arch_amd64::{Amd64, Interrupt};
    use vmi_core::{
        Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiCore,
        VmiDriver, VmiError, VmiInfo, VmiMappedPage, VmiRead, VmiSetProtection, VmiViewControl,
        VmiVmControl, VmiWrite,
    };

    use super::{BreakpointController, TapController};

    struct MockDriver {
        pages: RefCell<HashMap<Gfn, Vec<u8>>>,
        mappings: RefCell<HashMap<(View, Gfn), Gfn>>,
        next_gfn: Cell<u64>,
    }

    impl MockDriver {
        fn new() -> Self {
            Self {
                pages: RefCell::new(HashMap::new()),
                mappings: RefCell::new(HashMap::new()),
                next_gfn: Cell::new(0x100),
            }
        }

        fn insert_page(&self, gfn: Gfn, value: u8) {
            self.pages
                .borrow_mut()
                .insert(gfn, vec![value; Amd64::PAGE_SIZE as usize]);
        }

        fn write_byte(&self, gfn: Gfn, offset: usize, value: u8) {
            self.pages.borrow_mut().get_mut(&gfn).expect("page")[offset] = value;
        }

        fn read_byte(&self, gfn: Gfn, offset: usize) -> u8 {
            self.pages.borrow().get(&gfn).expect("page")[offset]
        }

        fn mapped_gfn(&self, view: View, gfn: Gfn) -> Option<Gfn> {
            self.mappings.borrow().get(&(view, gfn)).copied()
        }
    }

    impl VmiDriver for MockDriver {
        type Architecture = Amd64;

        fn info(&self) -> Result<VmiInfo, VmiError> {
            Ok(VmiInfo {
                page_size: Amd64::PAGE_SIZE,
                page_shift: 12,
                max_gfn: Gfn(0xffff),
                vcpus: 1,
            })
        }
    }

    impl VmiRead for MockDriver {
        fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
            let page = self
                .pages
                .borrow()
                .get(&gfn)
                .cloned()
                .ok_or(VmiError::Other("page not found"))?;
            Ok(VmiMappedPage::new(page))
        }
    }

    impl VmiWrite for MockDriver {
        fn write_page(
            &self,
            gfn: Gfn,
            offset: u64,
            content: &[u8],
        ) -> Result<VmiMappedPage, VmiError> {
            let offset = offset as usize;
            let mut pages = self.pages.borrow_mut();
            let page = pages
                .get_mut(&gfn)
                .ok_or(VmiError::Other("page not found"))?;

            if offset + content.len() > page.len() {
                return Err(VmiError::OutOfBounds);
            }

            page[offset..offset + content.len()].copy_from_slice(content);
            Ok(VmiMappedPage::new(page.clone()))
        }
    }

    impl VmiSetProtection for MockDriver {
        fn set_memory_access(
            &self,
            _gfn: Gfn,
            _view: View,
            _access: MemoryAccess,
        ) -> Result<(), VmiError> {
            Ok(())
        }

        fn set_memory_access_with_options(
            &self,
            _gfn: Gfn,
            _view: View,
            _access: MemoryAccess,
            _options: MemoryAccessOptions,
        ) -> Result<(), VmiError> {
            Ok(())
        }
    }

    impl VmiViewControl for MockDriver {
        fn default_view(&self) -> View {
            View(0)
        }

        fn create_view(&self, _default_access: MemoryAccess) -> Result<View, VmiError> {
            Ok(View(1))
        }

        fn destroy_view(&self, _view: View) -> Result<(), VmiError> {
            Ok(())
        }

        fn switch_to_view(&self, _view: View) -> Result<(), VmiError> {
            Ok(())
        }

        fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
            self.mappings.borrow_mut().insert((view, old_gfn), new_gfn);
            Ok(())
        }

        fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
            self.mappings.borrow_mut().remove(&(view, gfn));
            Ok(())
        }
    }

    impl VmiVmControl for MockDriver {
        fn pause(&self) -> Result<(), VmiError> {
            Ok(())
        }

        fn resume(&self) -> Result<(), VmiError> {
            Ok(())
        }

        fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
            let gfn = Gfn(self.next_gfn.get());
            self.next_gfn.set(gfn.0 + 1);
            self.insert_page(gfn, 0);
            Ok(gfn)
        }

        fn allocate_gfn_at(&self, gfn: Gfn) -> Result<(), VmiError> {
            self.insert_page(gfn, 0);
            Ok(())
        }

        fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
            self.pages.borrow_mut().remove(&gfn);
            Ok(())
        }

        fn inject_interrupt(&self, _vcpu: VcpuId, _interrupt: Interrupt) -> Result<(), VmiError> {
            Ok(())
        }

        fn reset_state(&self) -> Result<(), VmiError> {
            Ok(())
        }
    }

    #[test]
    fn shared_breakpoint_can_be_removed_and_reinserted() -> Result<(), VmiError> {
        const ORIGINAL_GFN: Gfn = Gfn(1);
        const VIEW: View = View(1);
        const OFFSET: usize = 0x123;

        let driver = MockDriver::new();
        driver.insert_page(ORIGINAL_GFN, 0x90);

        let vmi = VmiCore::new(driver)?;
        let address = Amd64::pa_from_gfn(ORIGINAL_GFN) + OFFSET as u64;
        let mut controller = BreakpointController::<MockDriver>::new();

        controller.insert_breakpoint(&vmi, address, VIEW)?;
        let shadow_gfn = vmi
            .driver()
            .mapped_gfn(VIEW, ORIGINAL_GFN)
            .expect("shadow mapping");
        assert_eq!(vmi.driver().read_byte(shadow_gfn, OFFSET), 0xcc);

        controller.insert_breakpoint(&vmi, address, VIEW)?;
        controller.remove_breakpoint(&vmi, address, VIEW)?;
        assert_eq!(
            vmi.driver().mapped_gfn(VIEW, ORIGINAL_GFN),
            Some(shadow_gfn)
        );

        controller.remove_breakpoint(&vmi, address, VIEW)?;
        assert_eq!(vmi.driver().mapped_gfn(VIEW, ORIGINAL_GFN), None);

        vmi.driver().write_byte(ORIGINAL_GFN, OFFSET + 1, 0x42);
        controller.insert_breakpoint(&vmi, address, VIEW)?;
        assert_eq!(
            vmi.driver().mapped_gfn(VIEW, ORIGINAL_GFN),
            Some(shadow_gfn)
        );
        assert_eq!(vmi.driver().read_byte(shadow_gfn, OFFSET), 0xcc);
        assert_eq!(vmi.driver().read_byte(shadow_gfn, OFFSET + 1), 0x42);

        controller.remove_breakpoint(&vmi, address, VIEW)?;
        assert_eq!(vmi.driver().mapped_gfn(VIEW, ORIGINAL_GFN), None);
        assert_eq!(vmi.driver().read_byte(shadow_gfn, OFFSET), 0x90);

        Ok(())
    }
}
