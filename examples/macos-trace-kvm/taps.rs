//! Owns targeted entry and return taps without patching original guest pages.

use std::collections::HashMap;

use vmi::{
    Architecture as _, Gfn, MemoryAccess, Pa, Registers as _, Va, VcpuId, View, VmiContext,
    VmiCore, VmiError,
    os::macos::MacOs,
    utils::{
        bpm::{Breakpoint, BreakpointController, BreakpointManager},
        ptm::{PageTableMonitor, PageTableMonitorEvent},
    },
};

use crate::{Arch, Driver, ipc::IpcHook};

/// Identifies observations performed at an entry instruction.
#[derive(Clone, Copy, Debug)]
pub enum TapKind {
    /// Decodes a selected Objective-C dispatcher or semantic fast path.
    Semantic(&'static str),

    /// Invalidates cached method metadata before a runtime mutation.
    Invalidate,

    /// Records one verified transport or handler observation.
    Ipc(IpcHook),

    /// Observes an initialized child before its image may be replaced.
    Fork,

    /// Observes a completed executable-image replacement.
    Exec,

    /// Retires process state before its kernel identity can be reused.
    Exit,

    /// Retires a terminating thread before its kernel state is dismantled.
    ThreadExit,
}

/// Keys shared code globally and private code by its address space.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TapKey {
    /// `None` denotes a global kernel or shared-cache instruction.
    pub root: Option<Pa>,

    /// Canonical virtual instruction address.
    pub address: u64,
}

/// Retains ownership until all entry and return users release an instruction.
struct Site {
    /// Translation context that originally resolved this instruction.
    translation: Pa,

    /// Entry observation, independent of temporary return ownership.
    kind: Option<TapKind>,

    /// Number of pending calls that expect this continuation.
    returns: u32,

    /// Views in which this instruction is patched.
    views: [Option<View>; 2],

    /// Original frames associated with the active view registrations.
    frames: [Option<Gfn>; 2],
}

/// Shares one patched instruction among entry hooks and concurrent returns.
pub struct Taps {
    /// Reuses the existing shadow-page and pending-breakpoint implementation.
    manager: BreakpointManager<BreakpointController<Driver>, (), ()>,

    /// Follows translations when code pages are paged out or replaced.
    ptm: PageTableMonitor<Driver, ()>,

    /// Owns sites independently of the process currently executing them.
    sites: HashMap<TapKey, Site>,

    /// Tracks original frames whose code shadows require data-access replay.
    pages: HashMap<(View, Gfn), usize>,

    /// Library and kernel execution view for related processes.
    system: View,

    /// Main-image execution view, including returns from in-image method
    /// bodies.
    target: View,

    /// Observation-only view for processes not yet related to the target.
    observer: View,
}

impl Taps {
    /// Creates a tap owner for the tracing and observation execution views.
    pub fn new(system: View, target: View, observer: View) -> Self {
        Self {
            manager: BreakpointManager::new(),
            ptm: PageTableMonitor::new(),
            sites: HashMap::new(),
            pages: HashMap::new(),
            system,
            target,
            observer,
        }
    }

    /// Installs an entry tap while preserving main-image execute-fault routing.
    pub fn entry(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        key: TapKey,
        kind: TapKind,
        main_image: bool,
    ) -> Result<(), VmiError> {
        let _pause_guard = vmi.core().pause_guard()?;
        let translation = key
            .root
            .unwrap_or_else(|| vmi.registers().translation_root(Va(key.address)));
        let site = self.sites.entry(key).or_insert(Site {
            translation,
            kind: None,
            returns: 0,
            views: [None, None],
            frames: [None, None],
        });
        site.kind = Some(kind);
        self.install(vmi, key, main_image)
    }

    /// Acquires an exact continuation tap, including in-image method returns.
    pub fn returning(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        mut key: TapKey,
        main_image: bool,
    ) -> Result<TapKey, VmiError> {
        let _pause_guard = vmi.core().pause_guard()?;
        let global = TapKey {
            root: None,
            address: key.address,
        };
        if self.sites.contains_key(&global) {
            key = global;
        }
        let translation = key
            .root
            .unwrap_or_else(|| vmi.registers().translation_root(Va(key.address)));
        let site = self.sites.entry(key).or_insert(Site {
            translation,
            kind: None,
            returns: 0,
            views: [None, None],
            frames: [None, None],
        });
        site.returns = site.returns.checked_add(1).ok_or(VmiError::OutOfBounds)?;
        self.install(vmi, key, main_image)?;
        Ok(key)
    }

    /// Installs missing views without making main-image pages executable there.
    fn install(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        key: TapKey,
        main_image: bool,
    ) -> Result<(), VmiError> {
        let site = self.sites.get_mut(&key).expect("tap site was registered");
        let views = [
            Some(if main_image { self.target } else { self.system }),
            Some(self.observer),
        ];
        for (index, view) in views.into_iter().enumerate() {
            let view = match view {
                Some(view) => view,
                None => continue,
            };
            if site.views[index].is_some() {
                continue;
            }
            let breakpoint = Breakpoint::new((Va(key.address), site.translation), view);
            let breakpoint = if key.root.is_none() {
                breakpoint.global()
            }
            else {
                breakpoint
            };
            self.ptm
                .monitor(vmi.core(), (Va(key.address), site.translation), view, ())?;
            self.manager.insert(vmi.core(), breakpoint)?;
            site.views[index] = Some(view);
            match vmi
                .core()
                .translate_address((Va(key.address), site.translation))
            {
                Ok(pa) => {
                    let gfn = Arch::gfn_from_pa(pa);
                    site.frames[index] = Some(gfn);
                    *self.pages.entry((view, gfn)).or_default() += 1;
                }
                Err(VmiError::Translation(_)) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Releases one return owner and restores an instruction with no users.
    pub fn release(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        key: TapKey,
    ) -> Result<(), VmiError> {
        let _pause_guard = vmi.core().pause_guard()?;
        let site = match self.sites.get_mut(&key) {
            Some(site) => site,
            None => return Ok(()),
        };
        site.returns = site.returns.saturating_sub(1);
        if site.returns != 0 || site.kind.is_some() {
            return Ok(());
        }
        for (index, view) in site.views.into_iter().enumerate() {
            let view = match view {
                Some(view) => view,
                None => continue,
            };
            let breakpoint = Breakpoint::new((Va(key.address), site.translation), view);
            let breakpoint = if key.root.is_none() {
                breakpoint.global()
            }
            else {
                breakpoint
            };
            self.manager.remove(vmi.core(), breakpoint)?;
            self.ptm
                .unmonitor(vmi.core(), (Va(key.address), site.translation), view)?;
            if let Some(gfn) = site.frames[index]
                && let Some(references) = self.pages.get_mut(&(view, gfn))
            {
                *references -= 1;
                if *references == 0 {
                    self.pages.remove(&(view, gfn));
                }
            }
        }
        self.sites.remove(&key);
        Ok(())
    }

    /// Returns an entry kind for a matched root or globally shared instruction.
    pub fn kind(&self, root: Pa, pc: u64) -> Option<TapKind> {
        self.sites
            .get(&TapKey {
                root: None,
                address: pc,
            })
            .or_else(|| {
                self.sites.get(&TapKey {
                    root: Some(root),
                    address: pc,
                })
            })
            .and_then(|site| site.kind)
    }

    /// Reports whether this page belongs to any installed code shadow.
    pub fn owns_page(&self, view: View, gfn: Gfn) -> bool {
        self.pages.contains_key(&(view, gfn))
    }

    /// Marks a protected page-table descriptor before its original write.
    pub fn mark_write(&mut self, pa: Pa, view: View, vcpu: VcpuId) {
        self.ptm.mark_dirty_entry(pa, view, vcpu);
    }

    /// Publishes remapped code and refreshed shadows after a serialized write.
    pub fn after_write(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        vcpu: VcpuId,
        gfn: Gfn,
    ) -> Result<(), VmiError> {
        let _pause_guard = vmi.core().pause_guard()?;
        let updates = self.ptm.process_dirty_entries(vmi.core(), vcpu)?;
        for update in &updates {
            let (update, paged_in) = match update {
                PageTableMonitorEvent::PageIn(update) => (update, true),
                PageTableMonitorEvent::PageOut(update) => (update, false),
            };
            let frame = Arch::gfn_from_pa(update.pa);
            for (key, site) in &mut self.sites {
                if key.address != update.ctx.va.0 || site.translation != update.ctx.root {
                    continue;
                }
                for index in 0..site.views.len() {
                    if site.views[index] != Some(update.view) {
                        continue;
                    }
                    if let Some(previous) = site.frames[index].take()
                        && let Some(references) = self.pages.get_mut(&(update.view, previous))
                    {
                        *references -= 1;
                        if *references == 0 {
                            self.pages.remove(&(update.view, previous));
                        }
                    }
                    if paged_in {
                        site.frames[index] = Some(frame);
                        *self.pages.entry((update.view, frame)).or_default() += 1;
                    }
                }
            }
        }
        self.manager.handle_ptm_events(vmi.core(), updates)?;
        self.refresh(vmi, gfn)
    }

    /// Removes private hooks when their process address space ends.
    pub fn remove_process(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        root: Pa,
    ) -> Result<(), VmiError> {
        let keys = self
            .sites
            .keys()
            .filter(|key| key.root == Some(root))
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(site) = self.sites.get_mut(&key) {
                site.kind = None;
                site.returns = 1;
            }
            self.release(vmi, key)?;
        }
        Ok(())
    }

    /// Restores execute-fault routing after a process's main image is
    /// discovered.
    pub fn main_image(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        root: Pa,
        lo: u64,
        hi: u64,
    ) -> Result<(), VmiError> {
        let _pause_guard = vmi.core().pause_guard()?;
        let mut migrated = Vec::new();
        for (key, site) in &mut self.sites {
            if key.root != Some(root)
                || key.address < lo
                || key.address >= hi
                || site.views[0] != Some(self.system)
            {
                continue;
            }
            let breakpoint = Breakpoint::new((Va(key.address), site.translation), self.system);
            self.manager.remove(vmi.core(), breakpoint)?;
            self.ptm
                .unmonitor(vmi.core(), (Va(key.address), site.translation), self.system)?;
            site.views[0] = None;
            if let Some(gfn) = site.frames[0].take() {
                if let Some(references) = self.pages.get_mut(&(self.system, gfn)) {
                    *references -= 1;
                    if *references == 0 {
                        self.pages.remove(&(self.system, gfn));
                    }
                }
                vmi.set_memory_access(gfn, self.system, MemoryAccess::RW)?;
            }
            migrated.push(*key);
        }
        for key in migrated {
            self.install(vmi, key, true)?;
        }
        Ok(())
    }

    /// Refreshes shadows after an original code page was written.
    pub fn refresh(&mut self, vmi: &VmiContext<MacOs<Driver>>, gfn: Gfn) -> Result<(), VmiError> {
        let _pause_guard = vmi.core().pause_guard()?;
        for view in [self.system, self.target, self.observer] {
            self.manager.refresh_page(vmi.core(), gfn, view)?;
        }
        Ok(())
    }

    /// Restores every original mapping before instrumented views are destroyed.
    pub fn clear(&mut self, core: &VmiCore<Driver>) -> Result<(), VmiError> {
        let _pause_guard = core.pause_guard()?;
        self.manager.clear(core)?;
        self.ptm.unmonitor_all(core);
        self.sites.clear();
        self.pages.clear();
        Ok(())
    }
}
