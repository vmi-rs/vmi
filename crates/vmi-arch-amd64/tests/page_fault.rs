//! Translations that check access rights, checked writes, and the page faults
//! that they raise.

use vmi_arch_amd64::{
    Amd64, ExceptionVector, Interrupt, PageFaultErrorCode, PageTableEntry, PageTableLevel,
};
use vmi_core::{
    Architecture as _, Gfn, MemoryAccess, Pa, PageFault, Va, VmiCore, VmiError,
    arch::Interrupt as _,
};
use vmi_driver_mock::arch::amd64::MockDriver;

/// P flag of a page table entry.
const PRESENT: u64 = 1 << 0;

/// R/W flag of a page table entry.
const WRITABLE: u64 = 1 << 1;

/// U/S flag of a page table entry.
const USER: u64 = 1 << 2;

/// D flag of a page table entry.
const DIRTY: u64 = 1 << 6;

/// PS flag of a page table entry.
const LARGE: u64 = 1 << 7;

/// XD flag of a page table entry.
const EXECUTE_DISABLE: u64 = 1 << 63;

/// The flags of a page that user code may write.
const USER_RW: u64 = PRESENT | WRITABLE | USER | DIRTY;

/// The flags of a page that the kernel may write.
const KERNEL_RW: u64 = PRESENT | WRITABLE | DIRTY;

/// The levels of a walk, from the root.
const LEVELS: [PageTableLevel; 4] = [
    PageTableLevel::Pml4,
    PageTableLevel::Pdpt,
    PageTableLevel::Pd,
    PageTableLevel::Pt,
];

/// A user address at the start of a page.
const USER_VA: Va = Va(0x7f12_3456_7000);

/// A kernel address at the start of a page.
const KERNEL_VA: Va = Va(0xffff_8880_1234_5000);

/// The frame of the page that the walks map. The next frame holds a second page.
const DATA: Gfn = Gfn(0x20);

/// Returns the frame of the table at a level. The tables map one region.
fn table(level: PageTableLevel) -> Gfn {
    match level {
        PageTableLevel::Pml4 => Gfn(0x10),
        PageTableLevel::Pdpt => Gfn(0x11),
        PageTableLevel::Pd => Gfn(0x12),
        PageTableLevel::Pt => Gfn(0x13),
    }
}

/// Returns the root of the walks.
fn root() -> Pa {
    Amd64::pa_from_gfn(table(PageTableLevel::Pml4))
}

/// Returns the address of the entry for `va` at a level.
fn entry_address(level: PageTableLevel, va: Va) -> Pa {
    Amd64::pa_from_gfn(table(level))
        + Amd64::va_index_for(va, level) * size_of::<PageTableEntry>() as u64
}

/// Returns an entry with flags that points to a frame.
fn entry(gfn: Gfn, flags: u64) -> PageTableEntry {
    PageTableEntry((gfn.0 << Amd64::PAGE_SHIFT) | flags)
}

/// Returns a driver with the tables and two data frames.
fn driver() -> MockDriver {
    let driver = MockDriver::new();
    for level in LEVELS {
        driver.insert_page(table(level));
    }

    driver.insert_page(DATA);
    driver.insert_page(Gfn(DATA.0 + 1));
    driver
}

/// Maps `va` to `data`, with the flags of each level from the root.
fn map(driver: &MockDriver, va: Va, flags: [u64; 4], data: Gfn) {
    for (level, flags) in LEVELS.into_iter().zip(flags) {
        let next = match level.next() {
            Some(next) => table(next),
            None => data,
        };

        driver.write_pte(entry_address(level, va), entry(next, flags));
    }
}

/// Returns a core over a driver that maps `va` with the flags of each level.
fn core_with(va: Va, flags: [u64; 4]) -> Result<VmiCore<MockDriver>, VmiError> {
    let driver = driver();
    map(&driver, va, flags, DATA);
    VmiCore::new(driver)
}

/// Returns the page fault of a result, and panics without one.
fn page_fault<T>(result: Result<T, VmiError>) -> PageFault
where
    T: std::fmt::Debug,
{
    match result {
        Err(VmiError::PageFault(pf)) => pf,
        other => panic!("expected a page fault, got {other:?}"),
    }
}

/// Returns the flags of a user page at each level, with one level changed.
fn with_level(level: PageTableLevel, change: impl Fn(u64) -> u64) -> [u64; 4] {
    LEVELS.map(|candidate| {
        if candidate == level {
            change(USER_RW)
        }
        else {
            USER_RW
        }
    })
}

#[test]
fn missing_entry_reports_its_level() -> Result<(), VmiError> {
    for level in LEVELS {
        let core = core_with(USER_VA, [USER_RW; 4])?;
        core.driver()
            .write_pte(entry_address(level, USER_VA), PageTableEntry(0));

        assert_eq!(
            page_fault(Amd64::translate_access(
                &core,
                USER_VA,
                root(),
                MemoryAccess::W
            )),
            PageFault::not_present((USER_VA, root()), MemoryAccess::W, level.into())
        );
        assert_eq!(
            page_fault(Amd64::translate_address(&core, USER_VA, root())),
            PageFault::not_present((USER_VA, root()), MemoryAccess::R, level.into())
        );
    }

    Ok(())
}

#[test]
fn write_needs_every_level_writable() -> Result<(), VmiError> {
    for level in LEVELS {
        let core = core_with(USER_VA, with_level(level, |flags| flags & !WRITABLE))?;

        assert_eq!(
            page_fault(Amd64::translate_access(
                &core,
                USER_VA,
                root(),
                MemoryAccess::W
            )),
            PageFault::permission((USER_VA, root()), MemoryAccess::W, level.into())
        );
        assert!(Amd64::translate_access(&core, USER_VA, root(), MemoryAccess::R).is_ok());
    }

    Ok(())
}

#[test]
fn user_access_needs_the_user_flag_at_every_level() -> Result<(), VmiError> {
    for level in LEVELS {
        let core = core_with(USER_VA, with_level(level, |flags| flags & !USER))?;

        assert_eq!(
            page_fault(Amd64::translate_access(
                &core,
                USER_VA,
                root(),
                MemoryAccess::R
            )),
            PageFault::permission((USER_VA, root()), MemoryAccess::R, level.into())
        );
    }

    Ok(())
}

#[test]
fn kernel_access_needs_no_user_flag() -> Result<(), VmiError> {
    let core = core_with(KERNEL_VA, [KERNEL_RW; 4])?;

    assert_eq!(
        Amd64::translate_access(&core, KERNEL_VA, root(), MemoryAccess::W)?,
        Amd64::pa_from_gfn(DATA)
    );
    Ok(())
}

#[test]
fn write_to_a_clean_page_reports_the_leaf() -> Result<(), VmiError> {
    let core = core_with(
        USER_VA,
        with_level(PageTableLevel::Pt, |flags| flags & !DIRTY),
    )?;

    assert_eq!(
        page_fault(Amd64::translate_access(
            &core,
            USER_VA,
            root(),
            MemoryAccess::W
        )),
        PageFault::permission(
            (USER_VA, root()),
            MemoryAccess::W,
            PageTableLevel::Pt.into()
        )
    );
    Ok(())
}

#[test]
fn write_to_a_writable_dirty_page_translates() -> Result<(), VmiError> {
    let core = core_with(USER_VA, [USER_RW; 4])?;

    assert_eq!(
        Amd64::translate_access(&core, USER_VA + 0x123, root(), MemoryAccess::W)?,
        Amd64::pa_from_gfn(DATA) + 0x123
    );
    Ok(())
}

#[test]
fn write_to_a_large_page_checks_its_entry() -> Result<(), VmiError> {
    let driver = driver();
    map(&driver, USER_VA, [USER_RW; 4], DATA);
    driver.write_pte(
        entry_address(PageTableLevel::Pd, USER_VA),
        entry(Gfn(0), (USER_RW & !DIRTY) | LARGE),
    );
    let core = VmiCore::new(driver)?;

    assert_eq!(
        page_fault(Amd64::translate_access(
            &core,
            USER_VA,
            root(),
            MemoryAccess::W
        )),
        PageFault::permission(
            (USER_VA, root()),
            MemoryAccess::W,
            PageTableLevel::Pd.into()
        )
    );
    Ok(())
}

#[test]
fn missing_entry_comes_before_a_refusal() -> Result<(), VmiError> {
    let core = core_with(
        USER_VA,
        with_level(PageTableLevel::Pml4, |flags| flags & !WRITABLE),
    )?;
    core.driver().write_pte(
        entry_address(PageTableLevel::Pt, USER_VA),
        PageTableEntry(0),
    );

    assert_eq!(
        page_fault(Amd64::translate_access(
            &core,
            USER_VA,
            root(),
            MemoryAccess::W
        )),
        PageFault::not_present(
            (USER_VA, root()),
            MemoryAccess::W,
            PageTableLevel::Pt.into()
        )
    );
    Ok(())
}

#[test]
fn fetch_needs_the_execute_disable_flag_clear() -> Result<(), VmiError> {
    let core = core_with(
        USER_VA,
        with_level(PageTableLevel::Pd, |flags| flags | EXECUTE_DISABLE),
    )?;

    assert_eq!(
        page_fault(Amd64::translate_access(
            &core,
            USER_VA,
            root(),
            MemoryAccess::X
        )),
        PageFault::permission(
            (USER_VA, root()),
            MemoryAccess::X,
            PageTableLevel::Pd.into()
        )
    );
    assert!(Amd64::translate_access(&core, USER_VA, root(), MemoryAccess::R).is_ok());
    Ok(())
}

#[test]
fn checked_write_refused_on_a_later_page_writes_nothing() -> Result<(), VmiError> {
    let second = USER_VA + Amd64::PAGE_SIZE;
    let driver = driver();
    map(&driver, USER_VA, [USER_RW; 4], DATA);
    map(
        &driver,
        second,
        with_level(PageTableLevel::Pt, |flags| flags & !WRITABLE),
        Gfn(DATA.0 + 1),
    );
    let core = VmiCore::new(driver)?;

    let start = second - 8;
    assert_eq!(
        page_fault(core.write_checked((start, root()), &[0xaa; 16])),
        PageFault::permission((second, root()), MemoryAccess::W, PageTableLevel::Pt.into())
    );
    assert!(core.driver().page(DATA).iter().all(|&byte| byte == 0));
    Ok(())
}

#[test]
fn checked_write_writes_every_page() -> Result<(), VmiError> {
    let second = USER_VA + Amd64::PAGE_SIZE;
    let driver = driver();
    map(&driver, USER_VA, [USER_RW; 4], DATA);
    map(&driver, second, [USER_RW; 4], Gfn(DATA.0 + 1));
    let core = VmiCore::new(driver)?;

    let start = second - 8;
    core.write_checked((start, root()), &[0xaa; 16])?;

    let mut buffer = [0; 16];
    core.read((start, root()), &mut buffer)?;
    assert_eq!(buffer, [0xaa; 16]);
    Ok(())
}

#[test]
fn plain_write_to_a_missing_page_reports_a_write() -> Result<(), VmiError> {
    let core = core_with(USER_VA, [USER_RW; 4])?;
    core.driver().write_pte(
        entry_address(PageTableLevel::Pt, USER_VA),
        PageTableEntry(0),
    );

    assert_eq!(
        page_fault(core.write((USER_VA, root()), &[0xaa; 8])),
        PageFault::not_present(
            (USER_VA, root()),
            MemoryAccess::W,
            PageTableLevel::Pt.into()
        )
    );
    Ok(())
}

#[test]
fn page_fault_error_code_describes_the_fault() {
    let level = PageTableLevel::Pt.into();
    let cases = [
        (
            PageFault::not_present((USER_VA, root()), MemoryAccess::W, level),
            PageFaultErrorCode::USER | PageFaultErrorCode::WRITE,
        ),
        (
            PageFault::permission((USER_VA, root()), MemoryAccess::W, level),
            PageFaultErrorCode::PROTECTION | PageFaultErrorCode::USER | PageFaultErrorCode::WRITE,
        ),
        (
            PageFault::permission((USER_VA, root()), MemoryAccess::X, level),
            PageFaultErrorCode::PROTECTION
                | PageFaultErrorCode::USER
                | PageFaultErrorCode::INSTRUCTION_FETCH,
        ),
        (
            PageFault::not_present((KERNEL_VA, root()), MemoryAccess::R, level),
            PageFaultErrorCode::empty(),
        ),
    ];

    for (pf, error_code) in cases {
        let interrupt = Interrupt::page_fault(pf);
        assert_eq!(interrupt.vector, ExceptionVector::PageFault);
        assert_eq!(interrupt.error_code, Some(error_code.bits()));
        assert_eq!(interrupt.extra, pf.va.0);
    }
}

#[test]
fn breakpoint_has_the_length_of_int3_and_no_error_code() {
    let interrupt = Interrupt::breakpoint();
    assert_eq!(
        usize::from(interrupt.instruction_length),
        Amd64::BREAKPOINT.len()
    );
    assert_eq!(interrupt.error_code, None);
}
