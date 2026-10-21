//! System V calls, the red zone in user mode, and library names.

use std::marker::PhantomData;

use vmi_arch_amd64::{Amd64, Cr3, PageTableEntry, PageTableLevel, Registers};
use vmi_core::{Architecture as _, Gfn, Va, VmiCore, VmiError, VmiSession, VmiState, os::NoOS};
use vmi_driver_mock::arch::amd64::MockDriver;

use super::{copy_to_stack, is_library, prepare_call, red_zone};
use crate::injector::{CallBuilder, OsAdapter, Recipe, RecipeControlFlow, RecipeExecutor, recipe};

/// P flag of a page table entry.
const PRESENT: u64 = 1 << 0;

/// R/W flag of a page table entry.
const WRITABLE: u64 = 1 << 1;

/// U/S flag of a page table entry.
const USER: u64 = 1 << 2;

/// D flag of a page table entry.
const DIRTY: u64 = 1 << 6;

/// The flags of a page that user code may write.
const USER_RW: u64 = PRESENT | WRITABLE | USER | DIRTY;

/// The frames of the test stack's PML4, PDPT, PD and PT.
const TABLES: [Gfn; 4] = [Gfn(0x10), Gfn(0x11), Gfn(0x12), Gfn(0x13)];

/// The frame of the test stack.
const STACK: Gfn = Gfn(0x20);

/// The page of the test stack.
const STACK_VA: Va = Va(0x7ffd_1234_5000);

/// A user address in the code of the interrupted thread.
const USER_RIP: u64 = 0x7f00_0000_1234;

/// A kernel address in the code of the interrupted thread.
const KERNEL_RIP: u64 = 0xffff_ffff_8100_1234;

/// The address of the called function.
const FUNCTION: u64 = 0x7f00_0000_5678;

/// The OS of the tests. Its calls follow the Linux adapter.
const NO_OS: NoOS<MockDriver> = NoOS(PhantomData);

impl OsAdapter for NoOS<MockDriver> {
    fn prepare_function_call(
        &self,
        vmi: &VmiCore<MockDriver>,
        registers: &mut Registers,
        builder: CallBuilder,
    ) -> Result<(), VmiError> {
        prepare_call(vmi, registers, builder)
    }

    fn find_image(_vmi: &VmiState<'_, Self>, _name: &str) -> Result<Option<Va>, VmiError> {
        Ok(None)
    }

    fn red_zone(&self, registers: &Registers) -> u64 {
        red_zone(registers)
    }

    fn copy_to_stack(
        &self,
        vmi: &VmiCore<MockDriver>,
        registers: &mut Registers,
        data: &[u8],
        alignment: usize,
    ) -> Result<Va, VmiError> {
        copy_to_stack(vmi, registers, data, alignment)
    }
}

/// Returns a core whose page tables map the test stack, writable by user
/// code, or without the PT entry for `missing`.
fn core(missing: bool) -> Result<VmiCore<MockDriver>, VmiError> {
    let driver = MockDriver::new();
    for gfn in TABLES {
        driver.insert_page(gfn);
    }
    driver.insert_page(STACK);

    let levels = [
        PageTableLevel::Pml4,
        PageTableLevel::Pdpt,
        PageTableLevel::Pd,
        PageTableLevel::Pt,
    ];

    for (index, level) in levels.into_iter().enumerate() {
        let next = TABLES.get(index + 1).copied().unwrap_or(STACK);
        let entry = if missing && level == PageTableLevel::Pt {
            PageTableEntry(0)
        }
        else {
            PageTableEntry((next.0 << Amd64::PAGE_SHIFT) | USER_RW)
        };

        let address = Amd64::pa_from_gfn(TABLES[index])
            + Amd64::va_index_for(STACK_VA, level) * size_of::<PageTableEntry>() as u64;
        driver.write_pte(address, entry);
    }

    VmiCore::new(driver)
}

/// Returns registers with the stack pointer at an offset into the test
/// stack.
fn registers(offset: u64, rip: u64) -> Registers {
    Registers {
        rip,
        rsp: (STACK_VA + offset).0,
        cr3: Cr3(Amd64::pa_from_gfn(TABLES[0]).0),
        ..Default::default()
    }
}

/// Reads a 64-bit value from the test stack.
fn stack_u64(vmi: &VmiCore<MockDriver>, va: u64) -> Result<u64, VmiError> {
    vmi.read_u64((Va(va), Amd64::pa_from_gfn(TABLES[0])))
}

/// Returns a call to the test function with the arguments 1 to `count`.
fn call(count: u64) -> CallBuilder {
    let arguments = (1..=count).collect::<Vec<u64>>();
    arguments
        .iter()
        .fold(CallBuilder::new(Va(FUNCTION)), |builder, argument| {
            builder.with_argument(argument)
        })
}

#[test]
fn six_arguments_go_to_registers() -> Result<(), VmiError> {
    let vmi = core(false)?;
    let mut registers = registers(0x800, USER_RIP);
    registers.rax = 0xff;

    prepare_call(&vmi, &mut registers, call(6))?;

    let arguments = [
        registers.rdi,
        registers.rsi,
        registers.rdx,
        registers.rcx,
        registers.r8,
        registers.r9,
    ];
    assert_eq!(arguments, [1, 2, 3, 4, 5, 6]);
    assert_eq!(registers.rax, 0);
    assert_eq!(registers.rip, FUNCTION);
    assert_eq!(stack_u64(&vmi, registers.rsp)?, USER_RIP);
    Ok(())
}

#[test]
fn arguments_after_the_sixth_lie_above_the_return_address() -> Result<(), VmiError> {
    for count in [7, 8] {
        for offset in [0x800, 0x808] {
            let vmi = core(false)?;
            let mut registers = registers(offset, USER_RIP);

            prepare_call(&vmi, &mut registers, call(count))?;

            // The call pushed the return address onto a stack aligned to 16
            // bytes.
            assert_eq!((registers.rsp + 8) % 16, 0);
            assert_eq!(stack_u64(&vmi, registers.rsp)?, USER_RIP);

            for argument in 7..=count {
                let address = registers.rsp + 8 * (argument - 6);
                assert_eq!(stack_u64(&vmi, address)?, argument);
            }

            assert!(registers.rsp + 8 * (count - 5) <= (STACK_VA + offset).0);
        }
    }

    Ok(())
}

#[test]
fn references_go_to_the_stack_first() -> Result<(), VmiError> {
    let vmi = core(false)?;
    let mut registers = registers(0x800, USER_RIP);

    let text = "/tmp/file";
    prepare_call(
        &vmi,
        &mut registers,
        CallBuilder::new(Va(FUNCTION)).with_argument(text),
    )?;

    let mut buffer = vec![0; text.len() + 1];
    vmi.read(
        (Va(registers.rdi), Amd64::pa_from_gfn(TABLES[0])),
        &mut buffer,
    )?;
    assert_eq!(buffer, b"/tmp/file\0");

    // The reference lies above the return address and below the original
    // stack pointer.
    assert!(registers.rdi > registers.rsp);
    assert!(registers.rdi + buffer.len() as u64 <= (STACK_VA + 0x800).0);
    Ok(())
}

/// Data of the test recipe.
struct Copies {
    /// The address of the first copy to the stack.
    address: Option<Va>,
}

/// Returns a recipe whose first step copies a value to the stack.
fn copy_recipe() -> Recipe<NoOS<MockDriver>, Copies> {
    recipe![Recipe::<NoOS<MockDriver>>::new(Copies { address: None }), {
        data![address] = Some(copy_to_stack!(0u64)?);
        Ok(RecipeControlFlow::Continue)
    }]
}

/// Runs the next step of the recipe with the given registers.
fn execute(
    vmi: &VmiCore<MockDriver>,
    executor: &mut RecipeExecutor<NoOS<MockDriver>, Copies>,
    registers: &Registers,
) -> Result<Option<Registers>, VmiError> {
    let session = VmiSession::new(vmi, &NO_OS);
    let state = session.with_registers(registers);
    executor.execute(&state)
}

#[test]
fn first_step_starts_below_the_red_zone_in_user_mode() -> Result<(), VmiError> {
    for (rip, red_zone) in [(USER_RIP, 128), (KERNEL_RIP, 0)] {
        let vmi = core(false)?;
        let registers = registers(0x800, rip);
        let mut executor = RecipeExecutor::new(copy_recipe());

        let after = execute(&vmi, &mut executor, &registers)?.expect("registers");
        assert_eq!(after.rsp, registers.rsp - red_zone - 8);
    }

    Ok(())
}

#[test]
fn step_after_a_page_fault_starts_below_the_red_zone_again() -> Result<(), VmiError> {
    let registers = registers(0x800, USER_RIP);
    let mut executor = RecipeExecutor::new(copy_recipe());

    // The page fault leaves the guest's registers as they were, and the step
    // runs again from them.
    let vmi = core(true)?;
    assert!(matches!(
        execute(&vmi, &mut executor, &registers),
        Err(VmiError::PageFault(_))
    ));

    let vmi = core(false)?;
    let after = execute(&vmi, &mut executor, &registers)?.expect("registers");
    assert_eq!(after.rsp, registers.rsp - 128 - 8);
    Ok(())
}

#[test]
fn library_names_match_with_and_without_a_version() {
    assert!(is_library("libc.so", "libc"));
    assert!(is_library("libc.so.6", "libc"));
    assert!(is_library("libpthread.so.0", "libpthread"));

    assert!(!is_library("libcap.so.2", "libc"));
    assert!(!is_library("libc-2.31.so", "libc"));
    assert!(!is_library("libc.sox", "libc"));
    assert!(!is_library("libc", "libc"));
}
