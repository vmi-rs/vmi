use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use vmi_arch_amd64::Registers;
use vmi_core::{VmiCore, VmiError, VmiSession, VmiState, os::NoOS};
use vmi_driver_mock::arch::amd64::MockDriver;

use super::super::{Recipe, RecipeContext, RecipeControlFlow, RecipeExecutor};

type Os = NoOS<MockDriver>;

type Step = Box<
    dyn Fn(&mut RecipeContext<'_, Os, ()>) -> Result<RecipeControlFlow, VmiError> + Send + Sync,
>;

/// Indices of the steps executed so far, in order.
type Log = Arc<Mutex<Vec<usize>>>;

/// Instruction pointer of the trap the recipe is driven from.
const TRAP: u64 = 0x1000;

/// Stack pointer of the hijacked thread.
const STACK: u64 = 0x2000;

fn trapped_registers() -> Registers {
    Registers {
        rip: TRAP,
        rsp: STACK,
        ..Default::default()
    }
}

/// Builds a step that records its index and applies `effect` to the registers.
fn step(log: &Log, index: usize, effect: fn(&mut Registers)) -> Step {
    let log = Arc::clone(log);

    Box::new(move |ctx| {
        log.lock().expect("log").push(index);
        effect(ctx.registers);
        Ok(RecipeControlFlow::Continue)
    })
}

/// Leaves the guest trapped on the same instruction.
fn host_only(_registers: &mut Registers) {}

/// Mimics an injected function call.
fn prepare_call(registers: &mut Registers) {
    registers.rip = TRAP + 5;
}

/// Mimics reserving stack space for an output parameter.
fn reserve_stack(registers: &mut Registers) {
    registers.rsp = STACK - 8;
}

#[test]
fn host_only_steps_run_without_resuming_the_guest() -> Result<(), VmiError> {
    let log = Log::default();

    let recipe = Recipe::<Os>::new(())
        .step(step(&log, 0, host_only))
        .step(step(&log, 1, prepare_call))
        .step(step(&log, 2, host_only));

    let mut executor = RecipeExecutor::new(recipe);

    let core = VmiCore::new(MockDriver::new())?;
    let os = NoOS(PhantomData);
    let session = VmiSession::new(&core, &os);
    let registers = trapped_registers();
    let vmi = VmiState::new(&session, &registers);

    // The first step changes nothing, so the second step runs in the same
    // execution; the second step prepares a call, which must reach the guest.
    let after = executor.execute(&vmi)?.expect("registers");
    assert_eq!(*log.lock().expect("log"), [0, 1]);
    assert_eq!(after.rip, TRAP + 5);
    assert!(!executor.done());

    // The call returned to the trap. The last step changes nothing, so the
    // recipe also finishes within this execution.
    let after = executor.execute(&vmi)?.expect("registers");
    assert_eq!(*log.lock().expect("log"), [0, 1, 2]);
    assert!(executor.done());
    assert_eq!(after.rip, TRAP);

    Ok(())
}

#[test]
fn step_reserving_stack_resumes_the_guest() -> Result<(), VmiError> {
    let log = Log::default();

    let recipe = Recipe::<Os>::new(())
        .step(step(&log, 0, reserve_stack))
        .step(step(&log, 1, host_only));

    let mut executor = RecipeExecutor::new(recipe);

    let core = VmiCore::new(MockDriver::new())?;
    let os = NoOS(PhantomData);
    let session = VmiSession::new(&core, &os);
    let registers = trapped_registers();
    let vmi = VmiState::new(&session, &registers);

    // Stack reserved for the guest must be committed before the next step
    // runs, so the reserved region stays above the guest stack pointer.
    let after = executor.execute(&vmi)?.expect("registers");
    assert_eq!(*log.lock().expect("log"), [0]);
    assert_eq!(after.rsp, STACK - 8);

    executor.execute(&vmi)?.expect("registers");
    assert_eq!(*log.lock().expect("log"), [0, 1]);

    Ok(())
}
