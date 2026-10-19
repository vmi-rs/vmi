use vmi_core::{
    Registers as _, Va, VmiError, VmiState,
    driver::{VmiDriver, VmiRead, VmiWrite},
    os::ProcessId,
    trace::Hex,
};
use vmi_os_macos::{MacOs, MacOsExt as _};

use super::Arch;
use crate::injector::{Recipe, RecipeControlFlow, recipe};

/// Index after the last step of the wake recipe.
///
/// A jump to this index ends the recipe once the injected call returns.
const STEP_END: usize = 6;

/// Data retained while the wake recipe executes.
pub(super) struct WakeRecipeData {
    /// ID of the process whose thread is woken.
    pid: ProcessId,

    /// ID of the thread to wake, as `thread.thread_id` holds it.
    thread_id: u64,

    /// Address of `proc_find`.
    proc_find: Va,

    /// Address of `proc_task`.
    proc_task: Va,

    /// Address of `task_findtid`.
    task_findtid: Va,

    /// Address of `proc_rele`.
    proc_rele: Va,

    /// Address of `thread_abort_safely`.
    thread_abort_safely: Va,

    /// Address of `thread_deallocate`.
    thread_deallocate: Va,

    /// Process that `proc_find` returns with a reference.
    process: Va,

    /// Thread that `task_findtid` returns with a reference.
    thread: Va,
}

impl WakeRecipeData {
    /// Creates the data of a wake recipe from the kernel symbols.
    ///
    /// Fails when the profile lacks one of the kernel functions that the
    /// recipe calls.
    pub(super) fn new<Driver>(
        vmi: &VmiState<MacOs<Driver>>,
        pid: ProcessId,
        thread_id: u64,
    ) -> Result<Self, VmiError>
    where
        Driver: VmiDriver<Architecture = Arch> + VmiRead,
    {
        let symbols = vmi.os().symbols();

        Ok(Self {
            pid,
            thread_id,
            proc_find: kernel_function(symbols.proc_find, "proc_find not found")?,
            proc_task: kernel_function(symbols.proc_task, "proc_task not found")?,
            task_findtid: kernel_function(symbols.task_findtid, "task_findtid not found")?,
            proc_rele: kernel_function(symbols.proc_rele, "proc_rele not found")?,
            thread_abort_safely: kernel_function(
                symbols.thread_abort_safely,
                "thread_abort_safely not found",
            )?,
            thread_deallocate: kernel_function(
                symbols.thread_deallocate,
                "thread_deallocate not found",
            )?,
            process: Va(0),
            thread: Va(0),
        })
    }
}

/// Returns the runtime address of a kernel function, or the error `missing`
/// when the profile lacks it.
fn kernel_function(address: Option<u64>, missing: &'static str) -> Result<Va, VmiError> {
    match address {
        Some(address) => Ok(Va(address)),
        None => Err(VmiError::Other(missing)),
    }
}

/// Builds the kernel recipe that wakes a thread that waits at a safe point.
///
/// The recipe finds the thread by its IDs and holds a reference on it while
/// `thread_abort_safely` ends its wait. The syscall of the thread then
/// returns an interrupted result, such as `MACH_RCV_INTERRUPTED`.
///
/// # Notes
///
/// When the recipe is aborted between `proc_find` and `proc_rele`, the
/// process keeps a reference and blocks forever when it exits. When it is
/// aborted between `task_findtid` and `thread_deallocate`, the thread leaks.
pub(super) fn wake_recipe<Driver>(data: WakeRecipeData) -> Recipe<MacOs<Driver>, WakeRecipeData>
where
    Driver: VmiDriver<Architecture = Arch> + VmiRead + VmiWrite,
{
    recipe![
        Recipe::<MacOs<Driver>>::new(data),
        //
        // Step 1:
        // - Find the process with a reference
        //
        {
            let proc_find = data![proc_find];

            inject! {
                proc_find(
                    u64::from(data![pid].0)     // pid
                )
            }
        },
        //
        // Step 2:
        // - Verify that the process exists
        // - Get its task
        //
        {
            data![process] = Va(registers!().result());
            if data![process].is_null() {
                tracing::debug!(pid = %data![pid], "wake: process not found");
                return Ok(RecipeControlFlow::Break);
            }

            let proc_task = data![proc_task];

            inject! {
                proc_task(
                    data![process]              // proc
                )
            }
        },
        //
        // Step 3:
        // - Find the thread with a reference
        //
        {
            let task = Va(registers!().result());
            if task.is_null() {
                tracing::debug!(pid = %data![pid], "wake: process has no task");

                let proc_rele = data![proc_rele];
                inject! {
                    proc_rele(
                        data![process]          // p
                    )
                }?;

                return Ok(RecipeControlFlow::Goto(STEP_END));
            }

            let task_findtid = data![task_findtid];

            inject! {
                task_findtid(
                    task,                       // task
                    data![thread_id]            // tid
                )
            }
        },
        //
        // Step 4:
        // - Release the process, the thread keeps its own reference
        //
        {
            data![thread] = Va(registers!().result());

            let proc_rele = data![proc_rele];

            inject! {
                proc_rele(
                    data![process]              // p
                )
            }
        },
        //
        // Step 5:
        // - Verify that the thread exists
        // - End its wait
        //
        {
            if data![thread].is_null() {
                tracing::debug!(thread_id = data![thread_id], "wake: thread not found");
                return Ok(RecipeControlFlow::Break);
            }

            let thread_abort_safely = data![thread_abort_safely];

            inject! {
                thread_abort_safely(
                    data![thread]               // thread
                )
            }
        },
        //
        // Step 6:
        // - Release the thread
        //
        {
            tracing::debug!(
                thread_id = data![thread_id],
                result = %Hex(registers!().result()),
                "wake: thread_abort_safely"
            );

            let thread_deallocate = data![thread_deallocate];

            inject! {
                thread_deallocate(
                    data![thread]               // thread
                )
            }
        },
    ]
}
