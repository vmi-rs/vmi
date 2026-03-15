use std::sync::{Arc, atomic::AtomicBool};

use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    Va, VcpuId, VmiCore, VmiError, VmiEventControl, VmiSession,
    arch::amd64::Amd64,
    driver::{
        VmiQueryRegisters, VmiRead, VmiSetProtection, VmiSetRegisters, VmiViewControl,
        VmiVmControl, VmiWrite, xen::VmiXenDriver,
    },
    os::windows::WindowsOs,
    utils::injector::{InjectorHandler, KernelMode, Recipe, recipe},
};
use xen::XenStore;

#[derive(Debug, Default)]
pub struct RecipeData {
    system_time_va: Va,
    previous_time_va: Va,
}

pub fn recipe_factory<Driver>() -> Recipe<WindowsOs<Driver>, RecipeData>
where
    Driver: VmiRead<Architecture = Amd64> + VmiWrite<Architecture = Amd64>,
{
    recipe![
        Recipe::<WindowsOs<Driver>, _>::new(RecipeData::default()),
        //
        // Step 1: Allocate memory from the non-paged pool.
        //         This guarantees that the memory will be present for the
        //         next step in the physical memory.
        //
        {
            tracing::debug!("[step 1]");

            const fn create_windows_time(
                year: u64,
                month: u64,
                day: u64,
                hour: u64,
                minute: u64,
                second: u64,
            ) -> u64 {
                // Days from years (accounting for leap years)
                let mut total_days: u64 = 0;
                let mut y = 1601;
                while y < year {
                    if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
                        total_days += 366;
                    }
                    else {
                        total_days += 365;
                    }
                    y += 1;
                }

                // Days from months
                let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
                let month_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                let mut m = 1;
                while m < month {
                    total_days += month_days[(m - 1) as usize];
                    if m == 2 && is_leap {
                        total_days += 1;
                    }
                    m += 1;
                }

                // Days
                total_days += day - 1;

                // Convert to 100-nanosecond intervals
                let total_seconds = total_days * 86400 + hour * 3600 + minute * 60 + second;
                total_seconds * 10_000_000
            }

            const NEW_SYSTEM_TIME: u64 = create_windows_time(2025, 2, 4, 9, 9, 9);

            data![system_time_va] = copy_to_stack!(NEW_SYSTEM_TIME)?;
            data![previous_time_va] = copy_to_stack!(0u64)?;

            inject! {
                nt!ZwSetSystemTime(
                    data![system_time_va],    // SystemTime
                    data![previous_time_va]   // PreviousTime
                )
            }

            //#[expect(non_upper_case_globals)]
            //const NonPagedPoolExecute: u64 = 0;
            //
            //inject! {
            //    nt!ExAllocatePool(
            //        NonPagedPoolExecute,    // PoolType
            //        0x10000                 // NumberOfBytes
            //    )
            //}
        },
    ]
}

pub fn injector_handler_factory<Driver>() -> impl FnOnce(
    &VmiSession<WindowsOs<Driver>>,
) -> Result<
    InjectorHandler<WindowsOs<Driver>, KernelMode, RecipeData>,
    VmiError,
>
where
    Driver: VmiRead<Architecture = Amd64>
        + VmiWrite<Architecture = Amd64>
        + VmiSetProtection<Architecture = Amd64>
        + VmiQueryRegisters<Architecture = Amd64>
        + VmiSetRegisters<Architecture = Amd64>
        + VmiEventControl<Architecture = Amd64>
        + VmiViewControl<Architecture = Amd64>
        + VmiVmControl<Architecture = Amd64>,
{
    move |session| InjectorHandler::new(session, recipe_factory())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let domain_id = match XenStore::new()?.domain_id_from_name("win10-22h2")? {
        Some(domain_id) => domain_id,
        None => {
            tracing::error!("Domain not found");
            return Ok(());
        }
    };

    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::new(domain_id)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.expect("kernel information")
    };

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::<JsonCodec>::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    session.handle(injector_handler_factory())?;
    //std::thread::sleep(std::time::Duration::from_millis(1000));

    Ok(())
}
