use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use deto_bridge::decoy::InjectorDownloadBridge;
use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    Hex, Registers as _, Va, VcpuId, VmiCore, VmiError, VmiEventControl, VmiMemory, VmiSession,
    VmiState,
    arch::amd64::Amd64,
    driver::{
        VmiQueryRegisters, VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
        xen::VmiXenDriver,
    },
    os::{ProcessId, VmiOsProcess as _, windows::WindowsOs},
    utils::{
        bridge::BridgeHandler,
        injector::{
            //km::{InjectorHandler, InjectorResultCode},
            //InjectorHandler,
            InjectorHandler,
            InjectorResultCode,
            Recipe,
            RecipeControlFlow,
            UserMode,
            recipe,
        },
    },
};
use xen::XenStore;

#[derive(Debug, Default)]
pub struct Data {
    shellcode: Vec<u8>,
    allocated_memory: u64,
}

impl Data {
    pub fn new(shellcode: Vec<u8>) -> Self {
        Self {
            shellcode,
            allocated_memory: 0,
        }
    }
}

#[tracing::instrument(name = "user_shellcode", skip_all)]
pub fn recipe_factory<Driver>(shellcode: Vec<u8>) -> Recipe<WindowsOs<Driver>, Data>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    recipe![
        Recipe::<WindowsOs<Driver>, _>::new(Data::new(shellcode)),
        //
        // Step 1: Allocate memory
        //
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            tracing::debug!("step 1 (pre): kernel32!VirtualAlloc()");

            inject! {
                kernel32!VirtualAlloc(
                    0,                          // lpAddress
                    0x1000,                     // dwSize
                    MEM_COMMIT | MEM_RESERVE,   // flAllocationType
                    PAGE_EXECUTE_READWRITE      // flProtect
                )
            }
        },
        //
        // Step 2: Fill memory with zeros.
        //         This also causes the memory to be paged-in.
        //
        {
            data![allocated_memory] = vmi!().registers().rax;

            tracing::debug!(
                result = %Hex(data![allocated_memory]),
                "step 1 (post)"
            );

            tracing::debug!(
                va = %Hex(data![allocated_memory]),
                "step 2 (pre): kernel32!RtlFillMemory()"
            );

            inject! {
                kernel32!RtlFillMemory(
                    data![allocated_memory],    // Destination
                    0x1000,                     // Length
                    0                           // Fill
                )
            }
        },
        //
        // Step 3: Write shellcode to allocated memory
        //         and create a new thread to execute it
        //
        {
            tracing::debug!("step 2 (post)");

            vmi!().write(data![allocated_memory].into(), &data![shellcode])?;

            let start_address = data![allocated_memory];
            let parameter = data![allocated_memory] + (4096 - 128);

            tracing::debug!(
                start_address = %Hex(start_address),
                parameter = %Hex(parameter),
                "step 3 (pre): kernel32!CreateThread()"
            );

            inject! {
                kernel32!CreateThread(
                    0,                          // lpThreadAttributes
                    0,                          // dwStackSize
                    start_address,              // lpStartAddress
                    parameter,                  // lpParameter
                    0,                          // dwCreationFlags
                    0                           // lpThreadId
                )
            }
        },
    ]
}

fn network_interface_address(interface: &str) -> Result<Option<IpAddr>, local_ip_address::Error> {
    let network_interfaces = local_ip_address::list_afinet_netifas()?;

    for (name, ip) in network_interfaces {
        if name == interface {
            return Ok(Some(ip));
        }
    }

    Ok(None)
}

fn find_process_by_name(
    vmi: &VmiState<WindowsOs<VmiXenDriver<Amd64>>>,
    name: &str,
) -> Result<Option<ProcessId>, VmiError> {
    let mut result = None;

    for process in vmi.os().processes()? {
        let process = process?;

        if process.name()?.to_lowercase().contains(name) {
            result = Some(process.id()?);
        }
    }

    Ok(result)
}

pub fn injector_handler_factory<Driver>(
    url: &str,
    pid: ProcessId,
) -> impl FnOnce(
    &VmiSession<WindowsOs<Driver>>,
) -> Result<
    InjectorHandler<WindowsOs<Driver>, UserMode, Data, InjectorDownloadBridge>,
    VmiError,
>
where
    Driver: VmiRead<Architecture = Amd64>
        + VmiWrite<Architecture = Amd64>
        + VmiSetProtection<Architecture = Amd64>
        + VmiEventControl<Architecture = Amd64>
        + VmiViewControl<Architecture = Amd64>
        + VmiVmControl<Architecture = Amd64>,
    InjectorDownloadBridge: BridgeHandler<WindowsOs<Driver>, InjectorResultCode>,
{
    // sc can have arbitrary length, but no more than 3.5KB
    let sc = include_bytes!(
        "/root/hypermon/crates/deto-injector/scfw/build-x64/shellcodes/download_and_unzip/download_and_unzip.bin"
    );
    assert!(sc.len() < 4096 - 128);

    let mut buffer1 = [0u8; 4096 - 128];

    // copy content of sc to buffer1. note that buffer lengths might be different
    buffer1[..sc.len()].copy_from_slice(sc);

    let mut scparam = Vec::new();
    scparam.extend_from_slice(url.as_bytes());
    scparam.push(0);
    assert!(scparam.len() < 128);

    let mut buffer2 = [0u8; 128];
    buffer2[..scparam.len()].copy_from_slice(&scparam);

    let shellcode = [&buffer1[..], &buffer2[..]].concat();
    assert_eq!(shellcode.len(), 0x1000);

    move |session| {
        InjectorHandler::with_bridge(
            session,
            InjectorDownloadBridge::new(1),
            recipe_factory(shellcode),
        )?
        .with_pid(pid)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let domain_id = match XenStore::new()?.domain_id_from_name("win10-22h2")? {
        //let domain_id = match XenStore::new()?.domain_id_from_name("win7-sp1")? {
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

    let pause_guard = core.pause_guard()?;
    let registers = core.registers(0.into())?;
    let vmi = session.with_registers(&registers);

    let pid = find_process_by_name(&vmi, "explorer.exe")?.expect("target process");
    drop(pause_guard);

    // Set up the server.
    let bridge = "dynabr0";
    let ip = network_interface_address(&bridge)?
        .expect(&format!("Cannot find IP address for '{bridge}'"));

    let addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let timeout = Duration::from_secs(60);

    let server = deto_injector_server::create(addr, "/root/hypermon/scripts.zip", timeout)?;
    let port = server.addr().port();
    let route = server.route();

    let url = url::Url::parse(&format!("http://{ip}:{port}{route}"))?;

    // Create and execute the injection handler.
    session.handle(injector_handler_factory(url.as_str(), pid))?;

    Ok(())
}
