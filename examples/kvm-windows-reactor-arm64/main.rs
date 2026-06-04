//! Demonstrates software breakpoints, NtCreateFile logging, and return-value
//! modification on an ARM64 Windows guest via the `vmi_utils::reactor_arm64`
//! module.
//!
//! Three breakpoints are installed:
//!
//! - `nt!NtCreateFile`: logs the name of the file being opened on every hit.
//! - `netio.sys!KfdIsLayerEmpty`: forces the return value to FALSE for the four
//!   ALE layers (auth-connect V4/V6, flow-established V4/V6) so that
//!   `KfdClassify` is called even when no active WFP filter is registered.
//! - `netio.sys!KfdClassify`: logs the layer id and a running hit count.
//!
//! On AAPCS64 the return address lives in x30 (LR), not on the stack, so the
//! return-value override writes x0 = FALSE and PC = LR without any
//! stack-pointer adjustment.
//!
//! Known limitation (16K host): `KfdIsLayerEmpty` and `KfdClassify` fall in the
//! same 16K host page, and the arm64 reactor cannot yet host two breakpoints in
//! one host page (see the comment on the breakpoint list below). Only the
//! last-inserted breakpoint in a shared host page fires today, so the breakpoint
//! list orders `KfdIsLayerEmpty` last to keep the return-value modification
//! working; `KfdClassify` stays in place and will start firing once the
//! limitation is fixed.
//!
//! # Usage
//!
//! Pass the QEMU pid as `argv[1]`, or let the example scan `/proc` for a
//! `qemu-system` process. The example runs until interrupted with Ctrl-C.
//!
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows utils-arm64" --example kvm-windows-reactor-arm64 -- <qemu pid>
//! ```

use std::{
    os::fd::AsFd,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use isr::{cache::IsrCache, macros::symbols};
use tracing_subscriber::EnvFilter;
use vmi::{
    Registers as _, Va, VcpuId, VmiContext, VmiCore, VmiError, VmiEventResponse, VmiSession,
    arch::{GpRegisters as _, arm64::Arm64},
    driver::{VmiFullDriver, kvm::VmiKvmDriver},
    os::windows::{ArchAdapter, WindowsOs, WindowsOsExt as _},
    utils::reactor_arm64::{Action, BreakpointSpec, ReactorArm64, ReactorHandler},
};

symbols! {
    #[derive(Debug)]
    pub struct Symbols {
        NtCreateFile: u64,
    }
}

symbols! {
    #[derive(Debug)]
    pub struct NetioSymbols {
        KfdIsLayerEmpty: u64,

        KfdClassify: u64,
    }
}

/// Scans `/proc` for the first running `qemu-system` process and returns its
/// pid.
fn find_qemu_pid() -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let pid = match entry.file_name().to_string_lossy().parse::<i32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim_end().starts_with("qemu-system") {
            return Some(pid);
        }
    }

    None
}

/// WFP filtering-layer id passed to `KfdIsLayerEmpty` / `KfdClassify` as
/// `layerId` (AAPCS64 `x0`, a `UINT16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FwpsLayer(u16);

impl FwpsLayer {
    /// `FWPS_LAYER_ALE_AUTH_CONNECT_V4`.
    const ALE_AUTH_CONNECT_V4: Self = Self(48);

    /// `FWPS_LAYER_ALE_AUTH_CONNECT_V6`.
    const ALE_AUTH_CONNECT_V6: Self = Self(50);

    /// `FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4`.
    const ALE_FLOW_ESTABLISHED_V4: Self = Self(52);

    /// `FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6`.
    const ALE_FLOW_ESTABLISHED_V6: Self = Self(54);

    /// Returns true for the ALE auth/flow layers the reactor forces active.
    fn is_forced(self) -> bool {
        matches!(
            self,
            Self::ALE_AUTH_CONNECT_V4
                | Self::ALE_AUTH_CONNECT_V6
                | Self::ALE_FLOW_ESTABLISHED_V4
                | Self::ALE_FLOW_ESTABLISHED_V6
        )
    }
}

/// Logs file opens, forces the WFP ALE layers active, and counts classify hits.
#[derive(Default)]
struct NetIo {
    /// Number of `KfdIsLayerEmpty` calls forced to return FALSE.
    forced: u64,

    /// Number of `KfdClassify` hits observed.
    classified: u64,
}

impl NetIo {
    /// Logs the filename from a `NtCreateFile` breakpoint hit.
    fn nt_create_file<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<()>, VmiError>
    where
        Driver: VmiFullDriver<Architecture = Arm64>,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        // NtCreateFile's third argument (AAPCS64 `x2`) is a POBJECT_ATTRIBUTES.
        // Its ObjectName field points at the UNICODE_STRING naming the file.
        // `function_argument` is the arm64 ArchAdapter accessor proven in
        // Milestone 1.
        let object_attributes = vmi.os().function_argument(2)?;

        // Walking OBJECT_ATTRIBUTES.ObjectName chases guest pointers that may
        // not be resident, so a translation failure is expected and not fatal.
        // When the name cannot be read, fall back to the raw pointer value.
        match vmi
            .os()
            .object_attributes(Va(object_attributes))
            .and_then(|object_attributes| object_attributes.object_name())
        {
            Ok(Some(filename)) => tracing::info!(%filename, "NtCreateFile"),
            Ok(None) => tracing::info!(
                object_attributes = format_args!("{object_attributes:#x}"),
                "NtCreateFile (no name)"
            ),
            Err(err) => tracing::info!(
                object_attributes = format_args!("{object_attributes:#x}"),
                %err,
                "NtCreateFile (name unreadable)"
            ),
        }

        Ok(Action::Default)
    }

    /// Forces `KfdIsLayerEmpty` to return FALSE for the ALE auth/flow layers.
    ///
    /// On AAPCS64 the return address lives in x30 (LR), not on the stack, so
    /// only x0 and PC change. No stack-pointer adjustment is needed.
    fn kfd_is_layer_empty<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<()>, VmiError>
    where
        Driver: VmiFullDriver<Architecture = Arm64>,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        let layer = FwpsLayer(vmi.os().function_argument(0)? as u16);
        if !layer.is_forced() {
            tracing::trace!(?layer, "passing through");
            return Ok(Action::Default);
        }

        self.forced += 1;
        tracing::info!(?layer, "forcing KfdIsLayerEmpty -> FALSE");

        // AAPCS64: the return address is in x30 (LR), not on the stack, so
        // only x0 and PC change (no stack-pointer fixup). x0 = FALSE makes the
        // caller treat the layer as non-empty and run KfdClassify. PC = LR
        // returns to the caller without running the function body, and moving
        // PC off the BRK avoids a re-trap.
        let return_address = vmi.return_address()?;
        let mut gp = vmi.registers().gp_registers();
        gp.set_result(0);
        gp.set_instruction_pointer(return_address.into());

        Ok(Action::Response(
            VmiEventResponse::default().with_registers(gp),
        ))
    }

    /// Logs a `KfdClassify` hit with the layer id and running count.
    fn kfd_classify<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<()>, VmiError>
    where
        Driver: VmiFullDriver<Architecture = Arm64>,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.classified += 1;
        let layer = FwpsLayer(vmi.os().function_argument(0)? as u16);
        tracing::info!(?layer, count = self.classified, "KfdClassify");
        Ok(Action::Default)
    }
}

impl<Driver> ReactorHandler<Driver> for NetIo
where
    Driver: VmiFullDriver<Architecture = Arm64>,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Output = ();

    fn handle_breakpoint(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        tag: &'static str,
    ) -> Result<Action<()>, VmiError> {
        match tag {
            "NtCreateFile" => self.nt_create_file(vmi),
            "KfdIsLayerEmpty" => self.kfd_is_layer_empty(vmi),
            "KfdClassify" => self.kfd_classify(vmi),
            tag => {
                tracing::warn!(tag, "unexpected breakpoint tag");
                Ok(Action::Default)
            }
        }
    }
}

impl Drop for NetIo {
    fn drop(&mut self) {
        tracing::info!(
            forced = self.forced,
            classified = self.classified,
            "netio reactor summary"
        );
    }
}

fn main() -> Result<(), Error> {
    let filter = EnvFilter::default().add_directive(tracing::Level::INFO.into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let pid = match std::env::args().nth(1) {
        Some(arg) => arg.parse::<i32>().context("invalid QEMU pid argument")?,
        None => find_qemu_pid().context("no qemu-system process found")?,
    };

    // Setup VMI.
    tracing::info!(pid, "setting up VMI");

    // Duplicate QEMU's KVM fds and create the VMI driver.
    let fds = kvm::attach::from_pid(pid)?;
    let driver = VmiKvmDriver::<Arm64>::new(fds.vm.as_fd(), fds.vcpus)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information and capture the boot vCPU registers.
    // The registers are needed to pick the breakpoint's translation root.
    //
    // On ARM64 the kernel is located via `VBAR_EL1`, the base address of the
    // exception vector table. That register is set during boot and left
    // unchanged, so any register snapshot taken after the OS has booted works.
    let (kernel_info, registers) = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        let kernel_info =
            WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?;

        (kernel_info, registers)
    };

    // Load the kernel profile.
    // The profile contains offsets to kernel functions and data structures.
    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    let symbols = Symbols::new(&profile)?;

    // Create the VMI session and arrange for a clean shutdown on signals.
    tracing::info!("creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiKvmDriver<Arm64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    // Resolve netio.sys to find KfdIsLayerEmpty and KfdClassify.
    let netio_resolved = {
        let paused = session.pause_guard()?;
        let vmi = paused.state();
        vmi::utils::resolver::resolve_kernel_module(&vmi, &isr, "netio.sys")?
            .context("netio.sys not found")?
    };
    let netio_entry = isr
        .entry_from_codeview(netio_resolved.debug_signature)
        .context("cannot find symbols for netio.sys")?;
    let netio_profile = netio_entry
        .profile()
        .context("cannot load profile for netio.sys")?;
    let netio_symbols = NetioSymbols::new(&netio_profile)?;
    let netio_base = netio_resolved.image_base;

    // Compute virtual addresses and translation roots for all three breakpoints.
    let nt_create_file_va = kernel_info.base_address + symbols.NtCreateFile;
    let kfd_is_layer_empty_va = netio_base + netio_symbols.KfdIsLayerEmpty;
    let kfd_classify_va = netio_base + netio_symbols.KfdClassify;

    // Breakpoint order matters here because of a current arm64 reactor
    // limitation. KfdIsLayerEmpty and KfdClassify both live in netio.sys and, on
    // this 16K host, fall in the SAME 16K host page. The reactor tracks a
    // breakpoint by its 4K guest gfn but allocates and maps the shadow page at
    // 16K host-page granularity, so inserting a second breakpoint into a host
    // page already shadowed remaps that page to a fresh shadow and drops the
    // earlier breakpoint's BRK. The last breakpoint inserted into a shared host
    // page therefore wins. KfdIsLayerEmpty is placed LAST so the return-value
    // modification (the point of this example) is the breakpoint that fires;
    // KfdClassify is kept to document the intended full design and will start
    // firing once two breakpoints can coexist in one host page.
    let breakpoints = [
        BreakpointSpec {
            va: nt_create_file_va,
            root: registers.translation_root(nt_create_file_va),
            tag: "NtCreateFile",
        },
        BreakpointSpec {
            va: kfd_classify_va,
            root: registers.translation_root(kfd_classify_va),
            tag: "KfdClassify",
        },
        BreakpointSpec {
            va: kfd_is_layer_empty_va,
            root: registers.translation_root(kfd_is_layer_empty_va),
            tag: "KfdIsLayerEmpty",
        },
    ];

    // And we're ready to create the reactor!
    // The stealth constructor keeps the breakpoint page execute-only so a
    // PatchGuard read is served the clean bytes, and on this 16K host it marks
    // the fused neighbor guest pages for in-kernel auto-step, so a hot target
    // like NtCreateFile does not storm the agent with mem-access events.
    session.handle(|session| {
        Ok(ReactorArm64::new(session, NetIo::default(), &breakpoints)?
            .with_termination_flag(terminate_flag))
    })?;

    Ok(())
}
