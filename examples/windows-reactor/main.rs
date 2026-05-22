//! This example demonstrates how to use the `vmi_utils::reactor` module to
//! monitor certain events in a Windows guest VM.
//!
//! In particular, we monitor these functions:
//! - `nt!NtWriteFile`: to log the full path of files being written to.
//! - `netio.sys!KfdClassify` and `netio.sys!KfdIsLayerEmpty`: to log network
//!   connections and their originating process.
//! - `ncrypt.dll!SslGenerateSessionKeys`: to log SSL/TLS session keys, to
//!   eventually decrypt the network traffic.
//!
//! # Usage
//!
//! ```text
//! VMI_XEN_DOMAIN_NAME=<domain name> cargo run --features="arch-amd64 driver-xen os-windows utils" --example windows-reactor
//! ```
//!
//! or
//!
//! ```text
//! VMI_XEN_DOMAIN_ID=<domain id> cargo run --features="arch-amd64 driver-xen os-windows utils" --example windows-reactor
//! ```
//!
//! # Possible log output
//!
//! ```text
//!  INFO resolving domain ID domain_name=win10-22h2
//!  INFO setting up VMI domain_id=417
//! DEBUG found kernel image base_address=0xfffff80106e00000
//!  INFO loading kernel profile codeview=CodeView { name: "ntkrnlmp.pdb", guid: "68a17faf3012b7846079aeecdbe0a583", age: 1 }
//! DEBUG found cached PE image path=cache/windows/ntkrnlmp.pdb/68a17faf3012b7846079aeecdbe0a5831/ntkrnlmp.pdb
//!  INFO creating VMI session
//! DEBUG resolver:user{module="ncrypt.dll"}:via_vad{process="lsass.exe"}: region found, reading image
//! DEBUG resolver:user{module="ncrypt.dll"}: module resolved via VAD process="lsass.exe" codeview=CodeView { name: "ncrypt.pdb", guid: "bdff5e7b85792ad5e6cac5e8b4a2addc", age: 1 }
//! DEBUG resolve_event{module=kernel name=NtWriteFile}: symbol found offset=0x00000000005ed180
//! DEBUG resolve_event{module=NetioSys name=KfdClassify}: symbol found offset=0x0000000000007e10
//! DEBUG resolve_event{module=NetioSys name=KfdIsLayerEmpty}: symbol found offset=0x0000000000005520
//! DEBUG resolve_event{module=NcryptDll name=SslGenerateSessionKeys}: symbol found offset=0x00000000000012a0
//! DEBUG active breakpoint inserted active=1 gfn=0x00000000000031ed ctx=0xfffff801073ed180 @ 0x00000000001aa000 view=1 global=true key=() tag=NtWriteFile
//! DEBUG created shadow page address=0x00000000031ed180 original_gfn=0x00000000000031ed shadow_gfn=0x00000000001100fc view=1
//! DEBUG active breakpoint inserted active=2 gfn=0x0000000000005a37 ctx=0xfffff8010bc37e10 @ 0x00000000001aa000 view=1 global=true key=() tag=KfdClassify
//! DEBUG created shadow page address=0x0000000005a37e10 original_gfn=0x0000000000005a37 shadow_gfn=0x00000000001100fd view=1
//! DEBUG active breakpoint inserted active=3 gfn=0x0000000000005a35 ctx=0xfffff8010bc35520 @ 0x00000000001aa000 view=1 global=true key=() tag=KfdIsLayerEmpty
//! DEBUG created shadow page address=0x0000000005a35520 original_gfn=0x0000000000005a35 shadow_gfn=0x00000000001100fe view=1
//! DEBUG active breakpoint inserted active=4 gfn=0x00000000000c81de ctx=0x00007ffbdc4f12a0 @ 0x00000000c39da000 view=1 global=true key=() tag=SslGenerateSessionKeys
//! DEBUG created shadow page address=0x00000000c81de2a0 original_gfn=0x00000000000c81de shadow_gfn=0x00000000001100ff view=1
//! ...
//!  INFO reactor{vcpu=1 view=1 pid=1844 tid=7672}:interrupt:KfdClassify: protocol=IPPROTO_UDP local_ip=192.168.1.1 local_port=60066 remote_ip=8.8.8.8 remote_port=53 pid=1844
//!  INFO reactor{vcpu=1 view=1 pid=1844 tid=7672}:interrupt:KfdClassify: protocol=IPPROTO_UDP local_ip=192.168.1.1 local_port=60066 remote_ip=8.8.8.8 remote_port=53 pid=1844
//!  INFO reactor{vcpu=1 view=1 pid=8120 tid=3616}:interrupt:KfdClassify: protocol=IPPROTO_TCP local_ip=192.168.1.1 local_port=55598 remote_ip=54.91.177.181 remote_port=443 pid=8120
//!  INFO reactor{vcpu=3 view=1 pid=4 tid=0}:interrupt:KfdClassify: protocol=IPPROTO_TCP local_ip=192.168.1.1 local_port=55598 remote_ip=54.91.177.181 remote_port=443 pid=8120
//!  INFO reactor{vcpu=0 view=1 pid=664 tid=788}:interrupt:SslGenerateSessionKeys: client_random="4a8979877a9386a10d1e488eea06eb33a6650008538514ba0d91d1a8ad50d45e" secret="61b835e7246e00bcca42f2067d0efebbb3809897118c6f20025056afbb7cd89d3cded737d15c26ab04f9b339d65810d5"
//! ...
//!  INFO reactor{vcpu=3 view=1 pid=2500 tid=5140}:interrupt:NtWriteFile: handle=0x00000000000004b4 path="\\Device\\HarddiskVolume2\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\57C8EDB95DF3F0AD4EE2DC2B8CFD4157"
//!  INFO reactor{vcpu=3 view=1 pid=2500 tid=5140}:interrupt:NtWriteFile: handle=0x00000000000004b4 path="\\Device\\HarddiskVolume2\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\FB0D848F74F70BB2EAA93746D24D9749"
//!  INFO reactor{vcpu=0 view=1 pid=5432 tid=2112}:interrupt:NtWriteFile: handle=0x00000000000018c0 path="\\Device\\HarddiskVolume2\\Users\\John\\AppData\\Local\\Microsoft\\Edge\\User Data\\Edge-Local-State-Tmp-53f0e37f-8e8f-4a36-87aa-4b0582035293.tmp"
//! ...
//! DEBUG active breakpoints removed active=3 gfn=0x00000000000c81de view=1 breakpoints={((), AddressContext { va: 0x00007ffbdc4f12a0, root: 0x00000000c39da000 }): {Breakpoint { ctx: AddressContext { va: 0x00007ffbdc4f12a0, root: 0x00000000c39da000 }, view: View(1), global: true, key: (), tag: SslGenerateSessionKeys }}}
//! DEBUG active breakpoints removed active=2 gfn=0x00000000000031ed view=1 breakpoints={((), AddressContext { va: 0xfffff801073ed180, root: 0x00000000001aa000 }): {Breakpoint { ctx: AddressContext { va: 0xfffff801073ed180, root: 0x00000000001aa000 }, view: View(1), global: true, key: (), tag: NtWriteFile }}}
//! DEBUG active breakpoints removed active=1 gfn=0x0000000000005a37 view=1 breakpoints={((), AddressContext { va: 0xfffff8010bc37e10, root: 0x00000000001aa000 }): {Breakpoint { ctx: AddressContext { va: 0xfffff8010bc37e10, root: 0x00000000001aa000 }, view: View(1), global: true, key: (), tag: KfdClassify }}}
//! DEBUG active breakpoints removed active=0 gfn=0x0000000000005a35 view=1 breakpoints={((), AddressContext { va: 0xfffff8010bc35520, root: 0x00000000001aa000 }): {Breakpoint { ctx: AddressContext { va: 0xfffff8010bc35520, root: 0x00000000001aa000 }, view: View(1), global: true, key: (), tag: KfdIsLayerEmpty }}}
//! ...
//!  INFO hit counts NtWriteFile=773 KfdClassify=30 KfdIsLayerEmpty=2131 SslGenerateSessionKeys=3
//! ```
//!

#![expect(non_snake_case)]

mod ncrypt;
mod netio;
mod ntoskrnl;

use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context as _, Error};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiContext, VmiCore, VmiError, VmiOs, VmiRead, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{
        VmiOsProcess as _,
        windows::{ArchAdapter, WindowsOs, WindowsProcess},
    },
    utils::reactor::{Action, Reactor, ReactorHandler, define_events, define_modules},
};
use xen::{XenDomainId, XenStore};

fn match_lsass<Driver>(process: &WindowsProcess<Driver>) -> Result<bool, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    // Match "lsass.exe" in SessionId 0.
    Ok(
        matches!(process.session()?, Some(session) if session.id()? == 0)
            && process.name()?.eq_ignore_ascii_case("lsass.exe"),
    )
}

define_modules! {
    /// Modules used by the reactor.
    #[os(
        <Driver: VmiRead> WindowsOs<Driver>
        where Driver::Architecture: ArchAdapter<Driver>
    )]
    enum Module {
        /// `netio.sys`
        #[module(name = "netio.sys")]
        NetioSys,

        /// `ncrypt.dll` in `lsass.exe`.
        // Note that `.., process = "lsass.exe"` would also work, but this
        // demonstrates how to use a custom predicate.
        #[module(name = "ncrypt.dll", mode(user, process = match_lsass))]
        NcryptDll,
    }

    #[resolver]
    struct ModuleResolver;

    #[cache]
    struct SymbolCache;
}

define_events! {
    /// Events monitored by the reactor.
    enum Event in Module {
        /// `nt!NtWriteFile`
        NtWriteFile,

        // `netio.sys`
        NetioSys {
            /// `netio.sys!KfdClassify`
            KfdClassify,

            /// `netio.sys!KfdIsLayerEmpty`
            KfdIsLayerEmpty,
        },

        // `ncrypt.dll`
        NcryptDll {
            /// `ncrypt.dll!SslGenerateSessionKeys`
            SslGenerateSessionKeys,
        },
    }
}

#[derive(Default)]
struct NetIo {
    NtWriteFile_counter: u64,
    KfdClassify_counter: u64,
    KfdIsLayerEmpty_counter: u64,
    SslGenerateSessionKeys_counter: u64,
}

impl NetIo {
    #[tracing::instrument(skip_all)]
    fn NtWriteFile<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.NtWriteFile_counter += 1;
        ntoskrnl::NtWriteFile(vmi)
    }

    #[tracing::instrument(skip_all)]
    fn KfdClassify<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.KfdClassify_counter += 1;
        netio::KfdClassify(vmi)
    }

    #[tracing::instrument(skip_all)]
    fn KfdIsLayerEmpty<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.KfdIsLayerEmpty_counter += 1;
        netio::KfdIsLayerEmpty(vmi)
    }

    #[tracing::instrument(skip_all)]
    fn SslGenerateSessionKeys<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.SslGenerateSessionKeys_counter += 1;
        ncrypt::SslGenerateSessionKeys(vmi)
    }
}

impl Drop for NetIo {
    fn drop(&mut self) {
        tracing::info!(
            NtWriteFile = self.NtWriteFile_counter,
            KfdClassify = self.KfdClassify_counter,
            KfdIsLayerEmpty = self.KfdIsLayerEmpty_counter,
            SslGenerateSessionKeys = self.SslGenerateSessionKeys_counter,
            "hit counts"
        );
    }
}

impl<Driver> ReactorHandler<WindowsOs<Driver>> for NetIo
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Output = ();
    type Event = Event;

    fn handle_event(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        event: Self::Event,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture, Self::Output>, VmiError> {
        match event {
            Self::Event::NtWriteFile => self.NtWriteFile(vmi),
            Self::Event::KfdClassify => self.KfdClassify(vmi),
            Self::Event::KfdIsLayerEmpty => self.KfdIsLayerEmpty(vmi),
            Self::Event::SslGenerateSessionKeys => self.SslGenerateSessionKeys(vmi),
        }
    }
}

fn main() -> Result<(), Error> {
    let filter = EnvFilter::default()
        .add_directive(tracing::Level::DEBUG.into())
        .add_directive("reqwest=warn".parse()?)
        .add_directive("rustls=warn".parse()?);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let domain_id = match std::env::var("VMI_XEN_DOMAIN_ID") {
        Ok(domain_id) => XenDomainId(
            domain_id
                .parse()
                .context("invalid VMI_XEN_DOMAIN_ID environment variable")?,
        ),
        Err(_) => {
            let domain_name = std::env::var("VMI_XEN_DOMAIN_NAME")
                .context("invalid VMI_XEN_DOMAIN_NAME environment variable")?;

            tracing::info!(%domain_name, "resolving domain ID");

            match XenStore::new()?.domain_id_from_name(&domain_name)? {
                Some(domain_id) => domain_id,
                None => return Err(anyhow::anyhow!("domain not found: {domain_name}")),
            }
        }
    };

    // Setup VMI.
    tracing::info!(%domain_id, "setting up VMI");
    let driver = VmiXenDriver::<Amd64>::new(domain_id)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    // Load the kernel profile.
    // The profile contains offsets to kernel functions and data structures.
    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    let handler = NetIo::default();

    //
    // The following `let ncrypt_* = ...` lines demonstrate how to manually
    // resolve a module, load its profile (symbols) and add it to the resolver
    // via `with_module(_in_process)`.
    //
    // Note that this is not strictly necessary, as `ModuleResolver::resolve()`
    // will automatically resolve modules if they are not explicitly added.
    //
    // Manually resolving modules can be useful in cases where you want to deal
    // with the resolved information (base address, profile) in other places.
    //

    let ncrypt_resolved = {
        let paused = session.pause_guard()?;
        let vmi = paused.state();

        // Calling `resolve_user_module(&vmi, &isr, "ncrypt.dll", "lsass.exe")`
        // would also work, but this demonstrates how to use a custom predicate.
        //
        // Also, `match_lsass` is more strict, because it specifically looks
        // for "lsass.exe" in SessionId 0 (therefore, avoiding potential false
        // positives or potential malicious processes).
        vmi::utils::resolver::resolve_user_module(&vmi, &isr, "ncrypt.dll", match_lsass)?
            .context("ncrypt.dll not found in lsass.exe")?
    };

    let ncrypt_process = ncrypt_resolved
        .process
        .context("resolved ncrypt.dll is not associated with a process")?;

    let ncrypt_entry = isr
        .entry_from_codeview(ncrypt_resolved.debug_signature)
        .context("cannot find symbols for ncrypt.dll")?;

    let ncrypt_profile = ncrypt_entry
        .profile()
        .context("cannot load profile for ncrypt.dll")?;

    // The `SymbolCache` holds the resolved `isr::Entry` items.
    let mut cache = SymbolCache::default();
    let modules = ModuleResolver::default()
        // `with_kernel` MUST be called if `Event` variants reference kernel
        // symbols - like `NtWriteFile` in this example.
        //
        // This is because the "kernel" module is always optional.
        .with_kernel(kernel_info.base_address, profile)
        .with_module_in_process(
            Module::NcryptDll,
            ncrypt_process,
            ncrypt_resolved.image_base,
            ncrypt_profile,
        )
        // This will automatically resolve the `netio.sys` module and load
        // its profile.
        //
        // Note that if we hadn't called `with_module_in_process` for
        // `ncrypt.dll`, it would also be automatically resolved here.
        .resolve(&session, &isr, &mut cache)?;

    // Finally, we collect the events according to the resolved information
    // and the metadata.
    //
    // For example, if some module/event is marked as `optional` and the
    // resolver fails to resolve it, then it will simply not be included
    // in the `events`.
    let events = modules.into_events()?;

    // And we're ready to create the reactor!
    session.handle(|session| {
        Ok(Reactor::new(session, handler, events)?.with_termination_flag(terminate_flag))
    })?;

    Ok(())
}
