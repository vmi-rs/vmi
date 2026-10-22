use vmi::{
    Va, VmiContext, VmiError, VmiOs,
    driver::VmiRead,
    os::{
        VmiOsProcess as _,
        linux::{ArchAdapter, LinuxOs},
    },
    utils::reactor::Action,
};

/// The size of a buffer that holds any host name, with its terminating NUL
/// (`NI_MAXHOST`).
const NI_MAXHOST: usize = 1025;

/// Logs each host name that a process looks up with `getaddrinfo`.
///
/// The host name lies in user memory. A read of a page that is not present
/// gives a page fault, which the reactor hands to the guest. The guest maps
/// the page, and the breakpoint hits again.
pub fn getaddrinfo<Driver>(
    vmi: &VmiContext<LinuxOs<Driver>>,
) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // int getaddrinfo(
    //     const char *node,
    //     const char *service,
    //     const struct addrinfo *hints,
    //     struct addrinfo **res
    //     )
    //

    let node = vmi.os().function_argument(0)?;

    // A NULL `node` asks for a local address.
    let host = if node == 0 {
        None
    }
    else {
        Some(vmi.read_string_limited(Va(node), NI_MAXHOST)?)
    };

    let process = vmi.os().current_process()?;
    tracing::info!(host, pid = process.id()?.0, process = process.name()?);

    Ok(Action::default())
}
