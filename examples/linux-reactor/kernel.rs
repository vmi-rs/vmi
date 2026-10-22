use std::net::Ipv4Addr;

use vmi::{
    Va, VmiContext, VmiError, VmiOs,
    driver::VmiRead,
    os::{
        VmiOsProcess as _,
        linux::{ArchAdapter, LinuxFile, LinuxOs},
    },
    utils::reactor::Action,
};
use zerocopy::{FromBytes, IntoBytes};

/// The start of `struct sockaddr_in`, without the padding behind the address.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
struct SockaddrIn {
    /// The address family (`sa_family_t`), `AF_INET` for IPv4.
    sin_family: u16,

    /// The port in network byte order (`__be16`).
    sin_port: [u8; 2],

    /// The IPv4 address in network byte order (`struct in_addr`).
    sin_addr: [u8; 4],
}

/// Logs the path of each file that `vfs_write` writes, together with the
/// writing process.
pub fn vfs_write<Driver>(
    vmi: &VmiContext<LinuxOs<Driver>>,
) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // ssize_t vfs_write(
    //     struct file *file,
    //     const char __user *buf,
    //     size_t count,
    //     loff_t *pos
    //     )
    //

    let file = vmi.os().function_argument(0)?;
    let path = LinuxFile::new(**vmi, Va(file)).f_path().absolute()?;

    let process = vmi.os().current_process()?;
    tracing::info!(path, pid = process.id()?.0, process = process.name()?);

    Ok(Action::default())
}

/// Logs the destination of each IPv4 TCP connection that a process opens.
///
/// `tcp_v4_connect` gets the address that the process passed to `connect`,
/// which the kernel copied to its own memory before the call.
pub fn tcp_v4_connect<Driver>(
    vmi: &VmiContext<LinuxOs<Driver>>,
) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // int tcp_v4_connect(
    //     struct sock *sk,
    //     struct sockaddr *uaddr,
    //     int addr_len
    //     )
    //

    let uaddr = vmi.os().function_argument(1)?;
    let address = vmi.read_struct::<SockaddrIn>(Va(uaddr))?;

    tracing::info!(
        family = address.sin_family,
        address = %Ipv4Addr::from(address.sin_addr),
        port = u16::from_be_bytes(address.sin_port),
    );

    Ok(Action::default())
}
