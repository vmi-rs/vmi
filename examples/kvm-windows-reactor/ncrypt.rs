use vmi::{
    Va, VmiContext, VmiError, VmiOs,
    driver::VmiRead,
    os::windows::{ArchAdapter, WindowsOs},
    utils::reactor::Action,
};
use zerocopy::{FromBytes, IntoBytes};

const NCRYPTBUFFER_SSL_CLIENT_RANDOM: u32 = 20;
//const NCRYPTBUFFER_SSL_SERVER_RANDOM: u32 = 21;

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct NCryptBuffer {
    cbBuffer: u32,   // ULONG
    BufferType: u32, // ULONG
    pvBuffer: u64,   // PVOID (pointer to the buffer)
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct NCryptBufferDesc {
    ulVersion: u32, // ULONG
    cBuffers: u32,  // ULONG
    pBuffers: u64,  // NCryptBuffer*
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct SSL_MASTER_KEY {
    cbLength: u32,          // ULONG
    dwMagic: u32,           // ULONG
    dwProtocol: u32,        // ULONG
    _pad: u32,              // Padding to align the next field to 8 bytes.
    pCipherSuite: u64,      // const SSL_CIPHER_SUITE*
    fClient: i32,           // BOOL
    rgbMasterKey: [u8; 48], // UCHAR[48]
    cbMasterKey: u32,       // ULONG
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct NCRYPT_SSL_KEY {
    cbLength: u32,  // ULONG
    dwMagic: u32,   // ULONG
    dwFlags: u32,   // ULONG
    RefCount: i32,  // LONG
    hSubKey: u64,   // NCRYPT_KEY_HANDLE (eg. SSL_MASTER_KEY*)
    pProvider: u64, // NCRYPT_SSL_PROVIDER*
}

/// Demonstrates how to monitor `SslGenerateSessionKeys` calls in `ncrypt.dll`
/// and log the master key and client random used in the SSL/TLS session key
/// generation.
///
/// This can be used to decrypt the SSL/TLS traffic managed by [Schannel].
///
/// More specifically, if the entries would be saved into a `SSLKEYLOGFILE` as
/// `CLIENT_RANDOM <client_random> <secret>`, then Wireshark can use them to
/// decrypt the SSL/TLS traffic captured in a pcap file.
///
/// [Schannel]: https://learn.microsoft.com/en-us/windows/win32/com/schannel
pub fn SslGenerateSessionKeys<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // SECURITY_STATUS
    // WINAPI
    // SslGenerateSessionKeys(
    //     _In_ NCRYPT_PROV_HANDLE hSslProvider,
    //     _In_ NCRYPT_KEY_HANDLE hMasterKey,
    //     _Out_ NCRYPT_KEY_HANDLE *phReadKey,
    //     _Out_ NCRYPT_KEY_HANDLE *phWriteKey,
    //     _In_ PNCryptBufferDesc pParameterList,
    //     _In_ DWORD dwFlags
    //     );
    //

    let hMasterKey = vmi.os().function_argument(1)?;
    let pParameterList = vmi.os().function_argument(4)?;

    let mut client_random = vec![0u8; 32];

    let parameter_list = vmi.read_struct::<NCryptBufferDesc>(Va(pParameterList))?;
    for i in 0..parameter_list.cBuffers {
        let offset = (i as u64) * size_of::<NCryptBuffer>() as u64;
        let buffer = vmi.read_struct::<NCryptBuffer>(Va(parameter_list.pBuffers + offset))?;

        if buffer.BufferType == NCRYPTBUFFER_SSL_CLIENT_RANDOM {
            vmi.read(Va(buffer.pvBuffer), &mut client_random)?;
            break;
        }
    }

    let master_key = vmi.read_struct::<NCRYPT_SSL_KEY>(Va(hMasterKey))?;
    let subkey = vmi.read_struct::<SSL_MASTER_KEY>(Va(master_key.hSubKey))?;

    tracing::info!(
        client_random = hex::encode(client_random),
        secret = hex::encode(subkey.rgbMasterKey),
    );

    Ok(Action::default())
}
