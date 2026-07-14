use vmi::{
    Va, VmiContext, VmiError, VmiOs,
    driver::VmiRead,
    os::windows::{ArchAdapter, WindowsOs, WindowsOsExt as _},
    trace::Hex,
    utils::reactor::Action,
};

/// Demonstrates how to monitor `NtCreateFile` calls in `ntdll.dll` and their
/// returns.
pub fn NtCreateFile<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // NTSTATUS
    // NTAPI
    // NtCreateFile(
    //     _Out_ PHANDLE FileHandle,
    //     _In_ ACCESS_MASK DesiredAccess,
    //     _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    //     _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    //     _In_opt_ PLARGE_INTEGER AllocationSize,
    //     _In_ ULONG FileAttributes,
    //     _In_ ULONG ShareAccess,
    //     _In_ ULONG CreateDisposition,
    //     _In_ ULONG CreateOptions,
    //     _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    //     _In_ ULONG EaLength
    //     );
    //

    let FileHandleAddress = vmi.os().function_argument(0)?;
    let ObjectAttributes = Va(vmi.os().function_argument(2)?);

    let object_attributes = vmi.os().object_attributes(ObjectAttributes)?;
    match object_attributes.object_name()? {
        Some(object_name) => tracing::info!(%object_name),
        None => tracing::warn!(%ObjectAttributes, "no object name found"),
    }

    Ok(Action::TrackReturn(FileHandleAddress))
}

/// Logs the result of an `NtCreateFile` invocation.
pub fn NtCreateFileReturn<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    FileHandleAddress: u64,
) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    let Status = vmi.os().function_return_value()? as u32;

    if (Status as i32) < 0 {
        tracing::info!(status = %Hex(Status), "failed");
        return Ok(Action::Default);
    }

    let FileHandle = vmi.read_va_native(Va(FileHandleAddress))?;
    tracing::info!(status = %Hex(Status), handle = %Hex(FileHandle.0));

    Ok(Action::Default)
}
