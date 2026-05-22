use vmi::{
    Hex, VmiContext, VmiError, VmiOs,
    driver::VmiRead,
    os::windows::{ArchAdapter, WindowsFileObject, WindowsOs, WindowsOsExt as _},
    utils::reactor::Action,
};

/// Demonstrates how to monitor `NtWriteFile` calls in the kernel and log the
/// full path of the file being written to.
pub fn NtWriteFile<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // NTSTATUS
    // NTAPI
    // NtWriteFile(
    //     _In_ HANDLE FileHandle,
    //     _In_opt_ HANDLE Event,
    //     _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    //     _In_opt_ PVOID ApcContext,
    //     _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    //     _In_reads_bytes_(Length) PVOID Buffer,
    //     _In_ ULONG Length,
    //     _In_opt_ PLARGE_INTEGER ByteOffset,
    //     _In_opt_ PULONG Key
    //     );
    //

    let FileHandle = vmi.os().function_argument(0)?;

    // Check if we have to look for the object in the kernel handle table
    // or the current process handle table.
    let owning_process = match vmi.os().is_kernel_handle(FileHandle)? {
        true => vmi.os().system_process()?,
        false => vmi.os().current_process()?,
    };

    let file_object = match owning_process.lookup_object::<WindowsFileObject<_>>(FileHandle)? {
        Some(file_object) => file_object,
        None => {
            tracing::error!(handle = %Hex(FileHandle), "cannot find file object");
            return Ok(Action::default());
        }
    };

    let path = file_object.full_path()?;
    tracing::info!(handle = %Hex(FileHandle), path);

    Ok(Action::default())
}
