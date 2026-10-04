mod arm64;

use vmi_core::{Architecture, Pa, Va, VmiCore, VmiError, VmiState, driver::VmiRead};

use crate::{
    MacOs, MacOsKernelInformation, MacOsSegment,
    macho::{MACH_HEADER_64_SIZE, MH_FILESET, MachHeader, MachO},
};

/// Architecture-specific macOS functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiRead<Architecture = Self>,
{
    /// Locates the kernel collection and the kernel image in memory.
    ///
    /// Returns `None` when no kernel collection is found.
    ///
    /// # Architecture-specific
    ///
    /// - **ARM64**: Scans backward from `VBAR_EL1` (up to 256 MiB) for the
    ///   `MH_FILESET` header of the kernel collection.
    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<MacOsKernelInformation>, VmiError>;

    /// Strips architecture-specific tag bits from a pointer read from guest
    /// memory.
    ///
    /// # Architecture-specific
    ///
    /// - **ARM64**: Removes pointer authentication codes and top-byte tags.
    fn canonical_address(raw: u64) -> Va;

    /// Returns the address of the `struct thread` running on the current CPU.
    ///
    /// # Architecture-specific
    ///
    /// - **ARM64**: `TPIDR_EL1`
    fn current_thread(vmi: VmiState<MacOs<Driver>>) -> Va;

    /// Reads a syscall argument by index from the current register state.
    ///
    /// Index 0 is the first argument.
    ///
    /// # Architecture-specific
    ///
    /// - **ARM64**: Arguments 0-7 come from `X0`-`X7`. Subsequent arguments
    ///   are read from the stack.
    fn syscall_argument(vmi: VmiState<MacOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    /// Reads a function-call argument by index from the current register state.
    ///
    /// # Architecture-specific
    ///
    /// - **ARM64**: AAPCS64. Arguments 0-7 come from `X0`-`X7`. Subsequent
    ///   arguments are read from the stack.
    fn function_argument(vmi: VmiState<MacOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    /// Reads the return value of the most recent function call.
    ///
    /// # Architecture-specific
    ///
    /// - **ARM64**: `X0`
    fn function_return_value(vmi: VmiState<MacOs<Driver>>) -> Result<u64, VmiError>;
}

/// Name of the kernel image in a kernel collection.
const KERNEL_FILESET_ENTRY: &str = "com.apple.kernel";

/// Prefix of the XNU version string.
const VERSION_PREFIX: &[u8] = b"Darwin Kernel Version";

/// Upper bound on the length of the version string, in bytes.
const MAX_VERSION_LENGTH: usize = 512;

/// Reads a Mach-O header and its load commands at `va`.
///
/// Returns `None` when `va` holds no 64-bit Mach-O header.
pub(crate) fn read_macho<Driver>(
    vmi: &VmiCore<Driver>,
    va: Va,
    root: Pa,
) -> Result<Option<Vec<u8>>, VmiError>
where
    Driver: VmiRead,
{
    let mut header = [0u8; MACH_HEADER_64_SIZE];
    vmi.read((va, root), &mut header)?;

    let total_size = match MachHeader::parse(&header) {
        Ok(header) => header.total_size()?,
        Err(_) => return Ok(None),
    };

    let mut data = vec![0u8; total_size];
    vmi.read((va, root), &mut data)?;
    Ok(Some(data))
}

/// Extracts the kernel information from the kernel collection whose header
/// lies at `collection_base`.
///
/// Returns `None` when the header is not a kernel collection or does not
/// contain the kernel image.
pub(crate) fn kernel_information<Driver>(
    vmi: &VmiCore<Driver>,
    collection_base: Va,
    root: Pa,
) -> Result<Option<MacOsKernelInformation>, VmiError>
where
    Driver: VmiRead,
{
    let collection = match read_macho(vmi, collection_base, root)? {
        Some(collection) => collection,
        None => return Ok(None),
    };

    let collection = MachO::parse(&collection)?;
    if collection.header().file_type != MH_FILESET {
        return Ok(None);
    }

    let kernel = match collection
        .fileset_entries()?
        .into_iter()
        .find(|entry| entry.name == KERNEL_FILESET_ENTRY)
    {
        Some(kernel) => kernel,
        None => return Ok(None),
    };

    let base_address = Va(kernel.vm_address);
    let kernel = match read_macho(vmi, base_address, root)? {
        Some(kernel) => kernel,
        None => return Ok(None),
    };

    let kernel = MachO::parse(&kernel)?;
    let uuid = match kernel.uuid()? {
        Some(uuid) => uuid,
        None => return Ok(None),
    };

    let segments = kernel
        .segments()?
        .into_iter()
        .map(|segment| MacOsSegment {
            name: segment.name,
            address: Va(segment.vm_address),
            size: segment.vm_size,
        })
        .collect::<Vec<_>>();

    let text = match segments.iter().find(|segment| segment.name == "__TEXT") {
        Some(text) => text,
        None => return Ok(None),
    };

    let version = match find_version(vmi, text, root)? {
        Some(version) => version,
        None => return Ok(None),
    };

    Ok(Some(MacOsKernelInformation {
        kernel_collection_base: collection_base,
        base_address,
        uuid,
        version,
        segments,
    }))
}

/// Searches the kernel `__TEXT` segment for the XNU version string.
///
/// Pages that cannot be read are treated as zero-filled.
fn find_version<Driver>(
    vmi: &VmiCore<Driver>,
    text: &MacOsSegment,
    root: Pa,
) -> Result<Option<String>, VmiError>
where
    Driver: VmiRead,
{
    let page_size = Driver::Architecture::PAGE_SIZE;
    let mut data = vec![0u8; text.size as usize];

    for (index, page) in data.chunks_mut(page_size as usize).enumerate() {
        let va = text.address + index as u64 * page_size;

        match vmi.read((va, root), page) {
            Ok(()) => {}
            Err(VmiError::Translation(_) | VmiError::OutOfBounds) => {}
            Err(err) => return Err(err),
        }
    }

    let start = match memchr::memmem::find(&data, VERSION_PREFIX) {
        Some(start) => start,
        None => return Ok(None),
    };

    let version = &data[start..data.len().min(start + MAX_VERSION_LENGTH)];
    let end = match memchr::memchr(0, version) {
        Some(end) => end,
        None => return Ok(None),
    };

    Ok(Some(String::from_utf8_lossy(&version[..end]).into_owned()))
}
