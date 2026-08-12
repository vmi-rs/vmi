use vmi::{
    VmiError,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::injector::{Recipe, RecipeControlFlow, recipe},
};

use super::parameters::PullParameters;

/// Windows allocation granularity used for committed pull memory.
const PAGE_SIZE: usize = 0x1000;

/// Parameter alignment required by the leading `u32` flags field.
const PARAMETER_ALIGNMENT: usize = align_of::<u32>();

/// Pull shellcode embedded from the selected SCFW build artifact.
const PULL_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scfw/build-x64/shellcodes/pull/pull.bin"
));

/// State shared by the pull injection recipe steps.
#[derive(Debug)]
pub(crate) struct PullRecipeData {
    /// Page-sized block copied to the guest allocation.
    allocation: Vec<u8>,

    /// Offset from the allocation base to the serialized parameters.
    parameter_offset: u64,

    /// Guest allocation returned by `VirtualAlloc`.
    guest_address: u64,

    /// Guest thread handle returned by `CreateThread`.
    thread_handle: u64,
}

impl PullRecipeData {
    /// Builds the page-aligned shellcode and parameter allocation.
    fn new(parameters: &PullParameters) -> Self {
        let parameter_offset = align_up(PULL_SHELLCODE.len(), PARAMETER_ALIGNMENT);
        let mut allocation = Vec::new();
        allocation.extend_from_slice(PULL_SHELLCODE);
        allocation.resize(parameter_offset, 0);
        parameters.append_to(&mut allocation);
        let allocation_size = align_up(allocation.len(), PAGE_SIZE);
        allocation.resize(allocation_size, 0);

        Self {
            allocation,
            parameter_offset: parameter_offset as u64,
            guest_address: 0,
            thread_handle: 0,
        }
    }
}

/// Builds the `VirtualAlloc` to `CreateThread` pull injection recipe.
#[tracing::instrument(name = "pull_recipe", skip_all)]
pub(crate) fn pull_recipe<Driver>(
    parameters: &PullParameters,
) -> Recipe<WindowsOs<Driver>, PullRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = PullRecipeData::new(parameters);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            tracing::debug!(size = data![allocation].len(), "allocating pull memory");

            inject! {
                kernel32!VirtualAlloc(
                    0u64,
                    data![allocation].len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )
            }
        },
        {
            data![guest_address] = vmi!().registers().rax;
            if data![guest_address] == 0 {
                return Err(VmiError::Other("VirtualAlloc failed"));
            }

            tracing::debug!(
                guest_address = data![guest_address],
                size = data![allocation].len(),
                "materializing pull memory"
            );

            inject! {
                kernel32!RtlFillMemory(
                    data![guest_address],
                    data![allocation].len(),
                    0u8
                )
            }
        },
        {
            vmi!().write(data![guest_address].into(), &data![allocation])?;

            let parameter_address = data![guest_address] + data![parameter_offset];

            tracing::debug!(
                start_address = data![guest_address],
                parameter_address,
                "launching pull thread"
            );

            inject! {
                kernel32!CreateThread(
                    0u64,
                    0u64,
                    data![guest_address],
                    parameter_address,
                    0u64,
                    0u64
                )
            }
        },
        {
            data![thread_handle] = vmi!().registers().rax;
            if data![thread_handle] == 0 {
                return Err(VmiError::Other("CreateThread failed"));
            }

            tracing::debug!(
                thread_handle = data![thread_handle],
                "closing pull thread handle"
            );

            inject! {
                kernel32!CloseHandle(data![thread_handle])
            }
        },
        {
            if vmi!().registers().rax == 0 {
                return Err(VmiError::Other("CloseHandle failed"));
            }

            Ok(RecipeControlFlow::Break)
        },
    ]
}

/// Rounds a byte count up to a power-of-two alignment.
const fn align_up(mut value: usize, alignment: usize) -> usize {
    debug_assert!(alignment.is_power_of_two());
    value += alignment - 1;
    value & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_starts_with_shellcode_and_contains_aligned_parameters() {
        let parameters = PullParameters::builder().build();
        let serialized = parameters.serialize();
        let data = PullRecipeData::new(&parameters);
        let parameter_offset = data.parameter_offset as usize;

        assert_eq!(data.allocation.len() % PAGE_SIZE, 0);
        assert_eq!(parameter_offset % PARAMETER_ALIGNMENT, 0);
        assert_eq!(&data.allocation[..PULL_SHELLCODE.len()], PULL_SHELLCODE);
        assert_eq!(
            &data.allocation[parameter_offset..parameter_offset + serialized.len()],
            serialized
        );
    }

    #[test]
    fn aligns_to_page_boundary() {
        assert_eq!(align_up(1, PAGE_SIZE), PAGE_SIZE);
        assert_eq!(align_up(PAGE_SIZE, PAGE_SIZE), PAGE_SIZE);
    }
}
