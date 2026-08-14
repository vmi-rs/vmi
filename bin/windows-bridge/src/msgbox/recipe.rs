use vmi::{
    VmiError,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::injector::{Recipe, RecipeControlFlow, recipe},
};

use super::parameters::MsgboxParameters;

/// Windows allocation granularity used for committed msgbox memory.
const PAGE_SIZE: usize = 0x1000;

/// Msgbox shellcode embedded from the selected SCFW build artifact.
const MSGBOX_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scfw/build-x64/shellcodes/msgbox/msgbox.bin"
));

/// State shared by the msgbox injection recipe steps.
#[derive(Debug)]
pub(crate) struct MsgboxRecipeData {
    /// Page-sized block copied to the guest allocation.
    allocation: Vec<u8>,

    /// Offset from the allocation base to the serialized parameters.
    parameter_offset: u64,

    /// Guest allocation returned by `VirtualAlloc`.
    guest_address: u64,

    /// Guest thread handle returned by `CreateThread`.
    thread_handle: u64,
}

impl MsgboxRecipeData {
    /// Builds the page-aligned shellcode and parameter allocation.
    fn new(parameters: &MsgboxParameters) -> Self {
        let parameter_offset = MSGBOX_SHELLCODE.len();
        let mut allocation = Vec::new();
        allocation.extend_from_slice(MSGBOX_SHELLCODE);
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

/// Builds the `VirtualAlloc` to `CreateThread` msgbox injection recipe.
#[tracing::instrument(name = "msgbox_recipe", skip_all)]
pub(crate) fn msgbox_recipe<Driver>(
    parameters: &MsgboxParameters,
) -> Recipe<WindowsOs<Driver>, MsgboxRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = MsgboxRecipeData::new(parameters);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            tracing::debug!(size = data![allocation].len(), "allocating msgbox memory");

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
                "materializing msgbox memory"
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
                "launching msgbox thread"
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
                "closing msgbox thread handle"
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
    fn allocation_starts_with_shellcode_and_contains_parameters() {
        let parameters = MsgboxParameters::new("VMI", "Hello");
        let serialized = parameters.serialize();
        let data = MsgboxRecipeData::new(&parameters);
        let parameter_offset = data.parameter_offset as usize;

        assert_eq!(data.allocation.len() % PAGE_SIZE, 0);
        assert_eq!(parameter_offset, MSGBOX_SHELLCODE.len());
        assert_eq!(&data.allocation[..MSGBOX_SHELLCODE.len()], MSGBOX_SHELLCODE);
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
