use vmi::{
    VmiError,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::injector::{Recipe, RecipeControlFlow, recipe},
};

/// Windows allocation granularity used for committed shellcode memory.
const PAGE_SIZE: usize = 0x1000;

/// Encodes one shellcode parameter block and declares its required alignment.
pub(crate) trait ShellcodeParameters {
    /// Alignment required for the parameter block's first byte.
    const ALIGNMENT: usize;

    /// Appends the exact parameter block while preserving existing output bytes.
    fn encode(&self, output: &mut Vec<u8>);
}

/// Data shared by the shellcode injection recipe steps.
#[derive(Debug)]
pub(crate) struct ShellcodeRecipeData {
    /// Complete host-side image copied into guest memory.
    payload: Vec<u8>,

    /// Offset from the guest allocation base to the parameter block.
    parameter_offset: u64,

    /// Guest allocation returned by `VirtualAlloc`.
    guest_address: u64,

    /// Guest thread handle returned by `CreateThread`.
    thread_handle: u64,
}

impl ShellcodeRecipeData {
    /// Builds the page-aligned shellcode and parameter payload.
    fn new<Parameters>(shellcode: &'static [u8], parameters: &Parameters) -> Self
    where
        Parameters: ShellcodeParameters,
    {
        assert!(
            Parameters::ALIGNMENT.is_power_of_two(),
            "shellcode parameter alignment must be a nonzero power of two"
        );

        let parameter_offset = align_up(shellcode.len(), Parameters::ALIGNMENT);
        let mut payload = Vec::new();
        payload.extend_from_slice(shellcode);
        payload.resize(parameter_offset, 0);
        parameters.encode(&mut payload);
        let payload_size = align_up(payload.len(), PAGE_SIZE);
        payload.resize(payload_size, 0);

        Self {
            payload,
            parameter_offset: parameter_offset as u64,
            guest_address: 0,
            thread_handle: 0,
        }
    }
}

/// Builds the shared `VirtualAlloc` to `CreateThread` shellcode recipe.
#[tracing::instrument(name = "shellcode_recipe", skip_all)]
pub(crate) fn shellcode_recipe<Driver>(
    shellcode: &'static [u8],
    parameters: &impl ShellcodeParameters,
) -> Recipe<WindowsOs<Driver>, ShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = ShellcodeRecipeData::new(shellcode, parameters);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            tracing::debug!(size = data![payload].len(), "allocating shellcode memory");

            inject! {
                kernel32!VirtualAlloc(
                    0u64,
                    data![payload].len(),
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
                size = data![payload].len(),
                "materializing shellcode memory"
            );

            inject! {
                kernel32!RtlFillMemory(
                    data![guest_address],
                    data![payload].len(),
                    0u8
                )
            }
        },
        {
            vmi!().write(data![guest_address].into(), &data![payload])?;

            let parameter_address = data![guest_address] + data![parameter_offset];

            tracing::debug!(
                start_address = data![guest_address],
                parameter_address,
                "launching shellcode thread"
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
                "closing shellcode thread handle"
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

    const SHELLCODE: &[u8] = &[0xaa, 0xbb, 0xcc];

    struct FourByteParameters;

    impl ShellcodeParameters for FourByteParameters {
        const ALIGNMENT: usize = 4;

        fn encode(&self, output: &mut Vec<u8>) {
            output.extend_from_slice(&[0x11, 0x22]);
        }
    }

    #[test]
    fn payload_aligns_parameters_and_preserves_bytes() {
        let data = ShellcodeRecipeData::new(SHELLCODE, &FourByteParameters);
        let parameter_offset = data.parameter_offset as usize;

        assert_eq!(parameter_offset, 4);
        assert_eq!(&data.payload[..SHELLCODE.len()], SHELLCODE);
        assert_eq!(data.payload[SHELLCODE.len()], 0);
        assert_eq!(&data.payload[parameter_offset..parameter_offset + 2], &[0x11, 0x22]);
        assert_eq!(data.payload.len() % PAGE_SIZE, 0);
    }

    #[test]
    fn already_aligned_parameter_offset_is_unchanged() {
        let data = ShellcodeRecipeData::new(&[0xaa, 0xbb, 0xcc, 0xdd], &FourByteParameters);

        assert_eq!(data.parameter_offset, 4);
    }

    struct ZeroAlignedParameters;

    impl ShellcodeParameters for ZeroAlignedParameters {
        const ALIGNMENT: usize = 0;

        fn encode(&self, _output: &mut Vec<u8>) {}
    }

    struct ThreeByteAlignedParameters;

    impl ShellcodeParameters for ThreeByteAlignedParameters {
        const ALIGNMENT: usize = 3;

        fn encode(&self, _output: &mut Vec<u8>) {}
    }

    #[test]
    #[should_panic(expected = "shellcode parameter alignment must be a nonzero power of two")]
    fn rejects_zero_parameter_alignment() {
        ShellcodeRecipeData::new(SHELLCODE, &ZeroAlignedParameters);
    }

    #[test]
    #[should_panic(expected = "shellcode parameter alignment must be a nonzero power of two")]
    fn rejects_non_power_of_two_parameter_alignment() {
        ShellcodeRecipeData::new(SHELLCODE, &ThreeByteAlignedParameters);
    }
}
