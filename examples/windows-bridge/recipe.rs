use vmi::{
    VmiError,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::injector::{Recipe, RecipeControlFlow, recipe},
};

/// Windows allocation granularity used for committed shellcode memory.
const PAGE_SIZE: usize = 0x1000;

/// Cursor-based encoder for shellcode parameter wire formats.
///
/// Multi-byte scalar values are written little-endian. String methods append
/// their respective NUL terminators.
pub struct ParameterWriter<'a> {
    output: &'a mut Vec<u8>,
}

impl<'a> ParameterWriter<'a> {
    /// Creates a writer at the output's current cursor position.
    pub fn new(output: &'a mut Vec<u8>) -> Self {
        Self { output }
    }

    /// Writes bytes unchanged.
    pub fn write_bytes(&mut self, value: &[u8]) {
        self.output.extend_from_slice(value);
    }

    /// Writes a little-endian signed 8-bit integer.
    #[expect(unused)]
    pub fn write_i8(&mut self, value: i8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 8-bit integer.
    pub fn write_u8(&mut self, value: u8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian signed 16-bit integer.
    #[expect(unused)]
    pub fn write_i16(&mut self, value: i16) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 16-bit integer.
    pub fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian signed 32-bit integer.
    pub fn write_i32(&mut self, value: i32) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 32-bit integer.
    pub fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian signed 64-bit integer.
    #[expect(unused)]
    pub fn write_i64(&mut self, value: i64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 64-bit integer.
    #[expect(unused)]
    pub fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes the string bytes unchanged followed by a NUL byte.
    ///
    /// This method does not transcode the value to a target ANSI code page.
    pub fn write_string(&mut self, value: &str) {
        self.write_bytes(value.as_bytes());
        self.write_u8(0);
    }

    /// Writes UTF-16LE code units followed by a NUL code unit.
    pub fn write_string_utf16(&mut self, value: &str) {
        for unit in value.encode_utf16() {
            self.write_bytes(&unit.to_le_bytes());
        }
        self.write_u16(0);
    }
}

/// Encodes one shellcode parameter block and declares its required alignment.
pub trait ShellcodeParameters {
    /// Alignment required for the parameter block's first byte.
    const ALIGNMENT: usize;

    /// Appends the exact parameter block while preserving existing output bytes.
    fn encode(&self, writer: &mut ParameterWriter);
}

/// Encodes a standalone parameter block for test assertions.
#[cfg(test)]
pub fn encode_parameters(parameters: &impl ShellcodeParameters) -> Vec<u8> {
    let mut output = Vec::new();
    parameters.encode(&mut ParameterWriter::new(&mut output));
    output
}

/// Data shared by the shellcode injection recipe steps.
#[derive(Debug)]
pub struct ShellcodeRecipeData {
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
    fn new<Parameters>(shellcode: impl AsRef<[u8]>, parameters: &Parameters) -> Self
    where
        Parameters: ShellcodeParameters,
    {
        debug_assert!(
            Parameters::ALIGNMENT.is_power_of_two(),
            "shellcode parameter alignment must be a nonzero power of two"
        );

        let mut payload = Vec::new();
        payload.extend_from_slice(shellcode.as_ref());

        // Align the parameter block within the shellcode payload.
        let parameter_offset = align_up(payload.len(), Parameters::ALIGNMENT);
        payload.resize(parameter_offset, 0);

        // Append the encoded parameters at the aligned offset.
        let mut writer = ParameterWriter::new(&mut payload);
        parameters.encode(&mut writer);

        // Pad the complete payload to the page size.
        let payload_size = align_up(payload.len(), PAGE_SIZE);
        payload.resize(payload_size, 0);

        debug_assert!(payload.len().is_multiple_of(PAGE_SIZE));

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
pub fn shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
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
    ]
}

/// Rounds a byte count up to a power-of-two alignment.
fn align_up(mut value: usize, alignment: usize) -> usize {
    debug_assert!(alignment.is_power_of_two());
    value += alignment - 1;
    value & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHELLCODE: &[u8] = &[0xaa, 0xbb, 0xcc];

    #[test]
    fn parameter_writer_writes_wire_values() {
        let mut output = Vec::new();
        let mut writer = ParameterWriter::new(&mut output);
        writer.write_u32(0x1122_3344);
        writer.write_i32(-2);
        writer.write_string("A");
        writer.write_string_utf16("B");
        writer.write_bytes(&[0x10, 0x20]);
        assert_eq!(
            output,
            [
                0x44, 0x33, 0x22, 0x11, // u32
                0xfe, 0xff, 0xff, 0xff, // i32
                b'A', 0x00, // byte string
                b'B', 0x00, 0x00, 0x00, // UTF-16 string
                0x10, 0x20, // raw bytes
            ]
        );
    }

    struct FourByteParameters;

    impl ShellcodeParameters for FourByteParameters {
        const ALIGNMENT: usize = 4;

        fn encode(&self, writer: &mut ParameterWriter<'_>) {
            writer.write_bytes(&[0x11, 0x22]);
        }
    }

    #[test]
    fn payload_aligns_parameters_and_preserves_bytes() {
        let data = ShellcodeRecipeData::new(SHELLCODE, &FourByteParameters);
        let parameter_offset = data.parameter_offset as usize;

        assert_eq!(parameter_offset, 4);
        assert_eq!(&data.payload[..SHELLCODE.len()], SHELLCODE);
        assert_eq!(data.payload[SHELLCODE.len()], 0);
        assert_eq!(
            &data.payload[parameter_offset..parameter_offset + 2],
            &[0x11, 0x22]
        );
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

        fn encode(&self, _writer: &mut ParameterWriter<'_>) {}
    }

    struct ThreeByteAlignedParameters;

    impl ShellcodeParameters for ThreeByteAlignedParameters {
        const ALIGNMENT: usize = 3;

        fn encode(&self, _writer: &mut ParameterWriter<'_>) {}
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
