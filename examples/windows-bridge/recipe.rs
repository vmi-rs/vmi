use vmi::{
    Registers as _, VmiError,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    trace::Hex,
    utils::injector::{Recipe, recipe},
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

/// Resolved value passed through `CreateThread::lpParameter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeParameter {
    /// Offset relative to the guest shellcode allocation.
    Offset(u64),

    /// Exact value passed to `CreateThread`.
    Value(u64),
}

/// Exact value to pass through `CreateThread::lpParameter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellcodeParameterValue(pub u64);

/// Resolves a shellcode parameter from appended data or an exact value.
pub trait ShellcodeParameterSource {
    /// Optionally appends parameter data and returns the resolved parameter.
    fn resolve(self, payload: &mut Vec<u8>) -> ShellcodeParameter;
}

impl<Parameters> ShellcodeParameterSource for &Parameters
where
    Parameters: ShellcodeParameters + ?Sized,
{
    fn resolve(self, payload: &mut Vec<u8>) -> ShellcodeParameter {
        debug_assert!(
            Parameters::ALIGNMENT.is_power_of_two(),
            "shellcode parameter alignment must be a nonzero power of two"
        );

        // Align the parameter block within the shellcode payload.
        let parameter_offset = align_up(payload.len(), Parameters::ALIGNMENT);
        payload.resize(parameter_offset, 0);

        // Append the encoded parameters at the aligned offset.
        let mut writer = ParameterWriter::new(payload);
        self.encode(&mut writer);

        ShellcodeParameter::Offset(parameter_offset as u64)
    }
}

impl ShellcodeParameterSource for ShellcodeParameterValue {
    fn resolve(self, _payload: &mut Vec<u8>) -> ShellcodeParameter {
        ShellcodeParameter::Value(self.0)
    }
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

    /// Value used to populate `CreateThread::lpParameter`.
    parameter: ShellcodeParameter,

    /// Guest allocation returned by `VirtualAlloc`.
    guest_address: u64,

    /// Guest thread handle returned by `CreateThread`.
    thread_handle: u64,
}

impl ShellcodeRecipeData {
    /// Builds the page-aligned shellcode payload and resolves its parameter.
    fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(shellcode.as_ref());

        let parameter = parameter.resolve(&mut payload);

        // Pad the complete payload to the page size.
        let payload_size = align_up(payload.len(), PAGE_SIZE);
        payload.resize(payload_size, 0);

        debug_assert!(payload.len().is_multiple_of(PAGE_SIZE));

        Self {
            payload,
            parameter,
            guest_address: 0,
            thread_handle: 0,
        }
    }
}

/// Builds the shared `VirtualAlloc` to `CreateThread` shellcode recipe.
#[tracing::instrument(name = "recipe", skip_all)]
pub fn shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, ShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = ShellcodeRecipeData::new(shellcode, parameter);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            tracing::debug!(size = data![payload].len(), "allocating shellcode memory");

            inject! {
                kernel32!VirtualAlloc(
                    0,                          // lpAddress
                    data![payload].len(),       // dwSize
                    MEM_COMMIT | MEM_RESERVE,   // flAllocationType
                    PAGE_EXECUTE_READWRITE      // flProtect
                )
            }
        },
        {
            data![guest_address] = vmi!().registers().result();
            if data![guest_address] == 0 {
                return Err(VmiError::Other("VirtualAlloc failed"));
            }

            tracing::debug!(
                guest_address = %Hex(data![guest_address]),
                size = data![payload].len(),
                "materializing shellcode memory"
            );

            inject! {
                kernel32!RtlFillMemory(
                    data![guest_address],       // Destination
                    data![payload].len(),       // Length
                    0                           // Fill
                )
            }
        },
        {
            vmi!().write(data![guest_address].into(), &data![payload])?;

            let parameter = match data![parameter] {
                ShellcodeParameter::Offset(offset) => data![guest_address] + offset,
                ShellcodeParameter::Value(value) => value,
            };

            tracing::debug!(
                start_address = %Hex(data![guest_address]),
                parameter = %Hex(parameter),
                "launching shellcode thread"
            );

            inject! {
                kernel32!CreateThread(
                    0,                          // lpThreadAttributes
                    0,                          // dwStackSize
                    data![guest_address],       // lpStartAddress
                    parameter,                  // lpParameter
                    0,                          // dwCreationFlags
                    0                           // lpThreadId
                )
            }
        },
        {
            data![thread_handle] = vmi!().registers().result();
            if data![thread_handle] == 0 {
                return Err(VmiError::Other("CreateThread failed"));
            }

            tracing::debug!(
                thread_handle = %Hex(data![thread_handle]),
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
        assert_eq!(data.parameter, ShellcodeParameter::Offset(4));
        let parameter_offset = 4;
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

        assert_eq!(data.parameter, ShellcodeParameter::Offset(4));
    }

    #[test]
    fn direct_parameter_value_is_preserved_without_appending_data() {
        const PARAMETER: u64 = 0x1122_3344_5566_7788;

        let data = ShellcodeRecipeData::new(SHELLCODE, ShellcodeParameterValue(PARAMETER));

        assert_eq!(data.parameter, ShellcodeParameter::Value(PARAMETER));
        assert_eq!(&data.payload[..SHELLCODE.len()], SHELLCODE);
        assert!(
            data.payload[SHELLCODE.len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(data.payload.len(), PAGE_SIZE);
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
