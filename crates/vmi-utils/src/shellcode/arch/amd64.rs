use vmi_arch_amd64::Amd64;
use vmi_core::Va;

use super::ArchAdapter;

impl ArchAdapter for Amd64 {
    type Thunk = [u8; 32];

    /// Creates a thunk that sets up the two arguments expected by the shellcode.
    ///
    /// `PsCreateSystemThread` supplies a single `StartContext` argument. The thunk
    /// instead loads the two arguments expected by the shellcode before jumping to
    /// its entry point:
    ///
    ///
    /// ```text
    /// mov rcx, kernel_image_base
    /// mov rdx, parameter
    /// mov rax, entry
    /// jmp rax
    /// ```
    fn encode_thunk(entry: Va, kernel_image_base: Va, parameter: u64) -> Self::Thunk {
        let mut thunk = Self::Thunk::default();

        // mov rcx, imm64
        thunk[0..2].copy_from_slice(&[0x48, 0xb9]);
        thunk[2..10].copy_from_slice(&kernel_image_base.0.to_le_bytes());

        // mov rdx, imm64
        thunk[10..12].copy_from_slice(&[0x48, 0xba]);
        thunk[12..20].copy_from_slice(&parameter.to_le_bytes());

        // mov rax, imm64
        thunk[20..22].copy_from_slice(&[0x48, 0xb8]);
        thunk[22..30].copy_from_slice(&entry.0.to_le_bytes());

        // jmp rax
        thunk[30..32].copy_from_slice(&[0xff, 0xe0]);

        thunk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thunk_loads_both_payload_arguments() {
        let thunk = Amd64::encode_thunk(
            Va(0xffffd000_deadbeef),
            Va(0xfffff800_01000000),
            0xffffe000_12345678,
        );

        assert_eq!(
            thunk,
            [
                // mov rcx, 0xfffff80001000000
                0x48, 0xb9, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf8, 0xff, 0xff,
                // mov rdx, 0xffffe00012345678
                0x48, 0xba, 0x78, 0x56, 0x34, 0x12, 0x00, 0xe0, 0xff, 0xff,
                // mov rax, 0xffffd000deadbeef
                0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0x00, 0xd0, 0xff, 0xff, // jmp rax
                0xff, 0xe0,
            ]
        );
    }
}
