use vmi_arch_arm64::{Arm64, PagingGeometry};
use vmi_core::{
    Registers as _, Va, VmiCore, VmiError,
    driver::{VmiDriver, VmiRead, VmiWrite},
};

use super::ArchAdapter;

/// Size of the red zone below the stack pointer, in bytes.
///
/// Code on Apple platforms may keep data in the 128 bytes below the stack
/// pointer, so data copied to the stack is placed below them. Skipping them
/// costs nothing where the platform has no red zone.
///
/// See "Respect the stack's red zone" in [Writing ARM64 code for Apple
/// platforms](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms).
const RED_ZONE_SIZE: u64 = 128;

impl<Driver, Geometry> ArchAdapter<Driver> for Arm64<Geometry>
where
    Driver: VmiDriver<Architecture = Self> + VmiRead + VmiWrite,
    Geometry: PagingGeometry,
{
    fn copy_bytes_to_stack(
        vmi: &VmiCore<Driver>,
        registers: &mut Self::Registers,
        data: &[u8],
        alignment: usize,
    ) -> Result<Va, VmiError> {
        let mut addr = registers.stack_pointer();
        addr -= RED_ZONE_SIZE;
        addr -= data.len() as u64;
        addr &= !(alignment as u64 - 1);

        let va = Va(addr);
        vmi.write((va, registers.translation_root(va)), data)?;

        registers.set_stack_pointer(addr);
        Ok(va)
    }
}
