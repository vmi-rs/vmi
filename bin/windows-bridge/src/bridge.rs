/// Little-endian ASCII `VMIB` bridge signature.
pub const BRIDGE_MAGIC: u32 = 0x4249_4d56;

/// Little-endian ASCII `VMI-RS3!` response signature.
pub const VERIFY_VALUE3: u64 = 0x2133_5352_2d49_4d56;

/// Little-endian ASCII `VMI-RS4!` response signature.
pub const VERIFY_VALUE4: u64 = 0x2134_5352_2d49_4d56;

/// Terminal result method.
pub const METHOD_EXIT: u16 = 0xffff;

/// Allows the shellcode to continue its current stage.
pub const RESPONSE_CONTINUE: u64 = 0x0000_0000;

/// Aborts the shellcode's current stage.
pub const RESPONSE_ABORT: u64 = 0xffff_ffff;

/// Implements the shared shellcode bridge contract for a handler.
macro_rules! impl_bridge_contract {
    ($bridge:ty) => {
        impl vmi::utils::bridge::BridgeContract for $bridge {
            const MAGIC: Option<u32> = Some($crate::bridge::BRIDGE_MAGIC);
            const VERIFY_VALUE3: Option<u64> = Some($crate::bridge::VERIFY_VALUE3);
            const VERIFY_VALUE4: Option<u64> = Some($crate::bridge::VERIFY_VALUE4);
        }
    };
}

pub(crate) use impl_bridge_contract;
