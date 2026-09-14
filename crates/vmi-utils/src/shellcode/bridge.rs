/// Magic value used to identify shellcode bridge requests (`VMIB`).
pub const BRIDGE_MAGIC: u32 = 0x4249_4d56;

/// Verification value expected in the 3rd bridge response field (`VMI-RS3!`).
pub const BRIDGE_VERIFY_VALUE3: u64 = 0x2133_5352_2d49_4d56;

/// Verification value expected in the 4th bridge response field (`VMI-RS4!`).
pub const BRIDGE_VERIFY_VALUE4: u64 = 0x2134_5352_2d49_4d56;

/// Implements the shellcode bridge contract for a handler.
#[doc(hidden)]
#[macro_export]
macro_rules! _private_impl_bridge_contract {
    ($bridge:ty) => {
        impl $crate::bridge::BridgeContract for $bridge {
            const MAGIC: Option<u32> = Some($crate::shellcode::BRIDGE_MAGIC);
            const VERIFY_VALUE3: Option<u64> = Some($crate::shellcode::BRIDGE_VERIFY_VALUE3);
            const VERIFY_VALUE4: Option<u64> = Some($crate::shellcode::BRIDGE_VERIFY_VALUE4);
        }
    };
}

#[doc(inline)]
pub use _private_impl_bridge_contract as impl_bridge_contract;
