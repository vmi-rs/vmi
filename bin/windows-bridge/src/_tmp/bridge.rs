pub use self::{
    environment::EnvironmentBridge,
    file_transfer::FileTransferBridge,
    hello::HelloBridge,
    injector::{ExecutePolicy, InjectorDownloadBridge, InjectorExecuteBridge},
};

pub const BRIDGE_MAGIC: u32 = 0x706e7964; // '@nyd'
pub const BRIDGE_VERIFY_VALUE: u64 = 0x616e7964; // 'anyd'

pub const BRIDGE_METHOD_ERROR: u16 = 0xFFFE;
pub const BRIDGE_METHOD_EXIT: u16 = 0xFFFF;

pub const BRIDGE_RESPONSE_CONTINUE: u64 = 0x00000000;
pub const BRIDGE_RESPONSE_ABORT: u64 = 0xFFFFFFFF;

#[macro_export]
macro_rules! impl_bridge_contract {
    ($ty:ty) => {
        impl vmi::utils::bridge::BridgeContract for $ty {
            const MAGIC: Option<u32> = Some($crate::BRIDGE_MAGIC);
            const VERIFY_VALUE3: Option<u64> = Some($crate::BRIDGE_VERIFY_VALUE);
            const VERIFY_VALUE4: Option<u64> = Some($crate::BRIDGE_VERIFY_VALUE);
        }
    };
}