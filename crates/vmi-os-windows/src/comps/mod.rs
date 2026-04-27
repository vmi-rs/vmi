mod control_area;
pub(crate) mod handle_table;
mod handle_table_entry;
pub(crate) mod hive;
mod image;
mod kprcb;
pub(crate) mod macros;
mod module;
mod name_info;
mod object;
mod object_attributes;
mod peb;
mod peb_ldr_data;
mod process_parameters;
mod region;
mod segment;
mod session;
mod teb;
mod trap_frame;
mod user_module;
mod wow64;

pub use self::{
    control_area::WindowsControlArea,
    handle_table::WindowsHandleTable,
    handle_table_entry::WindowsHandleTableEntry,
    hive::{
        WindowsHive, WindowsHiveBaseBlock, WindowsHiveCellIndex, WindowsHiveMapDirectory,
        WindowsHiveMapEntry, WindowsHiveMapTable, WindowsHiveStorageType, WindowsKeyControlBlock,
        WindowsKeyIndex, WindowsKeyNode, WindowsKeyValue, WindowsKeyValueData,
        WindowsKeyValueFlags, WindowsKeyValueType,
    },
    image::WindowsImage,
    kprcb::WindowsKernelProcessorBlock,
    module::WindowsModule,
    name_info::WindowsObjectHeaderNameInfo,
    object::{
        FromWindowsObject, ParseObjectTypeError, WindowsDirectoryObject, WindowsFileObject,
        WindowsObject, WindowsObjectType, WindowsObjectTypeKind, WindowsProcess,
        WindowsSectionObject, WindowsThread, WindowsThreadState, WindowsThreadWaitReason,
    },
    object_attributes::WindowsObjectAttributes,
    peb::{Peb, PebLayout, WindowsPeb, WindowsPebBase},
    peb_ldr_data::{
        LdrDataTableEntry, LdrDataTableEntryLayout, PebLdrData, PebLdrDataLayout,
        WindowsPebLdrData, WindowsPebLdrDataBase,
    },
    process_parameters::{
        CurDir, CurDirLayout, RtlUserProcessParameters, RtlUserProcessParametersLayout,
        WindowsProcessParameters, WindowsProcessParametersBase,
    },
    region::WindowsRegion,
    segment::WindowsSegment,
    session::WindowsSession,
    teb::{Teb, TebLayout, WindowsTeb, WindowsTebBase},
    trap_frame::WindowsTrapFrame,
    user_module::WindowsUserModule,
    wow64::{
        WOW64_TLS_APCLIST, WOW64_TLS_CPURESERVED, WOW64_TLS_FILESYSREDIR, WOW64_TLS_TEMPLIST,
        WOW64_TLS_USERCALLBACKDATA, WOW64_TLS_WOW64INFO, WindowsWow64Kind,
    },
};

/// A Windows processor mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsProcessorMode {
    /// Request originated from kernel-mode code.
    KernelMode,

    /// Request originated from user-mode code.
    UserMode,
}

impl From<u8> for WindowsProcessorMode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::KernelMode,
            1 => Self::UserMode,
            _ => {
                // Assume any non-0 value is user mode.
                tracing::warn!(value, "unknown processor mode value");
                Self::UserMode
            }
        }
    }
}
