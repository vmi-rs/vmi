pub(crate) mod v1;
pub(crate) mod v2;

use isr_core::Profile;
use isr_macros::{offsets, symbols, Bitfield, Error, Field};

symbols! {
    /// Windows kernel symbols used by the [`WindowsOs`] implementation.
    ///
    /// [`WindowsOs`]: crate::WindowsOs
    #[derive(Debug)]
    pub struct Symbols {
        PsActiveProcessHead: u64,
        PsInitialSystemProcess: u64,
        PsLoadedModuleList: u64,
        KiDispatchException: Option<u64>,
        DbgkpSendErrorMessage: Option<u64>,

        KiKvaShadow: Option<u64>,
        KiSystemCall32: u64,
        KiSystemCall64: u64,
        //KiSystemCall32Shadow: u64,
        //KiSystemCall64Shadow: u64,
        KiSystemServiceStart: u64,
        KiSystemServiceExit: u64,

        MmPfnDatabase: u64,
        MmHighestUserAddress: u64,

        AlpcpSendMessage: Option<u64>,

        MiDeletePartialVad: Option<u64>,
        MiDeleteVad: Option<u64>,
        MiDeleteVirtualAddresses: Option<u64>,
        MiGetWsAndInsertVad: Option<u64>,
        MiInsertPrivateVad: Option<u64>,
        MiInsertVad: Option<u64>,
        MiRemoveVadAndView: Option<u64>,

        NtBuildLab: u64,
        NtBuildLabEx: Option<u64>,

        NtAllocateVirtualMemory: Option<u64>,
        NtFreeVirtualMemory: Option<u64>,
        NtProtectVirtualMemory: Option<u64>,
        NtReadVirtualMemory: Option<u64>,
        NtWriteVirtualMemory: Option<u64>,
        NtQueryVirtualMemory: Option<u64>,

        NtMapViewOfSection: Option<u64>,
        NtUnmapViewOfSection: Option<u64>,

        NtCreateFile: Option<u64>,
        NtOpenFile: Option<u64>,
        NtQueryInformationFile: Option<u64>,
        NtSetInformationFile: Option<u64>,
        NtReadFile: Option<u64>,
        NtWriteFile: Option<u64>,
        NtDeviceIoControlFile: Option<u64>,

        NtClose: Option<u64>,

        ExAllocatePool: u64,
        ExAllocatePoolWithTag: u64,
        ExFreePool: u64,
        ExFreePoolWithTag: u64,
        MmGetSystemRoutineAddress: u64,

        ObpRootDirectoryObject: u64,
        ObHeaderCookie: Option<u64>,
        ObTypeIndexTable: u64,
        ObpInfoMaskToOffset: u64,
        ObpKernelHandleTable: u64,

        PspInsertProcess: Option<u64>,
        PspUserThreadStartup: Option<u64>,
        PspExitThread: Option<u64>,
        MmCleanProcessAddressSpace: Option<u64>,
    }
}

offsets! {
    /// Common Windows kernel offsets used by the [`WindowsOs`] implementation.
    ///
    /// These offsets are common to all Windows versions.
    ///
    /// [`WindowsOs`]: crate::WindowsOs
    #[derive(Debug)]
    pub struct OffsetsCommon {
        struct _LIST_ENTRY {
            Flink: Field,                   // struct _LIST_ENTRY*
            Blink: Field,                   // struct _LIST_ENTRY*
        }

        struct _EX_FAST_REF {
            RefCnt: Bitfield,
            Value: Field,
        }

        struct _UNICODE_STRING {
            Length: Field,
            MaximumLength: Field,
            Buffer: Field,
        }

        struct _KPCR {
            Prcb: Field,
        }

        struct _KPRCB {
            CurrentThread: Field,
        }

        #[isr(alias = "_LDR_DATA_TABLE_ENTRY")]
        struct _KLDR_DATA_TABLE_ENTRY {
            InLoadOrderLinks: Field,        // _LIST_ENTRY
            DllBase: Field,                 // PVOID
            EntryPoint: Field,              // PVOID
            SizeOfImage: Field,             // ULONG
            FullDllName: Field,             // _UNICODE_STRING
            BaseDllName: Field,             // _UNICODE_STRING
        }

        struct _CLIENT_ID {
            UniqueProcess: Field,
            UniqueThread: Field,
        }

        struct _EXCEPTION_RECORD {
            ExceptionCode: Field,
            ExceptionFlags: Field,
            ExceptionRecord: Field,
            ExceptionAddress: Field,
            NumberParameters: Field,
            ExceptionInformation: Field,
        }

        struct _HANDLE_TABLE {
            NextHandleNeedingPool: Field,   // ULONG
            TableCode: Field,               // ULONG_PTR
        }

        struct _OBJECT_ATTRIBUTES {
            RootDirectory: Field,
            ObjectName: Field,
            Attributes: Field,
        }

        struct _OBJECT_HEADER {
            TypeIndex: Field,
            InfoMask: Field,
            Body: Field,
        }

        struct _OBJECT_DIRECTORY {
            HashBuckets: Field,             // struct _OBJECT_DIRECTORY_ENTRY* [37]
        }

        struct _OBJECT_DIRECTORY_ENTRY {
            ChainLink: Field,               // struct _OBJECT_DIRECTORY_ENTRY*
            Object: Field,                  // PVOID
            HashValue: Field,               // ULONG
        }

        struct _OBJECT_HEADER_NAME_INFO {
            Directory: Field,               // _OBJECT_DIRECTORY*
            Name: Field,                    // _UNICODE_STRING
        }

        struct _OBJECT_TYPE {
            Name: Field,
        }

        struct _MMSECTION_FLAGS {
            Image: Bitfield,
            File: Bitfield,
        }

        struct _KTRAP_FRAME {
            Rax: Field,
            Rcx: Field,
            Rdx: Field,
            R8: Field,
            R9: Field,
            R10: Field,
            R11: Field,

            Rip: Field,
            Rsp: Field,
        }

        struct _KAPC_STATE {
            Process: Field,
        }

        struct _KTHREAD {
            TrapFrame: Field,
            ApcState: Field,
            Teb: Field,
            Process: Field,
        }

        struct _ETHREAD {
            Cid: Field,
        }

        struct _KPROCESS {
            DirectoryTableBase: Field,
            UserDirectoryTableBase: Option<Field>,
        }

        struct _EPROCESS {
            UniqueProcessId: Field,
            ActiveProcessLinks: Field,
            SectionBaseAddress: Field,
            InheritedFromUniqueProcessId: Field,
            Peb: Field,
            ObjectTable: Field,
            #[isr(alias = "Wow64Process")]
            WoW64Process: Field,
            ImageFileName: Field,
            VadRoot: Field,                 // _MM_AVL_TABLE (Windows 7, contains BalancedRoot at offset 0)
                                            // _RTL_AVL_TREE (Windows 10+)
            VadHint: Option<Field>,         // PVOID (Windows 10+, _MM_AVL_TABLE.NodeHint on Windows 7)
        }

        struct _PEB {
            ImageBaseAddress: Field,        // PVOID
            Ldr: Field,                     // _PEB_LDR_DATA*
            ProcessParameters: Field,       // _RTL_USER_PROCESS_PARAMETERS*
        }

        struct _TEB {
            LastErrorValue: Field,
            LastStatusValue: Field,
        }

        struct _RTL_USER_PROCESS_PARAMETERS {
            CurrentDirectory: Field,        // _CURDIR
            DllPath: Field,                 // _UNICODE_STRING
            ImagePathName: Field,           // _UNICODE_STRING
            CommandLine: Field,             // _UNICODE_STRING
        }

        struct _CURDIR {
            DosPath: Field,                 // _UNICODE_STRING
        }

        struct _MMPFN {
            ReferenceCount: Field,          // USHORT

            //
            // NOTE: The PageLocation field is located INSIDE the e1 field.
            //       However, on Windows 7 the e1 field is named _MMPFNENTRY,
            //       while on Windows 10 (since 1607/RS1 - build 14393) it is
            //       named _MMPFNENTRY1.
            //
            // NOTE: On Windows XP, the PageLocation field is located inside
            //       the e2 field. Therefore, Windows XP is unsupported.
            //
            // Instead of creating two separate structures, we can exploit the
            // fact that the ISR library allows us to search for nested fields.
            //

            e1: Field,
            PageLocation: Bitfield,
        }

        struct _MMVAD_FLAGS {
            // VadFlags: Field,             // _MMVAD_FLAGS
            VadType: Bitfield,              // ULONG (3 bits)
            Protection: Bitfield,           // ULONG bitfield (5 bits)
            PrivateMemory: Bitfield,        // ULONG bitfield (1 bit)
            MemCommit: Option<Bitfield>,    // ULONG bitfield (1 bit, might be in _MMVAD_FLAGS1)
        }

        struct _MMVAD_SHORT {
            //
            // On Windows 7, the LeftChild and RightChild fields are directly present
            // in the _MMVAD / _MMVAD_SHORT structure.
            //
            // In Windows 10, there is a _RTL_BALANCED_NODE structure (VadNode) at the
            // start of the _MMVAD structure, which contains the Left and Right fields.
            //

            // VadNode: Field,              // _RTL_BALANCED_NODE (always at offset 0)

            #[isr(alias = "LeftChild")]     // _MMVAD*
            Left: Field,                    // _RTL_BALANCED_NODE* (VadNode.Left)
            #[isr(alias = "RightChild")]    // _MMVAD*
            Right: Field,                   // _RTL_BALANCED_NODE* (VadNode.Right)

            StartingVpn: Field,             // ULONG
            EndingVpn: Field,               // ULONG
            StartingVpnHigh: Option<Field>, // UCHAR
            EndingVpnHigh: Option<Field>,   // UCHAR
            VadFlags: Field,                // _MMVAD_FLAGS
            VadFlags1: Option<Field>,       // _MMVAD_FLAGS1 (Windows 8+)
        }

        struct _MMVAD {
            // Core: Field,                 // _MMVAD_SHORT (always at offset 0)
            Subsection: Field,              // _SUBSECTION*
        }

        struct _SUBSECTION {
            ControlArea: Field,
        }

        struct _CONTROL_AREA {
            Flags: Field,
            FilePointer: Field,
        }

        struct _FILE_OBJECT {
            DeviceObject: Field,
            Vpb: Field,
            FileName: Field,
        }

        struct _DEVICE_OBJECT {
            DriverObject: Field,
            AttachedDevice: Field,
            Flags: Field,
            Vpb: Field,
        }

        struct _VPB {
            DeviceObject: Field,
            RealDevice: Field,
        }
    }
}

/// Extended offsets for Windows.
pub enum OffsetsExt {
    /// First version of extended offsets.
    ///
    /// This version is used for Windows 7.
    V1(v1::Offsets),

    /// Second version of extended offsets.
    ///
    /// This version is used for Windows 10+.
    V2(v2::Offsets),
}

/// Offsets for Windows.
pub struct Offsets {
    /// Offsets common to all Windows versions.
    pub common: OffsetsCommon,

    /// Extended offsets specific to the Windows version.
    pub ext: Option<OffsetsExt>,
}

impl std::ops::Deref for Offsets {
    type Target = OffsetsCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl Offsets {
    /// Creates a new `Offsets` instance.
    pub fn new(profile: &Profile) -> Result<Self, Error> {
        let common = OffsetsCommon::new(profile)?;
        let ext = if let Ok(v1) = v1::Offsets::new(profile) {
            Some(OffsetsExt::V1(v1))
        }
        else if let Ok(v2) = v2::Offsets::new(profile) {
            Some(OffsetsExt::V2(v2))
        }
        else {
            None
        };

        Ok(Self { common, ext })
    }

    /// Returns the extended offsets.
    pub fn ext(&self) -> Option<&OffsetsExt> {
        self.ext.as_ref()
    }
}
