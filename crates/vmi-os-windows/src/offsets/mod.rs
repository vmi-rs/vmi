pub(crate) mod v1;
pub(crate) mod v2;

use isr_core::Profile;
use isr_macros::{Bitfield, Error, Field, offsets, symbols};

symbols! {
    /// Windows kernel symbols used by the [`WindowsOs`] implementation.
    ///
    /// [`WindowsOs`]: crate::WindowsOs
    #[derive(Debug)]
    pub struct Symbols {
        PsActiveProcessHead: u64,
        PsIdleProcess: u64,
        PsInitialSystemProcess: u64,
        PsLoadedModuleList: u64,
        KiDeliverApc: Option<u64>,
        KiDispatchException: Option<u64>,
        DbgkpSendErrorMessage: Option<u64>,

        CmpHiveListHead: u64, // _LIST_ENTRY (_CMHIVE*)

        KeNumberProcessors: u64,
        KiProcessorBlock: u64,

        KiKvaShadow: Option<u64>,
        KiSystemCall32: u64,
        KiSystemCall64: u64,
        //KiSystemCall32Shadow: u64,
        //KiSystemCall64Shadow: u64,
        KiSystemServiceStart: Option<u64>,
        KiSystemServiceExit: Option<u64>,

        KeInitThread: Option<u64>,
        KiInitializeContextThread: Option<u64>,
        KeTerminateThread: Option<u64>,

        MmUnloadedDrivers: u64,     // _UNLOADED_DRIVERS*[MI_UNLOADED_DRIVERS /* 50 */]
        MmLastUnloadedDriver: u64,  // ULONG

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

        ExNotifyCallback: Option<u64>,
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
        ObReferenceObjectByPointerWithTag: Option<u64>,

        PspInsertProcess: Option<u64>,
        PspInsertThread: Option<u64>,
        PspUserThreadStartup: Option<u64>,
        PspExitThread: Option<u64>,
        PspThreadDelete: Option<u64>,
        PspSetContextThreadInternal: Option<u64>,
        PspWow64SetContextThread: Option<u64>,
        MmCleanProcessAddressSpace: Option<u64>,
        MmDeleteProcessAddressSpace: Option<u64>,

        SeAccessCheck: Option<u64>,

        CmKeyObjectType: u64,   // _OBJECT_TYPE*
        IoFileObjectType: u64,  // _OBJECT_TYPE*
        PsProcessType: u64,     // _OBJECT_TYPE*
        PsThreadType: u64,      // _OBJECT_TYPE*
        PsJobType: u64,         // _OBJECT_TYPE*
        SeTokenObjectType: u64, // _OBJECT_TYPE*
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
            NextThread: Field,
            IdleThread: Field,
            ProcessorState: Field,          // _KPROCESSOR_STATE
            Context: Field,                 // _CONTEXT* (bugcheck saved context)
        }

        struct _KPROCESSOR_STATE {
            SpecialRegisters: Field,        // _KSPECIAL_REGISTERS
            ContextFrame: Field,            // _CONTEXT
        }

        #[isr(alias = "_LDR_DATA_TABLE_ENTRY")]
        struct _KLDR_DATA_TABLE_ENTRY {
            InLoadOrderLinks: Field,        // _LIST_ENTRY
            DllBase: Field,                 // PVOID
            EntryPoint: Field,              // PVOID
            SizeOfImage: Field,             // ULONG
            FullDllName: Field,             // _UNICODE_STRING
            BaseDllName: Field,             // _UNICODE_STRING
            TimeDateStamp: Field,           // ULONG
        }

        //
        // See unloaded_driver.rs on why is this commented out.
        //
        // struct _UNLOADED_DRIVERS {
        //     Name: Field,                    // _UNICODE_STRING
        //     StartAddress: Field,            // PVOID
        //     EndAddress: Field,              // PVOID
        //     CurrentTime: Field,             // LARGE_INTEGER
        // }
        //

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

        /*

        Win7:

            typedef struct _HMAP_ENTRY
            {
                ULONG_PTR BlockAddress;
                ULONG_PTR BinAddress;
                struct _CM_VIEW_OF_FILE* CmView;
                unsigned long MemAlloc;
            } HMAP_ENTRY, *PHMAP_ENTRY;

        Win10 TH1/TH2:

            typedef union _EX_RUNDOWN_REF
            {
                ULONG Count;
                PVOID Ptr;
            } EX_RUNDOWN_REF, *PEX_RUNDOWN_REF;

            typedef struct _HMAP_ENTRY
            {
                ULONG BlockOffset;
                ULONG PermanentBinAddress;
                ULONG TemporaryBinAddress;
                EX_RUNDOWN_REF TemporaryBinRundown;
                ULONG MemAlloc;
            } HMAP_ENTRY, *PHMAP_ENTRY;

        Win10 RS4+:

            typedef struct _HMAP_ENTRY
            {
                ULONG_PTR BlockOffset;
                ULONG_PTR PermanentBinAddress;
                ULONG MemAlloc;
            } HMAP_ENTRY, *PHMAP_ENTRY;

         */

        struct _HBASE_BLOCK {
            // #define HBASE_BLOCK_SIGNATURE   0x66676572  // "regf"
            Signature: Field,               // ULONG
            Major: Field,                   // ULONG
            Minor: Field,                   // ULONG
            Type: Field,                    // ULONG
            Format: Field,                  // ULONG
            RootCell: Field,                // ULONG
            FileName: Field,                // CHAR[64]
        }

        struct _DUAL {
            Map: Field,                     // _HMAP_DIRECTORY*
        }

        struct _HMAP_DIRECTORY {
            Directory: Field,               // _HMAP_TABLE*[1024]
        }

        struct _HMAP_TABLE {
            Table: Field,                   // _HMAP_ENTRY[512]
        }

        struct _HMAP_ENTRY {
            BlockAddress: Option<Field>,          // ULONG_PTR (Win7) or ULONG (Win10 RS4+)

            BlockOffset: Option<Field>,             //  ULONG_PTR
            PermanentBinAddress: Option<Field>,     //  ULONG_PTR
        }

        struct _CMHIVE {
            // struct _HHIVE {
            // #define HHIVE_SIGNATURE 0xBEE0BEE0
            Signature: Field,               // ULONG
            BaseBlock: Field,               // struct _HBASE_BLOCK*
            Flat: Bitfield,                 // UCHAR or UCHAR : 1 (bitfield)
            Version: Field,                 // ULONG
            Storage: Field,                 // _DUAL[2]
            // } Hive;
            HiveList: Field,                // _LIST_ENTRY
            KcbCacheTable: Field,           // _CM_KEY_HASH_TABLE_ENTRY*
            KcbCacheTableSize: Field,       // ULONG

            FileFullPath: Field,            // _UNICODE_STRING
            FileUserName: Field,            // _UNICODE_STRING
            HiveRootPath: Field,            // _UNICODE_STRING
        }

        struct _CM_KEY_HASH_TABLE_ENTRY {
            Owner: Field,                   // _ETHREAD*
            Entry: Field,                   // _CM_KEY_HASH*
        }

        struct _CM_KEY_HASH {
            NextHash: Field,                // _CM_KEY_HASH*
            KeyHive: Field,                 // _HHIVE*
            KeyCell: Field,                 // ULONG
        }

        struct _CHILD_LIST {
            Count: Field,                   // ULONG
            List: Field,                    // ULONG
        }

        struct _CM_KEY_NODE {
            Signature: Field,               // USHORT
            Flags: Field,                   // USHORT
            SubKeyCounts: Field,            // ULONG[2]
            SubKeyLists: Field,             // ULONG[2]
            ValueList: Field,               // _CHILD_LIST
            NameLength: Field,              // USHORT
            Name: Field,                    // WCHAR[1] (variable length)
        }

        struct _CM_KEY_INDEX {
            Signature: Field,               // USHORT
            Count: Field,                   // USHORT
            List: Field,                    // ULONG[1]
        }

        struct _CM_KEY_VALUE {
            Signature: Field,               // USHORT
            NameLength: Field,              // USHORT
            DataLength: Field,              // ULONG
            Data: Field,                    // ULONG
            Type: Field,                    // ULONG
            Flags: Field,                   // USHORT
            Name: Field,                    // WCHAR[1] (variable length)
        }

        struct _CM_BIG_DATA {
            Signature: Field,               // USHORT
            Count: Field,                   // USHORT
            List: Field,                    // ULONG
        }

        struct _CM_KEY_BODY {
            KeyControlBlock: Field,
        }

        struct _CM_KEY_CONTROL_BLOCK {
            RefCount: Field,                // ULONG before Win10 1903/19H1 (18362)
                                            // ULONGLONG after
            // struct {
            #[isr(alias = "Delete")]        // Before Win10 1607 RS1 (14393)
            Discarded: Bitfield,            // ULONG: 1
            // } /* flags */

            KeyHash: Field,                 // _CM_KEY_HASH
            NextHash: Field,                // _CM_KEY_HASH*
            KeyHive: Field,                 // _HHIVE*
            KeyCell: Field,                 // ULONG

            ParentKcb: Field,               // _CM_KEY_CONTROL_BLOCK*
            NameBlock: Field,               // _CM_NAME_CONTROL_BLOCK*

            RealKeyName: Field,             // char*
            FullKCBName: Field,             // _UNICODE_STRING*
        }

        struct _CM_NAME_CONTROL_BLOCK {
            Compressed: Bitfield,           // BOOLEAN in Win7, ULONG: 1 in Win8+
            NameLength: Field,
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
            Alertable: Bitfield,            // part of ULONG MiscFlags
            TrapFrame: Field,
            ApcState: Field,
            ApcStateIndex: Field,
            SavedApcState: Field,
            NextProcessor: Field,           // ULONG
            WaitMode: Field,                // CCHAR - KPROCESSOR_MODE enum
            WaitReason: Field,              // UCHAR - KWAIT_REASON enum
            Teb: Field,
            Process: Field,
            ThreadListEntry: Field,         // _LIST_ENTRY
            State: Field,                   // UCHAR - KTHREAD_STATE enum
            KernelStack: Field,             // PVOID
        }

        struct _ETHREAD {
            Cid: Field,
            ThreadListEntry: Field,         // _LIST_ENTRY
            ClientSecurity: Field,          // _PS_CLIENT_SECURITY_CONTEXT

            // union {
            //     ULONG CrossThreadFlags;
            //     struct {
            ActiveImpersonationInfo: Bitfield, // ULONG : 1
            //     };
            // };
        }

        struct _KPROCESS {
            DirectoryTableBase: Field,
            UserDirectoryTableBase: Option<Field>,
            ThreadListHead: Field,          // _LIST_ENTRY
        }

        struct _EPROCESS {
            UniqueProcessId: Field,
            ActiveProcessLinks: Field,      // _LIST_ENTRY
            SessionProcessLinks: Field,     // _LIST_ENTRY
            SectionBaseAddress: Field,
            InheritedFromUniqueProcessId: Field,
            Peb: Field,
            Session: Field,                 // _MM_SESSION_SPACE*
            ObjectTable: Field,
            Token: Field,                   // _EX_FAST_REF (_TOKEN*)
            #[isr(alias = "Wow64Process")]
            WoW64Process: Field,
            ImageFileName: Field,
            VadRoot: Field,                 // _MM_AVL_TABLE (Windows 7, contains BalancedRoot at offset 0)
                                            // _RTL_AVL_TREE (Windows 10+)
            VadHint: Option<Field>,         // PVOID (Windows 10+, _MM_AVL_TABLE.NodeHint on Windows 7)
            ThreadListHead: Field,          // _LIST_ENTRY
        }

        struct _SID {
            Revision: Field,               // UCHAR
            SubAuthorityCount: Field,      // UCHAR
            IdentifierAuthority: Field,    // struct { UCHAR Value[6]; }
            SubAuthority: Field,           // ULONG[1] (variable length)
        }

        struct _SID_AND_ATTRIBUTES {
            Sid: Field,                    // _SID*
            Attributes: Field,             // ULONG
        }

        struct _PS_CLIENT_SECURITY_CONTEXT {
            ImpersonationToken: Field,       // _EX_FAST_REF (_TOKEN*)
        }

        struct _SEP_TOKEN_PRIVILEGES {
            Present: Field,                // ULONGLONG
            Enabled: Field,                // ULONGLONG
            EnabledByDefault: Field,       // ULONGLONG
        }

        struct _TOKEN_SOURCE {
            SourceName: Field,             // CHAR[8]
            SourceIdentifier: Field,       // _LUID
        }

        struct _TOKEN {
            TokenSource: Field,             // _TOKEN_SOURCE
            TokenId: Field,                 // _LUID
            AuthenticationId: Field,        // _LUID
            ParentTokenId: Field,           // _LUID
            // ExpirationTime: Field,          // _LARGE_INTEGER
            ModifiedId: Field,              // _LUID
            Privileges: Field,              // _SEP_TOKEN_PRIVILEGES
            // AuditPolicy: Field,             // _SEP_AUDIT_POLICY
            SessionId: Field,               // ULONG
            UserAndGroupCount: Field,       // ULONG
            RestrictedSidCount: Field,      // ULONG
            // VariableLength: Field,          // ULONG
            // DynamicCharged: Field,          // ULONG
            // DynamicAvailable: Field,        // ULONG
            DefaultOwnerIndex: Field,       // ULONG
            UserAndGroups: Field,           // _SID_AND_ATTRIBUTES*
            RestrictedSids: Field,          // _SID_AND_ATTRIBUTES*
            PrimaryGroup: Field,            // PVOID
            TokenType: Field,               // enum _TOKEN_TYPE
            ImpersonationLevel: Field,      // enum _SECURITY_IMPERSONATION_LEVEL
            TokenFlags: Field,              // ULONG
            TokenInUse: Field,              // UCHAR
            // IntegrityLevelIndex: Field,     // ULONG
            // MandatoryPolicy: Field,         // ULONG
            // LogonSession: Field,            // _SEP_LOGON_SESSION_REFERENCES*
            OriginatingLogonSession: Field, // _LUID
        }

        // Unfortunately, _PEB32 and _PEB64 are not defined in 32-bit ntoskrnl.
        struct _PEB {
            ImageBaseAddress: Field,        // PVOID
            Ldr: Field,                     // _PEB_LDR_DATA*
            ProcessParameters: Field,       // _RTL_USER_PROCESS_PARAMETERS*
        }

        struct _PEB_LDR_DATA {
            InLoadOrderModuleList: Field,           // _LIST_ENTRY
            InMemoryOrderModuleList: Field,         // _LIST_ENTRY
            InInitializationOrderModuleList: Field, // _LIST_ENTRY
        }

        struct _LDR_DATA_TABLE_ENTRY {
            InLoadOrderLinks: Field,            // _LIST_ENTRY
            InMemoryOrderLinks: Field,          // _LIST_ENTRY
            InInitializationOrderLinks: Field,  // _LIST_ENTRY
            DllBase: Field,                     // PVOID
            EntryPoint: Field,                  // PVOID
            SizeOfImage: Field,                 // ULONG
            FullDllName: Field,                 // _UNICODE_STRING
            BaseDllName: Field,                 // _UNICODE_STRING
            TimeDateStamp: Field,               // ULONG
        }

        struct _TEB {
            ProcessEnvironmentBlock: Field, // _PEB*
            LastErrorValue: Field,          // ULONG
            LastStatusValue: Field,         // NTSTATUS
            TlsSlots: Field,                // PVOID[64]
        }

        struct _TEB32 {
            ProcessEnvironmentBlock: Field, // _PEB*
            LastErrorValue: Field,          // ULONG
            LastStatusValue: Field,         // NTSTATUS
            TlsSlots: Field,                // PVOID[64]
        }

        struct _TEB64 {
            ProcessEnvironmentBlock: Field, // _PEB*
            LastErrorValue: Field,          // ULONG
            LastStatusValue: Field,         // NTSTATUS
            TlsSlots: Field,                // PVOID[64]
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

        //
        // See session.rs on why is this commented out.
        //
        // struct _MM_SESSION_SPACE {
        //     SessionId: Field,               // ULONG
        //     ProcessList: Field,             // _LIST_ENTRY
        // }
        //

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
            CommitCharge: Option<Bitfield>, // ULONG bitfield (31 bits, might be in _MMVAD_FLAGS1)
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
            Segment: Field,                 // _SEGMENT*
            Flags: Field,
            FilePointer: Field,             // _EX_FAST_REF (_FILE_OBJECT*)
            CommittedPageCount: Option<Bitfield>,   // Since Win10 1703/RS2 (15063)
                                                    // ULONG : 36 [x64]
                                                    // ULONG : 20 [x86]
        }

        struct _SEGMENT {
            ControlArea: Field,             // _CONTROL_AREA*
            TotalNumberOfPtes: Field,       // ULONG
            SegmentFlags: Field,            // _SEGMENT_FLAGS
            NumberOfCommittedPages: Field,  // SIZE_T
            SizeOfSegment: Field,           // UINT64
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
