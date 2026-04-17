/// Wrapper around `DUMP_HEADER64`.
#[derive(Debug, Clone, Copy)]
pub struct Header64 {
    pub(crate) signature: u32,
    pub(crate) valid_dump: u32,
    pub(crate) major_version: u32,
    pub(crate) minor_version: u32,
    pub(crate) directory_table_base: u64,
    pub(crate) pfn_database: u64,
    pub(crate) ps_loaded_module_list: u64,
    pub(crate) ps_active_process_head: u64,
    pub(crate) machine_image_type: u32,
    pub(crate) number_processors: u32,
    pub(crate) bug_check_code: u32,
    pub(crate) bug_check_parameter1: u64,
    pub(crate) bug_check_parameter2: u64,
    pub(crate) bug_check_parameter3: u64,
    pub(crate) bug_check_parameter4: u64,
    pub(crate) version_user: [u8; 32],
    pub(crate) kd_debugger_data_block: u64,
    pub(crate) physical_memory_block_buffer: [u8; 700],
    pub(crate) context_record_buffer: [u8; 3_000],
    pub(crate) exception: ExceptionRecord64,
    pub(crate) dump_type: u32,
    pub(crate) required_dump_space: i64,
    pub(crate) system_time: i64,
    pub(crate) comment: [u8; 128],
    pub(crate) system_up_time: i64,
    pub(crate) minidump_fields: u32,
    pub(crate) secondary_data_state: u32,
    pub(crate) product_type: u32,
    pub(crate) suite_mask: u32,
    pub(crate) writer_status: u32,
    pub(crate) kd_secondary_version: u8,
    pub(crate) attributes: u32,
    pub(crate) boot_id: u32,
}

impl Header64 {
    /// Corresponds to `DUMP_HEADER64.Signature`.
    pub fn signature(&self) -> u32 {
        self.signature
    }

    /// Corresponds to `DUMP_HEADER64.ValidDump`.
    pub fn valid_dump(&self) -> u32 {
        self.valid_dump
    }

    /// Corresponds to `DUMP_HEADER64.MajorVersion`.
    pub fn major_version(&self) -> u32 {
        self.major_version
    }

    /// Corresponds to `DUMP_HEADER64.MinorVersion`.
    pub fn minor_version(&self) -> u32 {
        self.minor_version
    }

    /// Corresponds to `DUMP_HEADER64.DirectoryTableBase`.
    pub fn directory_table_base(&self) -> u64 {
        self.directory_table_base
    }

    /// Corresponds to `DUMP_HEADER64.PfnDataBase`.
    pub fn pfn_database(&self) -> u64 {
        self.pfn_database
    }

    /// Corresponds to `DUMP_HEADER64.PsLoadedModuleList`.
    pub fn ps_loaded_module_list(&self) -> u64 {
        self.ps_loaded_module_list
    }

    /// Corresponds to `DUMP_HEADER64.PsActiveProcessHead`.
    pub fn ps_active_process_head(&self) -> u64 {
        self.ps_active_process_head
    }

    /// Corresponds to `DUMP_HEADER64.MachineImageType`.
    pub fn machine_image_type(&self) -> u32 {
        self.machine_image_type
    }

    /// Corresponds to `DUMP_HEADER64.NumberProcessors`.
    pub fn number_processors(&self) -> u32 {
        self.number_processors
    }

    /// Corresponds to `DUMP_HEADER64.BugCheckCode`.
    pub fn bug_check_code(&self) -> u32 {
        self.bug_check_code
    }

    /// Corresponds to `DUMP_HEADER64.BugCheckParameter1`.
    pub fn bug_check_parameter1(&self) -> u64 {
        self.bug_check_parameter1
    }

    /// Corresponds to `DUMP_HEADER64.BugCheckParameter2`.
    pub fn bug_check_parameter2(&self) -> u64 {
        self.bug_check_parameter2
    }

    /// Corresponds to `DUMP_HEADER64.BugCheckParameter3`.
    pub fn bug_check_parameter3(&self) -> u64 {
        self.bug_check_parameter3
    }

    /// Corresponds to `DUMP_HEADER64.BugCheckParameter4`.
    pub fn bug_check_parameter4(&self) -> u64 {
        self.bug_check_parameter4
    }

    /// Corresponds to `DUMP_HEADER64.VersionUser`.
    pub fn version_user(&self) -> [u8; 32] {
        self.version_user
    }

    /// Corresponds to `DUMP_HEADER64.KdDebuggerDataBlock`.
    pub fn kd_debugger_data_block(&self) -> u64 {
        self.kd_debugger_data_block
    }

    /// Corresponds to `DUMP_HEADER64.PhysicalMemoryBlockBuffer`.
    pub fn physical_memory_block_buffer(&self) -> [u8; 700] {
        self.physical_memory_block_buffer
    }

    /// Corresponds to `DUMP_HEADER64.ContextRecord`.
    pub fn context_record(&self) -> [u8; 3_000] {
        self.context_record_buffer
    }

    /// Corresponds to `DUMP_HEADER64.Exception`.
    pub fn exception(&self) -> ExceptionRecord64 {
        ExceptionRecord64 {
            exception_code: self.exception.exception_code,
            exception_flags: self.exception.exception_flags,
            exception_record: self.exception.exception_record,
            exception_address: self.exception.exception_address,
            number_parameters: self.exception.number_parameters,
            exception_information: self.exception.exception_information,
        }
    }

    /// Corresponds to `DUMP_HEADER64.DumpType`.
    pub fn dump_type(&self) -> u32 {
        self.dump_type
    }

    /// Corresponds to `DUMP_HEADER64.RequiredDumpSpace`.
    pub fn required_dump_space(&self) -> i64 {
        self.required_dump_space
    }

    /// Corresponds to `DUMP_HEADER64.SystemTime`.
    pub fn system_time(&self) -> i64 {
        self.system_time
    }

    /// Corresponds to `DUMP_HEADER64.Comment`.
    pub fn comment(&self) -> [u8; 128] {
        self.comment
    }

    /// Corresponds to `DUMP_HEADER64.SystemUpTime`.
    pub fn system_up_time(&self) -> i64 {
        self.system_up_time
    }

    /// Corresponds to `DUMP_HEADER64.MiniDumpFields`.
    pub fn minidump_fields(&self) -> u32 {
        self.minidump_fields
    }

    /// Corresponds to `DUMP_HEADER64.SecondaryDataState`.
    pub fn secondary_data_state(&self) -> u32 {
        self.secondary_data_state
    }

    /// Corresponds to `DUMP_HEADER64.ProductType`.
    pub fn product_type(&self) -> u32 {
        self.product_type
    }

    /// Corresponds to `DUMP_HEADER64.SuiteMask`.
    pub fn suite_mask(&self) -> u32 {
        self.suite_mask
    }

    /// Corresponds to `DUMP_HEADER64.WriterStatus`.
    pub fn writer_status(&self) -> u32 {
        self.writer_status
    }

    /// Corresponds to `DUMP_HEADER64.KdSecondaryVersion`.
    pub fn kd_secondary_version(&self) -> u8 {
        self.kd_secondary_version
    }

    /// Corresponds to `DUMP_HEADER64.Attributes`.
    pub fn attributes(&self) -> u32 {
        self.attributes
    }

    /// Corresponds to `DUMP_HEADER64.BootId`.
    pub fn boot_id(&self) -> u32 {
        self.boot_id
    }
}

/// Wrapper around `EXCEPTION_RECORD64`.
#[derive(Debug, Clone, Copy)]
pub struct ExceptionRecord64 {
    pub(crate) exception_code: u32,
    pub(crate) exception_flags: u32,
    pub(crate) exception_record: u64,
    pub(crate) exception_address: u64,
    pub(crate) number_parameters: u32,
    pub(crate) exception_information: [u64; 15],
}

impl ExceptionRecord64 {
    /// Corresponds to `EXCEPTION_RECORD64.ExceptionCode`.
    pub fn exception_code(&self) -> u32 {
        self.exception_code
    }

    /// Corresponds to `EXCEPTION_RECORD64.ExceptionFlags`.
    pub fn exception_flags(&self) -> u32 {
        self.exception_flags
    }

    /// Corresponds to `EXCEPTION_RECORD64.ExceptionRecord`.
    pub fn exception_record(&self) -> u64 {
        self.exception_record
    }

    /// Corresponds to `EXCEPTION_RECORD64.ExceptionAddress`.
    pub fn exception_address(&self) -> u64 {
        self.exception_address
    }

    /// Corresponds to `EXCEPTION_RECORD64.NumberParameters`.
    pub fn number_parameters(&self) -> u32 {
        self.number_parameters
    }

    /// Corresponds to `EXCEPTION_RECORD64.ExceptionInformation`.
    pub fn exception_information(&self) -> [u64; 15] {
        self.exception_information
    }
}
