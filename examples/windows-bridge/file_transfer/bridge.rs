use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Error, ErrorKind, Write as _},
    path::PathBuf,
};

use vmi::{
    Va, VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        shellcode::{Status, impl_bridge_contract, impl_stage},
    },
};

use crate::bridge::BridgeOutput;

/// Chunk size shared with the guest.
const CHUNK_SIZE: u64 = 64 * 1024;

/// Number of low bits reserved for the transfer handle in a begin response.
const TRANSFER_HANDLE_BITS: u32 = 12;

/// Largest transfer handle that fits in a begin response.
const TRANSFER_HANDLE_MAX: u32 = (1 << TRANSFER_HANDLE_BITS) - 1;

/// Stage reported by the `file-transfer` shellcode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileTransferStage(u8);

impl_stage!(FileTransferStage);

impl FileTransferStage {
    /// No transfer operation was started.
    pub const NONE: Self = Self(0x00);

    /// File name query stage.
    pub const FILE_NAME: Self = Self(0x01);

    /// File size query stage.
    pub const FILE_SIZE: Self = Self(0x02);

    /// File mapping stage.
    pub const MAPPING: Self = Self(0x03);

    /// Transfer buffer setup stage.
    pub const BUFFER: Self = Self(0x04);

    /// File transfer stage.
    pub const TRANSFER: Self = Self(0x05);
}

impl std::fmt::Debug for FileTransferStage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::NONE => "None",
            Self::FILE_NAME => "FileName",
            Self::FILE_SIZE => "FileSize",
            Self::MAPPING => "Mapping",
            Self::BUFFER => "Buffer",
            Self::TRANSFER => "Transfer",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

/// Status reported by the `file-transfer` shellcode.
pub type FileTransferStatus = Status<FileTransferStage>;

/// State associated with a host-side file for an active transfer.
struct HostFile {
    /// Host-side file corresponding to the active transfer.
    file: File,

    /// Host-side path to the file.
    path: PathBuf,

    /// Expected size of the file being transferred.
    expected_size: u64,

    /// Number of bytes received so far.
    received: u64,

    /// Guest virtual address of the shared transfer buffer.
    buffer: Option<Va>,
}

impl HostFile {
    /// Creates the host output file, truncating any existing content.
    fn create(path: PathBuf, expected_size: u64) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;

        Ok(Self {
            file,
            path,
            expected_size,
            received: 0,
            buffer: None,
        })
    }

    /// Sets the guest buffer address shared for this transfer.
    fn set_buffer(&mut self, buffer: Va) {
        self.buffer = Some(buffer);
    }

    /// Appends a chunk to the host output file.
    fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let length = bytes.len() as u64;
        if length > CHUNK_SIZE || self.received + length > self.expected_size {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "file-transfer chunk exceeds declared size",
            ));
        }

        self.file.write_all(bytes)?;
        self.received += length;

        Ok(())
    }

    /// Flushes the host output.
    fn flush(&mut self) -> Result<(), Error> {
        if self.received != self.expected_size {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "file-transfer byte count does not match declared size",
            ));
        }

        self.file.flush()
    }
}

/// State associated with a transfer handle.
struct TransferSession {
    /// Guest-side path of the file being transferred.
    path: String,

    /// Host-side state of the file being transferred.
    host_file: HostFile,

    /// Reusable buffer for transferring chunks.
    chunk_buffer: Vec<u8>,
}

impl TransferSession {
    /// Creates a transfer session with a buffer large enough for one chunk.
    fn new(path: String, host_file: HostFile) -> Self {
        Self {
            path,
            host_file,
            chunk_buffer: vec![0; CHUNK_SIZE as usize],
        }
    }
}

/// Host-side bridge handler for the `file-transfer` shellcode.
pub struct FileTransferBridge {
    /// Host-side output directory for transferred files.
    output_directory: PathBuf,

    /// Next candidate transfer handle.
    next_transfer_handle: u32,

    /// Next numeric prefix for output file names.
    next_output_id: u64,

    /// Active transfer sessions indexed by their transfer handle.
    transfers: HashMap<u32, TransferSession>,
}

impl_bridge_contract!(FileTransferBridge);

impl FileTransferBridge {
    /// Method used to begin a transfer.
    const METHOD_BEGIN: u16 = 0x0001;

    /// Method used to register the shared guest buffer.
    const METHOD_SET_BUFFER: u16 = 0x0002;

    /// Method used to transfer a guest buffer.
    const METHOD_CHUNK: u16 = 0x0003;

    /// Method used to close a transfer.
    const METHOD_CLOSE: u16 = 0x0004;

    /// Method used to report the final status.
    const METHOD_EXIT: u16 = 0xffff;

    /// Allows the shellcode to continue its current stage.
    const RESPONSE_CONTINUE: u64 = 0x0000_0000;

    /// Aborts the shellcode's current stage.
    const RESPONSE_ABORT: u64 = 0xffff_ffff;

    /// Creates a handler that writes transferred files to `output_directory`.
    pub fn new(output_directory: PathBuf) -> Self {
        Self {
            output_directory,
            next_transfer_handle: 1,
            next_output_id: 0,
            transfers: HashMap::new(),
        }
    }

    /// Allocates the next transfer handle.
    fn allocate_transfer_handle(&mut self) -> Option<u32> {
        if self.next_transfer_handle > TRANSFER_HANDLE_MAX {
            return None;
        }

        let handle = self.next_transfer_handle;
        self.next_transfer_handle += 1;
        Some(handle)
    }

    /// Handles a `file-transfer` bridge packet.
    fn handle_packet<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeOutput>>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let method = packet.method();

        match method {
            Self::METHOD_BEGIN => Some(self.handle_begin(vmi, packet)),
            Self::METHOD_SET_BUFFER => Some(self.handle_set_buffer(vmi, packet)),
            Self::METHOD_CHUNK => Some(self.handle_chunk(vmi, packet)),
            Self::METHOD_CLOSE => Some(self.handle_close(vmi, packet)),
            Self::METHOD_EXIT => Some(self.handle_exit(vmi, packet)),
            _ => self.handle_unknown(vmi, packet),
        }
    }

    /// Handles the [`METHOD_BEGIN`] bridge method.
    ///
    /// Starts a transfer and returns its newly allocated handle.
    ///
    /// [`METHOD_BEGIN`]: Self::METHOD_BEGIN
    fn handle_begin<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeOutput>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let file_handle = packet.value1();
        let file_size = packet.value2();
        let file_name_buffer = packet.value3();
        let file_name_length = packet.value4() as usize;

        let path = match vmi.read_string_utf16_limited(Va(file_name_buffer), file_name_length) {
            Ok(path) => path,
            Err(err) => {
                tracing::error!(%err, "cannot read filename");
                return BridgeResponse::new(0);
            }
        };

        // Windows file sizes are LONGLONG.
        if file_size > i64::MAX as u64 {
            tracing::error!(path, size = file_size, "rejected size");
            return BridgeResponse::new(0);
        }

        let transfer_handle = match self.allocate_transfer_handle() {
            Some(transfer_handle) => transfer_handle,
            None => {
                tracing::error!(path, "handles exhausted");
                return BridgeResponse::new(0);
            }
        };

        let output_id = self.next_output_id;
        self.next_output_id += 1;

        // REVIEW: avoid clone()
        let output_path = self
            .output_directory
            .join(output_filename(output_id, &path));

        let host_file = match HostFile::create(output_path.clone(), file_size) {
            Ok(host_file) => host_file,
            Err(err) => {
                tracing::error!(%err, path = ?output_path.display(), "cannot create file");
                return BridgeResponse::new(0);
            }
        };

        self.transfers.insert(
            transfer_handle,
            TransferSession::new(path.clone(), host_file),
        );

        tracing::info!(
            transfer_handle,
            file_handle = %Hex(file_handle),
            path,
            size = file_size,
            output = ?output_path.display(),
            "started"
        );

        BridgeResponse::new((CHUNK_SIZE << TRANSFER_HANDLE_BITS) | u64::from(transfer_handle))
    }

    /// Handles the [`METHOD_SET_BUFFER`] bridge method.
    ///
    /// [`METHOD_SET_BUFFER`]: Self::METHOD_SET_BUFFER
    fn handle_set_buffer<Driver>(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeOutput>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let transfer_handle = packet.value1() as u32;
        let buffer = packet.value2();

        let transfer = match self.transfers.get_mut(&transfer_handle) {
            Some(transfer) => transfer,
            None => return BridgeResponse::new(Self::RESPONSE_ABORT),
        };

        transfer.host_file.set_buffer(Va(buffer));

        BridgeResponse::new(Self::RESPONSE_CONTINUE)
    }

    /// Handles the [`METHOD_CHUNK`] bridge method.
    ///
    /// [`METHOD_CHUNK`]: Self::METHOD_CHUNK
    fn handle_chunk<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeOutput>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let transfer_handle = packet.value1() as u32;
        let length = packet.value2() as usize;

        let transfer = match self.transfers.get_mut(&transfer_handle) {
            Some(transfer) => transfer,
            None => return BridgeResponse::new(Self::RESPONSE_ABORT),
        };

        let buffer = match transfer.host_file.buffer {
            Some(buffer) => buffer,
            None => return BridgeResponse::new(Self::RESPONSE_ABORT),
        };

        if length > CHUNK_SIZE as usize {
            return BridgeResponse::new(Self::RESPONSE_ABORT);
        }

        let bytes = &mut transfer.chunk_buffer[..length];
        if let Err(err) = vmi.read(buffer, bytes) {
            tracing::error!(%err, "cannot read chunk");
            return BridgeResponse::new(Self::RESPONSE_ABORT);
        }

        if let Err(err) = transfer.host_file.append(bytes) {
            tracing::error!(%err, "cannot write chunk");
            return BridgeResponse::new(Self::RESPONSE_ABORT);
        }

        BridgeResponse::new(Self::RESPONSE_CONTINUE)
    }

    /// Handles the [`METHOD_CLOSE`] bridge method.
    ///
    /// [`METHOD_CLOSE`]: Self::METHOD_CLOSE
    fn handle_close<Driver>(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeOutput>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let transfer_handle = packet.value1() as u32;
        let transfer_status = packet.value2();

        const TRANSFER_SUCCESS: u64 = 0;

        let mut transfer = match self.transfers.remove(&transfer_handle) {
            Some(transfer) => transfer,
            None => return BridgeResponse::new(Self::RESPONSE_ABORT),
        };

        if transfer_status == TRANSFER_SUCCESS {
            if let Err(err) = transfer.host_file.flush() {
                tracing::error!(%err, path = transfer.path, "cannot flush file");
                return BridgeResponse::new(Self::RESPONSE_ABORT);
            }

            tracing::info!(
                path = ?transfer.host_file.path.display(),
                size = transfer.host_file.received,
                "closed"
            );
        }

        BridgeResponse::new(Self::RESPONSE_CONTINUE)
    }

    /// Handles the [`METHOD_EXIT`] bridge method.
    ///
    /// [`METHOD_EXIT`]: Self::METHOD_EXIT
    fn handle_exit<Driver>(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeOutput>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let encoded_status = packet.value1();

        let status = FileTransferStatus::decode(encoded_status);

        tracing::debug!(
            stage = ?status.stage(),
            kind = ?status.kind(),
            code = status.code(),
            native_code = status.native_code(),
            "shellcode completed"
        );

        BridgeResponse::default()
    }

    /// Handles a bridge packet with an unknown method.
    ///
    /// Logs the packet details and returns no response.
    fn handle_unknown<Driver>(
        &self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeOutput>>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        tracing::warn!(
            request = %Hex(packet.request()),
            method = %Hex(packet.method()),
            value1 = %Hex(packet.value1()),
            value2 = %Hex(packet.value2()),
            value3 = %Hex(packet.value3()),
            value4 = %Hex(packet.value4()),
            "unknown bridge method"
        );

        None
    }
}

impl<Driver> BridgeHandler<WindowsOs<Driver>> for FileTransferBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    type Output = BridgeOutput;

    /// Request code for the `file-transfer` shellcode.
    const REQUEST: u16 = 0x0012;

    #[tracing::instrument(name = "file_transfer", skip_all)]
    fn handle(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeOutput>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>>>::REQUEST
        );

        self.handle_packet(vmi, packet)
    }
}

/// Returns a filesystem-safe name for a transferred file.
fn output_filename(output_id: u64, path: &str) -> String {
    let basename = path
        .rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
        .unwrap_or("file");

    let basename = basename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            }
            else {
                '_'
            }
        })
        .collect::<String>();

    format!("{output_id:04}-{basename}")
}
