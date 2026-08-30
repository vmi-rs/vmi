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
    os::{ProcessId, VmiOsProcess as _, windows::WindowsOs},
    trace::Hex,
    utils::bridge::{BridgeHandler, BridgePacket, BridgeResponse},
};

use crate::bridge::{
    BridgeStatusCode, METHOD_EXIT, RESPONSE_ABORT, RESPONSE_CONTINUE, TerminalResult,
    impl_bridge_contract, impl_bridge_stage,
};

/// Number of bytes shared with the guest for each transfer chunk.
const CHUNK_SIZE: u64 = 64 * 1024;

/// Guest transfer handles occupy the low 12 bits of a begin response.
const TRANSFER_HANDLE_BITS: u32 = 12;
const TRANSFER_HANDLE_MAX: u32 = (1 << TRANSFER_HANDLE_BITS) - 1;

/// File-transfer operation stage encoded in a packed result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileTransferStage(u8);

impl_bridge_stage!(FileTransferStage);

impl FileTransferStage {
    /// No operation ran.
    pub const NONE: Self = Self(0x00);

    /// File name query failed.
    pub const FILE_NAME: Self = Self(0x01);

    /// File size query failed.
    pub const FILE_SIZE: Self = Self(0x02);

    /// File mapping failed.
    pub const MAPPING: Self = Self(0x03);

    /// Transfer buffer setup failed.
    pub const BUFFER: Self = Self(0x04);

    /// File transfer failed or was interrupted.
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

/// Decoded terminal status returned by the file-transfer shellcode.
pub type FileTransferStatus = TerminalResult<FileTransferStage>;

/// Host output for one active transfer.
struct HostFile {
    file: File,
    path: PathBuf,
    expected_size: u64,
    received: u64,
    buffer: Option<Va>,
}

impl HostFile {
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

    fn set_buffer(&mut self, buffer: Va) {
        self.buffer = Some(buffer);
    }

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

    fn commit(&mut self) -> Result<(), Error> {
        if self.received != self.expected_size {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "file-transfer byte count does not match declared size",
            ));
        }

        self.file.flush()
    }
}

/// Host session for one guest-issued transfer handle.
struct TransferSession {
    path: String,
    host_file: HostFile,
    chunk_buffer: Vec<u8>,
}

impl TransferSession {
    fn new(path: String, host_file: HostFile) -> Self {
        Self {
            path,
            host_file,
            chunk_buffer: vec![0; CHUNK_SIZE as usize],
        }
    }
}

/// Handles file-transfer negotiation and output for the deploy monitor.
pub struct FileTransferBridge {
    output_directory: PathBuf,
    next_transfer_handle: u32,
    next_output_id: u64,
    transfers: HashMap<u32, TransferSession>,
}

impl_bridge_contract!(FileTransferBridge);

impl FileTransferBridge {
    const METHOD_BEGIN: u16 = 0x0001;
    const METHOD_SET_BUFFER: u16 = 0x0002;
    const METHOD_CHUNK: u16 = 0x0003;
    const METHOD_CLOSE: u16 = 0x0004;
    const METHOD_EXIT: u16 = METHOD_EXIT;

    /// Creates a persistent handler writing files beneath `output_directory`.
    pub fn new(output_directory: PathBuf) -> Self {
        Self {
            output_directory,
            next_transfer_handle: 1,
            next_output_id: 0,
            transfers: HashMap::new(),
        }
    }

    fn allocate_transfer_handle(&mut self) -> Option<u32> {
        if self.next_transfer_handle > TRANSFER_HANDLE_MAX {
            return None;
        }

        let handle = self.next_transfer_handle;
        self.next_transfer_handle += 1;
        Some(handle)
    }

    /// Produces the protocol response for one file-transfer packet.
    fn handle_packet<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeStatusCode>>
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

    /// Starts one transfer and returns its newly allocated guest handle.
    fn handle_begin<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeStatusCode>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let file_handle = packet.value1();
        let file_size = packet.value2();
        let file_name_buffer = packet.value3();
        let file_name_length = packet.value4() as usize;

        // REVIEW: if let Some && if let Some?
        let process_id = match vmi.os().current_process().and_then(|process| process.id()) {
            Ok(process_id) => process_id,
            Err(err) => {
                tracing::error!(%err, "cannot resolve file-transfer process");
                return BridgeResponse::new(0);
            }
        };

        let path = match vmi.read_string_utf16_limited(Va(file_name_buffer), file_name_length) {
            Ok(path) => path,
            Err(err) => {
                tracing::error!(%err, "cannot read file-transfer filename");
                return BridgeResponse::new(0);
            }
        };

        let expected_size = match i64::try_from(file_size) {
            Ok(expected_size) => expected_size,
            Err(_) => {
                tracing::error!(size = file_size, "rejected file-transfer size");
                return BridgeResponse::new(0);
            }
        };

        let transfer_handle = match self.allocate_transfer_handle() {
            Some(transfer_handle) => transfer_handle,
            None => {
                tracing::error!("file-transfer handles exhausted");
                return BridgeResponse::new(0);
            }
        };

        let output_id = self.next_output_id;
        self.next_output_id += 1;

        // REVIEW: avoid clone()
        let output_path =
            self.output_directory
                .join(output_filename(process_id, file_handle, output_id, &path));
        let host_file = match HostFile::create(output_path.clone(), expected_size as u64) {
            Ok(host_file) => host_file,
            Err(err) => {
                tracing::error!(%err, path = %output_path.display(), "cannot create host transfer file");
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
            %path,
            size = expected_size,
            output = %output_path.display(),
            "file transfer started"
        );

        BridgeResponse::new((CHUNK_SIZE << TRANSFER_HANDLE_BITS) | u64::from(transfer_handle))
    }

    /// Registers the shared guest buffer for a transfer handle.
    fn handle_set_buffer<Driver>(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeStatusCode>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let transfer_handle = packet.value1() as u32;
        let buffer = packet.value2();

        let transfer = match self.transfers.get_mut(&transfer_handle) {
            Some(transfer) => transfer,
            None => return BridgeResponse::new(RESPONSE_ABORT),
        };

        transfer.host_file.set_buffer(Va(buffer));

        BridgeResponse::new(RESPONSE_CONTINUE)
    }

    /// Copies one filled guest buffer into its host output file.
    fn handle_chunk<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeStatusCode>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let transfer_handle = packet.value1() as u32;
        let length = packet.value2() as usize;

        let transfer = match self.transfers.get_mut(&transfer_handle) {
            Some(transfer) => transfer,
            None => return BridgeResponse::new(RESPONSE_ABORT),
        };

        let buffer = match transfer.host_file.buffer {
            Some(buffer) => buffer,
            None => return BridgeResponse::new(RESPONSE_ABORT),
        };

        if length > CHUNK_SIZE as usize {
            return BridgeResponse::new(RESPONSE_ABORT);
        }

        let bytes = &mut transfer.chunk_buffer[..length];
        if let Err(err) = vmi.read(buffer, bytes) {
            tracing::error!(%err, "cannot read file-transfer chunk");
            return BridgeResponse::new(RESPONSE_ABORT);
        }

        if let Err(err) = transfer.host_file.append(bytes) {
            tracing::error!(%err, "cannot write file-transfer chunk");
            return BridgeResponse::new(RESPONSE_ABORT);
        }

        BridgeResponse::new(RESPONSE_CONTINUE)
    }

    /// Closes a transfer handle and commits a successful host output.
    fn handle_close<Driver>(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeStatusCode>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let transfer_handle = packet.value1() as u32;
        let transfer_status = packet.value2();

        const TRANSFER_SUCCESS: u64 = 0;

        let mut transfer = match self.transfers.remove(&transfer_handle) {
            Some(transfer) => transfer,
            None => return BridgeResponse::new(RESPONSE_ABORT),
        };

        if transfer_status == TRANSFER_SUCCESS {
            if let Err(err) = transfer.host_file.commit() {
                tracing::error!(%err, path = %transfer.path, "cannot commit host transfer file");
                return BridgeResponse::new(RESPONSE_ABORT);
            }

            tracing::info!(
                path = %transfer.host_file.path.display(),
                size = transfer.host_file.received,
                "file transfer completed"
            );
        }

        BridgeResponse::new(RESPONSE_CONTINUE)
    }

    /// Completes one shellcode invocation.
    fn handle_exit<Driver>(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<BridgeStatusCode>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let packed_status = packet.value1();
        let native_code = packet.value2();

        let status = FileTransferStatus::decode(packed_status);
        tracing::debug!(
            stage = ?status.stage(),
            status = ?status.status(),
            code = status.code(),
            native_code,
            "file-transfer shellcode completed"
        );

        BridgeResponse::default()
    }

    /// Logs and rejects one unknown file-transfer method.
    fn handle_unknown<Driver>(
        &self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeStatusCode>>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        tracing::error!(
            request = %Hex(packet.request()),
            method = %Hex(packet.method()),
            value1 = %Hex(packet.value1()),
            value2 = %Hex(packet.value2()),
            value3 = %Hex(packet.value3()),
            value4 = %Hex(packet.value4()),
            "unknown file-transfer bridge method"
        );

        None
    }
}

impl<Driver> BridgeHandler<WindowsOs<Driver>, BridgeStatusCode> for FileTransferBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    const REQUEST: u16 = 0x0003;

    fn handle(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeStatusCode>> {
        self.handle_packet(vmi, packet)
    }
}

fn output_filename(process_id: ProcessId, handle: u64, output_id: u64, path: &str) -> String {
    let basename = path
        .rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
        .unwrap_or("file");

    let basename = basename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            }
            else {
                '_'
            }
        })
        .collect::<String>();

    let basename = if basename.is_empty() {
        "file"
    }
    else {
        &basename
    };

    format!("{process_id}-{handle:016x}-{output_id:016x}-{basename}")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn temporary_output(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);

        std::env::temp_dir().join(format!(
            "windows-bridge-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn transfer_handles_increment_until_exhausted() {
        let mut bridge = FileTransferBridge::new(PathBuf::new());

        assert_eq!(bridge.allocate_transfer_handle(), Some(1));

        bridge.next_transfer_handle = TRANSFER_HANDLE_MAX;
        assert_eq!(bridge.allocate_transfer_handle(), Some(TRANSFER_HANDLE_MAX));
        assert_eq!(bridge.allocate_transfer_handle(), None);
    }

    #[test]
    fn output_names_are_flat_sanitized_and_unique() {
        let first = output_filename(ProcessId(7), 0x10, 1, r"\dir\a:b.txt");
        let second = output_filename(ProcessId(7), 0x10, 2, r"\dir\a:b.txt");

        assert_eq!(first, "7-0000000000000010-0000000000000001-a_b.txt");
        assert_ne!(first, second);
    }

    #[test]
    fn host_file_commits_exact_declared_bytes() {
        let output = temporary_output("complete");
        let mut host_file = HostFile::create(output.clone(), 3).unwrap();

        host_file.append(b"abc").unwrap();
        host_file.commit().unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"abc");
        std::fs::remove_file(output).unwrap();
    }

    #[test]
    fn host_file_rejects_incomplete_transfer() {
        let output = temporary_output("incomplete");
        let mut host_file = HostFile::create(output.clone(), 4).unwrap();

        host_file.append(b"abc").unwrap();
        assert_eq!(
            host_file.commit().unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
        drop(host_file);

        assert_eq!(std::fs::read(&output).unwrap(), b"abc");
        std::fs::remove_file(output).unwrap();
    }
}
