use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::PathBuf,
};

use vmi::{
    Va, VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::{ThreadObject, VmiOsThread as _, windows::WindowsOs},
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        injector::InjectorStatusCode,
    },
};

use crate::bridge::{
    METHOD_EXIT, RESPONSE_ABORT, RESPONSE_CONTINUE, TerminalResult, TerminalStatus,
    impl_bridge_contract, impl_bridge_stage,
};

/// Number of bytes shared with the guest for each transfer chunk.
const CHUNK_SIZE: u64 = 64 * 1024;

/// Nonzero transfer identifier encoded in the low 12 response bits.
const TRANSFER_HANDLE: u64 = 1;

/// File-transfer operation stage encoded in a packed result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileTransferStage(u8);

impl_bridge_stage!(FileTransferStage);

impl FileTransferStage {
    pub const NONE: Self = Self(0x00);
    pub const FILE_NAME: Self = Self(0x01);
    pub const FILE_SIZE: Self = Self(0x02);
    pub const MAPPING: Self = Self(0x03);
    pub const BUFFER: Self = Self(0x04);
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

/// An incomplete host file removed unless it is committed successfully.
struct HostFile {
    file: Option<File>,
    temporary_path: PathBuf,
    final_path: PathBuf,
    expected_size: u64,
    received: u64,
    buffer: Option<Va>,
    committed: bool,
}

impl HostFile {
    fn create(final_path: PathBuf, expected_size: u64) -> io::Result<Self> {
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temporary_path = final_path.with_extension(match final_path.extension() {
            Some(extension) => format!("{}.part", extension.to_string_lossy()),
            None => String::from("part"),
        });
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary_path)?;

        Ok(Self {
            file: Some(file),
            temporary_path,
            final_path,
            expected_size,
            received: 0,
            buffer: None,
            committed: false,
        })
    }

    fn set_buffer(&mut self, buffer: Va) -> bool {
        if buffer.is_null() {
            return false;
        }
        self.buffer = Some(buffer);
        true
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let length = bytes.len() as u64;
        if length > CHUNK_SIZE || self.received.saturating_add(length) > self.expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file-transfer chunk exceeds declared size",
            ));
        }

        self.file
            .as_mut()
            .expect("uncommitted transfer has an open file")
            .write_all(bytes)?;
        self.received += length;
        Ok(())
    }

    fn commit(&mut self) -> io::Result<()> {
        if self.received != self.expected_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file-transfer byte count does not match declared size",
            ));
        }

        let mut file = self
            .file
            .take()
            .expect("uncommitted transfer has an open file");
        file.flush()?;
        drop(file);
        fs::rename(&self.temporary_path, &self.final_path)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for HostFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.file.take();
            let _ = fs::remove_file(&self.temporary_path);
        }
    }
}

/// State for one guest file-transfer shellcode invocation.
struct FileTransferSession {
    expected_file_handle: u64,
    tracked_path: String,
    output_path: PathBuf,
    host_file: Option<HostFile>,
    chunk_buffer: Vec<u8>,
    host_failed: bool,
    status: Option<FileTransferStatus>,
}

impl FileTransferSession {
    const METHOD_BEGIN: u16 = 0x0001;
    const METHOD_SET_BUFFER: u16 = 0x0002;
    const METHOD_CHUNK: u16 = 0x0003;
    const METHOD_CLOSE: u16 = 0x0004;
    const METHOD_EXIT: u16 = METHOD_EXIT;

    fn new(expected_file_handle: u64, tracked_path: String, output_path: PathBuf) -> Self {
        Self {
            expected_file_handle,
            tracked_path,
            output_path,
            host_file: None,
            chunk_buffer: vec![0; CHUNK_SIZE as usize],
            host_failed: false,
            status: None,
        }
    }

    fn packed_begin_response() -> u64 {
        (CHUNK_SIZE << 12) | TRANSFER_HANDLE
    }

    fn read_filename<Driver>(
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        address: u64,
        length: u64,
    ) -> Result<String, String>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let length = usize::try_from(length).map_err(|_| "filename length does not fit usize")?;
        if !length.is_multiple_of(2) || length > u16::MAX as usize {
            return Err(String::from("invalid UTF-16 filename length"));
        }

        let mut bytes = vec![0; length];
        vmi.read(Va(address), &mut bytes)
            .map_err(|err| format!("cannot read filename: {err}"))?;
        let units = bytes
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect::<Vec<_>>();
        Ok(String::from_utf16_lossy(&units))
    }

    fn begin<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<InjectorStatusCode>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        if packet.value1() != self.expected_file_handle || self.host_file.is_some() {
            tracing::error!(
                expected = %Hex(self.expected_file_handle),
                actual = %Hex(packet.value1()),
                "rejected file-transfer begin"
            );
            return BridgeResponse::new(0);
        }

        let guest_path = match Self::read_filename(vmi, packet.value3(), packet.value4()) {
            Ok(path) => path,
            Err(err) => {
                tracing::error!(%err, "rejected file-transfer filename");
                return BridgeResponse::new(0);
            }
        };

        let expected_size = match i64::try_from(packet.value2()) {
            Ok(size) if size >= 0 => size as u64,
            _ => {
                tracing::error!(size = packet.value2(), "rejected file-transfer size");
                return BridgeResponse::new(0);
            }
        };

        match HostFile::create(self.output_path.clone(), expected_size) {
            Ok(host_file) => self.host_file = Some(host_file),
            Err(err) => {
                tracing::error!(%err, path = %self.output_path.display(), "cannot create host transfer file");
                return BridgeResponse::new(0);
            }
        }

        tracing::info!(
            tracked_path = %self.tracked_path,
            guest_path,
            size = expected_size,
            output = %self.output_path.display(),
            "file transfer started"
        );
        BridgeResponse::new(Self::packed_begin_response())
    }

    fn set_buffer(&mut self, packet: BridgePacket) -> BridgeResponse<InjectorStatusCode> {
        let accepted = packet.value1() == TRANSFER_HANDLE
            && self
                .host_file
                .as_mut()
                .is_some_and(|host_file| host_file.set_buffer(Va(packet.value2())));

        BridgeResponse::new(if accepted {
            RESPONSE_CONTINUE
        }
        else {
            RESPONSE_ABORT
        })
    }

    fn chunk<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> BridgeResponse<InjectorStatusCode>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        let Some(host_file) = self.host_file.as_mut()
        else {
            return BridgeResponse::new(RESPONSE_ABORT);
        };
        let Some(buffer) = host_file.buffer
        else {
            return BridgeResponse::new(RESPONSE_ABORT);
        };
        let Ok(length) = usize::try_from(packet.value2())
        else {
            return BridgeResponse::new(RESPONSE_ABORT);
        };
        if packet.value1() != TRANSFER_HANDLE || length as u64 > CHUNK_SIZE {
            return BridgeResponse::new(RESPONSE_ABORT);
        }

        let bytes = &mut self.chunk_buffer[..length];
        if let Err(err) = vmi.read(buffer, bytes) {
            self.host_failed = true;
            tracing::error!(%err, "cannot read file-transfer chunk");
            return BridgeResponse::new(RESPONSE_ABORT);
        }
        if let Err(err) = host_file.append(bytes) {
            self.host_failed = true;
            tracing::error!(%err, "cannot write file-transfer chunk");
            return BridgeResponse::new(RESPONSE_ABORT);
        }

        BridgeResponse::new(RESPONSE_CONTINUE)
    }

    fn close(&mut self, packet: BridgePacket) -> BridgeResponse<InjectorStatusCode> {
        const TRANSFER_SUCCESS: u64 = 0;

        if packet.value1() != TRANSFER_HANDLE {
            self.host_failed = true;
            return BridgeResponse::new(RESPONSE_ABORT);
        }

        let Some(mut host_file) = self.host_file.take()
        else {
            self.host_failed = true;
            return BridgeResponse::new(RESPONSE_ABORT);
        };

        if packet.value2() == TRANSFER_SUCCESS {
            if let Err(err) = host_file.commit() {
                self.host_failed = true;
                tracing::error!(%err, "cannot commit host transfer file");
                return BridgeResponse::new(RESPONSE_ABORT);
            }

            tracing::info!(
                path = %host_file.final_path.display(),
                size = host_file.received,
                "file transfer completed"
            );
        }

        BridgeResponse::new(RESPONSE_CONTINUE)
    }

    fn exit(&mut self, packet: BridgePacket) -> BridgeResponse<InjectorStatusCode> {
        let guest_status = FileTransferStatus::decode(packet.value1());
        let status = if self.host_failed {
            FileTransferStatus::new(FileTransferStage::TRANSFER, TerminalStatus::ABORTED)
        }
        else {
            guest_status
        };
        self.status = Some(status);
        tracing::debug!(
            stage = ?status.stage(),
            status = ?status.status(),
            code = status.code(),
            native_code = packet.value2(),
            ?guest_status,
            host_failed = self.host_failed,
            "file-transfer shellcode completed"
        );
        BridgeResponse::default().with_result(status.encode())
    }

    fn handle_unknown(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        tracing::error!(
            method = %Hex(packet.method()),
            value1 = %Hex(packet.value1()),
            value2 = %Hex(packet.value2()),
            value3 = %Hex(packet.value3()),
            value4 = %Hex(packet.value4()),
            "unknown file-transfer bridge method"
        );
        None
    }

    fn handle<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>>
    where
        Driver: VmiRead<Architecture = Amd64>,
    {
        match packet.method() {
            Self::METHOD_BEGIN => Some(self.begin(vmi, packet)),
            Self::METHOD_SET_BUFFER => Some(self.set_buffer(packet)),
            Self::METHOD_CHUNK => Some(self.chunk(vmi, packet)),
            Self::METHOD_CLOSE => Some(self.close(packet)),
            Self::METHOD_EXIT => Some(self.exit(packet)),
            _ => self.handle_unknown(packet),
        }
    }
}

/// Active file-transfer invocations keyed by their executing thread.
#[derive(Default)]
pub struct FileTransferBridgeState {
    transfers: HashMap<ThreadObject, FileTransferSession>,
}

impl FileTransferBridgeState {
    /// Registers a file-transfer invocation on its executing thread.
    pub fn start(
        &mut self,
        thread_object: ThreadObject,
        expected_file_handle: u64,
        tracked_path: String,
        output_path: PathBuf,
    ) {
        let entry = self.transfers.entry(thread_object);
        let std::collections::hash_map::Entry::Vacant(entry) = entry
        else {
            panic!("file transfer already active on {thread_object}");
        };
        entry.insert(FileTransferSession::new(
            expected_file_handle,
            tracked_path,
            output_path,
        ));
    }

    /// Removes a completed invocation and returns its terminal status.
    pub fn finish(&mut self, thread_object: ThreadObject) -> Option<FileTransferStatus> {
        self.transfers
            .remove(&thread_object)
            .unwrap_or_else(|| panic!("no file transfer active on {thread_object}"))
            .status
    }
}

/// Routes file-transfer packets through the active invocation state.
pub struct FileTransferBridge<'a> {
    state: &'a mut FileTransferBridgeState,
}

impl_bridge_contract!(FileTransferBridge<'_>);

impl<'a> FileTransferBridge<'a> {
    /// File-transfer bridge request identifier.
    pub const REQUEST: u16 = 0x0003;

    /// Creates a handler over the active file-transfer state.
    pub fn new(state: &'a mut FileTransferBridgeState) -> Self {
        Self { state }
    }
}

impl<Driver> BridgeHandler<WindowsOs<Driver>, InjectorStatusCode> for FileTransferBridge<'_>
where
    Driver: VmiRead<Architecture = Amd64>,
{
    const REQUEST: u16 = Self::REQUEST;

    fn handle(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        let thread_object = match vmi.os().current_thread().and_then(|thread| thread.object()) {
            Ok(thread_object) => thread_object,
            Err(err) => {
                tracing::error!(%err, "cannot resolve file-transfer thread");
                return None;
            }
        };
        let Some(transfer) = self.state.transfers.get_mut(&thread_object)
        else {
            tracing::error!(%thread_object, "file-transfer packet without active invocation");
            return None;
        };
        transfer.handle(vmi, packet)
    }
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
    fn begin_response_packs_chunk_size_and_nonzero_handle() {
        let response = FileTransferSession::packed_begin_response();

        assert_eq!(response & 0xfff, TRANSFER_HANDLE);
        assert_eq!(response >> 12, CHUNK_SIZE);
    }

    #[test]
    fn bridge_state_isolates_concurrent_thread_invocations() {
        let first_thread = ThreadObject(Va(0x1000));
        let second_thread = ThreadObject(Va(0x2000));
        let first_status =
            FileTransferStatus::new(FileTransferStage::TRANSFER, TerminalStatus::SUCCESS);
        let mut state = FileTransferBridgeState::default();

        state.start(
            first_thread,
            0x10,
            String::from(r"\first"),
            PathBuf::from("first"),
        );
        state.start(
            second_thread,
            0x20,
            String::from(r"\second"),
            PathBuf::from("second"),
        );
        state
            .transfers
            .get_mut(&first_thread)
            .expect("first transfer is registered")
            .status = Some(first_status);

        assert_eq!(state.finish(first_thread), Some(first_status));
        assert!(state.transfers.contains_key(&second_thread));
        assert_eq!(state.finish(second_thread), None);
    }

    #[test]
    fn host_file_commits_exact_declared_bytes() {
        let output = temporary_output("complete");
        let mut host_file = HostFile::create(output.clone(), 3).unwrap();

        host_file.append(b"abc").unwrap();
        host_file.commit().unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"abc");
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn host_file_rejects_incomplete_transfer_and_removes_partial_file() {
        let output = temporary_output("incomplete");
        let temporary = output.with_extension("part");
        {
            let mut host_file = HostFile::create(output.clone(), 4).unwrap();
            host_file.append(b"abc").unwrap();
            assert_eq!(
                host_file.commit().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }

        assert!(!output.exists());
        assert!(!temporary.exists());
    }
}
