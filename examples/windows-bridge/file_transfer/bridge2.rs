use std::{
    fs::File,
    io::{Seek as _, Write as _},
};

use vmi::{
    Va, VmiContext,
    arch::amd64::Amd64,
    driver::VmiReadAccess,
    os::windows::WindowsOs,
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        injector::InjectorStatusCode,
    },
};

use crate::bridge::{
    METHOD_EXIT, RESPONSE_CONTINUE, TerminalResult, TerminalStatus, impl_bridge_contract,
    impl_bridge_stage,
};

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

/// Decoded status returned by the injector handler.
pub type FileTransferStatus = TerminalResult<FileTransferStage>;

/// Maximum size reserved for one host-side output transfer.
const MAX_OUTPUT_SIZE: usize = 1 << 20;

/// State attached to one guest transfer handle.
struct TransferState {
    /// Nonpaged guest buffer registered with the host.
    buffer: Va,

    /// Current file offset consumed by chunk notifications.
    offset: u64,
}

/// Handles file transfer negotiation and streams chunks into a host file.
pub struct FileTransferBridge {
    /// Destination file receiving the guest file content.
    output: File,

    /// Number of bytes accepted by the shellcode and accumulated by the host.
    bytes_transferred: u64,

    /// Buffer size selected at transfer start.
    chunk_size: u64,

    /// Active guest transfer handle.
    transfer_handle: u32,

    /// Active guest buffer state.
    transfer: Option<TransferState>,

    /// Terminal shellcode status.
    completion: Option<InjectorStatusCode>,
}

impl_bridge_contract!(FileTransferBridge);

impl FileTransferBridge {
    /// Transfer start method.
    const METHOD_BEGIN: u16 = 0x0001;

    /// Shared-buffer registration method.
    const METHOD_SET_BUFFER: u16 = 0x0002;

    /// Chunk delivery method.
    const METHOD_CHUNK: u16 = 0x0003;

    /// Transfer close method.
    const METHOD_CLOSE: u16 = 0x0004;

    /// Terminal result method.
    const METHOD_EXIT: u16 = METHOD_EXIT;

    /// Guest handle field width in `begin` responses.
    const TRANSFER_HANDLE_BITS: u64 = 12;

    /// Guest transfer handle returned by this host bridge.
    const TRANSFER_HANDLE: u32 = 1;

    /// Creates a bridge writing guest file content to the output file.
    pub fn new(output: File) -> Self {
        Self {
            output,
            bytes_transferred: 0,
            chunk_size: 0,
            transfer_handle: 0,
            transfer: None,
            completion: None,
        }
    }

    /// Returns the number of bytes written to the output file.
    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_transferred
    }

    /// Produces the protocol response for one file-transfer packet.
    fn handle_packet<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>>
    where
        Driver: VmiReadAccess<Architecture = Amd64>,
    {
        match packet.method() {
            Self::METHOD_BEGIN => self.handle_begin(vmi, packet),
            Self::METHOD_SET_BUFFER => self.handle_set_buffer(packet),
            Self::METHOD_CHUNK => self.handle_chunk(vmi, packet),
            Self::METHOD_CLOSE => self.handle_close(packet),
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => self.handle_unknown(packet),
        }
    }

    /// Starts a transfer and packs the host chunk size with a guest handle.
    fn handle_begin<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>>
    where
        Driver: VmiReadAccess<Architecture = Amd64>,
    {
        let file_handle = packet.value1();
        let file_size = packet.value2();
        let file_name_buffer = Va(packet.value3());
        let file_name_length = packet.value4() as usize;

        let mut file_name = vec![0u8; file_name_length];
        if let Err(error) = vmi.read(file_name_buffer, &mut file_name) {
            tracing::error!(
                %file_handle,
                file_size,
                %file_name_buffer,
                file_name_length,
                %error,
                "failed to read file name"
            );

            return Some(BridgeResponse::new(0));
        }

        let output_size = file_size
            .clamp(1, MAX_OUTPUT_SIZE as u64)
            .try_into()
            .expect("output size fits usize");

        self.output
            .set_len(output_size)
            .expect("file transfer output allocation");

        self.chunk_size = (1u64 << 12).min(file_size.max(1));
        self.transfer_handle = Self::TRANSFER_HANDLE;
        self.transfer = None;

        tracing::info!(
            %file_handle,
            file_size,
            %file_name_buffer,
            file_name_length,
            chunk_size = self.chunk_size,
            transfer_handle = self.transfer_handle,
            "file transfer started"
        );

        Some(BridgeResponse::new(
            (self.chunk_size << Self::TRANSFER_HANDLE_BITS)
                | u64::from(self.transfer_handle),
        ))
    }

    /// Registers the shared guest transfer buffer.
    fn handle_set_buffer(
        &mut self,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        let transfer_handle = packet.value1() as u32;
        let buffer = Va(packet.value2());

        if transfer_handle != self.transfer_handle || self.chunk_size == 0 {
            tracing::warn!(transfer_handle, %buffer, "unexpected transfer buffer");
            return Some(BridgeResponse::new(RESPONSE_CONTINUE));
        }

        self.transfer = Some(TransferState { buffer, offset: 0 });

        tracing::debug!(
            transfer_handle,
            %buffer,
            "registered file transfer buffer"
        );

        Some(BridgeResponse::new(RESPONSE_CONTINUE))
    }

    /// Copies one filled guest buffer into the output file.
    fn handle_chunk<Driver>(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>>
    where
        Driver: VmiReadAccess<Architecture = Amd64>,
    {
        let transfer_handle = packet.value1() as u32;
        let length = packet.value2() as usize;

        let Some(transfer) = self.transfer.as_mut()
        else {
            tracing::warn!(transfer_handle, length, "unexpected transfer chunk");
            return Some(BridgeResponse::new(RESPONSE_CONTINUE));
        };

        if transfer_handle != self.transfer_handle || length > self.chunk_size as usize {
            tracing::warn!(
                transfer_handle,
                length,
                chunk_size = self.chunk_size,
                "invalid transfer chunk"
            );

            return Some(BridgeResponse::new(RESPONSE_CONTINUE));
        }

        let mut chunk = vec![0u8; length];
        if let Err(error) = vmi.read(transfer.buffer, &mut chunk) {
            tracing::error!(transfer_handle, length, %error, "failed to read chunk");
            return Some(BridgeResponse::new(RESPONSE_CONTINUE));
        }

        self.output
            .seek(std::io::SeekFrom::Start(transfer.offset))
            .and_then(|_| self.output.write_all(&chunk))
            .expect("file transfer output write");

        transfer.offset += length as u64;
        self.bytes_transferred += length as u64;

        tracing::trace!(transfer_handle, length, "file transfer chunk received");

        Some(BridgeResponse::new(RESPONSE_CONTINUE))
    }

    /// Closes the active guest transfer handle.
    fn handle_close(&mut self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let transfer_handle = packet.value1() as u32;
        let status = packet.value2() as u8;

        tracing::info!(
            transfer_handle,
            status = %Hex(status),
            bytes_transferred = self.bytes_transferred,
            "file transfer closed"
        );

        if transfer_handle == self.transfer_handle {
            self.transfer_handle = 0;
            self.chunk_size = 0;
            self.transfer = None;
        }

        Some(BridgeResponse::default())
    }

    /// Completes the injector from a terminal result packet.
    fn handle_exit(&mut self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let result = FileTransferStatus::decode(packet.value1());
        let native_code = packet.value2();

        tracing::info!(
            stage = ?result.stage(),
            status = ?result.status(),
            code = result.code(),
            native_code,
            "file transfer shellcode completed"
        );

        self.completion = Some(packet.value1());
        Some(BridgeResponse::default().with_result(packet.value1()))
    }

    /// Logs and rejects one packet with an unknown file-transfer method.
    fn handle_unknown(
        &mut self,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        tracing::error!(
            request = %Hex(packet.request()),
            method = %Hex(packet.method()),
            value1 = %Hex(packet.value1()),
            value2 = %Hex(packet.value2()),
            value3 = %Hex(packet.value3()),
            value4 = %Hex(packet.value4()),
            "unknown file transfer bridge method"
        );

        None
    }
}

impl<Driver> BridgeHandler<WindowsOs<Driver>, InjectorStatusCode> for FileTransferBridge
where
    Driver: VmiReadAccess<Architecture = Amd64>,
{
    /// File-transfer bridge request identifier.
    const REQUEST: u16 = 0x0003;

    fn handle(
        &mut self,
        vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>, InjectorStatusCode>>::REQUEST
        );

        self.handle_packet(vmi, packet)
    }
}

/// Validates a terminal file-transfer status.
pub fn validate_file_transfer_result(result: u64) -> Result<FileTransferStatus, TerminalStatus> {
    let status = FileTransferStatus::decode(result);
    if status.status() == TerminalStatus::SUCCESS {
        Ok(status)
    }
    else {
        Err(status.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::BRIDGE_MAGIC;

    /// Creates a packet routed to the file-transfer handler.
    fn packet(method: u16) -> BridgePacket {
        BridgePacket::new(BRIDGE_MAGIC, 0x0003, method)
    }

    #[test]
    fn bridge_request_is_file_transfer() {
        assert_eq!(
            <FileTransferBridge as vmi::utils::bridge::BridgeHandler<
                WindowsOs<vmi::driver::mock::VmiMockDriver<Amd64>>,
                InjectorStatusCode,
            >>::REQUEST,
            0x0003
        );
    }

    #[test]
    fn terminal_result_decodes_file_transfer_status() {
        const STATUS: FileTransferStatus =
            FileTransferStatus::new(FileTransferStage::TRANSFER, TerminalStatus::SUCCESS);
        let decoded = FileTransferStatus::decode(STATUS.encode());

        assert_eq!(decoded.stage(), FileTransferStage::TRANSFER);
        assert_eq!(decoded.status(), TerminalStatus::SUCCESS);
    }

    #[test]
    fn validation_rejects_non_success_status() {
        const STATUS: FileTransferStatus =
            FileTransferStatus::new(FileTransferStage::BUFFER, TerminalStatus::ABORTED);

        assert!(validate_file_transfer_result(STATUS.encode()).is_err());
    }
}
