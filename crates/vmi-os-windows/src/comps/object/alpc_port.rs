use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::ProcessObject};

use super::{FromWindowsObject, WindowsObject, WindowsObjectTypeKind, WindowsProcess};
use crate::{ArchAdapter, WindowsOs, offset};

/// A Windows ALPC port object.
///
/// An ALPC port is the endpoint of an Advanced Local Procedure Call
/// connection. A server creates a named connection port, and each client
/// connects to it through its own, unnamed, communication port.
///
/// # Implementation Details
///
/// Corresponds to `_ALPC_PORT`.
pub struct WindowsAlpcPort<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_ALPC_PORT` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsAlpcPort<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsAlpcPort<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<'a, Driver> FromWindowsObject<'a, Driver> for WindowsAlpcPort<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from_object(object: WindowsObject<'a, Driver>) -> Result<Option<Self>, VmiError> {
        match object.type_kind()? {
            Some(WindowsObjectTypeKind::AlpcPort) => Ok(Some(Self::new(object.vmi, object.va))),
            _ => Ok(None),
        }
    }
}

impl<Driver> VmiVa for WindowsAlpcPort<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsAlpcPort<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows ALPC port object.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the process that owns the port.
    ///
    /// Returns `None` if the owner is not set.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_ALPC_PORT.OwnerProcess`.
    pub fn owner_process(&self) -> Result<Option<WindowsProcess<'a, Driver>>, VmiError> {
        let ALPC_PORT = offset!(self.vmi, _ALPC_PORT);

        let process = self
            .vmi
            .read_va_native(self.va + ALPC_PORT.OwnerProcess.offset())?;

        if process.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsProcess::new(self.vmi, ProcessObject(process))))
    }

    /// Returns the connection port of the port.
    ///
    /// For a communication port, this is the server's connection port, the
    /// port that carries the name, such as `\RPC Control\ntsvcs`. Returns
    /// `None` if the port has no communication information or no connection
    /// port.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_ALPC_PORT.CommunicationInfo->ConnectionPort`.
    pub fn connection_port(&self) -> Result<Option<WindowsAlpcPort<'a, Driver>>, VmiError> {
        let ALPC_PORT = offset!(self.vmi, _ALPC_PORT);
        let ALPC_COMMUNICATION_INFO = offset!(self.vmi, _ALPC_COMMUNICATION_INFO);

        let communication_info = self
            .vmi
            .read_va_native(self.va + ALPC_PORT.CommunicationInfo.offset())?;

        if communication_info.is_null() {
            return Ok(None);
        }

        let connection_port = self
            .vmi
            .read_va_native(communication_info + ALPC_COMMUNICATION_INFO.ConnectionPort.offset())?;

        if connection_port.is_null() {
            return Ok(None);
        }

        Ok(Some(Self::new(self.vmi, connection_port)))
    }
}
