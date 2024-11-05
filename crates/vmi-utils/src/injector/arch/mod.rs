#[cfg(feature = "arch-amd64")]
pub mod amd64;

use vmi_core::{Architecture, Va, VmiCore, VmiDriver, VmiError};
use zerocopy::{Immutable, IntoBytes};

use super::{Argument, ArgumentData};

/// Architecture-specific injection functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiDriver<Architecture = Self>,
{
    /// Copies bytes to the stack.
    fn copy_bytes_to_stack(
        vmi: &VmiCore<Driver>,
        registers: &mut Self::Registers,
        data: &[u8],
        alignment: usize,
    ) -> Result<Va, VmiError>;

    /// Copies a value to the stack.
    fn copy_to_stack<T>(
        vmi: &VmiCore<Driver>,
        registers: &mut Self::Registers,
        data: T,
    ) -> Result<Va, VmiError>
    where
        T: IntoBytes + Immutable,
    {
        Self::copy_bytes_to_stack(vmi, registers, data.as_bytes(), align_of::<T>())
    }

    // TODO: Move somewhere else?
    /// Pushes an argument onto the stack (or into a register) according to
    /// the architecture's calling convention.
    fn push_argument(
        vmi: &VmiCore<Driver>,
        registers: &mut Self::Registers,
        argument: &Argument,
    ) -> Result<u64, VmiError> {
        Ok(match &argument.data {
            ArgumentData::Value(data) => *data,
            ArgumentData::Reference(data) => {
                Self::copy_bytes_to_stack(vmi, registers, data, argument.alignment as usize)?.0
            }
        })
    }

    // TODO: Move somewhere else?
    /// Pushes multiple arguments onto the stack (or into registers) according
    /// to the architecture's calling convention.
    fn push_arguments(
        vmi: &VmiCore<Driver>,
        registers: &mut Self::Registers,
        arguments: &[Argument],
    ) -> Result<Vec<u64>, VmiError> {
        let mut values = Vec::with_capacity(arguments.len());

        for argument in arguments {
            let value = Self::push_argument(vmi, registers, argument)?;
            values.push(value);
        }

        Ok(values)
    }
}
