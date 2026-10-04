use std::collections::HashMap;

use serde::Deserialize;

use crate::Error;

/// Raw entry of one vCPU in the register file.
#[derive(Deserialize)]
struct RawVcpu {
    /// Register values keyed by name.
    regs: HashMap<String, String>,
}

/// Register values of one vCPU, read from the register file.
#[derive(Debug, Clone)]
pub struct JsonRegisters {
    /// Index of the vCPU in note order.
    vcpu: u16,

    /// Raw register values keyed by name.
    values: HashMap<String, String>,
}

impl JsonRegisters {
    /// Returns the value of `register`.
    ///
    /// Register names are case-sensitive and match the keys of the register
    /// file, such as `pc`, `x30` or `TTBR1_EL1`. Only the requested value has
    /// to be a `0x`-prefixed hexadecimal string that fits into 64 bits.
    pub fn get(&self, register: &str) -> Result<u64, Error> {
        let value = match self.values.get(register) {
            Some(value) => value,
            None => {
                return Err(Error::MissingRegister {
                    vcpu: self.vcpu,
                    register: register.into(),
                });
            }
        };

        match parse_hex(value) {
            Some(parsed) => Ok(parsed),
            None => Err(Error::InvalidRegisterValue {
                vcpu: self.vcpu,
                register: register.into(),
                value: value.clone(),
            }),
        }
    }

    /// Returns the index of the vCPU in note order.
    pub fn vcpu(&self) -> u16 {
        self.vcpu
    }
}

/// Parses the register file and returns the entries of `vcpus` vCPUs.
///
/// The entry of vCPU `n` is read from the key `cpu<n>`. Keys of vCPUs beyond
/// `vcpus` are ignored.
pub(crate) fn parse(content: &[u8], vcpus: u16) -> Result<Vec<JsonRegisters>, Error> {
    let mut raw = serde_json::from_slice::<HashMap<String, RawVcpu>>(content)?;

    let mut result = Vec::with_capacity(vcpus as usize);
    for vcpu in 0..vcpus {
        match raw.remove(&format!("cpu{vcpu}")) {
            Some(entry) => result.push(JsonRegisters {
                vcpu,
                values: entry.regs,
            }),
            None => return Err(Error::MissingVcpu { vcpu }),
        }
    }

    Ok(result)
}

/// Parses a `0x`-prefixed hexadecimal string.
fn parse_hex(value: &str) -> Option<u64> {
    let digits = match value.strip_prefix("0x") {
        Some(digits) => digits,
        None => value.strip_prefix("0X")?,
    };

    u64::from_str_radix(digits, 16).ok()
}
