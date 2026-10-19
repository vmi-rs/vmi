use serde::Deserialize;

use crate::Error;

/// Marks the VM description after the end of the sections
/// (`migration/savevm.h`).
const QEMU_VM_VMDESCRIPTION: u8 = 0x06;

/// The JSON VM description at the end of a migration stream.
///
/// QEMU builds the description while it writes the device sections
/// (`vmstate_save_vmsd_v` in `migration/vmstate.c`). It names each field of
/// each device section and gives the number of bytes that the field took in
/// the stream. With it, a reader can walk device sections that it knows
/// nothing about.
#[derive(Debug, Deserialize)]
pub(crate) struct VmDescription {
    /// Target page size, which is the unit of the RAM section.
    pub page_size: u64,

    /// Description of the configuration section, which QEMU adds since
    /// version 8.2.
    #[serde(default)]
    pub configuration: Option<VmsdDescription>,

    /// Device sections in stream order.
    pub devices: Vec<DeviceDescription>,
}

/// The description of one device section.
#[derive(Debug, Deserialize)]
pub(crate) struct DeviceDescription {
    /// Name of the section, such as `cpu` or `0000:00:02.0/virtio-blk`.
    pub name: String,

    /// Instance id of the section.
    pub instance_id: u32,

    /// Fields and subsections of the section.
    #[serde(flatten)]
    pub state: VmsdDescription,
}

/// The description of a `VMStateDescription` as QEMU saved it.
///
/// A device section, a subsection and the element of a struct field each
/// have one. A device without a `VMStateDescription` saves a single
/// `buffer` field (`vmstate_save_old_style` in `migration/savevm.c`).
#[derive(Debug, Deserialize)]
pub(crate) struct VmsdDescription {
    /// Name of the `VMStateDescription`, such as `cpu/pstate64`.
    #[serde(default)]
    pub vmsd_name: String,

    /// Fields in stream order.
    #[serde(default)]
    pub fields: Vec<FieldDescription>,

    /// Subsections in stream order. The list holds only the subsections that
    /// QEMU wrote.
    #[serde(default)]
    pub subsections: Vec<VmsdDescription>,
}

/// The description of one field of a device section.
#[derive(Debug, Deserialize)]
pub(crate) struct FieldDescription {
    /// Name of the field, such as `env.regs`.
    pub name: String,

    /// Name of the `VMStateInfo` of the field, such as `uint64`, or `struct`.
    #[serde(rename = "type")]
    pub kind: String,

    /// Number of bytes that QEMU wrote for the first element.
    pub size: u64,

    /// Number of elements of an array that one entry describes.
    ///
    /// QEMU describes all elements of an array with one entry when they have
    /// the same layout (`vmsd_can_compress` in `migration/vmstate.c`).
    /// Otherwise each element has an entry of its own with the same name.
    #[serde(default)]
    pub array_len: Option<u64>,

    /// Description of the element of a struct field.
    #[serde(default, rename = "struct")]
    pub structure: Option<VmsdDescription>,
}

impl FieldDescription {
    /// Returns the number of elements that the entry describes.
    pub fn count(&self) -> u64 {
        self.array_len.unwrap_or(1)
    }
}

/// Locates and parses the VM description at the end of a migration stream.
///
/// Returns the offset of the `QEMU_VM_VMDESCRIPTION` marker and the parsed
/// description.
///
/// The stream ends with `QEMU_VM_EOF`, `QEMU_VM_VMDESCRIPTION`, the length
/// of the JSON text as a big-endian 32-bit integer and the JSON text
/// (`qemu_savevm_state_vm_desc` in `migration/savevm.c`). QEMU's JSON writer
/// escapes all control characters (`qobject/json-writer.c`), so the JSON
/// text holds no NUL byte. The last NUL byte of the stream is therefore
/// either `QEMU_VM_EOF` or a byte of the length. The JSON text starts one to
/// six bytes after it, and the length must reach exactly to the end of the
/// stream.
pub(crate) fn locate(data: &[u8]) -> Result<(usize, VmDescription), Error> {
    let nul = match data.iter().rposition(|byte| *byte == 0) {
        Some(nul) => nul,
        None => return Err(Error::MissingVmDescription),
    };

    for start in nul + 1..=nul + 6 {
        let marker = match start.checked_sub(5) {
            Some(marker) => marker,
            None => continue,
        };

        // The marker and the length precede the JSON text.
        let header = match data.get(marker..).and_then(|rest| rest.first_chunk::<5>()) {
            Some(header) => header,
            None => continue,
        };

        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if header[0] == QEMU_VM_VMDESCRIPTION && start.checked_add(len) == Some(data.len()) {
            let description = serde_json::from_slice::<VmDescription>(&data[start..])?;
            return Ok((marker, description));
        }
    }

    Err(Error::MissingVmDescription)
}
