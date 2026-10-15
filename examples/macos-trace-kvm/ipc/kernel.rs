//! Kernel IPC entry points, argument positions and structure layouts read from
//! the KDK DWARF of the running kernel.
//!
//! Message flag and descriptor type values are preprocessor constants, absent
//! from DWARF, and are taken from xnu `osfmk/mach/message.h`.

use isr_core::{Profile, Type};

use super::IpcHook;

/// `MACH_MSGH_BITS_COMPLEX`, xnu `osfmk/mach/message.h:152`.
pub(super) const COMPLEX: u32 = 0x8000_0000;

/// `MACH_MSGH_BITS_REMOTE_MASK`, xnu `osfmk/mach/message.h:143`.
pub(super) const REMOTE_MASK: u32 = 0x1f;

/// Shift of `MACH_MSGH_BITS_LOCAL_MASK` (`0x1f00`), xnu
/// `osfmk/mach/message.h:144`.
pub(super) const LOCAL_SHIFT: u32 = 8;

/// `MACH_MSG_PORT_DESCRIPTOR`, xnu `osfmk/mach/message.h:382`.
pub(super) const PORT_DESCRIPTOR: u64 = 0;

/// `MACH_MSG_OOL_PORTS_DESCRIPTOR`, xnu `osfmk/mach/message.h:384`.
pub(super) const OOL_PORTS_DESCRIPTOR: u64 = 2;

/// `MACH_MSG_GUARDED_PORT_DESCRIPTOR`, xnu `osfmk/mach/message.h:386`.
pub(super) const GUARDED_PORT_DESCRIPTOR: u64 = 4;

/// `MSGR_PSEUDO_RECEIVE`, xnu `osfmk/mach/message.h:1682`.
///
/// `mach_msg_receive_pseudo` (xnu `osfmk/ipc/mach_msg.c:610-636`) hands a
/// message whose send failed back to its sender through
/// `ipc_kmsg_put_to_user` with this receive name.
pub(super) const PSEUDO_RECEIVE: u32 = 0xffff_fffe;

/// A field located by byte offset, starting bit and width in bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bits {
    /// Byte offset of the first byte holding the field.
    pub offset: u64,

    /// Bit position of the field within the bytes read from `offset`.
    pub position: u32,

    /// Width of the field in bits.
    pub length: u32,
}

impl Bits {
    /// Number of bytes read from `offset` to cover the field.
    pub fn bytes(&self) -> usize {
        (self.position + self.length).div_ceil(8) as usize
    }

    /// Extracts the field from the little-endian bytes read at `offset`.
    pub fn extract(&self, raw: &[u8]) -> u64 {
        let mut word = [0_u8; 8];
        let count = self.bytes().min(raw.len()).min(8);
        word[..count].copy_from_slice(&raw[..count]);
        let value = u64::from_le_bytes(word) >> self.position;
        if self.length >= 64 {
            value
        }
        else {
            value & ((1_u64 << self.length) - 1)
        }
    }
}

/// Offsets of the kernel IPC structures the tracker reads.
#[derive(Clone, Copy, Debug)]
pub struct KernelTypes {
    /// `ipc_kmsg.ikm_type`.
    pub kmsg_type: Bits,
    /// `ipc_kmsg.ikm_keep_alive`.
    pub keep_alive: Bits,
    /// `IKM_KEEP_ALIVE_OWNED`.
    pub keep_alive_owned: u64,
    /// `IKM_TYPE_ALL_INLINED`.
    pub all_inlined: u64,
    /// `IKM_TYPE_UDATA_OOL`.
    pub udata_ool: u64,
    /// `ipc_kmsg.ikm_big_data`, the header of an `IKM_TYPE_ALL_INLINED`
    /// message.
    pub big_data: u64,
    /// `ipc_kmsg.ikm_small_data`, the header of an `IKM_TYPE_UDATA_OOL`
    /// message.
    pub small_data: u64,
    /// `ipc_kmsg.ikm_kdata`, the header pointer of the other message types.
    pub kdata: u64,
    /// `mach_msg_header_t.msgh_bits`.
    pub header_bits: u64,
    /// `mach_msg_header_t.msgh_remote_port`.
    pub header_remote: u64,
    /// `mach_msg_header_t.msgh_local_port`.
    pub header_local: u64,
    /// `mach_msg_header_t.msgh_id`.
    pub header_id: u64,
    /// `mach_msg_kbase_t.msgb_dsc_count`.
    pub descriptor_count: u64,
    /// `mach_msg_kbase_t.msgb_dsc_array`.
    pub descriptors: u64,
    /// Size of `mach_msg_kdescriptor_t`.
    pub descriptor_size: u64,
    /// `mach_msg_port_descriptor_t.name`.
    pub port_name: u64,
    /// `mach_msg_port_descriptor_t.disposition`.
    pub port_disposition: Bits,
    /// `mach_msg_port_descriptor_t.type`, shared by every descriptor kind.
    pub descriptor_type: Bits,
    /// `mach_msg_ool_ports_descriptor_t.address`.
    pub array_address: u64,
    /// `mach_msg_ool_ports_descriptor_t.count`.
    pub array_count: u64,
    /// `mach_msg_ool_ports_descriptor_t.disposition`.
    pub array_disposition: Bits,
    /// `mach_msg_send_uctx_t.send_header.msgh_remote_port`.
    pub send_remote: u64,
    /// `mach_msg_send_uctx_t.send_header.msgh_local_port`.
    pub send_local: u64,
    /// `mach_msg_send_uctx_t.send_msg_addr`.
    pub send_message: u64,
    /// `mach_msg_recv_bufs_t.recv_msg_addr`.
    pub receive_address: u64,
    /// `mach_msg_recv_bufs_t.recv_msg_size`.
    pub receive_size: u64,
    /// `mach_msg_recv_result_t.msgr_msg_size`.
    pub result_message: u64,
    /// `mach_msg_recv_result_t.msgr_trailer_size`.
    pub result_trailer: u64,
    /// `mach_msg_recv_result_t.msgr_aux_size`.
    pub result_auxiliary: u64,
    /// `mach_msg_recv_result_t.msgr_recv_name`.
    pub result_name: u64,
    /// `MACH64_RCV_LINEAR_VECTOR`.
    pub linear_vector: u64,
    /// `MACH64_RCV_STACK`.
    pub stack: u64,
}

/// A kernel function whose entry is observed for every process.
#[derive(Clone, Copy, Debug)]
pub struct KernelHook {
    /// Observation kind.
    pub kind: IpcHook,
    /// Relocated entry address.
    pub address: u64,
    /// Argument registers of the parameters named for this kind.
    pub arguments: [usize; 4],
}

/// Kernel IPC entry points and layouts of the running kernel.
#[derive(Clone, Debug, Default)]
pub struct KernelLayout {
    /// Located entry points.
    pub hooks: Vec<KernelHook>,
    /// Structure layouts, `None` when the profile lacks any of them.
    pub types: Option<KernelTypes>,
    /// `mach_msg_type_name_t` enumerators, for right dispositions.
    pub dispositions: Vec<(u64, String)>,
}

impl KernelLayout {
    /// Names a right disposition as `move-send` for `MACH_MSG_TYPE_MOVE_SEND`.
    pub fn disposition(&self, value: u64) -> &str {
        match self
            .dispositions
            .iter()
            .find(|(candidate, _)| *candidate == value)
        {
            Some((_, name)) => name,
            None => "unknown",
        }
    }
}

/// Kernel functions, alternative names across kernel versions and the
/// parameters each observation reads.
const FUNCTIONS: &[(IpcHook, &[&str], &[&str])] = &[
    (
        IpcHook::KernelCopyin,
        &["ipc_kmsg_copyin_from_user"],
        &["kmsg", "send_uctx"],
    ),
    (IpcHook::KernelSend, &["ipc_kmsg_send"], &["kmsg"]),
    (IpcHook::KernelCopyout, &["ipc_kmsg_copyout"], &["kmsg"]),
    (
        IpcHook::KernelDeliver,
        &["ipc_kmsg_put_to_user"],
        &["kmsg", "recv_bufs", "msgr", "options"],
    ),
    (IpcHook::KernelMessageFree, &["ipc_kmsg_free"], &["kmsg"]),
    (IpcHook::KernelPortDestroy, &["ipc_port_destroy"], &["port"]),
    (
        IpcHook::KernelPortFree,
        &["ipc_port_free", "ipc_port_finalize"],
        &["port"],
    ),
];

impl KernelLayout {
    /// Reads entry points, argument positions and layouts from `profile`.
    ///
    /// `relocate` slides a profile address into the running kernel. Each
    /// missing function, parameter or type yields one line and leaves the
    /// observations depending on it disabled.
    pub fn from_profile<E>(
        profile: &Profile<'_>,
        mut relocate: impl FnMut(u64) -> Result<u64, E>,
    ) -> Result<(Self, Vec<String>), E> {
        let mut lines = Vec::new();
        let types = match types(profile) {
            Ok(types) => Some(types),
            Err(missing) => {
                lines.push(format!(
                    "ipc incomplete: kernel profile lacks {missing}, kernel transport hooks disabled"
                ));
                None
            }
        };
        let mut hooks = Vec::new();
        if types.is_some() {
            for &(kind, names, parameters) in FUNCTIONS {
                let found = names.iter().find_map(|&name| {
                    Some((
                        name,
                        profile.find_function(name)?,
                        profile.find_symbol(name)?,
                    ))
                });
                let (name, function, address) = match found {
                    Some(found) => found,
                    None => {
                        lines.push(format!(
                            "ipc incomplete: kernel profile lacks function {}",
                            names.join(" or ")
                        ));
                        continue;
                    }
                };
                let mut arguments = [0; 4];
                let mut complete = true;
                for (slot, parameter) in parameters.iter().enumerate() {
                    match argument(profile, function, parameter) {
                        Some(index) => arguments[slot] = index,
                        None => {
                            lines.push(format!(
                                "ipc incomplete: kernel {name} has no register parameter {parameter}"
                            ));
                            complete = false;
                        }
                    }
                }
                if complete {
                    hooks.push(KernelHook {
                        kind,
                        address: relocate(address)?,
                        arguments,
                    });
                }
            }
        }
        let dispositions = match profile.find_enum("mach_msg_type_name_t") {
            Some(enumeration) => enumeration
                .fields()
                .map(|(name, value)| {
                    let name = name.strip_prefix("MACH_MSG_TYPE_").unwrap_or(name);
                    (
                        variant_value(value),
                        name.to_ascii_lowercase().replace('_', "-"),
                    )
                })
                .collect(),
            None => Vec::new(),
        };
        Ok((
            Self {
                hooks,
                types,
                dispositions,
            },
            lines,
        ))
    }
}

/// Finds the argument register of a named parameter.
///
/// Every parameter up to and including it must be passed in one general
/// register, as integers, enums and pointers are on arm64.
pub fn argument(
    profile: &Profile<'_>,
    function: isr_core::Function<'_>,
    name: &str,
) -> Option<usize> {
    for (index, parameter) in function.parameters().enumerate() {
        let scalar = match parameter.ty() {
            Type::Base(_) | Type::Enum(_) | Type::Pointer(_) => profile
                .type_size(parameter.ty())
                .is_some_and(|size| size <= 8),
            _ => false,
        };
        if !scalar || index >= 8 {
            return None;
        }
        if parameter.name() == Some(name) {
            return Some(index);
        }
    }
    None
}

/// Resolves a field offset, searching anonymous members.
fn offset(profile: &Profile<'_>, structure: &str, field: &str) -> Result<u64, String> {
    bits(profile, structure, field).map(|bits| bits.offset)
}

/// Resolves a field as a bit range, whole fields spanning their type size.
fn bits(profile: &Profile<'_>, structure: &str, field: &str) -> Result<Bits, String> {
    let found = profile
        .find_struct(structure)
        .and_then(|udt| udt.find_field(profile, field));
    let found = match found {
        Some(found) => found,
        None => return Err(format!("{structure}.{field}")),
    };
    match found.ty() {
        Type::Bitfield(bitfield) => Ok(Bits {
            offset: found.offset(),
            position: bitfield.bit_position() as u32,
            length: bitfield.bit_length() as u32,
        }),
        ty => match profile.type_size(ty) {
            Some(size) if (1..=8).contains(&size) => Ok(Bits {
                offset: found.offset(),
                position: 0,
                length: size as u32 * 8,
            }),
            _ => Ok(Bits {
                offset: found.offset(),
                position: 0,
                length: 0,
            }),
        },
    }
}

/// Resolves an enumerator value, naming `type::variant` when it is missing.
pub fn enumerator(profile: &Profile<'_>, name: &str, variant: &str) -> Result<u64, String> {
    let value = profile.find_enum(name).and_then(|enumeration| {
        enumeration
            .fields()
            .find(|(candidate, _)| *candidate == variant)
            .map(|(_, value)| value)
    });
    match value {
        Some(value) => Ok(variant_value(value)),
        None => Err(format!("{name}::{variant}")),
    }
}

/// Widens an enumerator value to its unsigned bit pattern.
fn variant_value(value: isr_core::Variant) -> u64 {
    match value {
        isr_core::Variant::U8(value) => value.into(),
        isr_core::Variant::U16(value) => value.into(),
        isr_core::Variant::U32(value) => value.into(),
        isr_core::Variant::U64(value) => value,
        isr_core::Variant::U128(value) => value as u64,
        isr_core::Variant::I8(value) => value as u64,
        isr_core::Variant::I16(value) => value as u64,
        isr_core::Variant::I32(value) => value as u64,
        isr_core::Variant::I64(value) => value as u64,
        isr_core::Variant::I128(value) => value as u64,
    }
}

/// Reads every structure layout, naming the first missing item.
fn types(profile: &Profile<'_>) -> Result<KernelTypes, String> {
    let send_header = offset(profile, "mach_msg_send_uctx_t", "send_header")?;
    Ok(KernelTypes {
        kmsg_type: bits(profile, "ipc_kmsg", "ikm_type")?,
        keep_alive: bits(profile, "ipc_kmsg", "ikm_keep_alive")?,
        keep_alive_owned: enumerator(profile, "ipc_kmsg_keep_alive_t", "IKM_KEEP_ALIVE_OWNED")?,
        all_inlined: enumerator(profile, "ipc_kmsg_type_t", "IKM_TYPE_ALL_INLINED")?,
        udata_ool: enumerator(profile, "ipc_kmsg_type_t", "IKM_TYPE_UDATA_OOL")?,
        big_data: offset(profile, "ipc_kmsg", "ikm_big_data")?,
        small_data: offset(profile, "ipc_kmsg", "ikm_small_data")?,
        kdata: offset(profile, "ipc_kmsg", "ikm_kdata")?,
        header_bits: offset(profile, "mach_msg_header_t", "msgh_bits")?,
        header_remote: offset(profile, "mach_msg_header_t", "msgh_remote_port")?,
        header_local: offset(profile, "mach_msg_header_t", "msgh_local_port")?,
        header_id: offset(profile, "mach_msg_header_t", "msgh_id")?,
        descriptor_count: offset(profile, "mach_msg_kbase_t", "msgb_dsc_count")?,
        descriptors: offset(profile, "mach_msg_kbase_t", "msgb_dsc_array")?,
        descriptor_size: match profile.struct_size("mach_msg_kdescriptor_t") {
            Some(size) if size != 0 => size,
            _ => return Err(String::from("mach_msg_kdescriptor_t")),
        },
        port_name: offset(profile, "mach_msg_port_descriptor_t", "name")?,
        port_disposition: bits(profile, "mach_msg_port_descriptor_t", "disposition")?,
        descriptor_type: bits(profile, "mach_msg_type_descriptor_t", "type")?,
        array_address: offset(profile, "mach_msg_ool_ports_descriptor_t", "address")?,
        array_count: offset(profile, "mach_msg_ool_ports_descriptor_t", "count")?,
        array_disposition: bits(profile, "mach_msg_ool_ports_descriptor_t", "disposition")?,
        send_remote: send_header + offset(profile, "mach_msg_user_header_t", "msgh_remote_port")?,
        send_local: send_header + offset(profile, "mach_msg_user_header_t", "msgh_local_port")?,
        send_message: offset(profile, "mach_msg_send_uctx_t", "send_msg_addr")?,
        receive_address: offset(profile, "mach_msg_recv_bufs_t", "recv_msg_addr")?,
        receive_size: offset(profile, "mach_msg_recv_bufs_t", "recv_msg_size")?,
        result_message: offset(profile, "mach_msg_recv_result_t", "msgr_msg_size")?,
        result_trailer: offset(profile, "mach_msg_recv_result_t", "msgr_trailer_size")?,
        result_auxiliary: offset(profile, "mach_msg_recv_result_t", "msgr_aux_size")?,
        result_name: offset(profile, "mach_msg_recv_result_t", "msgr_recv_name")?,
        linear_vector: enumerator(profile, "mach_msg_option64_t", "MACH64_RCV_LINEAR_VECTOR")?,
        stack: enumerator(profile, "mach_msg_option64_t", "MACH64_RCV_STACK")?,
    })
}

/// Bit extraction at byte and sub-byte granularity.
#[cfg(test)]
mod tests {
    use super::Bits;

    /// Reads the two-bit `ikm_type` at bit 6 and a whole byte field.
    #[test]
    fn extracts_bitfields() {
        let kind = Bits {
            offset: 0x3f,
            position: 6,
            length: 2,
        };
        assert_eq!(kind.bytes(), 1);
        assert_eq!(kind.extract(&[0b1000_0000]), 2);
        assert_eq!(kind.extract(&[0b0011_1111]), 0);
        let whole = Bits {
            offset: 0,
            position: 0,
            length: 32,
        };
        assert_eq!(whole.bytes(), 4);
        assert_eq!(whole.extract(&[0x78, 0x56, 0x34, 0x12, 0xff]), 0x1234_5678);
        let wide = Bits {
            offset: 0,
            position: 4,
            length: 12,
        };
        assert_eq!(wide.bytes(), 2);
        assert_eq!(wide.extract(&[0xab, 0xcd]), 0xcda);
    }
}
