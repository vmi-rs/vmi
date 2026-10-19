use crate::{
    Error,
    cursor::Cursor,
    description::{VmDescription, VmsdDescription},
    ram::Ram,
    state::{self, VmState},
};

/// Magic number at the start of a migration stream, `QEVM`
/// (`migration/savevm.h`).
const QEMU_VM_FILE_MAGIC: u32 = 0x5145_564d;

/// Format version of the migration stream (`migration/savevm.h`).
const QEMU_VM_FILE_VERSION: u32 = 3;

/// Section type that ends the sections (`migration/savevm.h`).
const QEMU_VM_EOF: u8 = 0x00;

/// Section type that starts an iterable section (`migration/savevm.h`).
const QEMU_VM_SECTION_START: u8 = 0x01;

/// Section type that continues an iterable section (`migration/savevm.h`).
const QEMU_VM_SECTION_PART: u8 = 0x02;

/// Section type that ends an iterable section (`migration/savevm.h`).
const QEMU_VM_SECTION_END: u8 = 0x03;

/// Section type of a device section (`migration/savevm.h`).
const QEMU_VM_SECTION_FULL: u8 = 0x04;

/// Marks a subsection (`migration/savevm.h`).
const QEMU_VM_SUBSECTION: u8 = 0x05;

/// Section type of the configuration section (`migration/savevm.h`).
const QEMU_VM_CONFIGURATION: u8 = 0x07;

/// Section type of a command (`migration/savevm.h`).
const QEMU_VM_COMMAND: u8 = 0x08;

/// Section type of the footer after a section (`migration/savevm.h`).
const QEMU_VM_SECTION_FOOTER: u8 = 0x7e;

/// Command that asks the destination to open the return path
/// (`enum qemu_vm_cmd` in `migration/savevm.c`).
const MIG_CMD_OPEN_RETURN_PATH: u16 = 1;

/// Command that asks the destination for a reply on the return path.
const MIG_CMD_PING: u16 = 2;

/// Command that announces postcopy.
///
/// Without data, it announces only the postcopy of dirty bitmaps, which
/// leaves the RAM section unchanged (`qemu_savevm_send_postcopy_advise` in
/// `migration/savevm.c`).
const MIG_CMD_POSTCOPY_ADVISE: u16 = 3;

/// Command that announces the switchover to the destination.
const MIG_CMD_SWITCHOVER_START: u16 = 11;

/// Name of the iterable section that holds the RAM.
const RAM_SECTION: &str = "ram";

/// Name of the device sections that hold the vCPUs.
const CPU_SECTION: &str = "cpu";

/// Name of the configuration subsection that lists the migration
/// capabilities (`vmstate_capabilites` in `migration/savevm.c`).
const CAPABILITIES: &str = "configuration/capabilities";

/// Name of the configuration subsection that holds the target page bits
/// (`vmstate_target_page_bits` in `migration/savevm.c`).
const TARGET_PAGE_BITS: &str = "configuration/target-page-bits";

/// Name of the configuration subsection that holds the VM UUID
/// (`vmstate_uuid` in `migration/savevm.c`).
const UUID: &str = "configuration/uuid";

/// Migration capabilities that leave guest memory out of the stream or
/// change the layout of the RAM section.
///
/// With `x-ignore-shared`, QEMU skips the RAM blocks that the destination
/// shares with the source. With `mapped-ram`, QEMU writes pages at fixed
/// offsets of a file instead of into the stream.
const UNSUPPORTED_CAPABILITIES: [&str; 2] = ["x-ignore-shared", "mapped-ram"];

/// The parts of a migration stream that the driver uses.
pub(crate) struct Stream<'a> {
    /// Machine type of the source, such as `pc-q35-10.2`.
    pub machine: String,

    /// RAM blocks and the location of their pages.
    pub ram: Ram,

    /// `cpu` sections in stream order, with their instance ids.
    pub cpus: Vec<(u32, VmState<'a>)>,
}

/// Reads the sections of a migration stream.
///
/// `description` is the VM description of the stream, and `end` is the
/// offset of its marker. The sections must end there.
pub(crate) fn read<'a>(
    data: &'a [u8],
    description: &'a VmDescription,
    end: usize,
) -> Result<Stream<'a>, Error> {
    let mut cursor = Cursor::new(data);

    let magic = cursor.be32()?;
    if magic != QEMU_VM_FILE_MAGIC {
        return Err(Error::InvalidMagic { magic });
    }

    let version = cursor.be32()?;
    if version != QEMU_VM_FILE_VERSION {
        return Err(Error::UnsupportedVersion { version });
    }

    let mut devices = description.devices.iter();
    let mut machine = None;
    let mut ram = Ram::new(description.page_size);
    let mut ram_section = None;
    let mut last_section = None;
    let mut cpus = Vec::new();

    loop {
        let offset = cursor.offset();
        match cursor.u8()? {
            QEMU_VM_EOF => break,
            QEMU_VM_CONFIGURATION => {
                machine = Some(read_configuration(
                    &mut cursor,
                    description.configuration.as_ref(),
                )?);
            }
            section_type @ (QEMU_VM_SECTION_START | QEMU_VM_SECTION_FULL) => {
                // The section id, the name with a one-byte length, the
                // instance id and the version (`save_section_header` in
                // `migration/savevm.c`).
                let section_id = cursor.be32()?;
                let name = cursor.name()?;
                let instance_id = cursor.be32()?;
                cursor.be32()?;
                last_section = Some(section_id);

                if section_type == QEMU_VM_SECTION_START {
                    if name != RAM_SECTION {
                        return Err(Error::UnsupportedSection {
                            name: name.into(),
                            offset: offset as u64,
                        });
                    }

                    ram_section = Some(section_id);
                    ram.read_section(&mut cursor)?;
                    continue;
                }

                // QEMU adds a device to the VM description when it writes
                // the device's section. Both have the same order.
                let device = match devices.next() {
                    Some(device) if device.name == name && device.instance_id == instance_id => {
                        device
                    }
                    _ => {
                        return Err(Error::UnexpectedSection {
                            name: name.into(),
                            instance_id,
                            offset: offset as u64,
                        });
                    }
                };

                if name == CPU_SECTION {
                    cpus.push((instance_id, VmState::read(&mut cursor, &device.state)?));
                }
                else {
                    state::skip(&mut cursor, &device.state)?;
                }
            }
            QEMU_VM_SECTION_PART | QEMU_VM_SECTION_END => {
                let section_id = cursor.be32()?;
                if ram_section != Some(section_id) {
                    return Err(Error::UnknownSection {
                        section_id,
                        offset: offset as u64,
                    });
                }

                last_section = Some(section_id);
                ram.read_section(&mut cursor)?;
            }
            QEMU_VM_SECTION_FOOTER => {
                let section_id = cursor.be32()?;
                if last_section != Some(section_id) {
                    return Err(Error::FooterMismatch {
                        section_id,
                        offset: offset as u64,
                    });
                }
            }
            QEMU_VM_COMMAND => {
                // The command, the length of its data and the data
                // (`qemu_savevm_command_send` in `migration/savevm.c`).
                let command = cursor.be16()?;
                let len = cursor.be16()?;
                cursor.bytes(usize::from(len))?;

                match (command, len) {
                    (MIG_CMD_OPEN_RETURN_PATH | MIG_CMD_PING | MIG_CMD_SWITCHOVER_START, _)
                    | (MIG_CMD_POSTCOPY_ADVISE, 0) => (),
                    _ => {
                        return Err(Error::UnsupportedCommand {
                            command,
                            offset: offset as u64,
                        });
                    }
                }
            }
            section_type => {
                return Err(Error::UnknownSectionType {
                    section_type,
                    offset: offset as u64,
                });
            }
        }
    }

    if cursor.offset() != end {
        return Err(Error::TrailingData {
            offset: cursor.offset() as u64,
        });
    }

    if let Some(device) = devices.next() {
        return Err(Error::MissingSection {
            name: device.name.clone(),
            instance_id: device.instance_id,
        });
    }

    match machine {
        Some(machine) => Ok(Stream { machine, ram, cpus }),
        None => Err(Error::MissingConfiguration),
    }
}

/// Reads the configuration section and returns the machine type.
///
/// The section holds the length of the machine type as a big-endian 32-bit
/// integer, the machine type and subsections (`vmstate_configuration` in
/// `migration/savevm.c`). `description` describes the section in a VM
/// description of QEMU 8.2 or later. Without it, the subsections that QEMU
/// defines are read by their known layout.
///
/// Fails when the source enabled a capability of
/// [`UNSUPPORTED_CAPABILITIES`].
fn read_configuration<'a>(
    cursor: &mut Cursor<'a>,
    description: Option<&'a VmsdDescription>,
) -> Result<String, Error> {
    let start = cursor.offset();
    let (machine, capabilities) = match description {
        Some(description) => {
            let state = VmState::read(cursor, description)?;
            let machine = match state.field("name") {
                Some(machine) => machine,
                None => return Err(Error::MissingConfiguration),
            };

            let capabilities = state
                .subsection(CAPABILITIES)
                .and_then(|capabilities| capabilities.field("capabilities"))
                .unwrap_or_default();
            (machine, capabilities)
        }
        None => read_configuration_without_description(cursor)?,
    };

    // Each capability is its name with a one-byte length.
    let mut names = Cursor::new(capabilities);
    while names.peek().is_some() {
        let name = names.name()?;
        if UNSUPPORTED_CAPABILITIES.contains(&name) {
            return Err(Error::UnsupportedCapability { name: name.into() });
        }
    }

    match std::str::from_utf8(machine) {
        Ok(machine) => Ok(machine.into()),
        Err(_) => Err(Error::InvalidName {
            offset: start as u64,
        }),
    }
}

/// Reads a configuration section that the VM description does not
/// describe.
///
/// Returns the machine type and the bytes of the capability list.
fn read_configuration_without_description<'a>(
    cursor: &mut Cursor<'a>,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    let len = cursor.be32()?;
    let machine = cursor.bytes(len as usize)?;
    let mut capabilities = &[][..];

    while cursor.peek() == Some(QEMU_VM_SUBSECTION) {
        let offset = cursor.offset();
        cursor.u8()?;
        let name = cursor.name()?;
        cursor.be32()?;

        match name {
            TARGET_PAGE_BITS => {
                cursor.be32()?;
            }
            CAPABILITIES => {
                let count = cursor.be32()?;
                let start = cursor.offset();
                for _ in 0..count {
                    cursor.name()?;
                }

                capabilities = cursor.since(start);
            }
            UUID => {
                cursor.bytes(16)?;
            }
            _ => {
                return Err(Error::UnknownSubsection {
                    name: name.into(),
                    offset: offset as u64,
                });
            }
        }
    }

    Ok((machine, capabilities))
}
