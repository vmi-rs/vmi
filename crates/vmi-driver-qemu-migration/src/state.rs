use crate::{
    Error,
    cursor::Cursor,
    description::{FieldDescription, VmsdDescription},
};

/// Marks a subsection within a device section (`migration/savevm.h`).
const QEMU_VM_SUBSECTION: u8 = 0x05;

/// The `VMStateInfo` name of a migration capability.
///
/// QEMU writes a capability as its name with a one-byte length
/// (`save_capability` in `migration/savevm.c`). Capabilities in one array
/// therefore differ in size, but the description gives only the size of the
/// first element.
const CAPABILITY: &str = "capability";

/// The bytes of one field of a device section.
struct Field<'a> {
    /// Description of the field.
    description: &'a FieldDescription,

    /// All elements of the field, in stream order.
    data: &'a [u8],
}

/// A subsection of a device section.
struct Subsection<'a> {
    /// Name of the subsection, such as `cpu/pstate64`.
    name: &'a str,

    /// Fields and subsections of the subsection.
    state: VmState<'a>,
}

/// The fields and subsections of a device section as slices of the stream.
pub(crate) struct VmState<'a> {
    /// Fields in stream order.
    fields: Vec<Field<'a>>,

    /// Subsections in stream order.
    subsections: Vec<Subsection<'a>>,
}

impl<'a> VmState<'a> {
    /// Reads the device section or subsection that `description` describes.
    pub fn read(cursor: &mut Cursor<'a>, description: &'a VmsdDescription) -> Result<Self, Error> {
        let mut fields = Vec::with_capacity(description.fields.len());
        for field in &description.fields {
            let start = cursor.offset();
            skip_field(cursor, field)?;
            fields.push(Field {
                description: field,
                data: cursor.since(start),
            });
        }

        let mut subsections = Vec::with_capacity(description.subsections.len());
        for subsection in &description.subsections {
            read_subsection_header(cursor, subsection)?;
            subsections.push(Subsection {
                name: &subsection.vmsd_name,
                state: Self::read(cursor, subsection)?,
            });
        }

        Ok(Self {
            fields,
            subsections,
        })
    }

    /// Returns the bytes of the field named `name`, or `None` when the state
    /// has no such field.
    ///
    /// For an array of capabilities, the bytes hold all elements.
    pub fn field(&self, name: &str) -> Option<&'a [u8]> {
        self.fields
            .iter()
            .find(|field| field.description.name == name)
            .map(|field| field.data)
    }

    /// Returns one element of a field and the description of the field, or
    /// `None` when the state has no such element.
    ///
    /// QEMU describes an array either with one entry for all elements or with
    /// one entry per element, all of the same name. `index` counts the
    /// elements across all entries of the name.
    fn element(&self, name: &str, index: usize) -> Option<(&'a FieldDescription, &'a [u8])> {
        let mut index = index as u64;
        for field in &self.fields {
            if field.description.name != name {
                continue;
            }

            let count = field.description.count();
            if index < count {
                // An array of capabilities holds elements of different sizes,
                // and its elements cannot be addressed by index.
                let size = field.description.size as usize;
                let start = index as usize * size;
                return field
                    .data
                    .get(start..start + size)
                    .map(|bytes| (field.description, bytes));
            }

            index -= count;
        }

        None
    }

    /// Returns the number of elements of a field, or `None` when the state
    /// has no such field.
    fn count(&self, name: &str) -> Option<usize> {
        let mut count = None;
        for field in &self.fields {
            if field.description.name == name {
                *count.get_or_insert(0) += field.description.count() as usize;
            }
        }

        count
    }

    /// Returns a subsection, or `None` when the stream does not have it.
    pub fn subsection(&self, name: &str) -> Option<&VmState<'a>> {
        self.subsections
            .iter()
            .find(|subsection| subsection.name == name)
            .map(|subsection| &subsection.state)
    }
}

/// Skips the device section or subsection that `description` describes.
pub(crate) fn skip(cursor: &mut Cursor, description: &VmsdDescription) -> Result<(), Error> {
    for field in &description.fields {
        skip_field(cursor, field)?;
    }

    for subsection in &description.subsections {
        read_subsection_header(cursor, subsection)?;
        skip(cursor, subsection)?;
    }

    Ok(())
}

/// Skips all elements of one field.
fn skip_field(cursor: &mut Cursor, field: &FieldDescription) -> Result<(), Error> {
    if field.kind == CAPABILITY {
        for _ in 0..field.count() {
            cursor.name()?;
        }

        return Ok(());
    }

    match field.count().checked_mul(field.size) {
        Some(len) => cursor.bytes(len as usize).map(|_| ()),
        None => Err(Error::Truncated {
            offset: cursor.offset() as u64,
        }),
    }
}

/// Reads the header of a subsection and checks that it starts the subsection
/// that `description` describes.
///
/// The header is the marker, the name with a one-byte length and the version
/// as a big-endian 32-bit integer (`vmstate_subsection_save` in
/// `migration/vmstate.c`).
fn read_subsection_header(cursor: &mut Cursor, description: &VmsdDescription) -> Result<(), Error> {
    let offset = cursor.offset();
    if cursor.u8()? != QEMU_VM_SUBSECTION || cursor.name()? != description.vmsd_name {
        return Err(Error::MissingSubsection {
            name: description.vmsd_name.clone(),
            offset: offset as u64,
        });
    }

    cursor.be32()?;
    Ok(())
}

/// Reads an integer that QEMU wrote in big-endian byte order.
///
/// Returns `None` when `bytes` is not 1, 2, 4 or 8 bytes long.
fn be_uint(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        1 | 2 | 4 | 8 => Some(
            bytes
                .iter()
                .fold(0, |value, byte| (value << 8) | u64::from(*byte)),
        ),
        _ => None,
    }
}

/// The state of one vCPU in a `cpu` section of the stream.
///
/// QEMU saves each vCPU as a device section named `cpu`, with the index of
/// the vCPU as the instance id. The fields of the section are those of the
/// target's `VMStateDescription`, such as `vmstate_x86_cpu` in
/// `target/i386/machine.c` or `vmstate_arm_cpu` in `target/arm/machine.c`.
/// The VM description at the end of the stream names each field and gives
/// its size. Integers are in big-endian byte order.
#[derive(Clone, Copy)]
pub struct CpuState<'a> {
    /// Index of the vCPU.
    vcpu: u16,

    /// The `cpu` section, or one subsection of it.
    state: &'a VmState<'a>,
}

impl<'a> CpuState<'a> {
    /// Creates the state of a vCPU from its section.
    pub(crate) fn new(vcpu: u16, state: &'a VmState<'a>) -> Self {
        Self { vcpu, state }
    }

    /// Returns the index of the vCPU.
    pub fn vcpu(&self) -> u16 {
        self.vcpu
    }

    /// Returns the number of elements of a field, or `None` when the section
    /// has no such field.
    ///
    /// `field` is a field name of the VM description, such as `env.regs`. A
    /// field that is not an array has one element.
    pub fn count(&self, field: &str) -> Option<usize> {
        self.state.count(field)
    }

    /// Returns one element of an integer field.
    ///
    /// `field` is a field name of the VM description, such as `env.regs` or
    /// `env.cr[3]`, and `index` picks the element, 0 for a field that is not
    /// an array. The element must be 1, 2, 4 or 8 bytes long. The value is
    /// zero-extended to 64 bits.
    pub fn uint(&self, field: &str, index: usize) -> Result<u64, Error> {
        let (_, bytes) = match self.state.element(field, index) {
            Some(element) => element,
            None => {
                return Err(Error::MissingField {
                    vcpu: self.vcpu,
                    field: element_path(field, index),
                });
            }
        };

        match be_uint(bytes) {
            Some(value) => Ok(value),
            None => Err(Error::InvalidFieldSize {
                vcpu: self.vcpu,
                field: element_path(field, index),
                size: bytes.len() as u64,
            }),
        }
    }

    /// Returns an integer member of one element of a struct field.
    ///
    /// `field` and `index` pick the element as for [`uint`](Self::uint).
    /// `member` names a member of the struct as its description does, such as
    /// `base` in an element of `env.segs`. For a member that is an array, the
    /// value is its first element.
    pub fn member(&self, field: &str, index: usize, member: &str) -> Result<u64, Error> {
        let missing = || Error::MissingField {
            vcpu: self.vcpu,
            field: format!("{}.{member}", element_path(field, index)),
        };

        let (description, bytes) = match self.state.element(field, index) {
            Some(element) => element,
            None => return Err(missing()),
        };

        let structure = match &description.structure {
            Some(structure) => structure,
            None => return Err(missing()),
        };

        // The struct description gives the member sizes of the first element.
        // All elements that one entry describes share this layout.
        let mut offset = 0;
        for member_field in &structure.fields {
            let size = member_field.size as usize;
            if member_field.name == member {
                let value = match bytes.get(offset..offset + size) {
                    Some(value) => value,
                    None => return Err(missing()),
                };

                return match be_uint(value) {
                    Some(value) => Ok(value),
                    None => Err(Error::InvalidFieldSize {
                        vcpu: self.vcpu,
                        field: format!("{}.{member}", element_path(field, index)),
                        size: size as u64,
                    }),
                };
            }

            offset += member_field.count() as usize * size;
        }

        Err(missing())
    }

    /// Returns the state of a subsection, such as `cpu/pstate64`, or `None`
    /// when the stream does not have it.
    ///
    /// QEMU writes a subsection only when its `needed` callback asks for it.
    pub fn subsection(&self, name: &str) -> Option<CpuState<'a>> {
        self.state.subsection(name).map(|state| CpuState {
            vcpu: self.vcpu,
            state,
        })
    }
}

/// Formats the path of one element of a field for an error.
fn element_path(field: &str, index: usize) -> String {
    format!("{field}[{index}]")
}
