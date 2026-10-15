//! Bounded, read-only value decoding for macOS arm64e objects and XPC messages.
//!
//! CF strings are read from their published storage encoding, tagged strings
//! with the guest's own compression alphabet, and `NSPathStore2` through its
//! ivar metadata. XPC payloads are decoded from the bytes of the Mach message
//! that carries them, never from libxpc's private objects: the XPC wire type
//! IDs and the Mach message header, descriptor and trailer layouts are stable
//! (Orchard `docs/platform/tracer-stability.md`). No guest code is called.

use std::fmt::{self, Write as _};

use vmi::{Va, VmiContext, VmiError, os::macos::MacOs};

use crate::{
    Arch, Driver,
    encoding::{AbiKind, AbiType},
    objc::ObjcRuntime,
    style::Palette,
};

/// Maximum characters or bytes included in a string snapshot.
const STRING_LIMIT: usize = 256;
/// Maximum pointers included in an exec argument vector.
const ARGV_LIMIT: usize = 32;
/// Maximum entries included in each container.
const ENTRY_LIMIT: usize = 32;
/// Maximum wire values visited in one message.
const NODE_LIMIT: usize = 128;
/// Maximum recursive container depth.
const DEPTH_LIMIT: usize = 8;
/// Maximum data bytes included in a snapshot.
const DATA_LIMIT: usize = 128;
/// Maximum Mach message bytes copied for payload decoding.
const MESSAGE_LIMIT: u32 = 0x10000;
/// Maximum descriptors accepted in one Mach message.
const DESCRIPTOR_LIMIT: u32 = 256;

/// Size of the user-space `mach_msg_header_t`, xnu-12377.121.6
/// `osfmk/mach/message.h:610-617`.
const HEADER_SIZE: usize = 24;
/// `MACH_MSGH_BITS_COMPLEX`, message.h:152.
const COMPLEX: u32 = 0x8000_0000;
/// Size of `mach_msg_body_t`, message.h:602-604.
const BODY_SIZE: usize = 4;
/// `MACH_MSG_PORT_DESCRIPTOR`, the descriptor type of a single right.
const PORT_DESCRIPTOR: u8 = 0;
/// Size of a user `mach_msg_port_descriptor_t`, message.h:408-425.
const PORT_DESCRIPTOR_SIZE: usize = 12;
/// Size of the 64-bit user out-of-line, out-of-line ports and guarded port
/// descriptors, message.h:449-456, 495-502 and 540-546.
const WIDE_DESCRIPTOR_SIZE: usize = 16;
/// Offset of the type byte, common to every user descriptor.
const DESCRIPTOR_TYPE: usize = 11;
/// Offset of a port descriptor's disposition byte.
const DESCRIPTOR_DISPOSITION: usize = 10;
/// `MACH_MSG_TYPE_MOVE_SEND`, which a received send right reports as
/// `MACH_MSG_TYPE_PORT_SEND` (message.h:341).
const PORT_SEND: u8 = 17;
/// Bytes of XPC magic and version before the root object.
const WIRE_PREFIX: usize = 8;
/// XPC wire type ID of a dictionary, the root object of a message.
const WIRE_DICTIONARY: u32 = 0xf000;
/// Largest data value carried inline in a message with descriptors; larger
/// data travels in a Mach memory entry.
const WIRE_INLINE_DATA: u32 = 0x4000;
/// Right shift of the length in `NSPathStore2::_lengthAndRefCount`, from
/// `-[NSPathStore2 length]` (`lsr w0, w8, #20`, Foundation 26A434
/// @0x181ffd63c). This is the one private Foundation encoding still assumed.
const PATH_LENGTH_SHIFT: u32 = 20;
/// Longest path an `NSPathStore2` holds, `PATH_MAX`.
const PATH_LIMIT: u64 = 1024;

/// Per-process symbol addresses and object layouts read from metadata.
#[derive(Default)]
pub struct Values {
    /// Address of CoreFoundation's `__CFCharToUniCharTable` pointer, the
    /// native byte to UTF-16 conversion table.
    characters: Option<u64>,

    /// Address of CoreFoundation's `sixBitToCharLookup`, the alphabet of
    /// compressed tagged strings.
    alphabet_address: Option<u64>,

    /// Alphabet read once from the guest.
    alphabet: Option<[u8; 64]>,

    /// `NSPathStore2` class with its `_lengthAndRefCount` and `_characters`
    /// ivar offsets.
    path_store: Option<(u64, u64, u64)>,

    /// Address of non-resident metadata to page in at the next user-mode stop.
    page_in: Option<u64>,
}

/// A decoding failure, preserving inaccessible memory and invalid layouts.
#[derive(Debug)]
enum DecodeError {
    /// A guest read failed.
    Memory(VmiError),
    /// A representation cannot be decoded without guessing.
    Invalid(&'static str),
}

impl From<VmiError> for DecodeError {
    fn from(err: VmiError) -> Self {
        Self::Memory(err)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(err) => write!(formatter, "unreadable: {err}"),
            Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

/// One descriptor of a Mach message, in message order.
#[derive(Clone, Copy, Debug)]
enum Descriptor {
    /// A single right with its task-local name and disposition.
    Port {
        /// Name in the space of the task that holds the message.
        name: u32,
        /// Disposition, before or after kernel conversion.
        disposition: u8,
    },
    /// An out-of-line memory, out-of-line ports or guarded port descriptor.
    Other,
}

/// A bounded cursor over the copied XPC wire payload of one message.
struct Wire<'a> {
    /// Copied message bytes.
    bytes: &'a [u8],
    /// Offset of the next serialized byte.
    position: usize,
    /// Exclusive end of the containing value.
    end: usize,
    /// Descriptors of the carrying message.
    descriptors: &'a [Descriptor],
    /// Whether the message carries descriptors, so large data is out of line.
    complex: bool,
    /// Next descriptor in serialization order.
    descriptor: usize,
    /// Wire values visited so far.
    nodes: usize,
}

impl Wire<'_> {
    /// Consumes an exact range and returns its offset.
    fn take(&mut self, size: usize) -> Result<usize, DecodeError> {
        if size > self.end - self.position {
            return Err(DecodeError::Invalid("wire value exceeds its container"));
        }
        let position = self.position;
        self.position += size;
        Ok(position)
    }

    /// Reads a little-endian wire word.
    fn word(&mut self) -> Result<u32, DecodeError> {
        let position = self.take(4)?;
        Ok(u32::from_le_bytes(
            self.bytes[position..position + 4]
                .try_into()
                .expect("four bytes"),
        ))
    }

    /// Reads a little-endian wire doubleword.
    fn wide(&mut self) -> Result<u64, DecodeError> {
        let position = self.take(8)?;
        Ok(u64::from_le_bytes(
            self.bytes[position..position + 8]
                .try_into()
                .expect("eight bytes"),
        ))
    }

    /// Consumes the next port descriptor of the carrying message.
    fn port(&mut self) -> Result<(u32, u8), DecodeError> {
        match self.descriptors.get(self.descriptor) {
            Some(Descriptor::Port { name, disposition }) => {
                self.descriptor += 1;
                Ok((*name, *disposition))
            }
            Some(Descriptor::Other) => Err(DecodeError::Invalid(
                "wire right is not at a port descriptor",
            )),
            None => Err(DecodeError::Invalid("wire right without descriptor")),
        }
    }

    /// Reads a padded, null-terminated dictionary key.
    fn key(&mut self) -> Result<String, DecodeError> {
        let available = &self.bytes[self.position..self.end];
        let length = match available.iter().position(|byte| *byte == 0) {
            Some(length) => length,
            None => return Err(DecodeError::Invalid("unterminated wire key")),
        };
        let key = quote_bytes(&available[..length.min(STRING_LIMIT)]);
        self.take((length + 4) & !3)?;
        Ok(key)
    }

    /// A cursor over the next `size` bytes, sharing descriptor state.
    fn child(&self, start: usize, size: usize) -> Self {
        Wire {
            bytes: self.bytes,
            position: start,
            end: start + size,
            descriptors: self.descriptors,
            complex: self.complex,
            descriptor: self.descriptor,
            nodes: self.nodes,
        }
    }
}

impl Values {
    /// Records a CoreFoundation symbol the decoders use and reports whether
    /// it was consumed.
    ///
    /// `name` has one leading symbol underscore stripped.
    pub fn configure_symbol(&mut self, name: &str, address: u64) -> bool {
        match name {
            "__CFCharToUniCharTable" => self.characters = Some(address),
            "sixBitToCharLookup" => {
                self.alphabet_address = Some(address);
                self.alphabet = None;
            }
            _ => return false,
        }
        true
    }

    /// Forgets ivar offsets after the runtime changed class metadata.
    pub fn invalidate(&mut self) {
        self.path_store = None;
    }

    /// Takes the address of metadata that a decoder found not resident.
    pub fn take_page_in(&mut self) -> Option<u64> {
        self.page_in.take()
    }

    /// Renders an ABI value, reading only explicitly typed pointees.
    pub fn render(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        ty: &AbiType,
        raw: u64,
        objc: &mut ObjcRuntime,
        palette: &Palette,
    ) -> String {
        let bits = ty.size.min(8) * 8;
        let clipped = if bits == 64 {
            raw
        }
        else if bits == 0 {
            0
        }
        else {
            raw & ((1u64 << bits) - 1)
        };
        match ty.kind {
            AbiKind::Void => palette.number("void"),
            AbiKind::Bool => palette.number(if clipped == 0 { "false" } else { "true" }),
            AbiKind::Signed => {
                let signed = if bits == 0 {
                    0
                }
                else {
                    ((clipped << (64 - bits)) as i64) >> (64 - bits)
                };
                palette.number(&signed.to_string())
            }
            AbiKind::Unsigned => palette.number(&clipped.to_string()),
            AbiKind::CString | AbiKind::CString16 | AbiKind::CString32 | AbiKind::Selector => {
                if raw == 0 {
                    return palette.null();
                }
                let width = match ty.kind {
                    AbiKind::CString16 => 2,
                    AbiKind::CString32 => 4,
                    _ => 1,
                };
                match terminated(vmi, pointer(raw), width, STRING_LIMIT) {
                    Ok(text) => palette.string(&text),
                    Err(err) => palette.number(&format!("0x{raw:x}<{err}>")),
                }
            }
            AbiKind::Object | AbiKind::Class | AbiKind::Block => {
                if raw == 0 {
                    return palette.number("nil");
                }
                match self.object(vmi, raw, objc, ty.kind == AbiKind::Class) {
                    Ok(text) => palette.string(&text),
                    Err(err) => palette.number(&format!("0x{raw:x}<{err}>")),
                }
            }
            AbiKind::Float => palette.number(&format!("0x{raw:x}<floating-point ABI excluded>")),
            AbiKind::Aggregate => palette.number(&format!("0x{raw:x}<aggregate>")),
            AbiKind::Unknown => palette.number(&format!("0x{raw:x}<unknown ABI>")),
            AbiKind::Pointer => {
                if raw == 0 {
                    palette.null()
                }
                else {
                    palette.number(&format!("0x{raw:x}"))
                }
            }
        }
    }

    /// Snapshots a null-terminated exec argument vector without reading past
    /// caps.
    pub fn argv(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        address: u64,
        palette: &Palette,
    ) -> String {
        if address == 0 {
            return palette.null();
        }
        let mut output = String::from("[");
        for index in 0..ARGV_LIMIT {
            if index != 0 {
                output.push_str(", ");
            }
            match vmi.read_u64(Va(pointer(address).saturating_add(index as u64 * 8))) {
                Ok(0) => {
                    if index != 0 {
                        output.truncate(output.len() - 2);
                    }
                    output.push(']');
                    return output;
                }
                Ok(raw) => match terminated(vmi, pointer(raw), 1, STRING_LIMIT) {
                    Ok(text) => output.push_str(&palette.string(&text)),
                    Err(err) => {
                        let _ = write!(output, "0x{raw:x}<{err}>");
                    }
                },
                Err(err) => {
                    let _ = write!(output, "<argv unreadable: {err}>]");
                    return output;
                }
            }
        }
        output.push_str(", <argv truncated>]");
        output
    }

    /// Renders the XPC payload of the Mach message whose header is at
    /// `header`, as it is at this moment in this task.
    pub fn message(
        &self,
        vmi: &VmiContext<MacOs<Driver>>,
        header: u64,
        palette: &Palette,
    ) -> String {
        match read_message(vmi, header) {
            Ok(bytes) => palette.string(&render_message(&bytes)),
            Err(err) => palette.number(&format!("<message 0x{header:x}: {err}>")),
        }
    }

    /// Classifies an object, preserving unknown classes instead of
    /// descriptions.
    fn object(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        object: u64,
        objc: &mut ObjcRuntime,
        class_value: bool,
    ) -> Result<String, DecodeError> {
        let info = match objc.class_info(vmi, object)? {
            Some(info) => info,
            None => return Ok(format!("0x{object:x}<unknown class>")),
        };
        if class_value {
            return Ok(format!("{}<0x{object:x}>", info.name));
        }
        match info.name.as_str() {
            "NSPathStore2" => self.path_store(vmi, object, objc),
            "__NSCFString" | "__NSCFConstantString" => self.cf_string(vmi, pointer(object)),
            "NSTaggedPointerString" | "NSIndirectTaggedPointerString" => {
                let indirect = info.name == "NSIndirectTaggedPointerString";
                match objc.decode_tagged(vmi, object)? {
                    Some((tag, payload)) => self.tagged_string(vmi, tag, payload, indirect),
                    None => Err(DecodeError::Invalid("unresolved tagged string")),
                }
            }
            _ => Ok(format!("{}<0x{object:x}>", info.name)),
        }
    }

    /// Reads an `NSPathStore2` through the offsets of its ivars.
    fn path_store(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        object: u64,
        objc: &mut ObjcRuntime,
    ) -> Result<String, DecodeError> {
        let class = objc.object_class(vmi, object)?;
        let (length_offset, characters_offset) = match self.path_store {
            Some((cached, length, characters)) if cached == class => (length, characters),
            _ => {
                let lookup = objc
                    .ivar(vmi, class, "_lengthAndRefCount")
                    .and_then(|length| Ok((length, objc.ivar(vmi, class, "_characters")?)));
                let (length, characters) = match lookup {
                    Ok(ivars) => ivars,
                    Err(VmiError::Translation(context)) => {
                        self.page_in = Some(context.va.0);
                        return Err(DecodeError::Invalid(
                            "NSPathStore2 ivar metadata not resident, paging it in",
                        ));
                    }
                    Err(err) => return Err(err.into()),
                };
                match (length, characters) {
                    (Some(length), Some(characters)) if length.size == 4 => {
                        self.path_store = Some((class, length.offset, characters.offset));
                        (length.offset, characters.offset)
                    }
                    _ => return Err(DecodeError::Invalid("NSPathStore2 ivars unavailable")),
                }
            }
        };
        let object = pointer(object);
        let length = u64::from(vmi.read_u32(Va(object + length_offset))? >> PATH_LENGTH_SHIFT);
        if length > PATH_LIMIT {
            return Err(DecodeError::Invalid("NSPathStore2 length out of range"));
        }
        utf16(vmi, object + characters_offset, length)
    }

    /// Decodes the native inline, external, mutable and constant CF storage
    /// paths.
    fn cf_string(
        &self,
        vmi: &VmiContext<MacOs<Driver>>,
        object: u64,
    ) -> Result<String, DecodeError> {
        let flags = vmi.read_u8(Va(object + 8))?;
        let external = flags & 0x60 != 0;
        let prefixed = flags & 5 == 4;
        let mut data = if external {
            pointer(vmi.read_u64(Va(object + 0x10))?)
        }
        else {
            object + if prefixed { 0x10 } else { 0x18 }
        };
        let length = if prefixed {
            u64::from(vmi.read_u8(Va(data))?)
        }
        else {
            vmi.read_u64(Va(object + if external { 0x18 } else { 0x10 }))?
        };
        if length > i64::MAX as u64 {
            return Err(DecodeError::Invalid("negative CF length"));
        }
        if length == 0 {
            return Ok(String::from("\"\""));
        }
        if flags & 0x10 != 0 {
            return utf16(vmi, data, length);
        }
        if flags & 4 != 0 {
            data = data
                .checked_add(1)
                .ok_or(DecodeError::Invalid("CF string address overflow"))?;
        }
        let bytes = bounded_bytes(vmi, data, length, STRING_LIMIT)?;
        let variable = self
            .characters
            .ok_or(DecodeError::Invalid("no __CFCharToUniCharTable symbol"))?;
        let table = pointer(vmi.read_u64(Va(variable))?);
        if table == 0 {
            return Err(DecodeError::Invalid("missing native byte conversion table"));
        }
        let mut output = String::from("\"");
        let mut conversion = [0u8; 512];
        vmi.read(Va(table), &mut conversion)?;
        append_utf16(
            &mut output,
            bytes.into_iter().map(|byte| {
                let index = usize::from(byte) * 2;
                u16::from_le_bytes([conversion[index], conversion[index + 1]])
            }),
        );
        output.push('"');
        if length > STRING_LIMIT as u64 {
            output.push_str("<truncated>");
        }
        Ok(output)
    }

    /// Decodes compressed inline and indirect ASCII tagged strings.
    fn tagged_string(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        tag: u16,
        payload: u64,
        indirect: bool,
    ) -> Result<String, DecodeError> {
        if indirect {
            let length = (payload >> 47) & if tag >= 8 { 31 } else { 0x1fff };
            let bytes = bounded_bytes(vmi, payload & 0x7fffffffffff, length, STRING_LIMIT)?;
            if bytes.iter().any(|byte| *byte > 127) {
                return Err(DecodeError::Invalid("non-ASCII indirect tagged string"));
            }
            let mut output = quote_bytes(&bytes);
            if length > STRING_LIMIT as u64 {
                output.push_str("<truncated>");
            }
            return Ok(output);
        }
        let alphabet = match self.alphabet {
            Some(alphabet) => alphabet,
            None => {
                let address = self
                    .alphabet_address
                    .ok_or(DecodeError::Invalid("no sixBitToCharLookup symbol"))?;
                let mut alphabet = [0_u8; 64];
                vmi.read(Va(address), &mut alphabet)?;
                self.alphabet = Some(alphabet);
                alphabet
            }
        };
        inline_tagged_string(payload, &alphabet)
    }
}

/// Copies a Mach message, at most [`MESSAGE_LIMIT`] bytes of it.
fn read_message(vmi: &VmiContext<MacOs<Driver>>, header: u64) -> Result<Vec<u8>, DecodeError> {
    if header == 0 {
        return Err(DecodeError::Invalid("no message"));
    }
    let size = vmi.read_u32(Va(header + 4))?;
    if (size as usize) < HEADER_SIZE {
        return Err(DecodeError::Invalid("message shorter than its header"));
    }
    let mut bytes = vec![0; size.min(MESSAGE_LIMIT) as usize];
    vmi.read(Va(header), &mut bytes)?;
    Ok(bytes)
}

/// Decodes the XPC payload of a copied Mach message.
fn render_message(bytes: &[u8]) -> String {
    let mut output = String::new();
    if let Err(err) = decode_message(bytes, &mut output) {
        let _ = write!(output, "<{err}>");
    }
    output
}

/// Parses a Mach message's descriptors and decodes its root XPC dictionary.
fn decode_message(bytes: &[u8], output: &mut String) -> Result<(), DecodeError> {
    let word = |offset: usize| -> Result<u32, DecodeError> {
        match bytes.get(offset..offset + 4) {
            Some(word) => Ok(u32::from_le_bytes(word.try_into().expect("four bytes"))),
            None => Err(DecodeError::Invalid("message truncated")),
        }
    };
    let bits = word(0)?;
    let size = word(4)? as usize;
    let end = size.min(bytes.len());
    let mut position = HEADER_SIZE;
    let mut descriptors = Vec::new();
    if bits & COMPLEX != 0 {
        let count = word(position)?;
        if count > DESCRIPTOR_LIMIT {
            return Err(DecodeError::Invalid("too many descriptors"));
        }
        position += BODY_SIZE;
        for _ in 0..count {
            let kind = match bytes.get(position + DESCRIPTOR_TYPE) {
                Some(kind) => *kind,
                None => return Err(DecodeError::Invalid("message truncated")),
            };
            if kind == PORT_DESCRIPTOR {
                descriptors.push(Descriptor::Port {
                    name: word(position)?,
                    disposition: bytes[position + DESCRIPTOR_DISPOSITION],
                });
                position += PORT_DESCRIPTOR_SIZE;
            }
            else {
                descriptors.push(Descriptor::Other);
                position += WIDE_DESCRIPTOR_SIZE;
            }
        }
    }
    let root = position + WIRE_PREFIX;
    if root + 4 > end || word(root)? != WIRE_DICTIONARY {
        return Err(DecodeError::Invalid("not an XPC message"));
    }
    let mut wire = Wire {
        bytes,
        position: root,
        end,
        descriptors: &descriptors,
        complex: bits & COMPLEX != 0,
        descriptor: 0,
        nodes: 0,
    };
    let result = wire_value(&mut wire, 0, output);
    if size > bytes.len() {
        output.push_str("<message truncated>");
    }
    result
}

/// Decodes one XPC wire value and the containers below it.
fn wire_value(wire: &mut Wire<'_>, depth: usize, output: &mut String) -> Result<(), DecodeError> {
    let id = wire.word()?;
    if depth >= DEPTH_LIMIT || wire.nodes >= NODE_LIMIT {
        output.push_str("<wire graph truncated>");
        return Err(DecodeError::Invalid("wire traversal limit"));
    }
    wire.nodes += 1;
    match id {
        0x1000 => output.push_str("null"),
        0x2000 => match wire.word()? {
            0 => output.push_str("false"),
            1 => output.push_str("true"),
            _ => return Err(DecodeError::Invalid("invalid wire boolean")),
        },
        0x3000 => {
            let _ = write!(output, "{}", wire.wide()? as i64);
        }
        0x7000 => {
            let _ = write!(output, "date<unix-ns={}>", wire.wide()? as i64);
        }
        0x4000 => {
            let _ = write!(output, "{}", wire.wide()?);
        }
        0x5000 => {
            let _ = write!(output, "{}", f64::from_bits(wire.wide()?));
        }
        0xa000 => {
            let position = wire.take(16)?;
            append_data(output, &wire.bytes[position..position + 16]);
        }
        0xb000 | 0xd000 | 0x12000 => {
            let kind = match id {
                0xb000 => "fileport",
                0xd000 => "mach-send",
                _ => "endpoint",
            };
            match wire.port()? {
                (0, _) => {
                    let _ = write!(output, "{kind}<null>");
                }
                (name, PORT_SEND) => {
                    let _ = write!(output, "{kind}<local-port={name}>");
                }
                (name, disposition) => {
                    let _ = write!(
                        output,
                        "{kind}<local-port={name} disposition={disposition}>"
                    );
                }
            }
        }
        0x8000 | 0x9000 => {
            let length = wire.word()?;
            if id == 0x8000 && wire.complex && length > WIRE_INLINE_DATA {
                return Err(DecodeError::Invalid(
                    "out-of-line wire data requires guest mapping",
                ));
            }
            let position = wire.take((length as usize + 3) & !3)?;
            let value = &wire.bytes[position..position + length as usize];
            if id == 0x9000 {
                match value.split_last() {
                    Some((0, text)) => {
                        output.push_str(&quote_bytes(&text[..text.len().min(STRING_LIMIT)]));
                        if text.len() > STRING_LIMIT {
                            output.push_str("<truncated>");
                        }
                    }
                    _ => return Err(DecodeError::Invalid("unterminated wire string")),
                }
            }
            else {
                append_data(output, &value[..value.len().min(DATA_LIMIT)]);
                if value.len() > DATA_LIMIT {
                    output.push_str("<truncated>");
                }
                let _ = write!(output, "<length={length}>");
            }
        }
        0xe000 | 0xf000 | 0x10000 => {
            let size = wire.word()? as usize;
            if size < 4 {
                return Err(DecodeError::Invalid("short wire container"));
            }
            let start = wire.take((size + 3) & !3)?;
            let mut child = wire.child(start, size);
            let count = child.word()? as usize;
            let dictionary = id != 0xe000;
            output.push(if dictionary { '{' } else { '[' });
            let mut result = Ok(());
            for index in 0..count.min(ENTRY_LIMIT) {
                if index != 0 {
                    output.push_str(", ");
                }
                if dictionary {
                    match child.key() {
                        Ok(key) => output.push_str(&key),
                        Err(err) => {
                            result = Err(err);
                            break;
                        }
                    }
                    output.push_str(": ");
                }
                result = wire_value(&mut child, depth + 1, output);
                if result.is_err() {
                    break;
                }
            }
            if result.is_ok() && count > ENTRY_LIMIT {
                output.push_str(", <entries truncated>");
            }
            output.push(if dictionary { '}' } else { ']' });
            wire.descriptor = child.descriptor;
            wire.nodes = child.nodes;
            result?;
        }
        _ => {
            let _ = write!(output, "<unsupported wire type 0x{id:x}>");
            return Err(DecodeError::Invalid(
                "wire cursor cannot skip this type safely",
            ));
        }
    }
    Ok(())
}

/// Strips arm64e data PAC bits without claiming to authenticate a pointer.
fn pointer(raw: u64) -> u64 {
    Arch::canonical_address(raw).0
}

/// Reads at most a caller-supplied byte cap from an explicit-length buffer.
fn bounded_bytes(
    vmi: &VmiContext<MacOs<Driver>>,
    address: u64,
    length: u64,
    cap: usize,
) -> Result<Vec<u8>, DecodeError> {
    let size = length.min(cap as u64) as usize;
    address
        .checked_add(size as u64)
        .ok_or(DecodeError::Invalid("buffer address overflow"))?;
    let mut bytes = vec![0; size];
    if size != 0 {
        if address == 0 {
            return Err(DecodeError::Invalid("null nonempty buffer"));
        }
        vmi.read(Va(address), &mut bytes)?;
    }
    Ok(bytes)
}

/// Escapes a Unicode scalar for an unambiguous single-line string.
fn escaped(output: &mut String, character: char) {
    match character {
        '"' => output.push_str("\\\""),
        '\\' => output.push_str("\\\\"),
        '\n' => output.push_str("\\n"),
        '\r' => output.push_str("\\r"),
        '\t' => output.push_str("\\t"),
        character if character.is_control() => {
            let _ = write!(output, "\\u{{{:x}}}", character as u32);
        }
        character => output.push(character),
    }
}

/// Quotes UTF-8 bytes, preserving invalid bytes explicitly rather than
/// replacing them.
fn quote_bytes(bytes: &[u8]) -> String {
    let mut output = String::from("\"");
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                for character in text.chars() {
                    escaped(&mut output, character);
                }
                break;
            }
            Err(err) => {
                let valid = err.valid_up_to();
                if let Ok(text) = std::str::from_utf8(&remaining[..valid]) {
                    for character in text.chars() {
                        escaped(&mut output, character);
                    }
                }
                let invalid = err.error_len().unwrap_or(remaining.len() - valid);
                for byte in &remaining[valid..valid + invalid] {
                    let _ = write!(output, "\\x{byte:02x}");
                }
                remaining = &remaining[valid + invalid..];
            }
        }
    }
    output.push('"');
    output
}

/// Preserves unpaired UTF-16 surrogates as explicit escaped code units.
fn append_utf16(output: &mut String, units: impl IntoIterator<Item = u16>) {
    for scalar in char::decode_utf16(units) {
        match scalar {
            Ok(character) => escaped(output, character),
            Err(err) => {
                let _ = write!(output, "\\u{{{:x}}}", err.unpaired_surrogate());
            }
        }
    }
}

/// Reads a bounded explicit-length native UTF-16 string.
fn utf16(
    vmi: &VmiContext<MacOs<Driver>>,
    address: u64,
    length: u64,
) -> Result<String, DecodeError> {
    let count = length.min(STRING_LIMIT as u64);
    let bytes = bounded_bytes(vmi, address, count * 2, STRING_LIMIT * 2)?;
    let mut output = String::from("\"");
    append_utf16(
        &mut output,
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit)),
    );
    output.push('"');
    if length > count {
        output.push_str("<truncated>");
    }
    Ok(output)
}

/// Reads a bounded null-terminated C string of an explicit code-unit width.
fn terminated(
    vmi: &VmiContext<MacOs<Driver>>,
    address: u64,
    width: u64,
    limit: usize,
) -> Result<String, DecodeError> {
    if width == 1 {
        let mut bytes = Vec::with_capacity(limit);
        for index in 0..limit {
            let byte = vmi.read_u8(Va(address
                .checked_add(index as u64)
                .ok_or(DecodeError::Invalid("C string address overflow"))?))?;
            if byte == 0 {
                return Ok(quote_bytes(&bytes));
            }
            bytes.push(byte);
        }
        let mut output = quote_bytes(&bytes);
        output.push_str("<truncated>");
        return Ok(output);
    }
    let mut units = Vec::with_capacity(limit);
    let mut ended = false;
    for index in 0..limit {
        let address = address
            .checked_add(index as u64 * width)
            .ok_or(DecodeError::Invalid("C string address overflow"))?;
        let unit = if width == 2 {
            u32::from(vmi.read_u16(Va(address))?)
        }
        else {
            vmi.read_u32(Va(address))?
        };
        if unit == 0 {
            ended = true;
            break;
        }
        units.push(unit);
    }
    let mut output = String::from("\"");
    if width == 2 {
        append_utf16(&mut output, units.into_iter().map(|unit| unit as u16));
    }
    else {
        for unit in units {
            match char::from_u32(unit) {
                Some(character) => escaped(&mut output, character),
                None => {
                    let _ = write!(output, "\\u{{{unit:x}}}<invalid scalar>");
                }
            }
        }
    }
    output.push('"');
    if !ended {
        output.push_str("<truncated>");
    }
    Ok(output)
}

/// Appends an unambiguous hexadecimal data prefix.
fn append_data(output: &mut String, bytes: &[u8]) {
    output.push_str("data<");
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output.push('>');
}

/// Decodes a compressed inline tagged payload with the guest's alphabet.
fn inline_tagged_string(payload: u64, alphabet: &[u8; 64]) -> Result<String, DecodeError> {
    let length = (payload & 15) as usize;
    if length > 11 {
        return Err(DecodeError::Invalid("invalid compressed tagged length"));
    }
    let mut packed = payload >> 4;
    let mut bytes = [0u8; 11];
    if length < 8 {
        bytes[..length].copy_from_slice(&packed.to_le_bytes()[..length]);
    }
    else {
        let shift = if length < 10 { 6 } else { 5 };
        for index in (0..length).rev() {
            bytes[index] = alphabet[(packed & ((1 << shift) - 1)) as usize];
            packed >>= shift;
        }
    }
    if bytes[..length].iter().any(|byte| *byte > 127) {
        return Err(DecodeError::Invalid("non-ASCII inline tagged string"));
    }
    Ok(quote_bytes(&bytes[..length]))
}

/// Deterministic representation, escaping and message decoding checks.
#[cfg(test)]
mod tests {
    use super::{append_utf16, inline_tagged_string, quote_bytes, render_message};

    /// The 26A434 CoreFoundation `sixBitToCharLookup` bytes.
    const ALPHABET: &[u8; 64] = b"eilotrm.apdnsIc ufkMShjTRxgC4013bDNvwyUL2O856P-B79AFKEWV_zGJ/HYX";

    /// Builds a Mach message around an XPC root dictionary body.
    fn message(complex: bool, descriptors: &[u8], entries: &[u8], count: u32) -> Vec<u8> {
        let mut body = count.to_le_bytes().to_vec();
        body.extend_from_slice(entries);
        let mut bytes = vec![0_u8; 24];
        if complex {
            bytes.extend_from_slice(&(descriptors.len() as u32 / 12).to_le_bytes());
            bytes.extend_from_slice(descriptors);
        }
        bytes.extend_from_slice(b"CPX@\x05\0\0\0");
        bytes.extend_from_slice(&0xf000_u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);
        let bits: u32 = if complex { 0x8000_0000 } else { 0 };
        let size = bytes.len() as u32;
        bytes[..4].copy_from_slice(&bits.to_le_bytes());
        bytes[4..8].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    /// Invalid bytes and terminal controls cannot disappear or create trace
    /// lines.
    #[test]
    fn escaping_preserves_invalid_bytes() {
        assert_eq!(quote_bytes(b"a\n\"\\\xff"), "\"a\\n\\\"\\\\\\xff\"");
    }

    /// Valid surrogate pairs and unpaired surrogates remain distinguishable.
    #[test]
    fn utf16_preserves_surrogate_boundaries() {
        let mut output = String::new();
        append_utf16(&mut output, [0xd83d, 0xde00, 0xd800]);
        assert_eq!(output, "\u{1f600}\\u{d800}");
    }

    /// Packed widths change at eight and ten characters and reject invalid
    /// lengths.
    #[test]
    fn tagged_compression_boundaries() {
        assert_eq!(
            inline_tagged_string((u64::from_le_bytes(*b"abcdefg\0") << 4) | 7, ALPHABET).unwrap(),
            "\"abcdefg\""
        );
        assert_eq!(
            inline_tagged_string((63 << 4) | 8, ALPHABET).unwrap(),
            "\"eeeeeeeX\""
        );
        assert_eq!(
            inline_tagged_string((31 << 4) | 10, ALPHABET).unwrap(),
            "\"eeeeeeeee3\""
        );
        assert!(inline_tagged_string(12, ALPHABET).is_err());
        assert!(inline_tagged_string((128 << 4) | 1, ALPHABET).is_err());
    }

    /// Keys, strings and integers decode after the header and XPC prefix.
    #[test]
    fn simple_message_decodes() {
        let mut entries = b"cmd\0".to_vec();
        entries.extend_from_slice(&0x9000_u32.to_le_bytes());
        entries.extend_from_slice(&5_u32.to_le_bytes());
        entries.extend_from_slice(b"open\0\0\0\0");
        entries.extend_from_slice(b"pid\0");
        entries.extend_from_slice(&0x3000_u32.to_le_bytes());
        entries.extend_from_slice(&42_u64.to_le_bytes());
        assert_eq!(
            render_message(&message(false, &[], &entries, 2)),
            "{\"cmd\": \"open\", \"pid\": 42}"
        );
    }

    /// Rights consume port descriptors in order and keep their disposition.
    #[test]
    fn rights_follow_descriptors() {
        let mut descriptors = Vec::new();
        for (name, disposition) in [(0x1503_u32, 17_u8), (0x2207, 19)] {
            descriptors.extend_from_slice(&name.to_le_bytes());
            descriptors.extend_from_slice(&[0, 0, 0, 0, 0, 0, disposition, 0]);
        }
        let mut entries = Vec::new();
        for key in [b"a\0\0\0", b"b\0\0\0"] {
            entries.extend_from_slice(key);
            entries.extend_from_slice(&0xd000_u32.to_le_bytes());
        }
        assert_eq!(
            render_message(&message(true, &descriptors, &entries, 2)),
            "{\"a\": mach-send<local-port=5379>, \"b\": mach-send<local-port=8711 disposition=19>}"
        );
    }

    /// A value running past the copied bytes stops with an explicit marker.
    #[test]
    fn truncated_message_is_marked() {
        let mut entries = b"k\0\0\0".to_vec();
        entries.extend_from_slice(&0x3000_u32.to_le_bytes());
        entries.extend_from_slice(&7_u64.to_le_bytes());
        let mut bytes = message(false, &[], &entries, 1);
        bytes.truncate(bytes.len() - 4);
        assert!(
            render_message(&bytes)
                .ends_with("<message truncated><wire value exceeds its container>")
        );
        assert_eq!(render_message(&bytes[..30]), "<not an XPC message>");
    }
}
