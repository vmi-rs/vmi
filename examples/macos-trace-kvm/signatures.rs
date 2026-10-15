//! macOS signature lookup and argument rendering, backed by a [`sigmd`]
//! metadata archive built from the macOS SDK.
//!
//! The archive's `arm64` bucket holds C declarations from SDK headers and
//! frameworks, with omitted parameter names supplemented from man pages.
//! Live Objective-C declarations are decoded separately in [`crate::objc`].
//! Integer and pointer arguments use `x0`-`x7`, floating-point arguments use
//! `v0`-`v7`, and Apple stack arguments retain natural alignment rather than
//! fixed 8-byte slots. Unavailable vectors and unsupported aggregate values
//! remain unknown. Genuine variadic tails are not declared and are omitted.

use std::{fmt::Write as _, fs::File, path::PathBuf};

use anyhow::{Context as _, Error};
use memmap2::Mmap;
use sigmd::{Architecture, Database, Type, TypeKind};
use vmi::{Registers as _, Va, VmiContext, os::macos::MacOs};

use crate::{
    Driver,
    encoding::{AbiKind, AbiType},
    objc::ObjcRuntime,
    style::Palette,
    values::Values,
};

/// Number of general-purpose argument registers (`x0`-`x7`).
const GENERAL_REGISTERS: usize = 8;

/// Number of SIMD and floating-point argument registers (`v0`-`v7`).
const VECTOR_REGISTERS: usize = 8;

/// Read-only handle to the macOS signature database.
pub struct Signatures {
    /// Mapping of the archive file, validated by [`Signatures::load`].
    mmap: Mmap,
}

impl Signatures {
    /// Loads the metadata archive named by `SIGMD_METADATA`, or
    /// `assets/metadata.bin` next to this example if that variable is unset.
    pub fn load() -> Result<Self, Error> {
        let path = metadata_path();
        let file = File::open(&path)
            .with_context(|| format!("opening sigmd database {}", path.display()))?;

        // SAFETY: the file is opened read-only and the mapping is never resized
        // or written.
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("mapping sigmd database {}", path.display()))?;

        let db = Database::from_bytes(&mmap)
            .map_err(|err| anyhow::anyhow!("invalid sigmd archive: {err}"))?;

        let count = db.bucket(Architecture::Arm64).functions().len();
        if count == 0 {
            anyhow::bail!(
                "sigmd database {} has no arm64 signatures; build it with sigmd-macos.yaml",
                path.display()
            );
        }

        tracing::info!(functions = count, path = %path.display(), "loaded signatures");
        Ok(Self { mmap })
    }

    /// Returns the archived database.
    fn database(&self) -> Database<'_> {
        // SAFETY: `load` validated the archive, and the read-only mapping
        // does not change afterwards.
        unsafe { Database::from_bytes_unchecked(&self.mmap) }
    }

    /// Captures C arguments and the declared return ABI at function entry.
    ///
    /// Returns `None` when no declaration exists for the exported function.
    pub fn prepare_call(
        &self,
        vmi: &VmiContext<MacOs<Driver>>,
        function: &str,
        values: &mut Values,
        objc: &mut ObjcRuntime,
        palette: &Palette,
    ) -> Option<(String, AbiType)> {
        let name = match function.split_once('$') {
            Some((name, _)) => name,
            None => function,
        };
        let func = self.database().bucket(Architecture::Arm64).function(name)?;
        let mut locator = ArgumentLocator::default();
        let mut out = String::from("(");
        for (position, param) in func.parameters().enumerate() {
            if position > 0 {
                out.push_str(", ");
            }
            let ty = abi_type(&param.ty());
            let value = match read_argument(vmi, locator.next(&ty)) {
                Some(raw) if name == "execve" && position == 1 => values.argv(vmi, raw, palette),
                Some(raw) => values.render(vmi, &ty, raw, objc, palette),
                None => String::from("?"),
            };
            let name = match param.name() {
                Some(name) => palette.arg_name(name),
                None => palette.arg_name(&format!("arg{}", param.index())),
            };
            let _ = write!(out, "{name}{}{value}", palette.equals());
        }
        out.push(')');
        Some((out, abi_type(&func.return_ty())))
    }
}

/// Location of an argument at function entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    /// General-purpose register `x<n>`.
    General(usize),

    /// SIMD and floating-point register, which the event does not carry.
    Vector,

    /// Stack slot at `offset` bytes above the entry stack pointer.
    Stack {
        /// Offset from the stack pointer, in bytes.
        offset: u64,

        /// Size of the argument, in bytes.
        size: u64,
    },

    /// Not known, because the argument or an earlier one is passed in a way
    /// the declaration does not describe.
    Unknown,
}

/// Assigns locations to the declared arguments of one call in order.
#[derive(Debug, Default)]
pub struct ArgumentLocator {
    /// Next general-purpose register number.
    general: usize,

    /// Next SIMD and floating-point register number.
    vector: usize,

    /// Next free byte of the stack argument area.
    stack: u64,

    /// Set after an argument whose size is unknown, which leaves the
    /// location of every later argument unknown too.
    lost: bool,
}

impl ArgumentLocator {
    /// Creates a locator after the dispatcher's implicit general registers.
    pub fn with_general(general: usize) -> Self {
        Self {
            general,
            ..Self::default()
        }
    }

    /// Reads a fixed argument while preserving locations of following values.
    pub fn argument(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        ty: &AbiType,
        values: &mut Values,
        objc: &mut ObjcRuntime,
        palette: &Palette,
    ) -> String {
        match read_argument(vmi, self.next(ty)) {
            Some(raw) => values.render(vmi, ty, raw, objc, palette),
            None => String::from("?"),
        }
    }

    /// Assigns the next register or naturally aligned Apple stack slot.
    fn next(&mut self, ty: &AbiType) -> Location {
        if self.lost {
            return Location::Unknown;
        }
        if ty.kind == AbiKind::Unknown || ty.size == 0 || ty.alignment == 0 {
            self.lost = true;
            return Location::Unknown;
        }
        let aggregate = ty.kind == AbiKind::Aggregate;
        let indirect = aggregate && ty.size > 16;
        let size = if indirect { 8 } else { ty.size };
        let alignment = if indirect { 8 } else { ty.alignment };
        if ty.kind == AbiKind::Float {
            if self.vector < VECTOR_REGISTERS {
                self.vector += 1;
                return Location::Vector;
            }
        }
        else {
            let words = size.div_ceil(8) as usize;
            if self.general + words <= GENERAL_REGISTERS {
                let index = self.general;
                self.general += words;
                return if aggregate {
                    Location::Unknown
                }
                else {
                    Location::General(index)
                };
            }
            self.general = GENERAL_REGISTERS;
        }
        let offset = self.stack.next_multiple_of(alignment);
        self.stack = offset + size;
        if aggregate {
            Location::Unknown
        }
        else {
            Location::Stack { offset, size }
        }
    }
}

/// Reads the raw value of an argument at `location`, or returns `None` when
/// the value is not available.
fn read_argument(vmi: &VmiContext<MacOs<Driver>>, location: Location) -> Option<u64> {
    let registers = vmi.registers();
    match location {
        Location::General(index) => Some(registers.regs[index]),
        Location::Stack { offset, size } => {
            let va = Va(registers.stack_pointer()) + offset;
            let value = match size {
                1 => vmi.read_u8(va).map(u64::from),
                2 => vmi.read_u16(va).map(u64::from),
                4 => vmi.read_u32(va).map(u64::from),
                _ => vmi.read_u64(va),
            };
            value.ok()
        }
        Location::Vector | Location::Unknown => None,
    }
}

/// Converts archived C types without retaining pointers into an event frame.
fn abi_type(ty: &Type<'_>) -> AbiType {
    if ty.indirections() > 0 {
        let kind = if ty.indirections() == 1 {
            match ty.kind() {
                TypeKind::Char8 => AbiKind::CString,
                TypeKind::Char16 => AbiKind::CString16,
                TypeKind::Char32 => AbiKind::CString32,
                TypeKind::Unknown if ty.name() == "SEL" => AbiKind::Selector,
                TypeKind::Unknown if ty.name() == "Class" => AbiKind::Class,
                TypeKind::Unknown if matches!(ty.name(), "id" | "instancetype" | "__CFString") => {
                    AbiKind::Object
                }
                _ => AbiKind::Pointer,
            }
        }
        else {
            AbiKind::Pointer
        };
        return AbiType {
            kind,
            size: 8,
            alignment: 8,
        };
    }
    let (kind, size) = match ty.kind() {
        TypeKind::Bool => (AbiKind::Bool, 1),
        TypeKind::I8 => (AbiKind::Signed, 1),
        TypeKind::I16 => (AbiKind::Signed, 2),
        TypeKind::I32 => (AbiKind::Signed, 4),
        TypeKind::I64 => (AbiKind::Signed, 8),
        TypeKind::Char8 | TypeKind::U8 => (AbiKind::Unsigned, 1),
        TypeKind::Char16 | TypeKind::U16 => (AbiKind::Unsigned, 2),
        TypeKind::Char32 | TypeKind::U32 => (AbiKind::Unsigned, 4),
        TypeKind::U64 => (AbiKind::Unsigned, 8),
        TypeKind::F32 => (AbiKind::Float, 4),
        TypeKind::F64 => (AbiKind::Float, 8),
        TypeKind::Void => (AbiKind::Void, 0),
        TypeKind::Unknown | TypeKind::Custom(_) => (AbiKind::Unknown, 0),
    };
    AbiType {
        kind,
        size,
        alignment: size.max(1),
    }
}

/// Resolves the metadata database path: the `SIGMD_METADATA` override if set,
/// otherwise `assets/metadata.bin` next to this example.
fn metadata_path() -> PathBuf {
    match std::env::var_os("SIGMD_METADATA") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/macos-trace-kvm/assets/metadata.bin"
        )),
    }
}
