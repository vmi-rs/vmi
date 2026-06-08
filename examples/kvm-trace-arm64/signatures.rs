//! Windows API signature lookup and argument rendering, backed by a [`sigmd`]
//! metadata archive.
//!
//! The archive is a single rkyv blob (`mmap`-and-go, no parse step) keyed by
//! architecture. The arm64 guest follows AAPCS64, but sigmd ships only x86/x64
//! signatures. x64 is the right bucket: argument count, declaration order, and
//! pointer width (8 bytes) all match arm64, and the leaf type kinds (`int`,
//! `wchar_t *`, ...) are architecture-neutral. Only the register mapping
//! differs, and `function_argument` already abstracts that (x0-x7 then stack).

use std::{fmt::Write as _, fs::File, path::PathBuf};

use anyhow::{Context as _, Error};
use memmap2::Mmap;
use sigmd::{Architecture, Database, Type, TypeKind};
use vmi::{Va, VmiContext, os::windows::WindowsOs};

use crate::Driver;

/// Maximum characters read when dereferencing a string argument, bounding the
/// per-call guest read.
const STRING_LIMIT: usize = 256;

/// Read-only handle to the bundled Windows API signature database.
pub struct Signatures {
    /// The x64 signature bucket, borrowed from the leaked archive mapping.
    db: Database<'static>,
}

impl Signatures {
    /// Loads the metadata archive named by `SIGMD_METADATA`, or the bundled
    /// `assets/metadata.bin` if that variable is unset.
    pub fn load() -> Result<Self, Error> {
        let path = metadata_path();
        let file = File::open(&path)
            .with_context(|| format!("opening sigmd database {}", path.display()))?;

        // SAFETY: the file is opened read-only and the mapping is never resized
        // or written. It is leaked below, so it outlives every borrow of it.
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("mapping sigmd database {}", path.display()))?;

        // Leak the mapping so the archive's backing bytes live for the whole
        // process, which lets the borrowed `Database` handle be `'static` and
        // stored alongside the tracer. The map is released at process exit.
        let bytes = &Box::leak(Box::new(mmap))[..];
        let db = Database::from_bytes(bytes)
            .map_err(|err| anyhow::anyhow!("invalid sigmd archive: {err}"))?;

        Ok(Self { db })
    }

    /// Formats the live argument list for `function` as `(name=value, ...)`,
    /// reading each value from the guest per AAPCS64.
    ///
    /// Returns `None` when the function is absent from the database, so the
    /// caller can fall back to printing the bare `module!function`.
    pub fn format_call(
        &self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        function: &str,
    ) -> Option<String> {
        let func = self.db.bucket(Architecture::X64).function(function)?;

        let mut out = String::from("(");
        for (position, param) in func.input_parameters().enumerate() {
            if position > 0 {
                out.push_str(", ");
            }

            // `function_argument` maps the declaration index to x0-x7 or the
            // stack above SP_EL0. A stack read can fault, which renders "?".
            let value = match vmi.os().function_argument(param.index() as u64) {
                Ok(raw) => render_argument(vmi, param.ty(), raw),
                Err(_) => String::from("?"),
            };

            match param.name() {
                Some(name) => {
                    let _ = write!(out, "{name}={value}");
                }
                None => {
                    let _ = write!(out, "arg{}={value}", param.index());
                }
            }
        }
        out.push(')');
        Some(out)
    }
}

/// Renders a single argument from its declared type and raw register value.
///
/// Pointers print as `NULL` or `0x...`, except `char *` / `wchar_t *`, which
/// are dereferenced into a quoted string. Scalars print by kind: signed as
/// decimal, unsigned as hex, `bool` as `TRUE`/`FALSE`. A failed string
/// dereference, or a value whose real home is a SIMD register (`f32`/`f64`,
/// which AAPCS64 passes outside x0-x7), renders "?".
fn render_argument(vmi: &VmiContext<WindowsOs<Driver>>, ty: Type<'_>, raw: u64) -> String {
    if ty.indirections() >= 1 {
        if raw == 0 {
            return String::from("NULL");
        }
        if ty.indirections() == 1 {
            match ty.kind() {
                TypeKind::Char8 => {
                    return match vmi.read_string_limited(Va(raw), STRING_LIMIT) {
                        Ok(string) => format!("{string:?}"),
                        Err(_) => String::from("?"),
                    };
                }
                TypeKind::Char16 => {
                    return match vmi.read_string_utf16_limited(Va(raw), STRING_LIMIT) {
                        Ok(string) => format!("{string:?}"),
                        Err(_) => String::from("?"),
                    };
                }
                _ => {}
            }
        }
        return format!("0x{raw:x}");
    }

    match ty.kind() {
        TypeKind::Bool => String::from(if raw & 0xff != 0 { "TRUE" } else { "FALSE" }),
        TypeKind::Char8 => format!("0x{:x}", raw as u8),
        TypeKind::Char16 => format!("0x{:x}", raw as u16),
        TypeKind::I8 => (raw as u8 as i8 as i64).to_string(),
        TypeKind::I16 => (raw as u16 as i16 as i64).to_string(),
        TypeKind::I32 => (raw as u32 as i32 as i64).to_string(),
        TypeKind::I64 => (raw as i64).to_string(),
        TypeKind::U8 => format!("0x{:x}", raw as u8),
        TypeKind::U16 => format!("0x{:x}", raw as u16),
        TypeKind::U32 => format!("0x{:x}", raw as u32),
        TypeKind::U64 => format!("0x{raw:x}"),
        TypeKind::F32 | TypeKind::F64 => String::from("?"),
        TypeKind::Void | TypeKind::Unknown | TypeKind::Custom(_) => format!("0x{raw:x}"),
    }
}

/// Resolves the metadata database path: the `SIGMD_METADATA` override if set,
/// otherwise `assets/metadata.bin` next to this example.
fn metadata_path() -> PathBuf {
    match std::env::var_os("SIGMD_METADATA") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/kvm-trace-arm64/assets/metadata.bin"
        )),
    }
}
