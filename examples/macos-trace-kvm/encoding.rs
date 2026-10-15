//! Bounded Objective-C type encoding parsing for Apple's arm64 ABI.

/// Representation of a fixed method argument or result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiKind {
    /// An encoding without a safely known scalar or aggregate ABI.
    Unknown,
    /// No returned value.
    Void,
    /// An Objective-C Boolean.
    Bool,
    /// A signed integer.
    Signed,
    /// An unsigned integer.
    Unsigned,
    /// A floating-point scalar, excluded from method result tracing.
    Float,
    /// An untyped or typed data pointer.
    Pointer,
    /// A null-terminated byte string.
    CString,
    /// A null-terminated UTF-16 string supplied by C metadata.
    CString16,
    /// A null-terminated UTF-32 string supplied by C metadata.
    CString32,
    /// An Objective-C object reference.
    Object,
    /// An Objective-C class reference.
    Class,
    /// An interned Objective-C selector.
    Selector,
    /// An Objective-C block reference.
    Block,
    /// An aggregate with known storage layout, not a scalar register value.
    Aggregate,
}

/// Storage size and natural alignment of an encoded type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiType {
    /// Scalar interpretation or aggregate classification.
    pub kind: AbiKind,
    /// Bytes in the storage representation, zero when unknown.
    pub size: u64,
    /// Natural arm64 alignment in bytes.
    pub alignment: u64,
}

impl AbiType {
    /// Constructs a type with its natural scalar alignment.
    pub const fn scalar(kind: AbiKind, size: u64) -> Self {
        Self {
            kind,
            size,
            alignment: if size == 0 { 1 } else { size },
        }
    }
}

/// Declared fixed method ABI, including the hidden receiver and selector.
#[derive(Debug, Clone)]
pub struct MethodSignature {
    /// Declared result type after removing qualifiers.
    pub result: AbiType,
    /// Fixed arguments, with receiver and selector at indices zero and one.
    pub arguments: Vec<AbiType>,
}

/// Maximum accepted encoding length, matching the runtime reader bound.
const MAX_ENCODING: usize = 4096;
/// Maximum nesting of pointer and aggregate encodings.
const MAX_DEPTH: usize = 32;
/// Maximum number of fixed arguments in a method declaration.
const MAX_ARGUMENTS: usize = 128;
/// Maximum aggregate layout accepted from untrusted guest metadata.
const MAX_SIZE: u64 = 16 * 1024 * 1024;

/// Parses a complete encoding without interpreting numeric argument offsets.
///
/// Opaque aggregates and bitfields remain unknown instead of assigning a
/// guessed ABI. Aggregate storage layout does not assert HFA register layout.
/// True variadic tails are absent from runtime encodings and remain omitted.
pub fn parse_method_encoding(encoding: &str) -> Option<MethodSignature> {
    if encoding.is_empty() || encoding.len() > MAX_ENCODING || !encoding.is_ascii() {
        return None;
    }
    let mut parser = Parser {
        bytes: encoding.as_bytes(),
        position: 0,
    };
    let result = parser.ty(0)?;
    parser.offset()?;
    let mut arguments = Vec::new();
    while parser.position < parser.bytes.len() {
        if arguments.len() == MAX_ARGUMENTS {
            return None;
        }
        arguments.push(parser.ty(0)?);
        parser.offset()?;
    }
    if arguments.len() < 2
        || !matches!(arguments[0].kind, AbiKind::Object | AbiKind::Class)
        || arguments[1].kind != AbiKind::Selector
    {
        return None;
    }
    Some(MethodSignature { result, arguments })
}

/// Cursor over an ASCII encoding with checked size arithmetic.
struct Parser<'a> {
    /// Complete bounded encoding.
    bytes: &'a [u8],
    /// Next unread byte.
    position: usize,
}

impl Parser<'_> {
    /// Reads one byte while advancing the cursor.
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.position)?;
        self.position += 1;
        Some(byte)
    }

    /// Skips frame and argument offsets, including signed offsets.
    fn offset(&mut self) -> Option<()> {
        if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
            self.position += 1;
            if !self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                return None;
            }
        }
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_digit)
        {
            self.position += 1;
        }
        Some(())
    }

    /// Reads a checked decimal count.
    fn count(&mut self) -> Option<u64> {
        let start = self.position;
        let mut count = 0_u64;
        while let Some(byte) = self
            .bytes
            .get(self.position)
            .filter(|byte| byte.is_ascii_digit())
        {
            count = count
                .checked_mul(10)?
                .checked_add(u64::from(*byte - b'0'))?;
            self.position += 1;
        }
        (self.position != start).then_some(count)
    }

    /// Consumes a quoted class or field name without allocating it.
    fn quoted(&mut self) -> Option<()> {
        if self.byte()? != b'"' {
            return None;
        }
        loop {
            match self.byte()? {
                b'"' => return Some(()),
                b'\\' => {
                    self.byte()?;
                }
                _ => {}
            }
        }
    }

    /// Parses a type, recursively bounding aggregate and pointer nesting.
    fn ty(&mut self, depth: usize) -> Option<AbiType> {
        if depth >= MAX_DEPTH {
            return None;
        }
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| b"rnNoORVA".contains(byte))
        {
            self.position += 1;
        }
        let scalar = |kind, size| Some(AbiType::scalar(kind, size));
        match self.byte()? {
            b'v' => scalar(AbiKind::Void, 0),
            b'B' => scalar(AbiKind::Bool, 1),
            b'c' => scalar(AbiKind::Signed, 1),
            b'C' => scalar(AbiKind::Unsigned, 1),
            b's' => scalar(AbiKind::Signed, 2),
            b'S' => scalar(AbiKind::Unsigned, 2),
            b'i' => scalar(AbiKind::Signed, 4),
            b'I' => scalar(AbiKind::Unsigned, 4),
            b'l' | b'q' => scalar(AbiKind::Signed, 8),
            b'L' | b'Q' => scalar(AbiKind::Unsigned, 8),
            b'f' => scalar(AbiKind::Float, 4),
            b'd' | b'D' => scalar(AbiKind::Float, 8),
            b'*' => scalar(AbiKind::CString, 8),
            b'#' => scalar(AbiKind::Class, 8),
            b':' => scalar(AbiKind::Selector, 8),
            b'@' => {
                if self.bytes.get(self.position) == Some(&b'?') {
                    self.position += 1;
                    scalar(AbiKind::Block, 8)
                }
                else {
                    if self.bytes.get(self.position) == Some(&b'"') {
                        self.quoted()?;
                    }
                    scalar(AbiKind::Object, 8)
                }
            }
            b'^' => {
                self.ty(depth + 1)?;
                scalar(AbiKind::Pointer, 8)
            }
            b'?' => scalar(AbiKind::Unknown, 0),
            b'b' => {
                self.count()?;
                scalar(AbiKind::Unknown, 0)
            }
            b'j' => {
                self.ty(depth + 1)?;
                scalar(AbiKind::Unknown, 0)
            }
            b'[' => {
                let count = self.count()?;
                let element = self.ty(depth + 1)?;
                if self.byte()? != b']' {
                    return None;
                }
                if matches!(
                    element.kind,
                    AbiKind::Unknown | AbiKind::Void | AbiKind::Float
                ) {
                    return scalar(AbiKind::Unknown, 0);
                }
                let size = element.size.checked_mul(count)?;
                if size > MAX_SIZE {
                    return None;
                }
                Some(AbiType {
                    kind: AbiKind::Aggregate,
                    size,
                    alignment: element.alignment,
                })
            }
            b'{' => self.aggregate(depth, b'}', false),
            b'(' => self.aggregate(depth, b')', true),
            _ => None,
        }
    }

    /// Computes ordinary struct or union layout while preserving uncertainty.
    fn aggregate(&mut self, depth: usize, close: u8, union: bool) -> Option<AbiType> {
        while !matches!(self.bytes.get(self.position), Some(b'=') | None)
            && self.bytes.get(self.position) != Some(&close)
        {
            self.position += 1;
        }
        if self.byte()? == close {
            return Some(AbiType::scalar(AbiKind::Unknown, 0));
        }
        let mut size = 0_u64;
        let mut alignment = 1;
        let mut unknown = false;
        while self.bytes.get(self.position) != Some(&close) {
            if self.bytes.get(self.position) == Some(&b'"') {
                self.quoted()?;
            }
            let field = self.ty(depth + 1)?;
            unknown |= matches!(
                field.kind,
                AbiKind::Unknown | AbiKind::Void | AbiKind::Float
            );
            alignment = alignment.max(field.alignment);
            size = if union {
                size.max(field.size)
            }
            else {
                align(size, field.alignment)?.checked_add(field.size)?
            };
            if size > MAX_SIZE {
                return None;
            }
        }
        self.position += 1;
        if unknown {
            return Some(AbiType::scalar(AbiKind::Unknown, 0));
        }
        Some(AbiType {
            kind: AbiKind::Aggregate,
            size: align(size, alignment)?,
            alignment,
        })
    }
}

/// Rounds a layout offset to a power-of-two natural alignment.
fn align(size: u64, alignment: u64) -> Option<u64> {
    Some(size.checked_add(alignment - 1)? & !(alignment - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nested aggregate layouts and qualifiers must not corrupt later
    /// arguments.
    #[test]
    fn nested_and_qualified() {
        let signature = parse_method_encoding("rQ48@0:8{Pair=ci[2{Item=sq}]}16@?40").unwrap();
        assert_eq!(signature.result, AbiType::scalar(AbiKind::Unsigned, 8));
        assert_eq!(
            signature.arguments[2],
            AbiType {
                kind: AbiKind::Aggregate,
                size: 40,
                alignment: 8
            }
        );
        assert_eq!(signature.arguments[3].kind, AbiKind::Block);
        assert_eq!(
            parse_method_encoding("Vv16@0:8").unwrap().result.kind,
            AbiKind::Void
        );
        assert_eq!(
            parse_method_encoding("rd16@0:8").unwrap().result.kind,
            AbiKind::Float
        );
    }

    /// Malformed, overflowing and deeply recursive encodings are rejected.
    #[test]
    fn bounded_and_malformed() {
        assert!(parse_method_encoding("v24@0:8[18446744073709551616c]16").is_none());
        assert!(parse_method_encoding("v24@0:8{Broken=i16").is_none());
        assert!(parse_method_encoding("v24@0:8@\"Broken16").is_none());
        assert!(parse_method_encoding(&format!("v24@0:8{}i16", "^".repeat(MAX_DEPTH))).is_none());
        assert!(parse_method_encoding("v8i0").is_none());
        assert!(parse_method_encoding("v-@0:8").is_none());
        assert_eq!(
            parse_method_encoding("v24@0:8^{Opaque}16")
                .unwrap()
                .arguments[2]
                .kind,
            AbiKind::Pointer
        );
        assert_eq!(
            parse_method_encoding("v24@0:8{Bits=b3b5}16")
                .unwrap()
                .arguments[2]
                .kind,
            AbiKind::Unknown
        );
    }
}
