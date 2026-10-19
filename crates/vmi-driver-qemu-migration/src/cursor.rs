use crate::Error;

/// A reader of the items of a migration stream.
///
/// QEMU writes integers in big-endian byte order (`qemu_put_be16`,
/// `qemu_put_be32` and `qemu_put_be64` in `migration/qemu-file.c`). A read
/// past the end of the stream fails with [`Error::Truncated`].
pub(crate) struct Cursor<'a> {
    /// The whole stream.
    data: &'a [u8],

    /// Offset of the next byte to read, at most the length of `data`.
    offset: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a cursor at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the offset of the next byte to read.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the next byte without reading it, or `None` at the end of the
    /// stream.
    pub fn peek(&self) -> Option<u8> {
        self.data.get(self.offset).copied()
    }

    /// Returns the bytes from `start` up to the next byte to read.
    ///
    /// `start` must not be past the offset of the cursor.
    pub fn since(&self, start: usize) -> &'a [u8] {
        &self.data[start..self.offset]
    }

    /// Reads `len` bytes.
    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        match self.offset.checked_add(len) {
            Some(end) if end <= self.data.len() => {
                let bytes = &self.data[self.offset..end];
                self.offset = end;
                Ok(bytes)
            }
            _ => Err(Error::Truncated {
                offset: self.offset as u64,
            }),
        }
    }

    /// Reads `N` bytes into an array.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        match self.data[self.offset..].first_chunk::<N>() {
            Some(array) => {
                self.offset += N;
                Ok(*array)
            }
            None => Err(Error::Truncated {
                offset: self.offset as u64,
            }),
        }
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian 16-bit integer.
    pub fn be16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian 32-bit integer.
    pub fn be32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian 64-bit integer.
    pub fn be64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Reads a name with a one-byte length prefix.
    ///
    /// QEMU writes section names, subsection names and RAM block names in
    /// this form.
    pub fn name(&mut self) -> Result<&'a str, Error> {
        let offset = self.offset;
        let len = self.u8()?;
        match std::str::from_utf8(self.bytes(usize::from(len))?) {
            Ok(name) => Ok(name),
            Err(_) => Err(Error::InvalidName {
                offset: offset as u64,
            }),
        }
    }
}
