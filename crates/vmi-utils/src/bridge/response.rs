use super::arch::GpRegistersAdapter;

/// A response from the bridge.
///
/// `value1`-`value4` are written into guest registers by
/// [`write_to`](Self::write_to). `output` is returned to the caller and is not
/// sent to the guest.
///
/// # Architecture-specific
///
/// - **AMD64**: value1-value4 map to `RAX`, `RBX`, `RCX`, `RDX`.
#[derive(Debug)]
pub struct BridgeResponse<T = ()> {
    value1: Option<u64>,
    value2: Option<u64>,
    value3: Option<u64>,
    value4: Option<u64>,
    output: Option<T>,
}

impl<T> Default for BridgeResponse<T> {
    fn default() -> Self {
        Self {
            value1: None,
            value2: None,
            value3: None,
            value4: None,
            output: None,
        }
    }
}

impl<T> BridgeResponse<T> {
    /// Creates a new response with the first value set.
    pub fn new(value1: u64) -> Self {
        Self {
            value1: Some(value1),
            value2: None,
            value3: None,
            value4: None,
            output: None,
        }
    }

    /// Returns the first value of the response.
    pub fn value1(&self) -> Option<u64> {
        self.value1
    }

    /// Returns the second value of the response.
    pub fn value2(&self) -> Option<u64> {
        self.value2
    }

    /// Returns the third value of the response.
    pub fn value3(&self) -> Option<u64> {
        self.value3
    }

    /// Returns the fourth value of the response.
    pub fn value4(&self) -> Option<u64> {
        self.value4
    }

    /// Returns a reference to the output of the response.
    pub fn output(&self) -> Option<&T> {
        self.output.as_ref()
    }

    /// Consumes the response and returns the output, if present.
    ///
    /// A `Some` value can indicate that the handler has finished and the
    /// bridge dispatch loop should terminate.
    pub fn into_output(self) -> Option<T> {
        self.output
    }

    /// Sets the first value of the response.
    pub fn with_value1(self, value1: u64) -> Self {
        Self {
            value1: Some(value1),
            ..self
        }
    }

    /// Sets the second value of the response.
    pub fn with_value2(self, value2: u64) -> Self {
        Self {
            value2: Some(value2),
            ..self
        }
    }

    /// Sets the third value of the response.
    pub fn with_value3(self, value3: u64) -> Self {
        Self {
            value3: Some(value3),
            ..self
        }
    }

    /// Sets the fourth value of the response.
    pub fn with_value4(self, value4: u64) -> Self {
        Self {
            value4: Some(value4),
            ..self
        }
    }

    /// Sets the output of the response.
    ///
    /// When present, it can signal that the handler has finished processing
    /// and the bridge dispatch loop should terminate.
    pub fn with_output(self, output: T) -> Self {
        Self {
            output: Some(output),
            ..self
        }
    }

    /// Writes the response values into the given general-purpose registers.
    ///
    /// `None` values leave the corresponding register unchanged.
    pub fn write_to(&self, registers: &mut impl GpRegistersAdapter) {
        registers.write_response(self.value1, self.value2, self.value3, self.value4);
    }
}
