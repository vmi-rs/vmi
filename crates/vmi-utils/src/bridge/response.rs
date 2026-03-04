use super::arch::GpRegistersAdapter;

/// A response from the bridge.
///
/// Carries up to four architecture-mapped values and an optional typed
/// result. The values are written back into guest registers by
/// [`write_to`](Self::write_to); the result signals handler completion.
///
/// # Architecture-specific
///
/// - **AMD64**: value1–value4 map to `RAX`, `RBX`, `RCX`, `RDX`.
///
/// See the [`arch::amd64`](super::arch) module for the full register
/// layout.
#[derive(Debug)]
pub struct BridgeResponse<T = ()> {
    value1: Option<u64>,
    value2: Option<u64>,
    value3: Option<u64>,
    value4: Option<u64>,
    result: Option<T>,
}

impl<T> Default for BridgeResponse<T> {
    fn default() -> Self {
        Self {
            value1: None,
            value2: None,
            value3: None,
            value4: None,
            result: None,
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
            result: None,
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

    /// Returns a reference to the result of the response.
    pub fn result(&self) -> Option<&T> {
        self.result.as_ref()
    }

    /// Consumes the response and returns the result, if present.
    ///
    /// A `Some` value indicates that the handler has finished and the
    /// bridge dispatch loop should terminate.
    pub fn into_result(self) -> Option<T> {
        self.result
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

    /// Sets the completion result of the response.
    ///
    /// When present, signals that the handler has finished processing
    /// and the bridge dispatch loop should terminate.
    pub fn with_result(self, result: T) -> Self {
        Self {
            result: Some(result),
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
