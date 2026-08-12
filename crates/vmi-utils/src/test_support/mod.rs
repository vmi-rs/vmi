//! Deterministic state and operations for VMI unit tests.

mod amd64;

pub(crate) use self::amd64::{Amd64TestVm, DriverCall, DriverFault};
