//! Page table monitor unit tests, one module per supported architecture.

#[cfg(feature = "arch-amd64")]
mod amd64;

#[cfg(feature = "arch-arm64")]
mod arm64;
