//! VMI utilities

#[cfg(feature = "bpm")]
pub mod bpm;

#[cfg(feature = "injector")]
pub mod injector;

#[cfg(feature = "interceptor")]
pub mod interceptor;

#[cfg(feature = "ptm")]
pub mod ptm;

mod hexdump;
pub use self::hexdump::{hexdump, Representation};