//! VMI utilities.

#[cfg(feature = "bpm")]
pub mod bpm;

#[cfg(feature = "bridge")]
pub mod bridge;

#[cfg(feature = "injector")]
pub mod injector;

#[cfg(feature = "interceptor")]
pub mod interceptor;

#[cfg(feature = "ptm")]
pub mod ptm;

#[cfg(feature = "reactor")]
pub mod reactor;

#[cfg(feature = "resolver")]
pub mod resolver;

mod hexdump;
pub use self::hexdump::{Representation, hexdump};

#[cfg(all(test, feature = "arch-amd64"))]
mod mock_driver;
