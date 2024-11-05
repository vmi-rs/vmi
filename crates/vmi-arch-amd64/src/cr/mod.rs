mod cr0;
mod cr2;
mod cr3;
mod cr4;

pub use self::{cr0::Cr0, cr2::Cr2, cr3::Cr3, cr4::Cr4};

/// Control register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ControlRegister {
    /// Control Register 0 ([`Cr0`]).
    Cr0,

    /// Control Register 3 ([`Cr3`]).
    Cr3,

    /// Control Register 4 ([`Cr4`]).
    Cr4,

    /// Extended Control Register 0.
    Xcr0,
}
