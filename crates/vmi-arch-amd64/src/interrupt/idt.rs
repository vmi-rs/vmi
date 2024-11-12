use vmi_core::Va;
use zerocopy::{FromBytes, IntoBytes};

use crate::{DescriptorType, Selector};

/// Interrupt Descriptor Table Access Flags.
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes)]
pub struct IdtAccess(pub u16);

impl IdtAccess {
    /// Returns the IST index.
    fn ist_index(self) -> u8 {
        (self.0 & 0b111) as _
    }

    /// Returns the type of the interrupt gate.
    fn typ(self) -> u8 {
        ((self.0 >> 8) & 0b1111) as _
    }

    /// Returns the descriptor type.
    fn descriptor_type(self) -> DescriptorType {
        if (self.0 >> 11) & 1 == 0 {
            DescriptorType::System
        }
        else {
            DescriptorType::CodeOrData
        }
    }

    /// Returns the descriptor privilege level.
    fn descriptor_privilege_level(self) -> u8 {
        ((self.0 >> 13) & 0b11) as _
    }

    /// Returns whether the interrupt gate is present.
    fn present(self) -> bool {
        (self.0 >> 15) & 1 != 0
    }
}

impl From<u16> for IdtAccess {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<IdtAccess> for u16 {
    fn from(value: IdtAccess) -> Self {
        value.0
    }
}

impl std::fmt::Debug for IdtAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("IdtAccess")
            .field("ist_index", &self.ist_index())
            .field("type", &self.typ())
            .field("descriptor_type", &self.descriptor_type())
            .field(
                "descriptor_privilege_level",
                &self.descriptor_privilege_level(),
            )
            .field("present", &self.present())
            .finish()
    }
}

/// Interrupt Descriptor Table Entry.
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes)]
pub struct IdtEntry {
    /// Lower 16 bits of the base address.
    pub base_address_low: u16,

    /// Code segment selector.
    pub selector: Selector,

    /// Access flags.
    pub access: IdtAccess,

    /// Middle 16 bits of the base address.
    pub base_address_middle: u16,

    /// Higher 32 bits of the base address.
    pub base_address_high: u32,

    /// Must be zero.
    pub reserved: u32,
}

impl IdtEntry {
    /// Returns the base address of the interrupt handler.
    pub fn base_address(&self) -> Va {
        Va((self.base_address_low as u64)
            | ((self.base_address_middle as u64) << 16)
            | ((self.base_address_high as u64) << 32))
    }
}

impl std::fmt::Debug for IdtEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("IdtAccess")
            .field("selector", &self.selector)
            .field("access", &self.access)
            .field("base_address", &self.base_address())
            .finish()
    }
}

/// Interrupt Descriptor Table.
pub type Idt = [IdtEntry; 256];
