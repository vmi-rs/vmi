use vmi_core::{Architecture as _, Gfn, Pa};

use crate::{Amd64, Cr3};

impl From<Cr3> for Gfn {
    fn from(value: Cr3) -> Self {
        Self(value.page_frame_number())
    }
}

impl From<Cr3> for Pa {
    fn from(value: Cr3) -> Self {
        Amd64::pa_from_gfn(Gfn::from(value))
    }
}
