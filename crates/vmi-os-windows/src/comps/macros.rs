macro_rules! impl_symbols {
    () => {
        fn symbols(&self) -> &$crate::offsets::Symbols {
            &self.vmi.underlying_os().symbols
        }
    };
}

macro_rules! impl_offsets {
    () => {
        fn offsets(&self) -> &$crate::offsets::Offsets {
            &self.vmi.underlying_os().offsets
        }
    };
}

macro_rules! impl_offsets_ext_v1 {
    () => {
        fn offsets_ext(&self) -> &$crate::offsets::v1::Offsets {
            match self.vmi.underlying_os().offsets.ext() {
                Some($crate::offsets::OffsetsExt::V1(offsets)) => offsets,
                _ => unreachable!(),
            }
        }
    };
}

macro_rules! impl_offsets_ext_v2 {
    () => {
        fn offsets_ext(&self) -> &$crate::offsets::v2::Offsets {
            match self.vmi.underlying_os().offsets.ext() {
                Some($crate::offsets::OffsetsExt::V2(offsets)) => offsets,
                _ => unreachable!(),
            }
        }
    };
}

pub(crate) use impl_offsets;
pub(crate) use impl_offsets_ext_v1;
pub(crate) use impl_offsets_ext_v2;
pub(crate) use impl_symbols;
