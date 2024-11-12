macro_rules! impl_offsets {
    () => {
        fn offsets(&self) -> &$crate::offsets::Offsets {
            &self.vmi.underlying_os().offsets
        }
    };
}

pub(crate) use impl_offsets;
