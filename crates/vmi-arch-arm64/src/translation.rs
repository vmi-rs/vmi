use vmi_core::{Architecture as _, Pa, Va, VmiCore, VmiError, driver::VmiRead};
use zerocopy::FromBytes;

use crate::{Arm64, PageTableEntry, PageTableLevel, TranslationControl};

/// Returns the table index for `va` at `level` under the given control.
///
/// The index occupies `index_bits` bits sitting above the bits resolved by all
/// lower levels plus the in-page offset.
pub(crate) fn index_for(va: Va, level: PageTableLevel, control: TranslationControl) -> u64 {
    let index_bits = control.index_bits();
    let levels_below = match level {
        PageTableLevel::L0 => 3,
        PageTableLevel::L1 => 2,
        PageTableLevel::L2 => 1,
        PageTableLevel::L3 => 0,
    };
    let shift = control.granule.page_shift() + levels_below * index_bits;
    let mask = (1u64 << index_bits) - 1;
    (va.0 >> shift) & mask
}

/// Returns the in-block offset of `va` for a leaf descriptor at `level`.
///
/// A block at L1 spans `3 * index_bits + page_shift` bits, at L2 one fewer
/// level, and an L3 page spans exactly the page offset.
pub(crate) fn offset_for(va: Va, level: PageTableLevel, control: TranslationControl) -> u64 {
    let index_bits = control.index_bits();
    let levels_below = match level {
        PageTableLevel::L0 => 3,
        PageTableLevel::L1 => 2,
        PageTableLevel::L2 => 1,
        PageTableLevel::L3 => 0,
    };
    let shift = control.granule.page_shift() + levels_below * index_bits;
    va.0 & ((1u64 << shift) - 1)
}

/// Walks the AArch64 stage-1 tables to translate `va` under `control`.
///
/// Starts at `control.start_level()` and reads one descriptor per level. A
/// table descriptor (`0b11` at a non-leaf level) advances to the next level. A
/// block descriptor (`0b01`) at L1 or L2 and a page descriptor (`0b11`) at L3
/// terminate the walk and yield the output physical address. Any invalid or
/// malformed descriptor raises a page fault.
pub(crate) fn translate<Driver>(
    vmi: &VmiCore<Driver>,
    va: Va,
    root: Pa,
    control: TranslationControl,
) -> Result<Pa, VmiError>
where
    Driver: VmiRead<Architecture = Arm64>,
{
    let granule = control.granule;
    let mut table = root;
    let mut level = control.start_level();

    loop {
        let entry = read_descriptor(vmi, table, va, level, control)?;

        if !entry.valid() {
            return Err(VmiError::page_fault((va, root)));
        }

        // L3 is always a page descriptor (0b11); a block encoding is invalid at
        // the lowest level.
        if level == PageTableLevel::L3 {
            if !entry.table_or_page() {
                return Err(VmiError::page_fault((va, root)));
            }

            let base = Arm64::pa_from_gfn(entry.output_frame(granule));
            return Ok(base + offset_for(va, level, control));
        }

        // A block descriptor terminates the walk at L1 or L2.
        if entry.block() {
            match level {
                PageTableLevel::L1 | PageTableLevel::L2 => {
                    let base = Arm64::pa_from_gfn(entry.output_frame(granule));
                    return Ok(base + offset_for(va, level, control));
                }
                _ => return Err(VmiError::page_fault((va, root))),
            }
        }

        // Otherwise it must be a table descriptor pointing at the next level.
        if !entry.table_or_page() {
            return Err(VmiError::page_fault((va, root)));
        }

        table = Arm64::pa_from_gfn(entry.output_frame(granule));
        level = match level.next() {
            Some(level) => level,
            None => return Err(VmiError::page_fault((va, root))),
        };
    }
}

/// Reads the descriptor at `level` for `va` from the table at `table`.
fn read_descriptor<Driver>(
    vmi: &VmiCore<Driver>,
    table: Pa,
    va: Va,
    level: PageTableLevel,
    control: TranslationControl,
) -> Result<PageTableEntry, VmiError>
where
    Driver: VmiRead<Architecture = Arm64>,
{
    let buffer = vmi.read_page(Arm64::gfn_from_pa(table))?;
    let descriptors = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
    let index = index_for(va, level, control) as usize;
    Ok(descriptors[index])
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use vmi_core::{
        Gfn, Pa, Va, VmiCore, VmiDriver, VmiError, VmiInfo, VmiMappedPage, driver::VmiRead,
    };

    use super::index_for;
    use crate::{Arm64, Granule, PageTableLevel, TranslationControl};

    /// In-memory driver returning crafted guest physical pages by GFN.
    struct MockDriver {
        /// Page contents keyed by guest frame number.
        pages: RefCell<HashMap<u64, [u8; 0x1000]>>,
    }

    impl MockDriver {
        /// Builds an empty mock backing store.
        fn new() -> Self {
            Self {
                pages: RefCell::new(HashMap::new()),
            }
        }

        /// Writes `value` as a little-endian descriptor at `index` in `gfn`.
        fn set_descriptor(&self, gfn: u64, index: usize, value: u64) {
            let mut pages = self.pages.borrow_mut();
            let page = pages.entry(gfn).or_insert([0u8; 0x1000]);
            let offset = index * 8;
            page[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    impl VmiDriver for MockDriver {
        type Architecture = Arm64;

        fn info(&self) -> Result<VmiInfo, VmiError> {
            unimplemented!()
        }
    }

    impl VmiRead for MockDriver {
        fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
            let page = self
                .pages
                .borrow()
                .get(&gfn.0)
                .copied()
                .unwrap_or([0u8; 0x1000]);
            Ok(VmiMappedPage::new(page.to_vec().into_boxed_slice()))
        }
    }

    /// Builds a table descriptor pointing at `next_gfn`.
    fn table_descriptor(next_gfn: u64) -> u64 {
        // 0b11 = table, valid. Output address = next_gfn << 12.
        (next_gfn << 12) | 0b11
    }

    /// Builds an L3 page descriptor for `out_gfn`.
    fn page_descriptor(out_gfn: u64) -> u64 {
        // 0b11 = page at L3, valid, access flag set.
        (out_gfn << 12) | (1 << 10) | 0b11
    }

    /// Builds an L2 2MB block descriptor for `out_gfn`.
    fn block_descriptor(out_gfn: u64) -> u64 {
        // 0b01 = block, valid, access flag set.
        (out_gfn << 12) | (1 << 10) | 0b01
    }

    /// Returns 4KB-granule control with a 48-bit low region (T0SZ = 16).
    fn control_4k() -> TranslationControl {
        let control = TranslationControl::from_tcr(16, false).unwrap();
        assert_eq!(control.granule, Granule::_4K);
        assert_eq!(control.start_level(), PageTableLevel::L0);
        control
    }

    /// Walks a full L0->L3 4KB chain to a known page.
    #[test]
    fn walk_4k_l3_page() {
        let driver = MockDriver::new();
        let control = control_4k();

        // VA with distinct indices at each level and a non-zero page offset.
        // L0=1, L1=2, L2=3, L3=4, offset=0x123.
        let va = Va((1 << 39) | (2 << 30) | (3 << 21) | (4 << 12) | 0x123);

        let root_gfn = 0x10;
        let l1_gfn = 0x11;
        let l2_gfn = 0x12;
        let l3_gfn = 0x13;
        let out_gfn = 0x55;

        assert_eq!(index_for(va, PageTableLevel::L0, control), 1);
        assert_eq!(index_for(va, PageTableLevel::L1, control), 2);
        assert_eq!(index_for(va, PageTableLevel::L2, control), 3);
        assert_eq!(index_for(va, PageTableLevel::L3, control), 4);

        driver.set_descriptor(root_gfn, 1, table_descriptor(l1_gfn));
        driver.set_descriptor(l1_gfn, 2, table_descriptor(l2_gfn));
        driver.set_descriptor(l2_gfn, 3, table_descriptor(l3_gfn));
        driver.set_descriptor(l3_gfn, 4, page_descriptor(out_gfn));

        let vmi = VmiCore::new(driver).unwrap();
        let pa = super::translate(&vmi, va, Pa(root_gfn << 12), control).unwrap();
        assert_eq!(pa, Pa((out_gfn << 12) | 0x123));
    }

    /// Walks an L0->L2 chain ending in a 2MB block descriptor.
    #[test]
    fn walk_4k_l2_block() {
        let driver = MockDriver::new();
        let control = control_4k();

        // L0=1, L1=2, L2=3, in-block offset within 2MB = 0x4_5678.
        let va = Va((1 << 39) | (2 << 30) | (3 << 21) | 0x4_5678);

        let root_gfn = 0x20;
        let l1_gfn = 0x21;
        let l2_gfn = 0x22;
        // 2MB block output base must be 2MB aligned: frame is a multiple of 512.
        let out_gfn = 0x600;

        driver.set_descriptor(root_gfn, 1, table_descriptor(l1_gfn));
        driver.set_descriptor(l1_gfn, 2, table_descriptor(l2_gfn));
        driver.set_descriptor(l2_gfn, 3, block_descriptor(out_gfn));

        let vmi = VmiCore::new(driver).unwrap();
        let pa = super::translate(&vmi, va, Pa(root_gfn << 12), control).unwrap();
        assert_eq!(pa, Pa((out_gfn << 12) | 0x4_5678));
    }

    /// Raises a page fault when a descriptor is invalid.
    #[test]
    fn walk_invalid_faults() {
        let driver = MockDriver::new();
        let control = control_4k();
        let va = Va((1 << 39) | 0x123);

        // Root index 1 left zero (invalid).
        let vmi = VmiCore::new(driver).unwrap();
        let result = super::translate(&vmi, va, Pa(0x10 << 12), control);
        assert!(result.is_err());
    }
}
