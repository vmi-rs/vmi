use vmi_core::{Architecture as _, Pa, Va, VmiCore, VmiError, driver::VmiRead};
use zerocopy::FromBytes;

use crate::{Arm64, PageTableEntry, PageTableLevel, PagingGeometry};

/// Walks the stage-1 tables rooted at `root` to translate `va`.
///
/// The walk starts at the geometry's starting level and reads one descriptor
/// per level. A table descriptor advances to the next level. A block
/// descriptor at a level permitted by the granule, or a page descriptor at
/// L3, terminates the walk. Any other descriptor is a translation error.
pub(crate) fn translate<Driver, Geometry>(
    vmi: &VmiCore<Driver>,
    va: Va,
    root: Pa,
) -> Result<Pa, VmiError>
where
    Driver: VmiRead<Architecture = Arm64<Geometry>>,
    Geometry: PagingGeometry,
{
    let control = Geometry::control();
    let page_shift = Geometry::GRANULE.page_shift();
    let mut table = root;
    let mut level = control.start_level();

    loop {
        let entry = read_descriptor(vmi, table, va, level)?;

        if !entry.valid() {
            return Err(VmiError::translation((va, root)));
        }

        if level == PageTableLevel::L3 {
            // L3 holds page descriptors only. The block encoding is reserved.
            if !entry.table_or_page() {
                return Err(VmiError::translation((va, root)));
            }

            return Ok(Pa(
                entry.output_address(page_shift) + control.offset(va, level)
            ));
        }

        if entry.block() {
            if !Geometry::GRANULE.allows_block(level) {
                return Err(VmiError::translation((va, root)));
            }

            let shift = control.level_shift(level);
            return Ok(Pa(entry.output_address(shift) + control.offset(va, level)));
        }

        table = Pa(entry.output_address(page_shift));
        level = match level.next() {
            Some(level) => level,
            None => return Err(VmiError::translation((va, root))),
        };
    }
}

/// Walks the stage-1 tables for `va` and returns the raw L3 descriptor, even
/// when it is not valid.
///
/// Returns `None` when no L3 descriptor is reachable because an intermediate
/// descriptor is invalid or maps a block.
pub(crate) fn leaf_descriptor<Driver, Geometry>(
    vmi: &VmiCore<Driver>,
    va: Va,
    root: Pa,
) -> Result<Option<PageTableEntry>, VmiError>
where
    Driver: VmiRead<Architecture = Arm64<Geometry>>,
    Geometry: PagingGeometry,
{
    let page_shift = Geometry::GRANULE.page_shift();
    let mut table = root;
    let mut level = Geometry::control().start_level();

    loop {
        let entry = read_descriptor(vmi, table, va, level)?;

        if level == PageTableLevel::L3 {
            return Ok(Some(entry));
        }

        if !entry.valid() || !entry.table_or_page() {
            return Ok(None);
        }

        table = Pa(entry.output_address(page_shift));
        level = match level.next() {
            Some(level) => level,
            None => return Ok(None),
        };
    }
}

/// Reads the descriptor for `va` at `level` from the table at `table`.
///
/// A table occupies exactly one granule page. A table base that is not page
/// aligned, which happens when the root table is smaller than a page, offsets
/// the index within the page.
fn read_descriptor<Driver, Geometry>(
    vmi: &VmiCore<Driver>,
    table: Pa,
    va: Va,
    level: PageTableLevel,
) -> Result<PageTableEntry, VmiError>
where
    Driver: VmiRead<Architecture = Arm64<Geometry>>,
    Geometry: PagingGeometry,
{
    let buffer = vmi.read_page(Arm64::<Geometry>::gfn_from_pa(table))?;
    let descriptors = match <[PageTableEntry]>::ref_from_bytes(&buffer) {
        Ok(descriptors) => descriptors,
        Err(_) => return Err(VmiError::OutOfBounds),
    };

    let base = Arm64::<Geometry>::pa_offset(table) as usize / size_of::<PageTableEntry>();
    let index = base + Geometry::control().index(va, level) as usize;
    match descriptors.get(index) {
        Some(descriptor) => Ok(*descriptor),
        None => Err(VmiError::OutOfBounds),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use vmi_core::{
        Architecture as _, Gfn, Pa, Va, VmiCore, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
        arch::{GpRegisters as _, Registers as _},
        driver::VmiRead,
    };

    use crate::{Arm64, Granule4KVa48, Granule16KVa47, PageTableLevel, PagingGeometry, Registers};

    /// In-memory driver returning crafted guest physical pages by GFN.
    struct MockDriver<Geometry> {
        /// Page contents keyed by guest frame number.
        pages: RefCell<HashMap<u64, Vec<u8>>>,
        _geometry: std::marker::PhantomData<Geometry>,
    }

    impl<Geometry> MockDriver<Geometry>
    where
        Geometry: PagingGeometry,
    {
        /// Creates an empty backing store.
        fn new() -> Self {
            Self {
                pages: RefCell::new(HashMap::new()),
                _geometry: std::marker::PhantomData,
            }
        }

        /// Writes `value` as a little-endian descriptor at `index` in the
        /// table at `gfn`.
        fn set_descriptor(&self, gfn: u64, index: u64, value: u64) {
            let mut pages = self.pages.borrow_mut();
            let page = pages
                .entry(gfn)
                .or_insert_with(|| vec![0; Arm64::<Geometry>::PAGE_SIZE as usize]);
            let offset = index as usize * 8;
            page[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    impl<Geometry> VmiDriver for MockDriver<Geometry>
    where
        Geometry: PagingGeometry,
    {
        type Architecture = Arm64<Geometry>;

        fn info(&self) -> Result<VmiInfo, VmiError> {
            Ok(VmiInfo {
                page_size: Arm64::<Geometry>::PAGE_SIZE,
                page_shift: Arm64::<Geometry>::PAGE_SHIFT,
                max_gfn: Gfn(0),
                vcpus: 1,
            })
        }
    }

    impl<Geometry> VmiRead for MockDriver<Geometry>
    where
        Geometry: PagingGeometry,
    {
        fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
            let page = match self.pages.borrow().get(&gfn.0) {
                Some(page) => page.clone(),
                None => vec![0; Arm64::<Geometry>::PAGE_SIZE as usize],
            };

            Ok(VmiMappedPage::new(page))
        }
    }

    /// Returns the page shift of the geometry.
    fn shift<Geometry: PagingGeometry>() -> u64 {
        Arm64::<Geometry>::PAGE_SHIFT
    }

    /// Builds a table descriptor pointing at `next_gfn`.
    fn table_descriptor<Geometry: PagingGeometry>(next_gfn: u64) -> u64 {
        (next_gfn << shift::<Geometry>()) | 0b11
    }

    /// Builds an L3 page descriptor for `out_gfn` with the access flag set.
    fn page_descriptor<Geometry: PagingGeometry>(out_gfn: u64) -> u64 {
        (out_gfn << shift::<Geometry>()) | (1 << 10) | 0b11
    }

    /// Builds a block descriptor for `out_gfn` with the access flag set.
    fn block_descriptor<Geometry: PagingGeometry>(out_gfn: u64) -> u64 {
        (out_gfn << shift::<Geometry>()) | (1 << 10) | 0b01
    }

    /// Translates `va` through the public `Architecture` entry point.
    fn translate<Geometry: PagingGeometry>(
        driver: MockDriver<Geometry>,
        va: Va,
        root_gfn: u64,
    ) -> Result<Pa, VmiError> {
        let vmi = VmiCore::new(driver).unwrap();
        Arm64::<Geometry>::translate_address(&vmi, va, Pa(root_gfn << shift::<Geometry>()))
    }

    #[test]
    fn walk_4k_l0_to_l3_page() {
        let driver = MockDriver::<Granule4KVa48>::new();

        // L0=1, L1=2, L2=3, L3=4, offset=0x123.
        let va = Va((1 << 39) | (2 << 30) | (3 << 21) | (4 << 12) | 0x123);

        driver.set_descriptor(0x10, 1, table_descriptor::<Granule4KVa48>(0x11));
        driver.set_descriptor(0x11, 2, table_descriptor::<Granule4KVa48>(0x12));
        driver.set_descriptor(0x12, 3, table_descriptor::<Granule4KVa48>(0x13));
        driver.set_descriptor(0x13, 4, page_descriptor::<Granule4KVa48>(0x55));

        let pa = translate(driver, va, 0x10).unwrap();
        assert_eq!(pa, Pa(0x55_123));
    }

    #[test]
    fn walk_4k_l2_block() {
        let driver = MockDriver::<Granule4KVa48>::new();

        // L0=1, L1=2, L2=3, offset within the 2MB block = 0x4_5678.
        let va = Va((1 << 39) | (2 << 30) | (3 << 21) | 0x4_5678);

        driver.set_descriptor(0x20, 1, table_descriptor::<Granule4KVa48>(0x21));
        driver.set_descriptor(0x21, 2, table_descriptor::<Granule4KVa48>(0x22));
        driver.set_descriptor(0x22, 3, block_descriptor::<Granule4KVa48>(0x600));

        let pa = translate(driver, va, 0x20).unwrap();
        assert_eq!(pa, Pa(0x60_0000 + 0x4_5678));
    }

    #[test]
    fn walk_4k_l1_block() {
        let driver = MockDriver::<Granule4KVa48>::new();

        // L0=1, L1=2, offset within the 1GB block = 0x1234_5678.
        let va = Va((1 << 39) | (2 << 30) | 0x1234_5678);

        driver.set_descriptor(0x20, 1, table_descriptor::<Granule4KVa48>(0x21));
        driver.set_descriptor(0x21, 2, block_descriptor::<Granule4KVa48>(0x40000));

        let pa = translate(driver, va, 0x20).unwrap();
        assert_eq!(pa, Pa(0x4000_0000 + 0x1234_5678));
    }

    #[test]
    fn walk_16k_l1_to_l3_page_with_high_indices() {
        let driver = MockDriver::<Granule16KVa47>::new();

        // L1=2047, L2=2046, L3=2045, offset=0x3abc. The walk starts at L1
        // with 11-bit indices, so bit 47 and above are not part of any index.
        let va = Va(0xffff_8000_0000_0000 | (2047 << 36) | (2046 << 25) | (2045 << 14) | 0x3abc);

        assert_eq!(Granule16KVa47::control().start_level(), PageTableLevel::L1);

        driver.set_descriptor(0x100, 2047, table_descriptor::<Granule16KVa47>(0x101));
        driver.set_descriptor(0x101, 2046, table_descriptor::<Granule16KVa47>(0x102));
        driver.set_descriptor(0x102, 2045, page_descriptor::<Granule16KVa47>(0x2d9f9));

        let pa = translate(driver, va, 0x100).unwrap();
        assert_eq!(pa, Pa((0x2d9f9 << 14) | 0x3abc));
    }

    #[test]
    fn walk_16k_l2_block() {
        let driver = MockDriver::<Granule16KVa47>::new();

        // L1=5, L2=7, offset within the 32MB block = 0x1ab_cdef.
        let va = Va((5 << 36) | (7 << 25) | 0x1ab_cdef);

        // A 32MB block base is a multiple of 2048 16KB frames.
        driver.set_descriptor(0x100, 5, table_descriptor::<Granule16KVa47>(0x101));
        driver.set_descriptor(0x101, 7, block_descriptor::<Granule16KVa47>(3 * 2048));

        let pa = translate(driver, va, 0x100).unwrap();
        assert_eq!(pa, Pa(3 * 0x200_0000 + 0x1ab_cdef));
    }

    #[test]
    fn walk_16k_l1_block_faults() {
        let driver = MockDriver::<Granule16KVa47>::new();
        let va = Va((5 << 36) | 0x1234);

        driver.set_descriptor(0x100, 5, block_descriptor::<Granule16KVa47>(0x80000));

        let result = translate(driver, va, 0x100);
        assert!(matches!(result, Err(VmiError::Translation(_))));
    }

    #[test]
    fn walk_invalid_descriptor_faults() {
        let driver = MockDriver::<Granule4KVa48>::new();
        let va = Va((1 << 39) | (2 << 30) | 0x123);

        // L0 index 1 is valid, the L1 descriptor has the valid bit clear.
        driver.set_descriptor(0x10, 1, table_descriptor::<Granule4KVa48>(0x11));
        driver.set_descriptor(0x11, 2, 0x4000_0000 | 0b10);

        let result = translate(driver, va, 0x10);
        assert!(matches!(result, Err(VmiError::Translation(_))));
    }

    #[test]
    fn walk_16k_l3_block_encoding_faults() {
        let driver = MockDriver::<Granule16KVa47>::new();
        let va = Va((1 << 36) | (2 << 25) | (3 << 14));

        driver.set_descriptor(0x100, 1, table_descriptor::<Granule16KVa47>(0x101));
        driver.set_descriptor(0x101, 2, table_descriptor::<Granule16KVa47>(0x102));
        driver.set_descriptor(0x102, 3, block_descriptor::<Granule16KVa47>(0x200));

        let result = translate(driver, va, 0x100);
        assert!(matches!(result, Err(VmiError::Translation(_))));
    }

    #[test]
    fn leaf_descriptor_returns_invalid_l3_slot() {
        let driver = MockDriver::<Granule4KVa48>::new();
        let va = Va((1 << 39) | (2 << 30) | (3 << 21) | (4 << 12));
        let software_pte = 1u64 << 11;

        driver.set_descriptor(0x30, 1, table_descriptor::<Granule4KVa48>(0x31));
        driver.set_descriptor(0x31, 2, table_descriptor::<Granule4KVa48>(0x32));
        driver.set_descriptor(0x32, 3, table_descriptor::<Granule4KVa48>(0x33));
        driver.set_descriptor(0x33, 4, software_pte);

        let vmi = VmiCore::new(driver).unwrap();
        let leaf = Arm64::<Granule4KVa48>::leaf_descriptor(&vmi, va, Pa(0x30 << 12)).unwrap();
        assert_eq!(leaf.map(|leaf| leaf.0), Some(software_pte));
    }

    #[test]
    fn leaf_descriptor_none_on_block() {
        let driver = MockDriver::<Granule16KVa47>::new();
        let va = Va((5 << 36) | (7 << 25));

        driver.set_descriptor(0x100, 5, table_descriptor::<Granule16KVa47>(0x101));
        driver.set_descriptor(0x101, 7, block_descriptor::<Granule16KVa47>(2048));

        let vmi = VmiCore::new(driver).unwrap();
        let leaf = Arm64::<Granule16KVa47>::leaf_descriptor(&vmi, va, Pa(0x100 << 14)).unwrap();
        assert!(leaf.is_none());
    }

    #[test]
    fn return_from_function_returns_through_link_register() {
        let vmi = VmiCore::new(MockDriver::<Granule16KVa47>::new()).unwrap();

        let mut registers = Registers::<Granule16KVa47>::default();
        registers.regs[0] = 7;
        registers.regs[30] = 0xffff_fe00_2c7e_0000;
        registers.pc = 0xffff_fe00_2c7e_5434;
        registers.pstate = 0b0101;
        registers.sp_el1 = 0xffff_fe40_0000_8000;

        let gp = registers.return_from_function(&vmi, 42).unwrap();
        assert_eq!(gp.result(), 42);
        assert_eq!(gp.instruction_pointer(), 0xffff_fe00_2c7e_0000);
        assert_eq!(gp.stack_pointer(), 0xffff_fe40_0000_8000);

        let mut applied = registers;
        applied.set_gp_registers(&gp);
        assert_eq!(applied.regs[0], 42);
        assert_eq!(applied.pc, 0xffff_fe00_2c7e_0000);
        assert_eq!(applied.sp_el1, 0xffff_fe40_0000_8000);
    }
}
