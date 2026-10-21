//! Reads of null-terminated strings that cross pages.

use std::ops::Range;

use vmi_core::{Gfn, Pa, VmiCore, VmiError};
use vmi_driver_mock::arch::amd64::MockDriver;

/// Page size of the mock driver.
const PAGE_SIZE: u64 = 0x1000;

/// Returns the byte at an index of a test string, never 0.
fn pattern(index: usize) -> u8 {
    (index % 251) as u8 + 1
}

/// Returns the code unit at an index of a test string, without a 0 byte.
fn unit(index: usize) -> u16 {
    0x0400 + u16::from(pattern(index))
}

/// Encodes code units as little-endian bytes.
fn utf16_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// Builds a core over blank pages, with bytes written from the physical
/// address `start` on.
fn core_with(pages: Range<u64>, start: u64, bytes: &[u8]) -> Result<VmiCore<MockDriver>, VmiError> {
    let driver = MockDriver::new();
    for gfn in pages {
        driver.insert_page(Gfn(gfn));
    }

    for (index, byte) in bytes.iter().enumerate() {
        let address = start + index as u64;
        driver.write_original(
            Gfn(address / PAGE_SIZE),
            (address % PAGE_SIZE) as usize,
            &[*byte],
        );
    }

    VmiCore::new(driver)
}

#[test]
fn string_across_three_pages_keeps_every_byte() -> Result<(), VmiError> {
    // 16 bytes end page 1, page 2 is full, and 100 bytes start page 3.
    let start = 2 * PAGE_SIZE - 16;
    let text: Vec<u8> = (0..16 + 4096 + 100).map(pattern).collect();
    let core = core_with(1..5, start, &[text.as_slice(), &[0]].concat())?;

    assert_eq!(core.read_string_bytes_limited(Pa(start), usize::MAX)?, text);
    Ok(())
}

#[test]
fn limit_within_the_first_page_reads_no_further() -> Result<(), VmiError> {
    // 256 bytes without a terminator end page 1, and page 2 is absent.
    let start = 2 * PAGE_SIZE - 256;
    let text: Vec<u8> = (0..256).map(pattern).collect();
    let core = core_with(1..2, start, &text)?;

    assert_eq!(core.read_string_bytes_limited(Pa(start), 16)?, text[..16]);
    Ok(())
}

#[test]
fn utf16_string_across_three_pages_keeps_every_unit() -> Result<(), VmiError> {
    // 8 units end page 1, page 2 is full, and 50 units start page 3.
    let start = 2 * PAGE_SIZE - 16;
    let units: Vec<u16> = (0..8 + 2048 + 50).map(unit).collect();
    let core = core_with(
        1..5,
        start,
        &utf16_bytes(&[units.as_slice(), &[0]].concat()),
    )?;

    assert_eq!(
        core.read_string_utf16_bytes_limited(Pa(start), usize::MAX)?,
        units
    );
    Ok(())
}

#[test]
fn utf16_string_at_an_odd_address_keeps_every_unit() -> Result<(), VmiError> {
    // 15 bytes end page 1, and unit 7 spans the two pages. Bytes of 0xff
    // follow the terminator in page 2.
    let start = 2 * PAGE_SIZE - 15;
    let units: Vec<u16> = (0..40).map(unit).collect();
    let bytes = [
        utf16_bytes(&[units.as_slice(), &[0]].concat()),
        vec![0xff; 64],
    ]
    .concat();
    let core = core_with(1..3, start, &bytes)?;

    assert_eq!(
        core.read_string_utf16_bytes_limited(Pa(start), usize::MAX)?,
        units
    );
    Ok(())
}

#[test]
fn utf16_limit_within_the_first_page_reads_no_further() -> Result<(), VmiError> {
    // 128 units without a terminator end page 1, and page 2 is absent. The
    // limit counts bytes.
    let start = 2 * PAGE_SIZE - 256;
    let units: Vec<u16> = (0..128).map(unit).collect();
    let core = core_with(1..2, start, &utf16_bytes(&units))?;

    assert_eq!(
        core.read_string_utf16_bytes_limited(Pa(start), 16)?,
        units[..8]
    );
    Ok(())
}
