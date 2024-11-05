use vmi_core::{AccessContext, VmiCore, VmiDriver, VmiError};

/// Representation of memory for hexdump.
pub enum Representation {
    /// Display memory as 8-bit values.
    U8,

    /// Display memory as 32-bit values.
    U32,

    /// Display memory as 64-bit values.
    U64,
}

/// Print a hexdump of memory at the given address.
pub fn hexdump<Driver>(
    vmi: &VmiCore<Driver>,
    ctx: impl Into<AccessContext>,
    count: usize,
    representation: Representation,
) -> Result<(), VmiError>
where
    Driver: VmiDriver,
{
    let ctx = ctx.into();

    let mut buf = vec![0u8; count];
    vmi.read(ctx, &mut buf)?;

    println!(
        "--------------------|  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F | 0123456789ABCDEF"
    );
    for (index, chunk) in buf.chunks(16).enumerate() {
        print!(" 0x{:016X} |", ctx.address + (index * 16) as u64);

        match representation {
            Representation::U8 => {
                for &byte in chunk {
                    print!(" {:02X}", byte);
                }

                if chunk.len() < 16 {
                    for _ in 0..(16 - chunk.len()) {
                        print!("   ");
                    }
                }
            }

            Representation::U32 => {
                for dword in chunk.chunks(4) {
                    print!(
                        "  0x{:08X}",
                        u32::from_le_bytes([dword[0], dword[1], dword[2], dword[3]])
                    );
                }

                if (chunk.len() % 4) != 0 {
                    for _ in 0..(4 - (chunk.len() % 4)) {
                        print!("            ");
                    }
                }
            }

            Representation::U64 => {
                for qword in chunk.chunks(8) {
                    print!(
                        "      0x{:016X}",
                        u64::from_le_bytes([
                            qword[0], qword[1], qword[2], qword[3], qword[4], qword[5], qword[6],
                            qword[7],
                        ])
                    );
                }

                if (chunk.len() % 8) != 0 {
                    for _ in 0..(8 - (chunk.len() % 8)) {
                        print!("                        ");
                    }
                }
            }
        }

        print!(" | ");

        for &byte in chunk {
            print!(
                "{}",
                if byte.is_ascii_graphic() {
                    byte as char
                }
                else {
                    '.'
                }
            );
        }

        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                print!(" ");
            }
        }

        println!();
    }

    Ok(())
}
