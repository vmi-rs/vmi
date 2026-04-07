//! x64 (AMD64) stack unwinding using .pdata / UNWIND_INFO.
//!
//! Implements the Windows x64 stack unwinding algorithm by reading
//! RUNTIME_FUNCTION entries from the PE exception directory and
//! processing UNWIND_INFO structures to recover caller register state.

use object::endian::LittleEndian as LE;
use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use super::{StackFrame, StackUnwind};
use crate::{ArchAdapter, WindowsOs, pe::PeImage};

// Reference:
// https://github.com/dotnet/coreclr/blob/a9f3fc16483eecfc47fb79c362811d870be02249/src/unwinder/amd64/unwinder_amd64.cpp
// TODO: epilog unwind

/// Process UNWIND_INFO entries, following chains.
/// Limit chain depth to guard against corrupted/circular data.
pub const UNWIND_CHAIN_LIMIT: u32 = 32;

// Unwind operation codes.

/// Push a nonvolatile integer register, decrementing RSP by 8.
///
/// The operation info is the number of the register. Because of the constraints
/// on epilogs, `UWOP_PUSH_NONVOL` unwind codes must appear first in the prolog
/// and correspondingly, last in the unwind code array. This relative ordering
/// applies to all other unwind codes except `UWOP_PUSH_MACHFRAME`.
pub const UWOP_PUSH_NONVOL: u8 = 0;

/// Allocate a large-sized area on the stack.
///
/// There are two forms. If the operation info equals 0, then the size of the
/// allocation divided by 8 is recorded in the next slot, allowing an allocation
/// up to 512K - 8. If the operation info equals 1, then the unscaled size of
/// the allocation is recorded in the next two slots in little-endian format,
/// allowing allocations up to 4GB - 8.
pub const UWOP_ALLOC_LARGE: u8 = 1;

/// Allocate a small-sized area on the stack.
///
/// The size of the allocation is the operation info field * 8 + 8, allowing
/// allocations from 8 to 128 bytes.
///
/// The unwind code for a stack allocation should always use the shortest
/// possible encoding:
///
/// | Allocation Size     | Unwind Code                            |
/// | ------------------- | -------------------------------------- |
/// | 8 to 128 bytes      | `UWOP_ALLOC_SMALL`                     |
/// | 136 to 512K-8 bytes | `UWOP_ALLOC_LARGE`, operation info = 0 |
/// | 512K to 4G-8 bytes  | `UWOP_ALLOC_LARGE`, operation info = 1 |
pub const UWOP_ALLOC_SMALL: u8 = 2;

/// Establish the frame pointer register by setting the register to some offset of the current RSP.
///
/// The offset is equal to the Frame Register offset (scaled) field in the
/// `UNWIND_INFO * 16`, allowing offsets from 0 to 240. The use of an offset
/// permits establishing a frame pointer that points to the middle of the fixed
/// stack allocation, helping code density by allowing more accesses to use
/// short instruction forms. The operation info field is reserved and shouldn't
/// be used.
pub const UWOP_SET_FPREG: u8 = 3;

/// Save a nonvolatile integer register on the stack using a MOV instead of a PUSH.
///
/// This code is primarily used for *shrink-wrapping*, where a nonvolatile
/// register is saved to the stack in a position that was previously allocated.
/// The operation info is the number of the register. The scaled-by-8 stack
/// offset is recorded in the next unwind operation code slot.
pub const UWOP_SAVE_NONVOL: u8 = 4;

/// Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH.
///
/// This code is primarily used for *shrink-wrapping*, where a nonvolatile
/// register is saved to the stack in a position that was previously allocated.
/// The operation info is the number of the register. The unscaled stack offset
/// is recorded in the next two unwind operation code slots.
pub const UWOP_SAVE_NONVOL_FAR: u8 = 5;

/// Undocumented.
pub const UWOP_EPILOG: u8 = 6;

/// Undocumented.
///
/// Previously 64-bit `UWOP_SAVE_XMM_FAR`.
pub const UWOP_SPARE_CODE: u8 = 7;

/// Save all 128 bits of a nonvolatile XMM register on the stack.
///
/// The operation info is the number of the register. The scaled-by-16 stack
/// offset is recorded in the next slot.
pub const UWOP_SAVE_XMM128: u8 = 8;

/// Save all 128 bits of a nonvolatile XMM register on the stack with a long offset.
///
/// The operation info is the number of the register. The unscaled stack offset
/// is recorded in the next two slots.
pub const UWOP_SAVE_XMM128_FAR: u8 = 9;

/// Push a machine frame.
///
/// This unwind code is used to record the effect of a hardware interrupt or
/// exception. There are two forms. If the operation info equals 0, one of these
/// frames has been pushed on the stack:
///
/// | Location | Value   |
/// | -------- | ------- |
/// | RSP+32   | SS      |
/// | RSP+24   | Old RSP |
/// | RSP+16   | EFLAGS  |
/// | RSP+8    | CS      |
/// | RSP      | RIP     |
///
/// If the operation info equals 1, then one of these frames has been pushed:
///
/// | Location | Value      |
/// | -------- | ---------- |
/// | RSP+40   | SS         |
/// | RSP+32   | Old RSP    |
/// | RSP+24   | EFLAGS     |
/// | RSP+16   | CS         |
/// | RSP+8    | RIP        |
/// | RSP      | Error code |
///
/// This unwind code always appears in a dummy prolog, which is never actually
/// executed, but instead appears before the real entry point of an interrupt
/// routine, and exists only to provide a place to simulate the push of a
/// machine frame. `UWOP_PUSH_MACHFRAME` records that simulation, which
/// indicates the machine has conceptually done this operation:
///
/// 1. Pop RIP return address from top of stack into *Temp*
/// 2. Push SS
/// 3. Push old RSP
/// 4. Push EFLAGS
/// 5. Push CS
/// 6. Push *Temp*
/// 7. Push Error Code (if op info equals 1)
///
/// The simulated `UWOP_PUSH_MACHFRAME` operation decrements RSP by 40 (op info
/// equals 0) or 48 (op info equals 1).
pub const UWOP_PUSH_MACHFRAME: u8 = 10;

// UNW_FLAG values.

/// The function has no handler.
pub const UNW_FLAG_NHANDLER: u8 = 0x0;

/// The function has an exception handler that should be called.
pub const UNW_FLAG_EHANDLER: u8 = 0x1;

/// The function has a termination handler that should be called when unwinding an exception.
pub const UNW_FLAG_UHANDLER: u8 = 0x2;

/// The FunctionEntry member is the contents of a previous function table entry.
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

// x64 register encoding indices, matching the CPU instruction encoding
// (REX.B + reg field) and the UNWIND_CODE.OpInfo numbering. These are
// used to index into the unwind context when processing unwind codes.

/// Index of `AMD64_CONTEXT::Rax`.
pub const REG_RAX: u8 = 0;

/// Index of `AMD64_CONTEXT::Rcx`.
pub const REG_RCX: u8 = 1;

/// Index of `AMD64_CONTEXT::Rdx`.
pub const REG_RDX: u8 = 2;

/// Index of `AMD64_CONTEXT::Rbx`.
pub const REG_RBX: u8 = 3;

/// Index of `AMD64_CONTEXT::Rsp`.
pub const REG_RSP: u8 = 4;

/// Index of `AMD64_CONTEXT::Rbp`.
pub const REG_RBP: u8 = 5;

/// Index of `AMD64_CONTEXT::Rsi`.
pub const REG_RSI: u8 = 6;

/// Index of `AMD64_CONTEXT::Rdi`.
pub const REG_RDI: u8 = 7;

/// Index of `AMD64_CONTEXT::R8`.
pub const REG_R8: u8 = 8;

/// Index of `AMD64_CONTEXT::R9`.
pub const REG_R9: u8 = 9;

/// Index of `AMD64_CONTEXT::R10`.
pub const REG_R10: u8 = 10;

/// Index of `AMD64_CONTEXT::R11`.
pub const REG_R11: u8 = 11;

/// Index of `AMD64_CONTEXT::R12`.
pub const REG_R12: u8 = 12;

/// Index of `AMD64_CONTEXT::R13`.
pub const REG_R13: u8 = 13;

/// Index of `AMD64_CONTEXT::R14`.
pub const REG_R14: u8 = 14;

/// Index of `AMD64_CONTEXT::R15`.
pub const REG_R15: u8 = 15;

/// Unwind context for x64 (AMD64).
///
/// Holds the register state needed for stack unwinding, including
/// the instruction pointer, stack pointer, and all callee-saved
/// (non-volatile) general-purpose registers.
#[derive(Debug, Clone)]
pub struct UnwindContextAmd64 {
    /// Instruction pointer (RIP).
    pub rip: u64,
    /// Stack pointer (RSP).
    pub rsp: u64,
    /// Base pointer (RBP) - callee-saved.
    pub rbp: u64,
    /// RBX - callee-saved.
    pub rbx: u64,
    /// RSI - callee-saved.
    pub rsi: u64,
    /// RDI - callee-saved.
    pub rdi: u64,
    /// R12 - callee-saved.
    pub r12: u64,
    /// R13 - callee-saved.
    pub r13: u64,
    /// R14 - callee-saved.
    pub r14: u64,
    /// R15 - callee-saved.
    pub r15: u64,
}

impl UnwindContextAmd64 {
    /// Returns the value of a register by its x64 encoding index.
    pub fn get_register(&self, reg: u8) -> u64 {
        match reg {
            REG_RBX => self.rbx,
            REG_RBP => self.rbp,
            REG_RSI => self.rsi,
            REG_RDI => self.rdi,
            REG_R12 => self.r12,
            REG_R13 => self.r13,
            REG_R14 => self.r14,
            REG_R15 => self.r15,
            _ => 0,
        }
    }

    /// Sets the value of a register by its x64 encoding index.
    ///
    /// Only updates non-volatile registers; volatile registers are ignored.
    pub fn set_register(&mut self, reg: u8, value: u64) {
        match reg {
            REG_RBX => self.rbx = value,
            REG_RBP => self.rbp = value,
            REG_RSI => self.rsi = value,
            REG_RDI => self.rdi = value,
            REG_R12 => self.r12 = value,
            REG_R13 => self.r13 = value,
            REG_R14 => self.r14 = value,
            REG_R15 => self.r15 = value,
            _ => {} // volatile registers - ignore
        }
    }
}

/// x64 stack unwinder.
///
/// Implements stack unwinding for the Windows x64 ABI by reading
/// .pdata RUNTIME_FUNCTION entries and processing UNWIND_INFO
/// structures to recover the caller's register state.
pub struct StackUnwindAmd64;

impl<Driver> StackUnwind<Driver> for StackUnwindAmd64
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Context = UnwindContextAmd64;

    fn unwind(
        &self,
        vmi: &VmiState<WindowsOs<Driver>>,
        image_base: Va,
        image: &impl PeImage,
        context: &mut UnwindContextAmd64,
    ) -> Result<Option<StackFrame>, VmiError> {
        // Compute RVA of the current instruction pointer.
        let rva = context.rip.saturating_sub(image_base.0) as u32;

        // Look up RUNTIME_FUNCTION for this RVA.
        let exception_dir = image.exception_directory()?;
        let runtime_function = exception_dir.as_ref().and_then(|dir| dir.find(rva));

        let entry = match runtime_function {
            Some(entry) => entry,
            None => {
                // Leaf function: return address is at [RSP].
                return unwind_leaf(vmi, context);
            }
        };

        let begin_address = entry.begin_address.get(LE);
        let unwind_data_rva = entry.unwind_info_address_or_data.get(LE);
        let mut unwind_rva = unwind_data_rva;

        // RIP offset within the function, for prolog detection.
        // Only meaningful for the first (non-chained) UNWIND_INFO.
        let rip_offset = rva.saturating_sub(begin_address);
        let mut is_first = true;
        let mut machine_frame = false;
        let mut chain_count = 0u32;

        loop {
            let mut header = [0u8; 4];
            image.read_at_rva(unwind_rva, &mut header)?;

            let flags = (header[0] >> 3) & 0x1f;
            let size_of_prolog = header[1];
            let count_of_codes = header[2] as usize;
            let frame_register = header[3] & 0x0f;
            let frame_offset = (header[3] >> 4) & 0x0f;

            // Read unwind codes.
            let codes_size = count_of_codes * 2;
            let mut codes_data = vec![0u8; codes_size];
            if codes_size > 0 {
                image.read_at_rva(unwind_rva + 4, &mut codes_data)?;
            }

            // Compute FrameBase (per Microsoft spec, computed ONCE before
            // processing codes). SAVE_NONVOL offsets are relative to this.
            let frame_base = if frame_register != 0 {
                context.get_register(frame_register) - (frame_offset as u64) * 16
            }
            else {
                context.rsp
            };

            // If frame_register is set and we are past the prolog (or in
            // a chained entry), restore RSP from the frame register.
            if frame_register != 0 && (!is_first || rip_offset >= size_of_prolog as u32) {
                context.rsp = frame_base;
            }

            // Process unwind codes.
            let mut slot = 0;
            while slot < count_of_codes {
                let code_offset = codes_data[slot * 2];
                let op_info = codes_data[slot * 2 + 1];
                let op = op_info & 0x0f;
                let info = (op_info >> 4) & 0x0f;

                // In the first (non-chained) entry, if we are in the prolog,
                // skip codes whose instructions have not yet executed.
                if is_first
                    && (rip_offset < size_of_prolog as u32)
                    && (code_offset as u32 > rip_offset)
                {
                    slot += slots_for_op(op, info);
                    continue;
                }

                match op {
                    UWOP_PUSH_NONVOL => {
                        let value = vmi.read_u64(Va(context.rsp))?;
                        context.set_register(info, value);
                        context.rsp += 8;
                        slot += 1;
                    }
                    UWOP_ALLOC_LARGE => {
                        if info == 0 {
                            let alloc = read_u16_from_codes(&codes_data, slot + 1) as u64 * 8;
                            context.rsp += alloc;
                            slot += 2;
                        }
                        else {
                            let alloc = read_u32_from_codes(&codes_data, slot + 1) as u64;
                            context.rsp += alloc;
                            slot += 3;
                        }
                    }
                    UWOP_ALLOC_SMALL => {
                        context.rsp += info as u64 * 8 + 8;
                        slot += 1;
                    }
                    UWOP_SET_FPREG => {
                        // Restore RSP from the frame register.
                        // frame_base was already computed with the same formula.
                        context.rsp = frame_base;
                        slot += 1;
                    }
                    UWOP_SAVE_NONVOL => {
                        // Offset is relative to FrameBase, NOT current RSP.
                        let offset = read_u16_from_codes(&codes_data, slot + 1) as u64 * 8;
                        let value = vmi.read_u64(Va(frame_base + offset))?;
                        context.set_register(info, value);
                        slot += 2;
                    }
                    UWOP_SAVE_NONVOL_FAR => {
                        // Offset is relative to FrameBase, NOT current RSP.
                        let offset = read_u32_from_codes(&codes_data, slot + 1) as u64;
                        let value = vmi.read_u64(Va(frame_base + offset))?;
                        context.set_register(info, value);
                        slot += 3;
                    }
                    UWOP_EPILOG => {
                        // v2 epilog descriptor - skip.
                        slot += 2;
                    }
                    UWOP_SPARE_CODE => {
                        // Reserved/undocumented opcode, consumes 3 slots.
                        slot += 3;
                    }
                    UWOP_SAVE_XMM128 => {
                        slot += 2;
                    }
                    UWOP_SAVE_XMM128_FAR => {
                        slot += 3;
                    }
                    UWOP_PUSH_MACHFRAME => {
                        if info == 1 {
                            context.rsp += 8; // skip error code
                        }
                        // Machine frame: RIP at [RSP], RSP at [RSP+24].
                        let new_rip = vmi.read_u64(Va(context.rsp))?;
                        let new_rsp = vmi.read_u64(Va(context.rsp + 24))?;
                        context.rip = new_rip;
                        context.rsp = new_rsp;
                        machine_frame = true;
                        slot += 1;
                    }
                    _ => {
                        tracing::warn!(op, info, "unknown unwind opcode");
                        slot += 1;
                    }
                }
            }

            // If no chained info, we are done processing codes.
            if flags & UNW_FLAG_CHAININFO == 0 {
                break;
            }

            // Follow the chain: RUNTIME_FUNCTION is after the codes,
            // aligned to a 4-byte boundary.
            let aligned_count = count_of_codes + (count_of_codes & 1);
            let chain_offset = (4 + aligned_count * 2) as u32;

            let mut chain_buf = [0u8; 12];
            image.read_at_rva(unwind_rva + chain_offset, &mut chain_buf)?;

            let chained_unwind_rva = u32::from_le_bytes(chain_buf[8..12].try_into().unwrap());
            unwind_rva = chained_unwind_rva;
            is_first = false;
            chain_count += 1;

            if chain_count > UNWIND_CHAIN_LIMIT {
                tracing::warn!("unwind chain limit exceeded");
                break;
            }
        }

        // If a machine frame was encountered, RIP/RSP are already set.
        if machine_frame {
            if context.rip == 0 {
                return Ok(None);
            }

            // Read home space from the caller's RSP.
            let params = read_params(vmi, context.rsp);

            return Ok(Some(StackFrame {
                number: 0,
                instruction_pointer: Va(context.rip),
                stack_pointer: Va(context.rsp),
                params,
                machine_frame: true,
            }));
        }

        // Pop return address from [RSP].
        let return_addr = vmi.read_u64(Va(context.rsp))?;
        context.rsp += 8;

        if return_addr == 0 {
            return Ok(None);
        }

        context.rip = return_addr;

        // Read home space from the caller's RSP (after popping the
        // return address, RSP points to the start of the home space).
        let params = read_params(vmi, context.rsp);

        Ok(Some(StackFrame {
            number: 0,
            instruction_pointer: Va(return_addr),
            stack_pointer: Va(context.rsp),
            params,
            machine_frame: false,
        }))
    }
}

/// Reads the four parameter home-space values from the caller's stack.
///
/// Called after unwinding and popping the return address, so RSP
/// points to the start of the home space (P1Home at RSP+0).
/// Returns zeros for any unreadable slots.
fn read_params<Driver>(vmi: &VmiState<WindowsOs<Driver>>, rsp: u64) -> [u64; 4]
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    // Params are informational only - don't abort the unwind on failure.
    [
        vmi.read_u64(Va(rsp)).unwrap_or(0),
        vmi.read_u64(Va(rsp + 8)).unwrap_or(0),
        vmi.read_u64(Va(rsp + 16)).unwrap_or(0),
        vmi.read_u64(Va(rsp + 24)).unwrap_or(0),
    ]
}

/// Unwinds a leaf function (no RUNTIME_FUNCTION entry).
///
/// For leaf functions, the return address is at [RSP] and the
/// caller's RSP is RSP + 8. This is also useful as a fallback
/// when .pdata is unavailable (e.g., file-backed pages missing
/// from a crash dump).
pub fn unwind_leaf<Driver>(
    vmi: &VmiState<WindowsOs<Driver>>,
    context: &mut UnwindContextAmd64,
) -> Result<Option<StackFrame>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    let return_addr = vmi.read_u64(Va(context.rsp))?;
    context.rsp += 8;

    if return_addr == 0 {
        return Ok(None);
    }

    context.rip = return_addr;

    // Read home space from the caller's RSP.
    let params = read_params(vmi, context.rsp);

    Ok(Some(StackFrame {
        number: 0,
        instruction_pointer: Va(return_addr),
        stack_pointer: Va(context.rsp),
        params,
        machine_frame: false,
    }))
}

/// Returns the number of code slots consumed by an unwind operation.
fn slots_for_op(op: u8, info: u8) -> usize {
    match op {
        UWOP_PUSH_NONVOL => 1,
        UWOP_ALLOC_LARGE => {
            if info == 0 {
                2
            }
            else {
                3
            }
        }
        UWOP_ALLOC_SMALL => 1,
        UWOP_SET_FPREG => 1,
        UWOP_SAVE_NONVOL => 2,
        UWOP_SAVE_NONVOL_FAR => 3,
        UWOP_SPARE_CODE => 3,
        UWOP_SAVE_XMM128 => 2,
        UWOP_SAVE_XMM128_FAR => 3,
        UWOP_PUSH_MACHFRAME => 1,
        _ => 1,
    }
}

/// Reads a u16 from the unwind code data at the given slot index.
///
/// Each slot is 2 bytes. The u16 is stored in little-endian format.
fn read_u16_from_codes(data: &[u8], slot: usize) -> u16 {
    let offset = slot * 2;
    if offset + 2 <= data.len() {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    }
    else {
        0
    }
}

/// Reads a u32 from the unwind code data at the given slot index.
///
/// The u32 spans two consecutive slots (4 bytes) in little-endian format.
fn read_u32_from_codes(data: &[u8], slot: usize) -> u32 {
    let offset = slot * 2;
    if offset + 4 <= data.len() {
        u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    }
    else {
        0
    }
}
