mod amd64;

use vmi_core::{Architecture, Pa, Va, VmiCore, VmiError, VmiState, driver::VmiRead};

use crate::{LinuxKernelInformation, LinuxOs};

/// Architecture-specific Linux functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiRead<Architecture = Self>,
{
    /// Locates the Linux kernel banner by scanning forward from the syscall
    /// entry point.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: Scans forward from the 2 MiB page that holds `MSR_LSTAR`
    ///   (up to 64 MiB). Returns the last banner that names the release of the
    ///   first one, within 16 MiB after it. When the scan finds nothing and CR3
    ///   has `PTI_USER_PGTABLE_BIT` set, it scans again through the root with
    ///   the bit cleared, the kernel page tables of KPTI.
    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<LinuxKernelInformation>, VmiError>;

    /// Reads a syscall argument by index.
    ///
    /// Index 0 is the first argument. Linux syscalls have at most six
    /// arguments.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: At the syscall entry (`RIP` equals `MSR_LSTAR`), the
    ///   arguments are in `RDI`, `RSI`, `RDX`, `R10`, `R8` and `R9`. In the
    ///   prologue of a syscall handler (`__x64_sys_*`), they are the fields
    ///   `di`, `si`, `dx`, `r10`, `r8` and `r9` of the `pt_regs` that `RDI`
    ///   points to.
    fn syscall_argument(vmi: VmiState<LinuxOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    /// Reads a function-call argument by index from the current register state.
    ///
    /// Unlike [`syscall_argument`](Self::syscall_argument), this follows the
    /// standard calling convention.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: System V calling convention (`RDI`, `RSI`, `RDX`, `RCX`,
    ///   `R8`, `R9`, then the stack) in long mode, stack-based in
    ///   compatibility mode.
    fn function_argument(vmi: VmiState<LinuxOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    /// Reads the return value of the most recent function call.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `RAX`
    fn function_return_value(vmi: VmiState<LinuxOs<Driver>>) -> Result<u64, VmiError>;

    /// Returns the KASLR offset, caching the result for subsequent calls.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `MSR_LSTAR - entry_SYSCALL_64`
    fn kaslr_offset(vmi: VmiState<LinuxOs<Driver>>) -> Result<u64, VmiError>;

    /// Returns the per-CPU base of the vCPU of the VMI state.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `GS.base` in kernel mode, `KERNEL_GS_BASE` in user mode.
    fn per_cpu_base(vmi: VmiState<LinuxOs<Driver>>) -> Va;

    /// Checks whether the kernel runs with page table isolation.
    ///
    /// The check reads through explicit roots, never through
    /// [`translation_root`](Self::translation_root), which depends on its
    /// result.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: `X86_FEATURE_PTI` in `boot_cpu_data.x86_capability`. When
    ///   the root in CR3 does not map it and has `PTI_USER_PGTABLE_BIT` set, the
    ///   read uses the root with the bit cleared.
    fn kpti_enabled(vmi: VmiState<LinuxOs<Driver>>) -> Result<bool, VmiError>;

    /// Returns the page table root that translates a virtual address for the
    /// VMI state.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: Under KPTI, a vCPU in user mode has the user page tables in
    ///   CR3 (`PTI_USER_PGTABLE_BIT` set), which map almost none of the kernel.
    ///   For a kernel address, the root then becomes the kernel page tables of
    ///   the same process, with the bit cleared.
    fn translation_root(vmi: VmiState<LinuxOs<Driver>>, va: Va) -> Pa;

    /// Returns the page table root of user mode under page table isolation.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: The user page table directly follows the kernel one, so
    ///   the root is the kernel root plus 4 KiB (`PTI_USER_PGTABLE_BIT`).
    fn user_translation_root(root: Pa) -> Pa;
}
