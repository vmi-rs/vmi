//! Kernel symbols and structure offsets, read from an isr profile.
//!
//! Every symbol and field here exists in Linux 6.8 and later, except in two
//! places with two layouts each:
//!
//! - The per-CPU current task changed in Linux 6.15 (see [`LinuxOs`]). The
//!   crate picks its layout by the symbols that the profile holds.
//! - `module_notes_attrs` changed in Linux 6.14. [`ModuleNotesLayout`] picks
//!   its layout by the fields `notes` and `grp`, and it needs exactly one of
//!   them.
//!
//! The absence of a field alone never picks a layout. isr's nested field
//! lookup can find a field of the same name in a nested structure.
//!
//! [`LinuxOs`]: crate::LinuxOs

// The structures keep the names that the kernel gives them.
#![allow(non_camel_case_types)]

use isr_macros::{Field, offsets, symbols};

use crate::LinuxError;

symbols! {
    /// Linux kernel symbols used by the [`LinuxOs`] implementation.
    ///
    /// The values are link-time addresses. At runtime, every kernel symbol
    /// lies at its link-time address plus the KASLR offset. The zero-based
    /// per-CPU offset `pcpu_hot` is the exception.
    ///
    /// [`LinuxOs`]: crate::LinuxOs
    #[derive(Debug)]
    pub struct Symbols {
        _text: u64,
        entry_SYSCALL_64: u64,
        init_task: u64,                 // struct task_struct
        init_mm: u64,                   // struct mm_struct
        linux_banner: u64,              // const char[]
        modules: u64,                   // struct list_head
        boot_cpu_data: u64,             // struct cpuinfo_x86
        __start___ksymtab: u64,         // struct kernel_symbol[]
        __stop___ksymtab: u64,
        __start___ksymtab_gpl: u64,     // struct kernel_symbol[]
        __stop___ksymtab_gpl: u64,
        __start_notes: u64,             // Elf64_Nhdr[]
        __stop_notes: u64,

        current_task: Option<u64>,      // per-CPU struct task_struct*, Linux 6.15 and later
        pcpu_hot: Option<u64>,          // per-CPU struct pcpu_hot, Linux 6.2 to 6.14
        x64_sys_call: Option<u64>,      // Linux 6.9 and later, and the stable 6.8.12
    }
}

offsets! {
    /// Linux kernel structure offsets used by the [`LinuxOs`] implementation.
    ///
    /// [`LinuxOs`]: crate::LinuxOs
    #[derive(Debug)]
    pub struct Offsets {
        struct list_head {
            next: Field,                // struct list_head*
            prev: Field,                // struct list_head*
        }

        struct task_struct {
            __state: Field,             // unsigned int
            flags: Field,               // unsigned int
            tasks: Field,               // struct list_head
            mm: Field,                  // struct mm_struct*
            active_mm: Field,           // struct mm_struct*
            pid: Field,                 // pid_t
            tgid: Field,                // pid_t
            real_parent: Field,         // struct task_struct*
            group_leader: Field,        // struct task_struct*
            thread_node: Field,         // struct list_head
            comm: Field,                // char[TASK_COMM_LEN]
            signal: Field,              // struct signal_struct*
        }

        struct signal_struct {
            thread_head: Field,         // struct list_head
        }

        struct mm_struct {
            mm_mt: Field,               // struct maple_tree
            pgd: Field,                 // pgd_t*
            task_size: Field,           // unsigned long
            exe_file: Field,            // struct file*
            saved_auxv: Field,          // unsigned long[AT_VECTOR_SIZE]
        }

        struct vm_area_struct {
            vm_start: Field,            // unsigned long
            vm_end: Field,              // unsigned long
            vm_flags: Field,            // vm_flags_t
            vm_pgoff: Field,            // unsigned long
            vm_file: Field,             // struct file*
            vm_mm: Field,               // struct mm_struct*
        }

        struct maple_tree {
            ma_flags: Field,            // unsigned int
            ma_root: Field,             // void*
        }

        struct maple_range_64 {
            pivot: Field,               // unsigned long[MAPLE_RANGE64_SLOTS - 1]
            slot: Field,                // void*[MAPLE_RANGE64_SLOTS]
            meta: Field,                // struct maple_metadata
        }

        struct maple_arange_64 {
            pivot: Field,               // unsigned long[MAPLE_ARANGE64_SLOTS - 1]
            slot: Field,                // void*[MAPLE_ARANGE64_SLOTS]
            meta: Field,                // struct maple_metadata
        }

        struct maple_metadata {
            end: Field,                 // unsigned char
        }

        struct module {
            state: Field,               // enum module_state
            list: Field,                // struct list_head
            name: Field,                // char[MODULE_NAME_LEN]
            mem: Field,                 // struct module_memory[MOD_MEM_NUM_TYPES]
            syms: Field,                // const struct kernel_symbol*
            num_syms: Field,            // unsigned int
            gpl_syms: Field,            // const struct kernel_symbol*
            num_gpl_syms: Field,        // unsigned int
            kallsyms: Field,            // struct mod_kallsyms*
            notes_attrs: Field,         // struct module_notes_attrs*
        }

        struct module_memory {
            base: Field,                // void*
            size: Field,                // unsigned int
        }

        struct mod_kallsyms {
            symtab: Field,              // Elf64_Sym*
            num_symtab: Field,          // unsigned int
            strtab: Field,              // char*
        }

        // One of two layouts, which `ModuleNotesLayout` picks.
        struct module_notes_attrs {
            notes: Option<Field>,       // unsigned int, Linux 6.8 to 6.13
            grp: Option<Field>,         // struct attribute_group, Linux 6.14 and later
            attrs: Field,               // struct bin_attribute[]
        }

        struct attribute_group {
            bin_attrs: Field,           // const struct bin_attribute* const*
        }

        struct bin_attribute {
            attr: Field,                // struct attribute
            size: Field,                // size_t
            private: Field,             // void*
        }

        struct attribute {
            name: Field,                // const char*
        }

        struct file {
            f_path: Field,              // struct path
        }

        struct path {
            mnt: Field,                 // struct vfsmount*
            dentry: Field,              // struct dentry*
        }

        struct dentry {
            d_parent: Field,            // struct dentry*
            d_name: Field,              // struct qstr
        }

        struct qstr {
            len: Field,                 // u32
            name: Field,                // const unsigned char*
        }

        struct mount {
            mnt_parent: Field,          // struct mount*
            mnt_mountpoint: Field,      // struct dentry*
            mnt: Field,                 // struct vfsmount
        }

        struct vfsmount {
            mnt_root: Field,            // struct dentry*
        }

        struct cpuinfo_x86 {
            x86_capability: Field,      // __u32[NCAPINTS + NBUGINTS]
        }

        struct pt_regs {
            di: Field,                  // unsigned long
            si: Field,                  // unsigned long
            dx: Field,                  // unsigned long
            r10: Field,                 // unsigned long
            r8: Field,                  // unsigned long
            r9: Field,                  // unsigned long
            ip: Field,                  // unsigned long
            sp: Field,                  // unsigned long
        }

        // Linux 6.2 to 6.14.
        #[isr(optional)]
        struct pcpu_hot {
            current_task: Field,        // struct task_struct*
        }
    }
}

/// The layout of `module_notes_attrs`.
///
/// The kernel keeps the notes sections of a module in this structure, for
/// the files in `/sys/module/<name>/notes`. Each section has an entry. The
/// entry is a `bin_attribute` that holds the section's name, address and
/// size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleNotesLayout {
    /// The layout of Linux 6.8 to 6.13. The field `notes` counts the entries
    /// in the array `attrs`.
    Counted {
        /// Offset of `module_notes_attrs.notes`.
        notes: u64,

        /// Offset of `module_notes_attrs.attrs`.
        attrs: u64,
    },

    /// The layout of Linux 6.14 and later. The field `grp.bin_attrs` points
    /// to an array of pointers to the entries, which ends with `NULL`.
    Grouped {
        /// Offset of `module_notes_attrs.grp.bin_attrs`.
        bin_attrs: u64,
    },
}

impl ModuleNotesLayout {
    /// Picks the layout from the fields that the profile gives
    /// `module_notes_attrs`.
    pub(crate) fn new(offsets: &Offsets) -> Result<Self, LinuxError> {
        let MODULE_NOTES_ATTRS = &offsets.module_notes_attrs;
        let ATTRIBUTE_GROUP = &offsets.attribute_group;

        match (&MODULE_NOTES_ATTRS.notes, &MODULE_NOTES_ATTRS.grp) {
            (Some(notes), None) => Ok(Self::Counted {
                notes: notes.offset(),
                attrs: MODULE_NOTES_ATTRS.attrs.offset(),
            }),
            (None, Some(grp)) => Ok(Self::Grouped {
                bin_attrs: grp.offset() + ATTRIBUTE_GROUP.bin_attrs.offset(),
            }),
            _ => Err(LinuxError::UnsupportedProfile(
                "module_notes_attrs needs exactly one of notes and grp",
            )),
        }
    }
}
