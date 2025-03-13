#![allow(non_snake_case, dead_code, non_camel_case_types)]

use isr_macros::{Field, offsets, symbols};

symbols! {
    #[derive(Debug)]
    pub struct Symbols {
        _text: u64,
        init_task: u64,
        entry_SYSCALL_64: u64,
        pcpu_hot: u64,

        __bad_area_nosemaphore: u64,
    }
}

// TODO: TASK_SIZE_MAX defines the same as MmHighestUserAddress
// for 32-bit it's... complicated. Default value is 0xC0000000, but it depends on Kconfig:
//  default 0xB0000000 if VMSPLIT_3G_OPT
//  default 0x80000000 if VMSPLIT_2G
//  default 0x78000000 if VMSPLIT_2G_OPT
//  default 0x40000000 if VMSPLIT_1G
//  default 0xC0000000
// for 64-bit it has value ((1UL << 47) - PAGE_SIZE) = 7FFF_FFFF_F000
// for 32-bit on 64-bit it has value 0xFFFF_E000 or 0xC000_0000 (if (current->personality & ADDR_LIMIT_3GB))

offsets! {
    #[derive(Debug)]
    pub struct Offsets {
        struct pcpu_hot {
            current_task: Field,
        }

        struct fs_struct {
            root: Field,                    // struct path root;
            pwd: Field,                     // struct path pwd;
        }

        struct mm_struct {
            // mmap: Field,
            mm_mt: Field,                   // struct maple_tree mm_mt;
            pgd: Field,                     // pgd_t *pgd;
            exe_file: Field,                // struct file *exe_file;
        }

        struct vm_area_struct {
            vm_start: Field,
            vm_end: Field,
            vm_page_prot: Field,
            vm_flags: Field,
            vm_file: Field,
        }

        struct task_struct {
            flags: Field,
            tasks: Field,
            mm: Field,
            active_mm: Field,
            pid: Field,
            tgid: Field,
            real_parent: Field,             // struct task_struct *real_parent;
            parent: Field,                  // struct task_struct *parent;
            comm: Field,
            fs: Field,
        }

        struct dentry {
            d_name: Field,                  // struct qstr d_name;
            d_parent: Field,                // struct dentry *d_parent;
        }

        struct file {
            f_path: Field,                  // struct path f_path;
        }

        struct path {
            dentry: Field,                  // struct dentry *dentry;
            mnt: Field,                     // struct vfsmount *mnt;
        }

        struct vfsmount {
            mnt_root: Field,                // struct dentry *mnt_root;
        }

        struct qstr {
            name: Field,                    // const unsigned char *name;
            len: Field,                     // u32 len;
        }

        struct list_head {
            next: Field,                    // struct list_head *next;
            prev: Field,                    // struct list_head *prev;
        }

        struct maple_tree {
            ma_flags: Field,                // unsigned int ma_flags;
            ma_root: Field,                 // void __rcu *ma_root;
        }

        struct maple_node {
            parent: Field,                  // struct maple_pnode *parent;
            slot: Field,                    // void __rcu *slot[MAPLE_NODE_SLOTS];
            mr64: Field,                    // struct maple_range_64 mr64;
            ma64: Field,                    // struct maple_arange_64 ma64;
        }

        struct maple_range_64 {
            parent: Field,                  // struct maple_pnode *parent;
            pivot: Field,                   // unsigned long pivot[MAPLE_RANGE64_SLOTS - 1];
            slot: Field,                    // void __rcu *slot[MAPLE_RANGE64_SLOTS];
        }

        struct maple_arange_64 {
            parent: Field,                  // struct maple_pnode *parent;
            pivot: Field,                   // unsigned long pivot[MAPLE_ARANGE64_SLOTS - 1];
            slot: Field,                    // void __rcu *slot[MAPLE_ARANGE64_SLOTS];
        }
    }
}
