use isr_macros::{Bitfield, Field, offsets, symbols};

symbols! {
    /// XNU kernel symbols used by the [`MacOs`] implementation.
    ///
    /// The profile stores the addresses of the unslid kernel. [`MacOs::new`]
    /// relocates them to their runtime addresses.
    ///
    /// [`MacOs`]: crate::MacOs
    /// [`MacOs::new`]: crate::MacOs::new
    #[derive(Debug)]
    pub struct Symbols {
        allproc: u64,                       // struct proclist
        kernproc: u64,                      // struct proc *
        kernel_task: u64,                   // task_t
        gLoadedKextSummaries: u64,          // OSKextLoadedKextSummaryHeader *
        rootvnode: u64,                     // vnode_t
        vnode_pager_ops: u64,               // const struct memory_object_pager_ops
        dyld_pager_ops: Option<u64>,
        shared_region_pager_ops: Option<u64>,
        apple_protect_pager_ops: Option<u64>,
    }
}

offsets! {
    /// XNU kernel structure offsets used by the [`MacOs`] implementation.
    ///
    /// [`MacOs`]: crate::MacOs
    #[derive(Debug)]
    pub struct Offsets {
        struct proc {
            p_list: Field,                  // LIST_ENTRY(proc), in an anonymous union
            p_ppid: Field,                  // pid_t
            p_uid: Field,                   // uid_t
            p_gid: Field,                   // gid_t
            p_pid: Field,                   // pid_t
            p_fd: Field,                    // struct filedesc
            p_lflag: Field,                 // unsigned int
            p_start: Field,                 // struct timeval
            p_argslen: Field,               // u_int
            p_argc: Field,                  // int
            user_stack: Field,              // user_addr_t
            p_textvp: Field,                // struct vnode *
            p_comm: Field,                  // char[MAXCOMLEN + 1]
            p_name: Field,                  // char[2 * MAXCOMLEN + 1]
            p_main_exec_load_addr: Field,   // uint64_t
            p_cputype: Field,               // cpu_type_t
        }

        struct filedesc {
            fd_nfiles: Field,               // int
            fd_afterlast: Field,            // int
            fd_ofiles: Field,               // struct fileproc **
        }

        struct timeval {
            tv_sec: Field,                  // __darwin_time_t
            tv_usec: Field,                 // __darwin_suseconds_t
        }

        struct queue_entry {
            next: Field,                    // struct queue_entry *
            prev: Field,                    // struct queue_entry *
        }

        struct task {
            map: Field,                     // vm_map_t
            threads: Field,                 // queue_head_t
            thread_count: Field,            // int
            all_image_info_addr: Field,     // mach_vm_address_t
        }

        struct thread {
            task_threads: Field,            // queue_chain_t
            t_tro: Field,                   // struct thread_ro *
            thread_id: Field,               // uint64_t
        }

        struct thread_ro {
            tro_proc: Field,                // struct proc *
            tro_task: Field,                // struct task *
        }

        struct _vm_map {
            hdr: Field,                     // struct vm_map_header
            pmap: Field,                    // pmap_t
        }

        #[isr(alias = "vm_map_header")]
        struct vm_map_copy {
            first: Field,                   // struct vm_map_entry *
            last: Field,                    // struct vm_map_entry *
            nentries: Field,                // int
        }

        struct pmap {
            ttep: Field,                    // pmap_paddr_t
        }

        struct vm_map_entry {
            vme_next: Field,                // struct vm_map_entry *
            vme_start: Field,               // vm_map_offset_t
            vme_end: Field,                 // vm_map_offset_t
            vme_kind: Bitfield,             // vme_kind_t
            vme_value: Bitfield,            // packed object or submap pointer
            vme_alias: Bitfield,            // VM tag
            protection: Bitfield,           // vm_prot_t
            max_protection: Bitfield,       // vm_prot_t
        }

        struct vm_object {
            shadow: Field,                  // struct vm_object *
            pager: Field,                   // memory_object_t
        }

        struct memory_object {
            mo_pager_ops: Field,            // const struct memory_object_pager_ops *
        }

        struct vnode_pager {
            vnode_handle: Field,            // struct vnode *
        }

        #[isr(optional)]
        struct dyld_pager {
            dyld_backing_object: Field,     // vm_object_t
        }

        #[isr(optional)]
        struct shared_region_pager {
            srp_backing_object: Field,      // vm_object_t
        }

        #[isr(optional)]
        struct apple_protect_pager {
            backing_object: Field,          // vm_object_t
        }

        struct vnode {
            v_flag: Field,                  // uint32_t
            v_type: Field,                  // uint8_t
            v_name: Field,                  // const char *
            v_parent: Field,                // vnode_t
            v_mount: Field,                 // mount_t
        }

        struct mount {
            mnt_vnodecovered: Field,        // vnode_t
        }

        struct fileproc {
            fp_glob: Field,                 // struct fileglob *
        }

        struct fileglob {
            fg_ops: Field,                  // const struct fileops *
            fg_data: Field,                 // void *
        }

        struct fileops {
            fo_type: Field,                 // file_type_t
        }

        struct _loaded_kext_summary_header {
            version: Field,                 // uint32_t
            entry_size: Field,              // uint32_t
            numSummaries: Field,            // uint32_t
            summaries: Field,               // OSKextLoadedKextSummary[0]
        }

        struct _loaded_kext_summary {
            name: Field,                    // char[KMOD_MAX_NAME]
            uuid: Field,                    // uuid_t
            address: Field,                 // uint64_t
            size: Field,                    // uint64_t
            version: Field,                 // uint64_t
            loadTag: Field,                 // uint32_t
            flags: Field,                   // uint32_t
            text_exec_address: Field,       // uint64_t
            text_exec_size: Field,          // uint64_t
        }
    }
}
