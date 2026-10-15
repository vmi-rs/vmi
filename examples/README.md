# Examples

The framework includes several examples demonstrating various VMI
capabilities, from basic operations to more complex scenarios.

- **[`basic.rs`]**

  Demonstrates fundamental VMI operations like retrieving the Interrupt
  Descriptor Table (IDT) for each virtual CPU.

- **[`basic-process-list.rs`]**

  Shows how to retrieve and display a list of running processes in the
  guest VM.

- **[`basic-process-list-kvm-macos.rs`]**

  Shows how to retrieve and display a list of running processes in a macOS
  guest that runs in a KVM virtual machine on an Apple silicon host.

- **[`macos-dump.rs`]**

  Demonstrates how to use the VMI library to analyze a macOS memory dump
  created by the QEMU `dump-guest-memory` command.

- **[`macos-breakpoint-manager-kvm.rs`]**

  Demonstrates the [`BreakpointManager`] and [`PageTableMonitor`] on a live
  macOS KVM guest, following the structure of the Windows example. A fixed
  symbol table supplies tagged breakpoints, and separate handlers report
  process lifecycle and vnode file operations. Original-instruction stepping,
  mapping tracking, shadow refresh, and Ctrl-C cleanup remain enabled.

  Run as root on an aarch64 host with matching 16KB host and guest pages:

  ```sh
  cargo run --release \
    --example macos-breakpoint-manager-kvm \
    --features arch-arm64,driver-kvm,os-macos,utils-bpm
  ```

  Optional arguments after `--` are `PID CACHE HITS`. Defaults are the first
  QEMU process, `cache`, and unlimited hits (`0`). Only one VMI client can
  attach to the VM at a time.

  | Kernel hook | Observation |
  | --- | --- |
  | `dtrace_proc_fork` | An initialized fork/spawn child, its parent PID, and its inherited name. |
  | `mac_proc_notify_exec_complete` | Exec-completion notification with the current name and image path. |
  | `mac_proc_notify_exit` | Final process cleanup, excluding exec's old shadow-proc teardown. |
  | `mac_vnode_notify_create` | Creation notification with the initialized result vnode's path. |
  | `vn_write` | Vnode write requests from `write`, `pwrite`, and `writev`, including requested bytes and positional offsets. |

  These private kernel hook signatures were checked in IDA against macOS
  27.0.1 (26A434). A creation notification is not an unconditional successful
  create: compound opens can notify for an existing vnode, and later policy
  checks can fail. Write lengths are requested bytes, not completed transfers.
  Memory-mapped writes and non-vnode I/O are not covered. Paths follow the
  mount hierarchy, so data-volume files can appear under `/System/Volumes/Data`.

- **[`macos-trace-kvm`]**

  Traces semantic calls and XPC activity in a live macOS arm64 KVM guest.
  Main-image/library view transitions provide C call coverage using [sigmd]
  SDK declarations. Selected shadow breakpoints cover Objective-C dispatch
  and `objc_opt_*` helpers, method mutations, XPC, dispatch handoffs and kernel
  lifecycle boundaries. The original instruction view remains unmodified.

  Objective-C output uses live method encodings and actual receiver classes,
  for example `-[OrchardProbe<0x...> roundTrip:-41] returned -42`.
  Entry snapshots and per-thread LR/SP matching capture scalar, pointer,
  object and void returns. Floating-point-returning Objective-C methods and
  `retain`/`release`/`autorelease` messages are excluded. Genuine variadic tails,
  unavailable SIMD and unsupported aggregate arguments stay unknown.
  Concrete heap, constant, mutable,
  tagged and NSPathStore2 strings are read without guest getters.
  `execve` prints bounded `argv` contents.

  XPC output separates send intent, authoritative kernel transport and
  delivery, decoded handlers, sync/async replies, dispatch continuations and
  launch/exec lineage. Discovered peers are traced as well. Port names,
  timing, payload equality and launchd ancestry alone are not causal proof.
  Private layouts/hooks are UUID and instruction guarded for build 26A434.
  Reads, strings, containers and recursion are bounded with explicit
  unsupported, unreadable and truncated output.

  ```sh
  cargo run --release --example macos-trace-kvm \
    --features arch-arm64,driver-kvm,os-macos,utils-bpm -- TARGET [QEMU-PID] [CACHE]
  ```

  `TARGET` is a process ID or name. To trace a short-lived command such as
  `ls -als`, build `examples/macos-trace-kvm/spawn-suspended.c` in the guest
  and run `./spawn-suspended ls -als`: it stops the command right after exec
  and prints its pid. Attach the tracer to that pid, then press Enter in the
  guest. Successful exec refreshes the primary image catalog and retires
  old calls instead of inventing returns. Ordinary newly loaded exports and
  library-to-library calls are not exhaustively traced, but selected semantic
  hooks cover those boundaries. Allocation and Objective-C reference-counting
  helper noise remains filtered (`IGNORED_MODULES` in `tracer.rs`).
  Stop with Ctrl-C. When capturing with `tee`, use `tee --ignore-interrupts`
  so the tracer can finish writing its cleanup diagnostics.

  The tracer reads the database from
  `examples/macos-trace-kvm/assets/metadata.bin` or from `SIGMD_METADATA`.
  Build it in a [sigmd] checkout: copy the SDK from a Mac with
  `scripts/fetch-macsdk.sh --host MAC`, then run
  `cargo run --release -- -c sigmd-macos.yaml build -o metadata-macos.bin`.

- **[`windows-breakpoint-manager.rs`]**

  Illustrates the usage of the [`BreakpointManager`] and
  [`PageTableMonitor`] to set and manage breakpoints on Windows systems.

- **[`windows-dump.rs`]**

  Demonstrates how to use the VMI library to analyze a Windows kernel dump file.

- **[`windows-recipe-messagebox.rs`]**

  A simple example of code injection using a recipe to display a message
  box in the guest.

- **[`windows-recipe-writefile.rs`]**

  Demonstrates injecting code that writes data to a file in the guest.

- **[`windows-recipe-writefile-advanced.rs`]**

  A more complex example showing how to write to a file in chunks and
  handle potential errors during injection.

- **[`windows-bridge`]**

  Demonstrates advanced VMI utilities:
  - guest-host bridges
  - shellcode injection
  - page-table monitoring (PTM)
  - breakpoint management (BPM)
  - process/thread tracking

- **[`windows-shellcode`]**

  Demonstrates how to inject shellcode into the guest VM.


[`BreakpointManager`]: https://docs.rs/vmi/latest/vmi/utils/bpm/struct.BreakpointManager.html
[`PageTableMonitor`]: https://docs.rs/vmi/latest/vmi/utils/ptm/struct.PageTableMonitor.html

[`basic.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic.rs
[`basic-process-list.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic-process-list.rs
[`basic-process-list-kvm-macos.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic-process-list-kvm-macos.rs
[`macos-dump.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/macos-dump.rs
[`macos-breakpoint-manager-kvm.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/macos-breakpoint-manager-kvm.rs
[`macos-trace-kvm`]: https://github.com/vmi-rs/vmi/blob/master/examples/macos-trace-kvm/main.rs
[`windows-breakpoint-manager.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-breakpoint-manager.rs
[`windows-dump.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-dump.rs
[`windows-recipe-messagebox.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-messagebox.rs
[`windows-recipe-writefile.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile.rs
[`windows-recipe-writefile-advanced.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile-advanced.rs
[`windows-shellcode`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-shellcode
[`windows-bridge`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-bridge
[sigmd]: https://github.com/vmi-rs/sigmd
