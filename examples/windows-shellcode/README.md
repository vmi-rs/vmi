# Windows shellcode example

This example runs two C++ shellcodes in a Windows guest. The Rust program on the
host loads and starts them directly through Xen. No guest agent is required.

- `msgbox` displays a message box with `MessageBoxA` in a guest process.
- `kernel-file` creates or overwrites a guest file and writes `hello world`
  from kernel mode.

The shellcodes use [`scfw`] for startup, Windows API resolution, and automatic
memory cleanup. They report results to the host through a bridge, using a
special CPU instruction (`VMCALL`).

For an example that combines shellcodes with host decisions, process monitoring,
and file transfer, see the [Windows bridge guide].

## Build the shellcodes

Run these commands on the host from the repository root. Use a booted Windows
x64 guest on Xen, and replace `win10-22h2` with its domain name or numeric ID.

```bash
cmake --preset x64 -S examples/shellcodes
cmake --build examples/shellcodes/build-x64
export VMI_XEN_DOMAIN=win10-22h2
```

The Release preset publishes shellcode under `examples/shellcodes/bin/x64/`.
Rust embeds `msgbox.bin` and `kernel-file.bin` with
`include_bytes!`. After changing a shellcode, rebuild it before running the host example.

Use a disposable guest. Kernel injection can hang or crash it, and
`kernel-file` overwrites an existing file at the selected path.

## Choose a mode

A recipe is a short list of host-controlled setup steps in the guest. Each
mode uses an injector to hijack an existing guest thread and run those steps.

| Command | Shellcode | Where the shellcode runs | Recipe finishes when |
| --- | --- | --- | --- |
| `user-call` | `msgbox` | Hijacked user-mode thread | Shellcode returns |
| `user-spawn` | `msgbox` | New thread in the carrier process | Thread has been created |
| `kernel-call` | `kernel-file` | Hijacked thread in kernel mode | Shellcode returns |
| `kernel-spawn` | `kernel-file` | New system thread | Thread has been created |

Prefer `user-spawn` for the message box and `kernel-spawn` for file I/O.
Call modes demonstrate execution on the hijacked thread. Their risks are
described below.

### Display a message box

```bash
cargo run --example windows-shellcode \
    --features arch-amd64,driver-xen,os-windows,utils -- user-spawn \
    --process explorer.exe --title 'Hello from VMI' --text 'A new guest thread'

cargo run --example windows-shellcode \
    --features arch-amd64,driver-xen,os-windows,utils -- user-call \
    --process explorer.exe --title 'Hello from VMI' --text 'A hijacked guest thread'
```

Both commands accept the same options:

| Option | Meaning | Default |
| --- | --- | --- |
| `--process` | Name of the running carrier process | `explorer.exe` |
| `--title` | Message box title | `Hello from VMI` |
| `--text` | Message box text | `Injected by windows-shellcode` |

The carrier process contains the allocation holding the shellcode
and its parameters. Spawn mode runs the shellcode on a new thread in that
process. Dismiss the message box in the guest to let the shellcode report its
`MessageBoxA` result. The host logs `message box closed` on success and treats
a zero return from `MessageBoxA` as a failure.

**`user-call` blocks the hijacked thread until the box is dismissed.** With
`explorer.exe`, parts of the guest shell may stop responding during that time.
With `user-spawn`, the new thread displays the dialog while the hijacked thread
resumes its previous work. The host waits for the dialog result.

### Write a guest file

Choose an existing guest directory and a file that is safe to overwrite. Change
`John` in these examples to a directory that exists in your guest.

```bash
cargo run --example windows-shellcode \
    --features arch-amd64,driver-xen,os-windows,utils -- kernel-spawn \
    --path 'C:\Users\John\Desktop\kernel-spawn.txt'

cargo run --example windows-shellcode \
    --features arch-amd64,driver-xen,os-windows,utils -- kernel-call \
    --path 'C:\Users\John\Desktop\kernel-call.txt'
```

The default `--path` is `C:\Users\John\Desktop\test-{timestamp}.txt`, using a
host timestamp in seconds. Create the parent directory before running the
shellcode.

Use an absolute DOS path such as `C:\Temp\result.txt`, or an absolute NT path
such as `\??\C:\Temp\result.txt`. The host prefixes absolute DOS paths with
`\??\` and passes paths beginning with `\` through unchanged. Convert UNC paths
to NT form before passing them.

The shellcode creates or truncates the file, writes the eleven bytes of
`hello world`, and closes its file handle. It reports whether file creation or
writing failed, including the native Windows status code. On success, the host
logs `file written`.

**`kernel-call` can deadlock the guest.** The injector hijacks a thread at
`SeAccessCheck`. That thread may already hold file-system or object-manager
locks, and the shellcode's file operations can try to acquire those locks again.
Use `kernel-spawn` unless you specifically need call mode and understand that
risk.

`kernel-spawn` runs in the `System` process. A handle or user-mode address from
the original process can refer to a different object or become unusable there.
The parameters in the kernel allocation remain available. This shellcode
uses an absolute NT path and opens its file with `OBJ_KERNEL_HANDLE`, which
creates a handle usable across processes in kernel mode.

## Code flow

### Host calls

The selected command follows one branch. Inside `VmiSession::handle`, the
callback builds one recipe and creates its injector and bridge handler:

```text
main
+-- common::VmiSetup::new
+-- msgbox::run
|   +-- common::find_process_id
|   `-- VmiSession::handle
|       +-- call:  msgbox_call_recipe -> user_shellcode_call_recipe
|       +-- spawn: msgbox_spawn_recipe -> user_shellcode_spawn_recipe
|       `-- UserInjectorHandler + MsgboxBridge
`-- kernel_file::run
    `-- VmiSession::handle
        +-- call:  kernel_file_call_recipe -> kernel_shellcode_call_recipe
        +-- spawn: kernel_file_spawn_recipe -> kernel_shellcode_spawn_recipe
        `-- KernelInjectorHandler + KernelFileBridge
```

The builders prepare the recipe on the host. The injector then hijacks a guest
thread and advances the recipe as Windows returns from each injected call.

### Injection steps

These are simplified successful paths, with shortened API arguments.
`[guest]` means Windows executes the call. `[host]` means Rust acts through VMI.
The payload includes the shellcode, parameters, and alignment padding.

For `user-spawn`:

```text
[guest] VirtualAlloc(payload size, RWX)
  -> [guest] RtlFillMemory(allocation, payload size, 0)
  -> [host]  VMI write(payload)
  -> [guest] CreateThread(shellcode start, parameter address)
  -> [guest] CloseHandle(thread handle)
  -> [host]  restore hijacked-thread registers
```

`RtlFillMemory` touches the allocated pages before the host writes them.
`user-call` uses the allocation and copy steps, then calls
`shellcode(parameter address, 0)` on the hijacked thread. The host restores
the thread's registers after that call returns.

For `kernel-spawn`, the payload also reserves an entry wrapper that supplies
the kernel image base and parameter address:

```text
[guest] ExAllocatePool(NonPagedPoolExecute, payload size)
  -> [host]  VMI write(payload)
  -> [host]  VMI write(entry wrapper with resolved addresses)
  -> [guest] PsCreateSystemThread(entry wrapper)
  -> [guest] ZwClose(thread handle)
  -> [host]  restore hijacked-thread registers
```

`kernel-call` allocates executable kernel memory, copies the payload,
and calls `shellcode(kernel_image_base, parameter_data)` on the hijacked thread.
The host restores its registers when the shellcode returns.

### Guest calls and output

The guest-side `scfw` startup calls `sc::entry` in the [message box shellcode] or
[kernel file shellcode]:

```text
msgbox: sc::entry
+-- MessageBoxA
`-- bridge::exit(result)

kernel-file: sc::entry
+-- WriteHelloWorld
|   +-- ZwCreateFile
|   +-- ZwWriteFile
|   `-- ZwClose
`-- bridge::exit(status)
```

The shellcode reports to the host through a VM event:

```text
[guest] bridge::exit -> VMCALL
  -> [Xen]   VM event
  -> [host]  injector bridge dispatch
             -> MsgboxBridge::handle or KernelFileBridge::handle
  -> [guest] resume after the host response
```

The request code selects the host bridge handler, and the method code selects
an operation within that handler. `msgbox` sends the raw `MessageBoxA` result
as `value1`, and `MsgboxBridge` exposes it as a `u64` output. `kernel-file`
sends an encoded status as `value1`. `KernelFileBridge` exposes the encoded
value as `EncodedStatus`.

`BridgeResponse::with_output()` attaches output, while register values
carry the response back to the guest. Output does not universally mean
completion: each consumer decides when to finish. These example injectors wait
for both the recipe to finish and a final output. In call mode, the
injector retains that output until the shellcode returns. In spawn mode, the
recipe finishes after thread creation, and the injector waits for the final report.

### Self-freeing allocations

The [Shellcode build configuration] enables `SCFW_OPT_CLEANUP`, so the shellcodes
free their own allocations after `sc::entry` returns. `scfw` jumps to
`VirtualFree` in user mode or `ExFreePool` in kernel mode. The Windows routine
frees the allocation and returns to the caller.

The shellcode and parameters share that allocation and
are freed together. For `kernel-spawn`, the entry wrapper is freed with them.

The recipe frees the allocation before retrying a failed copy or thread
creation. After a successful start, the guest-side `scfw` code owns cleanup.

The final `VMCALL` reports the result before this cleanup. The host replies and
resumes the guest so `sc::entry` can return and `scfw` can free the allocation.
Call mode then resumes the hijacked thread. In spawn mode, the new thread
finishes after cleanup. The recipe closes its thread handle during startup.

## Source files

- [Host entry point] selects a command and starts the shared VMI setup.
- [Message box host code] and [kernel file host code] define the options,
  parameter objects, recipes, and bridge handlers.
- [Message box shellcode] and [kernel file shellcode] contain the guest operations.
- [Shellcode utilities] explain the reusable recipe and ownership contracts.
- [Parameter encoding] defines the host `ParameterWriter` and parameter traits.
- [Payload assembly] defines the host-only `Payload`.
- [Guest parameter reader] defines `sc::vmi::parameter_reader` and `read_*`.
- [Bridge contract] defines the shared magic and verification values.
- [Status encoding] defines stages, kinds, and encoded status decoding.
- [Shellcode build configuration] fetches `scfw` and enables cleanup.

The host parameter objects own strings. The guest reader returns views into
the parameter block, without adding padding, bounds checks, or encoding policy.
`MsgboxParameters` encodes title then text as NUL-terminated byte strings with
alignment 1. `KernelFileParameters` encodes `nt_path` as a NUL-terminated
UTF-16LE string with alignment 2. Both modes use `entry(argument1, argument2)`.
For user mode, `argument1` points to the parameter block and `argument2` is unused.
For kernel mode, `argument1` carries the kernel image base for the `scfw`
bootstrap and `argument2` points to the parameter block. The argument positions
and entry ABI are unchanged.

[`scfw`]: https://github.com/vmi-rs/scfw
[Windows bridge guide]: ../windows-bridge/README.md
[Host entry point]: main.rs
[Message box host code]: msgbox/
[kernel file host code]: kernel_file/
[Message box shellcode]: ../shellcodes/msgbox/main.cpp
[kernel file shellcode]: ../shellcodes/kernel-file/main.cpp
[Shellcode utilities]: ../../crates/vmi-utils/src/shellcode/mod.rs
[Parameter encoding]: ../../crates/vmi-utils/src/shellcode/parameters.rs
[Payload assembly]: ../../crates/vmi-utils/src/shellcode/payload.rs
[Guest parameter reader]: ../../crates/vmi-utils/shellcode/include/vmi/shellcode/parameters.hpp
[Bridge contract]: ../../crates/vmi-utils/src/shellcode/bridge.rs
[Status encoding]: ../../crates/vmi-utils/src/shellcode/status.rs
[Shellcode build configuration]: ../shellcodes/CMakeLists.txt
