# Windows bridge example

`windows-bridge` downloads, extracts, or launches a program in a Windows guest.
With `--monitor`, it also watches the launched process and copies files that
process writes to a directory on the host.

This example demonstrates advanced VMI utilities, including guest-host bridges,
shellcode injection, page-table monitoring (PTM), breakpoint management (BPM),
and process/thread tracking.

The Rust program runs on the host. Two C++ shellcodes built with [`scfw`] run in
the guest. The deploy shellcode calls Windows APIs in user mode. The file-transfer
shellcode runs in kernel mode when the monitored process closes a file. They ask
the host for decisions or report results using a special CPU instruction
(`VMCALL`). The host reads guest memory through VMI and writes the copied files.

Despite its complexity, this example lives in `examples/` so it stays alongside
its shellcode sources in `examples/shellcodes/`.

For the injection recipes and the difference between calling a shellcode and
starting a new thread, see the [Windows shellcode guide].

## Build the shellcodes

Run these commands on the host from the repository root. Use a booted Windows
x64 guest on Xen, and replace `windows-vm` with its domain name or numeric ID.

```sh
cmake --preset x64 -S examples/shellcodes
cmake --build examples/shellcodes/build-x64
export VMI_XEN_DOMAIN=windows-vm

cargo run --example windows-bridge \
  --features arch-amd64,driver-xen,os-windows,utils -- deploy --help
```

The Release preset publishes shellcode as `deploy.bin` and
`file-transfer.bin` under `examples/shellcodes/bin/x64/`. Rust embeds these
`.bin` code bytes at compile time. After changing a shellcode, rebuild it
before running the host example.

## Choose the work

The `deploy` command runs enabled actions in this order: download, extract,
then execute. A failed stage prevents later stages from running.

These combinations are supported:

| Options | Work performed |
| --- | --- |
| `deploy` with default options | Run the shellcode and host handshake |
| `--url` and `--download-path` | Download a file |
| Download options and `--extract-to` | Download and extract an archive |
| `--execute` | Launch an existing guest executable |
| Download options and `--execute` | Download, then launch the specified executable |
| Download options, `--extract-to`, and `--execute` | Download, extract, then launch the specified executable |

`--extract-to` requires a download. Supply `--url` and `--download-path`
together, and set `--execute` to the guest executable you want to launch.

### Options and paths

| Option | Meaning and default |
| --- | --- |
| `--process NAME` | Guest process used to run the deploy shellcode. Default: `explorer.exe` |
| `--url URL` | URL fetched by Windows in the guest. Requires `--download-path` |
| `--download-path PATH` | Guest destination file. Requires `--url` |
| `--extract-to DIRECTORY` | Guest destination for the downloaded archive. Requires `--url` |
| `--execute PATH` | Guest executable to launch |
| `--arguments STRING` | Command-line string for that executable. Requires `--execute` |
| `--working-directory PATH` | Guest working directory. Default: executable's parent directory when available, otherwise Windows' default. Requires `--execute` |
| `--show-window NUMBER` | Windows `SW_*` value. Default: `SW_SHOWNORMAL` (`1`). Requires `--execute` |
| `--monitor` | Watch the launched process and copy eligible files until it exits or monitoring is cancelled. Requires `--execute` |
| `--output-directory PATH` | Host directory for copied files . Default: `artifacts`. Only used with `--monitor` |
| `--max-download-retries NUMBER` | Retries after a failed download attempt. Default: `0` |

`--download-path`, `--extract-to`, `--execute`, and `--working-directory`
refer to guest paths. `--output-directory` refers to a host directory.
Relative host output paths are resolved from the host program's working directory.

The shellcode expands Windows environment variables in the download, extraction,
executable, and explicit working-directory paths. It passes the URL and
arguments string unchanged. The launched program can interpret its arguments.
Quote Windows paths with single quotes in a POSIX host shell so spaces and
backslashes reach the guest unchanged.

Use absolute guest paths where possible. Expanded paths must fit in the
shellcode's fixed `MAX_PATH` buffers. Longer expansions fail initialization.

### Examples

To launch an existing executable:

```sh
cargo run --example windows-bridge \
  --features arch-amd64,driver-xen,os-windows,utils -- deploy \
  --execute '%SystemRoot%\System32\cmd.exe' \
  --arguments '/c echo bridge-test'
```

The program's console output stays in the guest.

To launch a program that writes a file and collect that file:

```sh
cargo run --example windows-bridge \
  --features arch-amd64,driver-xen,os-windows,utils -- deploy \
  --execute '%SystemRoot%\System32\cmd.exe' \
  --arguments '/c echo bridge-test > "%TEMP%\bridge-test.txt"' \
  --monitor \
  --output-directory ./artifacts
```

Here `cmd.exe` expands `%TEMP%` in its own arguments and writes the file inside
the guest. The host output name will look like `0000-bridge_test_txt`.

To download an archive, extract it, then monitor an executable from it:

```sh
cargo run --example windows-bridge \
  --features arch-amd64,driver-xen,os-windows,utils -- deploy \
  --url 'https://example.com/tool.zip' \
  --download-path '%TEMP%\bridge-demo\tool.zip' \
  --extract-to '%TEMP%\bridge-demo\unpacked' \
  --execute '%TEMP%\bridge-demo\unpacked\tool.exe' \
  --max-download-retries 2 \
  --monitor \
  --output-directory ./artifacts
```

Replace the example URL and executable path with a real archive and the correct
path inside it. For a download and extraction, omit `--execute` and `--monitor`.
Use a fresh extraction directory. The shellcode estimates completion from item
counts, so existing files can make it report completion while extraction is
still running.

## Code flow

### Host calls and injection

The [host entry point] calls `deploy::run` in the [CLI source]. The first event
loop injects the payload. With `--monitor`, a second event loop watches the
launched process:

```text
main
+-- common::VmiSetup::new
`-- deploy::run
    +-- common::find_process_id
    +-- VmiSession::handle [injection]
    |   +-- deploy_recipe
    |   |   `-- user_shellcode_spawn_recipe
    |   `-- UserInjectorHandler + DeployBridge
    `-- VmiSession::handle [with --monitor, after DeployWaiting output]
        `-- Monitor::new
```

The [deploy recipe] uses the `user-spawn` injection sequence described in the
[Windows shellcode guide]. Windows executes `VirtualAlloc`, `RtlFillMemory`,
`CreateThread`, and `CloseHandle` inside the guest. The host assembles the
payload from shellcode, parameters, and alignment padding, copies it to the
allocation through VMI, and restores the hijacked thread's registers. The
deploy shellcode continues on its new guest thread.

### Parameters and entry arguments

The host [deploy parameters] own nested `download` and `execution`
configurations. The guest [deploy shellcode] decodes a flat `parameters` view
whose strings point into the parameter block. Shared domain vocabulary does
not require identical implementation shapes:

| Host field | Guest field | Meaning |
| --- | --- | --- |
| `download.url` | `url` | URL fetched by the guest |
| `download.path` | `download_path` | Guest download destination |
| `download.extraction_directory` | `extraction_directory` | Guest extraction destination |
| `execution.path` | `executable_path` | Guest executable to launch |
| `execution.arguments` | `arguments` | Optional command-line string |
| `execution.working_directory` | `working_directory` | Optional guest working directory |
| `execution.show_window` | `show_window` | Optional Windows display value |

The host `ParameterWriter` encodes a little-endian `u32` flags value, then
NUL-terminated UTF-16LE strings and an optional little-endian `i32`
`show_window`. The parameter block starts at alignment 4. Its fields have no
internal padding or placeholders. Order is flags, then URL and download path
when download is enabled, extraction directory when extraction is enabled,
then executable path and any present arguments, working directory, and
show-window value when execution is enabled. The guest
`sc::vmi::parameter_reader` consumes this order with `read_uint32()`,
`read_wstring()`, and `read_int32()`. It adds no bounds checks, padding, or
encoding policy. Host builder states and guest decoded views remain distinct.

Both modes use `entry(argument1, argument2)`. The user-mode deploy shellcode reads
its parameter block from `argument1` and leaves `argument2` unused. For the
file-transfer kernel shellcode, `argument1` carries the kernel image base for
the `scfw` bootstrap and `argument2` carries the file handle unchanged. File
transfer has no encoded parameter block. The argument positions, pointer types,
and entry ABI are unchanged.

### Guest calls and host decisions

The guest-side `scfw` startup calls `sc::entry` in the [guest deploy shellcode]:

```text
sc::entry [guest]
+-- Deploy
|   +-- bridge::wait_for_host
|   +-- parse_parameters
|   `-- DeployInternal
|       `-- Entry
|           +-- Download [if requested]
|           +-- Extract [if requested]
|           +-- bridge::wait_for_execute [before execution]
|           `-- Execute [if requested] -> ShellExecuteExW
`-- bridge::exit(status)
```

The bridge calls cross the guest-host boundary through VM events:

```text
[guest] bridge::wait_for_* or bridge::exit -> VMCALL
  -> [Xen]   VM event
  -> [host]  injector bridge dispatch -> DeployBridge::handle
  -> [guest] resume with the host's response
```

The host chooses whether to retry failed downloads and whether to allow
execution:

- `--max-download-retries 0` stops after the first failed attempt.
  `2` permits up to three attempts.
- Extraction proceeds automatically after a successful download. The shellcode
  checks the output item count for about one minute. Existing items can make
  this check finish before extraction is complete.
- Before launching, the host can allow execution, abort it, or ask the shellcode
  to wait. The CLI allows execution immediately unless monitoring needs to be
  installed first.

These decisions control retries and launch timing. The caller is responsible
for checking downloaded files and executables.

When monitoring is disabled, the host waits for the shellcode's final report
and returns an error if deployment failed. A successful deployment status
means Windows accepted the launch request, not that the launched program
finished successfully. The host does not receive that program's exit code.

The request code selects a host bridge handler. The method code selects an
operation within that handler.

`BridgeResponse::with_output()` attaches optional output without changing
`value1`-`value4`. `BridgeOutput::DeployWaiting` and
`DeployExecuting` are progress notifications, while `DeployFinished` carries
the final deployment status. Output does not universally end an event
loop: the injector uses it for its handoff, and the monitor continues after
`DeployExecuting`. The consumer decides when to finish.

### Self-freeing allocations

The [Shellcode build configuration] enables `SCFW_OPT_CLEANUP` for both shellcodes.
After `sc::entry` returns, `scfw` jumps to the Windows routine that frees the
allocation and returns to the caller:

- `deploy` uses `VirtualFree` to release its allocation.
- `file-transfer` uses `ExFreePool` to release its allocation.
  `TransferFile` also frees its temporary buffers and unmaps the file before
  returning to `sc::entry`.

The recipes free the allocation before retrying a failed copy or thread
creation. After a successful start, the guest-side `scfw` code owns cleanup.

The final `VMCALL` reports the result before the shellcode frees its allocation.
The host replies and resumes the guest so cleanup can finish. The deploy thread
then exits. The file-transfer shellcode returns to the recipe, which restores the
closing thread's registers and lets Windows finish `NtClose`.

## What monitoring watches

With `--monitor`, the first event loop asks the shellcode to wait before launching.
`deploy::run` then starts a second event loop with `Monitor::new`, which installs
the hooks before allowing execution:

```text
deploy::run [host, after the DeployWaiting output]
`-- VmiSession::handle
    `-- Monitor::new -> install process, thread, and file hooks

VM event [host]
`-- Monitor::handle_event
    `-- Monitor::dispatch
        +-- Monitor::hypercall [guest VMCALL]
        |   +-- Bridge::dispatch -> DeployBridge::handle
        |   `-- Monitor::process_bridge -> record requesting thread
        `-- Monitor::interrupt [guest reaches a kernel breakpoint]
            `-- hooks::PspInsertProcess -> select the new process
```

The host records the requesting thread before resuming the guest. The
`PspInsertProcess` hook then selects the process created by that thread.

The monitor tracks the selected process through its Windows process object.
It collects files from that process and skips its children. If Windows launches
the program from another process or thread, the monitor can miss the launch.
A launch failure before process selection can also leave the monitor waiting.

Monitoring ends when Windows cleans up the selected process's address space.
Use Ctrl-C to cancel if it keeps waiting. The host also handles `SIGHUP`,
`SIGINT`, `SIGALRM`, and `SIGTERM` as cancellation requests. Cancellation stops
the host monitor. The guest program keeps running.

## Which files reach the host

Use `deploy --monitor` to collect files written by the launched process.

The [monitor hooks] and [transfer state] run on the host. The guest's
`NtWriteFile` and `NtClose` calls trigger kernel breakpoints:

```text
[guest] NtWriteFile
  -> [host] Monitor::interrupt -> hooks::NtWriteFile
              -> FileTransfer::new
              -> Process::record_file_transfer

[guest] NtClose
  -> [host] Monitor::interrupt -> hooks::NtClose
              +-- FileTransfer::start
              |   +-- file_transfer_recipe -> kernel_shellcode_call_recipe
              |   `-- RecipeExecutor::new
              `-- advance_file_transfer
                  `-- FileTransfer::execute
                      `-- RecipeExecutor::execute
```

The write hook records a handle at `NtWriteFile` entry, before Windows returns
the write status. Kernel handles are skipped. The close hook discards a pending
copy if it detects that the handle now refers to a different file.

The [transfer recipe] runs this successful path before the original close
continues. It passes the file handle unchanged as the second entry argument:

```text
[guest] ExAllocatePool(NonPagedPoolExecute, shellcode size)
  -> [host]  VMI write(file-transfer shellcode)
  -> [guest] shellcode(kernel image base, file handle)
  -> [host]  restore closing-thread registers
  -> [guest] original NtClose continues
```

Inside the [guest transfer shellcode], `scfw` calls `sc::entry`. It calls
`TransferFile`, which reads the whole file and sends chunks of up to 64 KiB:

```text
sc::entry [guest]
+-- TransferFile
|   +-- bridge::begin
|   +-- bridge::set_buffer
|   +-- bridge::chunk [repeated for each chunk]
|   `-- bridge::close
`-- bridge::exit(status)
```

Each bridge call crosses back to the host:

```text
[guest] bridge request -> VMCALL
  -> [Xen]   VM event
  -> [host]  Monitor::hypercall
             -> Bridge::dispatch -> FileTransferBridge::handle
  -> [guest] resume with the host's response
```

`FileTransferBridge::handle_chunk` reads each guest buffer through VMI and
writes it to the host file. After the shellcode returns, the recipe restores the
thread's registers and lets Windows finish the original `NtClose`.

The shellcode runs on the closing thread, where the handle refers to the file
being copied. A new kernel thread would use the `System` process's handle table
and could access a different file or an invalid handle.

The close stays blocked until the transfer finishes. Locks held by the
intercepted thread remain held during the copy, which can delay other guest
operations.

A successful copy requires a nonempty file, an observed `NtWriteFile` attempt,
and an observed close on a tracked thread. Memory-mapped writes bypass
`NtWriteFile`. Files left open at process exit can be missed. Other writers
can change the file contents during a transfer.

### Output files and failures

The host creates the output directory when a transfer starts and writes all
copied files directly into it. Output names use the guest file's basename,
replace each character outside ASCII letters and digits with `_`, and add a
numeric prefix with at least four digits. For example, `C:\Temp\result.bin`
becomes `0000-result_bin`.

The counter starts at zero for each run. The host truncates any existing file
with the same generated name, so use a fresh output directory to avoid
replacing files from an earlier run.

Files are written directly to their final host paths. The host rejects chunks
larger than 64 KiB or beyond the declared size. It logs `closed` after receiving
the expected byte count and flushing the file. Failed or cancelled transfers
can leave partial files at those paths. The shellcode can report success after
a host flush failure, so check the host's transfer logs before using the file.

The close method's `transfer_status` reports a transfer result (`success` or
`error`). Likewise, the host's continue/abort response controls the next guest
action. The transfer handler logs the exit status without publishing
a `BridgeOutput` notification.

The transfer handler allocates up to 4095 handles per monitoring run. Each
handle is used once. Failed output-file creation can consume a handle.
Further transfers are rejected after exhaustion.

Treat collected files as untrusted guest content. Check their contents before
opening or executing them, and manage disk-space limits for the output directory.

## Source files

- [Host entry point] selects a command and starts the shared VMI setup.
- [CLI source] defines the deployment options and starts the injection.
- [Deploy recipe] and [transfer recipe] build user-mode deployment and
  kernel-mode file-transfer recipes.
- [Guest deploy shellcode] and [guest transfer shellcode] contain the guest operations.
- [Monitor source] and [monitor hooks] track the launched process and intercept
  its file writes and closes.
- [Transfer state] runs the file-transfer recipe. The [file-transfer handler]
  writes the host files.
- [Deploy parameters] encode the host input block. [Output] defines
  deployment progress notifications.
- [Parameter encoding] defines the host `ParameterWriter` and parameter traits.
- [Payload assembly] defines the host-only `Payload`.
- [Guest parameter reader] defines the guest `read_*` API.
- [Bridge contract] and [status encoding] define shared constants and encoded
  status. Host and guest bridge traits remain separate implementations.

[Windows shellcode guide]: ../windows-shellcode/README.md
[`scfw`]: https://github.com/vmi-rs/scfw
[CLI source]: deploy/command.rs
[guest deploy shellcode]: ../shellcodes/deploy/main.cpp
[monitor source]: monitor/mod.rs
[file-transfer handler]: file_transfer/bridge.rs
[host entry point]: main.rs
[deploy recipe]: deploy/recipe.rs
[monitor hooks]: monitor/hooks.rs
[transfer state]: file_transfer/mod.rs
[transfer recipe]: file_transfer/recipe.rs
[guest transfer shellcode]: ../shellcodes/file-transfer/main.cpp
[Shellcode build configuration]: ../shellcodes/CMakeLists.txt
[deploy parameters]: deploy/parameters.rs
[deploy shellcode]: ../shellcodes/deploy/main.cpp
[Output]: bridge.rs
[Parameter encoding]: ../../crates/vmi-utils/src/shellcode/parameters.rs
[Payload assembly]: ../../crates/vmi-utils/src/shellcode/payload.rs
[Guest parameter reader]: ../../crates/vmi-utils/shellcode/include/vmi/shellcode/parameters.hpp
[Bridge contract]: ../../crates/vmi-utils/src/shellcode/bridge.rs
[status encoding]: ../../crates/vmi-utils/src/shellcode/status.rs
