# Pull `stage::execute` implementation plan

## Scope

Finalize execution in `bin/windows-bridge/scfw/shellcodes/pull/main.cpp` using the prototype in `bin/windows-bridge/_scfw/shellcodes/download/main.cpp` as a behavioral reference, while retaining the active shellcode's result/error model and coding conventions.

The legacy `_scfw` source remains reference-only. No Rust pull-parameter serializer exists yet, so the C++ sequential ABI and the active handoff are the only current consumers to reconcile.

## Parameter ABI decision

Keep the fixed prefix and operation flags:

```text
u32 flags
i32 show_window
UTF-16LE NUL-terminated URL
UTF-16LE NUL-terminated download path
if flags.extract:
    UTF-16LE NUL-terminated extraction directory
if flags.execute:
    UTF-16LE NUL-terminated executable path
    if flags.arguments:
        UTF-16LE NUL-terminated arguments
    if flags.working_directory:
        UTF-16LE NUL-terminated working directory
```

Use the prototype's non-overlapping bit assignments:

```text
extract             = 1 << 0
execute             = 1 << 1
arguments           = 1 << 8
working_directory   = 1 << 9
```

`show_window` remains an always-present `i32`; this change adds only the two flags needed to omit the optional string slots. The execution-only flags are invalid unless `execute` is also set.

Validation rules:

- Reject unknown flag bits.
- Reject `arguments` or `working_directory` without `execute`.
- Keep URL, download path, flagged extraction directory, and executable path non-empty.
- Read the arguments slot only when `arguments` is set. An empty present slot is valid and means no arguments.
- Read the working-directory slot only when `working_directory` is set. A present but empty working directory is invalid; add a stable `parameter_error::working_directory` code.
- Value-initialize absent pointers to `nullptr`; do not consume placeholder UTF-16 terminators for absent slots.

## Implementation steps

1. Extend constants and parsing.
   - Add `flag_arguments` and `flag_working_directory` and include them in `valid_flags`.
   - Add an execution-knob dependency check to `parse_parameters`.
   - Gate the two optional `next_wstring()` calls independently.
   - Preserve the current upfront parsing model and the cursor's no-bounds-check contract.

2. Add the execution bridge/API surface.
   - Add bridge method `0x0003` and `bridge::wait_for_execute()` using the existing unbounded verified wait loop.
   - Dynamically import `ShellExecuteExW` from Shell32.
   - Do not request `SEE_MASK_NOCLOSEPROCESS`; successful process creation is sufficient and no process handle/wait policy is needed.

3. Implement an execute operation in the active result model.
   - Add a compact `execute_error` enum covering executable-path expansion, working-directory expansion, and `ShellExecuteExW` failure.
   - Expand the executable path with `ExpandEnvironmentStringsW` into a `MAX_PATH` buffer.
   - If an explicit working directory is present, expand it into its own `MAX_PATH` buffer.
   - Otherwise derive the default working directory from the expanded executable's parent. If the expanded path has no parent separator, pass `nullptr` so Windows uses the current directory rather than passing the executable name as a directory.
   - Pass optional arguments (normalizing an empty string to `nullptr`), the resolved working directory, and `show_window` through `SHELLEXECUTEINFOW` to `ShellExecuteExW`.
   - Return the `ShellExecuteExW` result directly; a false result maps to `failure{execute_error::shell_execute}` with no `GetLastError` import or native-code lookup.

4. Integrate execution into the stage pipeline.
   - Thread executable path, optional arguments, optional working directory, and `show_window` from `parameters` into `Entry`/the execute helper without copying strings.
   - Remove the current early success return when extraction is absent; extraction and execution must be independent optional stages.
   - After download and optional extraction, wait for the execute bridge gate before launching.
   - A host abort at that gate returns `result::aborted(stage::execute)`.
   - An execute-helper failure returns `result::operation_failed(stage::execute, ...)`.
   - Successful execution returns `result::success(stage::execute)`; otherwise preserve download/extract as the last successful stage.
   - Keep `CoUninitialize()` balanced across every `Entry` result by retaining the current single return-to-`__entry` cleanup structure.

## Verification

Run from `bin/windows-bridge/scfw`:

```bash
cmake --preset x64
cmake --build --preset x64
```

Inspect `build-x64/shellcodes/pull/pull` and `pull.bin` to confirm:

- the PE still has one `.text` section and no import/export tables;
- `pull.bin` exactly matches the extracted `.text` raw size;
- the new Shell32 call resolves through SCFW rather than an ordinary PE import.

Review the four parameter-layout cases explicitly against `parse_parameters`:

1. execute only: executable slot only;
2. execute + arguments: executable, then arguments;
3. execute + working directory: executable, then working directory with no arguments placeholder;
4. execute + both: executable, arguments, then working directory.

Also check the negative contracts: either optional bit without `execute`, and an empty flagged working-directory slot.

A Linux cross-build/artifact inspection cannot prove that Windows successfully launches the process. Do not claim end-to-end execution without a live Windows/Xen guest run.
