# Examples

The framework includes several examples demonstrating various VMI
capabilities, from basic operations to more complex scenarios.

- **[`basic.rs`]**

  Demonstrates fundamental VMI operations like retrieving the Interrupt
  Descriptor Table (IDT) for each virtual CPU.

- **[`basic-process-list.rs`]**

  Shows how to retrieve and display a list of running processes in the
  guest VM.

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
