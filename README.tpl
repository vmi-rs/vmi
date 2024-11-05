[![Crates.io](https://img.shields.io/crates/v/vmi.svg)](https://crates.io/crates/vmi)
[![Downloads](https://img.shields.io/crates/d/vmi.svg)](https://crates.io/crates/vmi)
[![Docs](https://docs.rs/vmi/badge.svg)](https://docs.rs/vmi/latest/vmi/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/vmi-rs/vmi/blob/master/LICENSE)

{{readme}}

[`AccessContext`]: https://docs.rs/vmi/latest/vmi/struct.AccessContext.html
[`AddressContext`]: https://docs.rs/vmi/latest/vmi/struct.AddressContext.html
[`Architecture`]: https://docs.rs/vmi/latest/vmi/trait.Architecture.html
[`Gfn`]: https://docs.rs/vmi/latest/vmi/struct.Gfn.html
[`Pa`]: https://docs.rs/vmi/latest/vmi/latest/vmi/struct.Pa.html
[`PageFault`]: https://docs.rs/vmi/latest/vmi/struct.PageFault.html
[`TranslationMechanism`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html
[`Va`]: https://docs.rs/vmi/latest/vmi/latest/vmi/struct.Va.html
[`VmiContext`]: https://docs.rs/vmi/latest/vmi/struct.VmiContext.html
[`VmiCore`]: https://docs.rs/vmi/latest/vmi/struct.VmiCore.html
[`VmiDriver`]: https://docs.rs/vmi/latest/vmi/trait.VmiDriver.html
[`VmiError`]: https://docs.rs/vmi/latest/vmi/enum.VmiError.html
[`VmiEvent`]: https://docs.rs/vmi/latest/vmi/struct.VmiEvent.html
[`VmiEventResponse`]: https://docs.rs/vmi/latest/vmi/struct.VmiEventResponse.html
[`VmiHandler`]: https://docs.rs/vmi/latest/vmi/trait.VmiHandler.html
[`VmiOs`]: https://docs.rs/vmi/latest/vmi/trait.VmiOs.html
[`VmiSession`]: https://docs.rs/vmi/latest/vmi/struct.VmiSession.html

[`Amd64`]: https://docs.rs/vmi/latest/vmi/arch/amd64/struct.Amd64.html
[`VmiXenDriver`]: https://docs.rs/vmi/latest/vmi/driver/xen/struct.VmiXenDriver.html
[`LinuxOs`]: https://docs.rs/vmi/latest/vmi/os/linux/struct.LinuxOs.html
[`WindowsOs`]: https://docs.rs/vmi/latest/vmi/os/windows/struct.WindowsOs.html
[`Direct`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html#variant.Direct
[`Paging`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html#variant.Paging
[`root`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html#variant.Paging.field.root
[`BreakpointManager`]: https://docs.rs/vmi/latest/vmi/utils/bpm/struct.BreakpointManager.html
[`InjectorHandler`]: https://docs.rs/vmi/latest/vmi/utils/injector/struct.InjectorHandler.html
[`Interceptor`]: https://docs.rs/vmi/latest/vmi/utils/interceptor/struct.Interceptor.html
[`PageTableMonitor`]: https://docs.rs/vmi/latest/vmi/utils/ptm/struct.PageTableMonitor.html
[`PageIn`]: https://docs.rs/vmi/latest/vmi/utils/ptm/enum.PageTableMonitorEvent.html#variant.PageIn
[`PageOut`]: https://docs.rs/vmi/latest/vmi/utils/ptm/enum.PageTableMonitorEvent.html#variant.PageOut
[`handle_event`]: https://docs.rs/vmi/latest/vmi/trait.VmiHandler.html#tymethod.handle_event
[`os()`]: https://docs.rs/vmi/latest/vmi/struct.VmiSession.html#method.os
[physical page lookups]: https://docs.rs/vmi/latest/vmi/struct.VmiCore.html#method.with_gfn_cache
[Virtual-to-Physical address translations]: https://docs.rs/vmi/latest/vmi/struct.VmiCore.html#method.with_v2p_cache

[`Deref`]: https://doc.rust-lang.org/std/ops/trait.Deref.html

[ISR]: https://docs.rs/isr/latest/isr/index.html
[`isr`]: https://docs.rs/isr/latest/isr/index.html
[`IsrCache`]: https://docs.rs/isr/latest/isr/cache/struct.IsrCache.html
[`offsets!`]: https://docs.rs/isr/latest/isr/macros/macro.offsets.html
[`symbols!`]: https://docs.rs/isr/latest/isr/macros/macro.symbols.html

[KVM-VMI]: https://github.com/KVM-VMI/kvm-vmi
[libvmi]: https://github.com/libvmi/libvmi
[hvmi]: https://github.com/bitdefender/hvmi
[drakvuf]: https://github.com/tklengyel/drakvuf

[`basic.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic.rs
[`basic-process-list.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic-process-list.rs
[`windows-breakpoint-manager.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-breakpoint-manager.rs
[`windows-recipe-messagebox.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-messagebox.rs
[`windows-recipe-writefile.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile.rs
[`windows-recipe-writefile-advanced.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile-advanced.rs
