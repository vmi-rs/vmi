use vmi::{
    VmiContext, VmiError, VmiOs,
    driver::VmiRead,
    os::{
        VmiOsProcess as _,
        linux::{ArchAdapter, LinuxOs},
    },
    utils::reactor::Action,
};

/// Logs each process that asks the kernel for the settings of an `fq_codel`
/// queueing discipline, as `tc qdisc show` does.
///
/// `fq_codel_dump` is a static function. The module's kallsyms list it, but
/// the module does not export it.
pub fn fq_codel_dump<Driver>(
    vmi: &VmiContext<LinuxOs<Driver>>,
) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // static int fq_codel_dump(
    //     struct Qdisc *sch,
    //     struct sk_buff *skb
    //     )
    //

    let process = vmi.os().current_process()?;
    tracing::info!(pid = process.id()?.0, process = process.name()?);

    Ok(Action::default())
}
