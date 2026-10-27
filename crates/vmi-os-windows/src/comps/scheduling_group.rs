use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::WindowsKernelProcessorBlock;
use crate::{ArchAdapter, WindowsOs, offset_optional};

/// A Windows scheduling group.
///
/// A job that limits the CPU rate of its processes puts their threads in a
/// scheduling group. The group keeps one queue per processor, a
/// [`WindowsSchedulingControlBlock`]. Once the group uses its share of a
/// processor, the scheduler keeps the group's ready threads in that queue,
/// behind every other ready thread of priority 1 or higher.
///
/// # Implementation Details
///
/// Corresponds to `_KSCHEDULING_GROUP`.
pub struct WindowsSchedulingGroup<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_KSCHEDULING_GROUP` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsSchedulingGroup<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSchedulingGroup<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new scheduling group.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the group's queue on a processor.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the group's address plus `_KPRCB.ScbOffset`, as
    /// `KiGetThreadScb` computes it.
    pub fn scb(
        &self,
        prcb: &WindowsKernelProcessorBlock<'a, Driver>,
    ) -> Result<WindowsSchedulingControlBlock<'a, Driver>, VmiError> {
        let scb_offset = match prcb.scb_offset()? {
            Some(scb_offset) => scb_offset,
            None => return Err(VmiError::NotSupported),
        };

        Ok(WindowsSchedulingControlBlock::new(
            self.vmi,
            self.va + scb_offset as u64,
        ))
    }
}

/// The queue of a Windows scheduling group on one processor.
///
/// The queue holds the group's ready threads that the scheduler keeps back
/// on that processor. Its flags and its rank tell whether the group uses its
/// share of the processor at the moment.
///
/// # Implementation Details
///
/// Corresponds to `_KSCB`.
pub struct WindowsSchedulingControlBlock<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_KSCB` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsSchedulingControlBlock<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSchedulingControlBlock<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new scheduling group queue.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns whether the queue is in the processor's tree of queues.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KSCB.Inserted`.
    pub fn inserted(&self) -> Result<bool, VmiError> {
        let KSCB = offset_optional!(self.vmi, _KSCB)?;

        let value = self.vmi.read_field(self.va, &KSCB.Inserted)?;
        Ok(KSCB.Inserted.extract(value) != 0)
    }

    /// Returns whether the group uses its share of the processor in the
    /// current scheduling period.
    ///
    /// The kernel sets the flag together with a non-zero [`rank`].
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KSCB.MinOverQuota`, and to `_KSCB.OverQuota` on
    /// Windows 8 and 8.1.
    ///
    /// [`rank`]: Self::rank
    pub fn min_over_quota(&self) -> Result<bool, VmiError> {
        let KSCB = offset_optional!(self.vmi, _KSCB)?;

        let value = self.vmi.read_field(self.va, &KSCB.MinOverQuota)?;
        Ok(KSCB.MinOverQuota.extract(value) != 0)
    }

    /// Returns whether the group is over its hard cap on the processor in the
    /// current scheduling period.
    ///
    /// The scheduler then keeps the group's ready threads back, even on an
    /// idle processor.
    ///
    /// # Notes
    ///
    /// Windows 8 and 8.1 give a queue one share per scheduling period instead
    /// of a minimum and a maximum. On these versions, a hard-capped group is
    /// over its hard cap as soon as it uses its share, so this method and
    /// [`min_over_quota`] become `true` at the same moment.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KSCB.MaxOverQuota`, and to `_KSCB.OverQuota` together
    /// with `_KSCB.HardCap` on Windows 8 and 8.1.
    ///
    /// [`min_over_quota`]: Self::min_over_quota
    pub fn max_over_quota(&self) -> Result<bool, VmiError> {
        let KSCB = offset_optional!(self.vmi, _KSCB)?;

        let value = self.vmi.read_field(self.va, &KSCB.MaxOverQuota)?;
        if KSCB.MaxOverQuota.extract(value) == 0 {
            return Ok(false);
        }

        match &KSCB.HardCap {
            Some(HardCap) => {
                let value = self.vmi.read_field(self.va, HardCap)?;
                Ok(HardCap.extract(value) != 0)
            }
            None => Ok(true),
        }
    }

    /// Returns the queue's rank.
    ///
    /// While the queue's rank, or the rank of a parent's queue, is not zero,
    /// the scheduler runs the group's ready threads on the processor only
    /// when no other thread of priority 1 or higher is ready there.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KSCB.Rank`.
    pub fn rank(&self) -> Result<u32, VmiError> {
        let KSCB = offset_optional!(self.vmi, _KSCB)?;

        self.vmi.read_u32(self.va + KSCB.Rank.offset())
    }

    /// Returns the queue of the parent group on the same processor, or `None`
    /// for a group without a parent.
    ///
    /// Groups on Windows 8 and 8.1 have no parents.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KSCB.Parent`.
    pub fn parent(&self) -> Result<Option<Self>, VmiError> {
        let KSCB = offset_optional!(self.vmi, _KSCB)?;

        let Parent = match &KSCB.Parent {
            Some(Parent) => Parent,
            None => return Ok(None),
        };

        let parent = self.vmi.read_va_native(self.va + Parent.offset())?;
        if parent.is_null() {
            return Ok(None);
        }

        Ok(Some(Self::new(self.vmi, parent)))
    }
}
