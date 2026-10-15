use std::time::Duration;

/// How [`VmiXenDriver`] waits for the next `vm_event` request after it
/// answered one.
///
/// Instead of sleeping right away, the driver can keep checking the `vm_event`
/// ring for a while. A request that arrives in that time is handled without
/// an interrupt in dom0, without waking the thread and without three of the
/// four syscalls of an event.
///
/// # Notes
///
/// While the driver checks the ring, it keeps one CPU busy.
///
/// [`VmiXenDriver`]: crate::VmiXenDriver
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmiXenBusyWait {
    /// The driver sleeps right after every answer.
    Off,

    /// The driver checks the ring for a time that follows the gaps between
    /// requests.
    ///
    /// The time starts at zero. A sleep that ends within `max` raises it to
    /// `start`, or doubles it up to `max`. A longer sleep sets it back to
    /// zero, so that rare events cost no checks.
    Adaptive {
        /// Time after the first short gap.
        start: Duration,

        /// Longest time. A longer gap sets the time back to zero.
        max: Duration,
    },
}

impl Default for VmiXenBusyWait {
    /// Returns [`Adaptive`](Self::Adaptive) with a `start` of 10 microseconds
    /// and a `max` of 50 microseconds.
    fn default() -> Self {
        Self::Adaptive {
            start: Duration::from_micros(10),
            max: Duration::from_micros(50),
        }
    }
}

impl VmiXenBusyWait {
    /// Returns the time to check the ring after the next answer.
    ///
    /// `window` is the current time, and `gap` is the time from the last
    /// answer to the request that ended the last sleep.
    pub(crate) fn next_window(self, window: Duration, gap: Duration) -> Duration {
        match self {
            Self::Off => Duration::ZERO,
            Self::Adaptive { start, max } => {
                if gap > max {
                    Duration::ZERO
                }
                else if window < start {
                    start.min(max)
                }
                else {
                    (window * 2).min(max)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::VmiXenBusyWait;

    const fn micros(value: u64) -> Duration {
        Duration::from_micros(value)
    }

    #[test]
    fn off_never_checks_the_ring() {
        let off = VmiXenBusyWait::Off;
        assert_eq!(off.next_window(Duration::ZERO, micros(5)), Duration::ZERO);
        assert_eq!(off.next_window(micros(40), micros(5)), Duration::ZERO);
    }

    #[test]
    fn adaptive_grows_after_short_gaps_up_to_max() {
        let adaptive = VmiXenBusyWait::default();
        let mut window = Duration::ZERO;
        let mut windows = Vec::new();
        for _ in 0..5 {
            window = adaptive.next_window(window, micros(30));
            windows.push(window);
        }
        assert_eq!(
            windows,
            [micros(10), micros(20), micros(40), micros(50), micros(50)]
        );
    }

    #[test]
    fn adaptive_resets_after_a_gap_above_max() {
        let adaptive = VmiXenBusyWait::default();
        assert_eq!(adaptive.next_window(micros(50), micros(51)), Duration::ZERO);
        assert_eq!(
            adaptive.next_window(Duration::ZERO, micros(51)),
            Duration::ZERO
        );
        assert_eq!(adaptive.next_window(micros(20), micros(50)), micros(40));
    }

    #[test]
    fn adaptive_keeps_start_within_max() {
        let adaptive = VmiXenBusyWait::Adaptive {
            start: micros(80),
            max: micros(50),
        };
        assert_eq!(adaptive.next_window(Duration::ZERO, micros(5)), micros(50));
    }
}
