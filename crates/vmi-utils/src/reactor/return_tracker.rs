//! Per-thread function return tracking.

use std::collections::HashMap;

use vmi_core::{AddressContext, os::ThreadObject};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReturnFrame<Event> {
    pub event: Event,
    pub cookie: u64,
    pub site: AddressContext,
    pub stack_pointer: u64,
}

pub(super) struct ReturnTracker<Event> {
    frames: HashMap<ThreadObject, Vec<ReturnFrame<Event>>>,
    sites: HashMap<AddressContext, u32>,
}

impl<Event> Default for ReturnTracker<Event> {
    fn default() -> Self {
        Self {
            frames: HashMap::new(),
            sites: HashMap::new(),
        }
    }
}

impl<Event> ReturnTracker<Event>
where
    Event: Copy,
{
    /// Pushes a frame and returns whether it is the first frame for the site.
    pub fn push(&mut self, thread: ThreadObject, frame: ReturnFrame<Event>) -> bool {
        let site_was_new = match self.sites.get_mut(&frame.site) {
            Some(references) => {
                *references = references
                    .checked_add(1)
                    .expect("return site reference count overflow");
                false
            }
            None => {
                self.sites.insert(frame.site, 1);
                true
            }
        };

        self.frames.entry(thread).or_default().push(frame);
        site_was_new
    }

    /// Returns the top frame if the thread is returning through its site.
    pub fn get(
        &self,
        thread: ThreadObject,
        site: AddressContext,
        stack_pointer: u64,
    ) -> Option<ReturnFrame<Event>> {
        let frame = self.frames.get(&thread)?.last()?;

        if frame.site != site || stack_pointer < frame.stack_pointer {
            return None;
        }

        Some(*frame)
    }

    /// Pops the top frame and returns whether it was the last frame for its site.
    pub fn pop(&mut self, thread: ThreadObject) -> Option<(ReturnFrame<Event>, bool)> {
        let frames = self.frames.get_mut(&thread)?;
        let frame = frames.pop().expect("tracked thread has no return frames");

        if frames.is_empty() {
            self.frames.remove(&thread);
        }

        let site_was_removed = match self.sites.get_mut(&frame.site) {
            Some(1) => {
                self.sites.remove(&frame.site);
                true
            }
            Some(references) => {
                *references -= 1;
                false
            }
            None => panic!("return frame references an untracked site"),
        };

        Some((frame, site_was_removed))
    }
}

#[cfg(test)]
mod tests {
    use vmi_core::{AddressContext, Pa, Va, os::ThreadObject};

    use super::{ReturnFrame, ReturnTracker};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        First,
        Second,
    }

    fn thread(value: u64) -> ThreadObject {
        ThreadObject(Va(value))
    }

    fn site(va: u64, root: u64) -> AddressContext {
        AddressContext::new(Va(va), Pa(root))
    }

    fn frame(
        event: Event,
        cookie: u64,
        site: AddressContext,
        stack_pointer: u64,
    ) -> ReturnFrame<Event> {
        ReturnFrame {
            event,
            cookie,
            site,
            stack_pointer,
        }
    }

    #[test]
    fn tracks_one_return() {
        let mut tracker = ReturnTracker::default();
        let thread = thread(0x1000);
        let site = site(0x2000, 0x3000);
        let frame = frame(Event::First, 42, site, 0x4008);

        assert!(tracker.push(thread, frame));
        assert_eq!(tracker.get(thread, site, 0x4007), None);
        assert_eq!(tracker.get(thread, site, 0x4008), Some(frame));

        assert_eq!(tracker.pop(thread), Some((frame, true)));
        assert_eq!(tracker.get(thread, site, 0x4008), None);
        assert_eq!(tracker.pop(thread), None);
    }

    #[test]
    fn shares_a_return_site_between_threads() {
        let mut tracker = ReturnTracker::default();
        let first_thread = thread(0x1000);
        let second_thread = thread(0x2000);
        let site = site(0x3000, 0x4000);
        let first = frame(Event::First, 1, site, 0x5008);
        let second = frame(Event::Second, 2, site, 0x6008);

        assert!(tracker.push(first_thread, first));
        assert!(!tracker.push(second_thread, second));

        assert_eq!(tracker.get(first_thread, site, 0x5008), Some(first));
        assert_eq!(tracker.get(second_thread, site, 0x6008), Some(second));
        assert_eq!(tracker.get(thread(0x7000), site, 0x6008), None);

        assert_eq!(tracker.pop(first_thread), Some((first, false)));
        assert_eq!(tracker.pop(second_thread), Some((second, true)));
    }

    #[test]
    fn only_matches_the_top_frame() {
        let mut tracker = ReturnTracker::default();
        let thread = thread(0x1000);
        let outer_site = site(0x2000, 0x3000);
        let inner_site = site(0x4000, 0x3000);
        let outer = frame(Event::First, 1, outer_site, 0x5008);
        let inner = frame(Event::Second, 2, inner_site, 0x4008);

        assert!(tracker.push(thread, outer));
        assert!(tracker.push(thread, inner));

        assert_eq!(tracker.get(thread, outer_site, 0x5008), None);
        assert_eq!(tracker.get(thread, inner_site, 0x4008), Some(inner));
        assert_eq!(tracker.pop(thread), Some((inner, true)));
        assert_eq!(tracker.get(thread, outer_site, 0x5008), Some(outer));
        assert_eq!(tracker.pop(thread), Some((outer, true)));
    }

    #[test]
    fn reference_counts_recursive_returns_at_the_same_site() {
        let mut tracker = ReturnTracker::default();
        let thread = thread(0x1000);
        let site = site(0x2000, 0x3000);
        let outer = frame(Event::First, 1, site, 0x5008);
        let inner = frame(Event::First, 2, site, 0x4008);

        assert!(tracker.push(thread, outer));
        assert!(!tracker.push(thread, inner));

        assert_eq!(tracker.get(thread, site, 0x4008), Some(inner));
        assert_eq!(tracker.pop(thread), Some((inner, false)));
        assert_eq!(tracker.get(thread, site, 0x5008), Some(outer));
        assert_eq!(tracker.pop(thread), Some((outer, true)));
    }
}
