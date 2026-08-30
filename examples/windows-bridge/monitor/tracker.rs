//! Generic process/thread identity tracker decoupled from payload interpretation.

use std::collections::{HashMap, HashSet, hash_map::Entry};

use vmi::os::{ProcessObject, ThreadObject};

/// Opaque process payload and its tracked thread identities.
struct ProcessEntry<P> {
    value: P,
    threads: HashSet<ThreadObject>,
}

/// Opaque thread payload and its owning process identity.
struct ThreadEntry<T> {
    value: T,
    process: ProcessObject,
}

/// Maintains process and thread identity relationships without interpreting payloads.
pub struct ProcessTracker<P, T> {
    processes: HashMap<ProcessObject, ProcessEntry<P>>,
    threads: HashMap<ThreadObject, ThreadEntry<T>>,
}

impl<P, T> Default for ProcessTracker<P, T> {
    fn default() -> Self {
        Self {
            processes: HashMap::new(),
            threads: HashMap::new(),
        }
    }
}

impl<P, T> ProcessTracker<P, T> {
    /// Inserts a process payload while retaining any threads already associated with it.
    pub fn insert_process(&mut self, object: ProcessObject, value: P) -> Option<P> {
        match self.processes.entry(object) {
            Entry::Occupied(mut entry) => {
                Some(std::mem::replace(&mut entry.get_mut().value, value))
            }
            Entry::Vacant(entry) => {
                entry.insert(ProcessEntry {
                    value,
                    threads: HashSet::new(),
                });
                None
            }
        }
    }

    /// Inserts a thread payload and records its owning process.
    ///
    /// Returns `Err(value)` when the owning process is not tracked.
    pub fn insert_thread(
        &mut self,
        process: ProcessObject,
        object: ThreadObject,
        value: T,
    ) -> Result<Option<T>, T> {
        if !self.processes.contains_key(&process) {
            return Err(value);
        }

        let previous = self.threads.insert(object, ThreadEntry { value, process });
        if let Some(previous) = &previous
            && let Some(entry) = self.processes.get_mut(&previous.process)
        {
            entry.threads.remove(&object);
        }

        self.processes
            .get_mut(&process)
            .expect("owning process checked above")
            .threads
            .insert(object);

        Ok(previous.map(|entry| entry.value))
    }

    /// Returns a process payload.
    pub fn get_process(&self, object: ProcessObject) -> Option<&P> {
        self.processes.get(&object).map(|entry| &entry.value)
    }

    /// Returns a mutable process payload.
    pub fn get_process_mut(&mut self, object: ProcessObject) -> Option<&mut P> {
        self.processes
            .get_mut(&object)
            .map(|entry| &mut entry.value)
    }

    /// Returns a thread payload.
    pub fn get_thread(&self, object: ThreadObject) -> Option<&T> {
        self.threads.get(&object).map(|entry| &entry.value)
    }

    /// Returns a mutable thread payload.
    pub fn get_thread_mut(&mut self, object: ThreadObject) -> Option<&mut T> {
        self.threads.get_mut(&object).map(|entry| &mut entry.value)
    }

    /// Returns the process that owns a tracked thread.
    pub fn process_of(&self, object: ThreadObject) -> Option<ProcessObject> {
        self.threads.get(&object).map(|entry| entry.process)
    }

    /// Iterates over the thread identities associated with a process.
    pub fn threads_of(&self, object: ProcessObject) -> impl Iterator<Item = ThreadObject> + '_ {
        self.processes
            .get(&object)
            .into_iter()
            .flat_map(|entry| entry.threads.iter().copied())
    }
}

#[cfg(test)]
mod tests {
    use vmi::Va;

    use super::*;

    fn process(value: u64) -> ProcessObject {
        ProcessObject(Va(value))
    }

    fn thread(value: u64) -> ThreadObject {
        ThreadObject(Va(value))
    }

    #[test]
    fn tracks_threads_in_both_directions() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert_process(process, "process");
        tracker.insert_thread(process, thread1, 1).unwrap();
        tracker.insert_thread(process, thread2, 2).unwrap();

        assert_eq!(tracker.process_of(thread1), Some(process));
        assert_eq!(tracker.get_thread(thread2), Some(&2));

        let mut threads = tracker.threads_of(process).collect::<Vec<_>>();
        threads.sort_by_key(|object| object.0);
        assert_eq!(threads, [thread1, thread2]);
    }

    #[test]
    fn rejects_thread_without_tracked_process() {
        let mut tracker = ProcessTracker::<(), u32>::default();
        let value = tracker.insert_thread(process(0x1000), thread(0x2000), 7);

        assert_eq!(value, Err(7));
        assert!(tracker.get_thread(thread(0x2000)).is_none());
    }

    #[test]
    fn replacing_thread_updates_process_membership() {
        let mut tracker = ProcessTracker::<(), u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);
        tracker.insert_process(process1, ());
        tracker.insert_process(process2, ());
        tracker.insert_thread(process1, thread, 1).unwrap();

        assert_eq!(tracker.insert_thread(process2, thread, 2), Ok(Some(1)));
        assert_eq!(tracker.process_of(thread), Some(process2));
        assert_eq!(tracker.threads_of(process1).count(), 0);
        assert_eq!(tracker.threads_of(process2).collect::<Vec<_>>(), [thread]);
    }
}
