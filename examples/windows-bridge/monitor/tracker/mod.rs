#![allow(
    dead_code,
    reason = "the tracker API is intentionally broader than this example currently uses"
)]

//! Tracks process and thread identities with their associated values.

mod process;
mod thread;

use vmi::os::{ProcessObject, ThreadObject};

use self::{process::ProcessMap, thread::ThreadMap};

/// Tracks process and thread relationships with their associated values.
pub struct ProcessTracker<P, T> {
    processes: ProcessMap<P>,
    threads: ThreadMap<T>,
}

impl<P, T> Default for ProcessTracker<P, T> {
    fn default() -> Self {
        Self {
            processes: ProcessMap::default(),
            threads: ThreadMap::default(),
        }
    }
}

impl<P, T> ProcessTracker<P, T> {
    fn evict_terminated_process(&mut self, process_object: ProcessObject) {
        let terminated = self
            .processes
            .get(process_object)
            .is_some_and(|process| process.terminated);

        if !terminated {
            return;
        }

        let process = match self.processes.remove(process_object) {
            Some(process) => process,
            None => {
                debug_assert!(false, "terminated process must have an entry");
                return;
            }
        };

        tracing::debug!(
            %process_object,
            stale_threads = process.threads.len(),
            "evicting terminated process"
        );

        for thread_object in process.threads {
            let thread = self.threads.remove(thread_object);

            debug_assert!(
                thread.is_some(),
                "tracked process thread must have an entry"
            );

            if let Some(thread) = thread {
                debug_assert_eq!(
                    thread.process, process_object,
                    "tracked thread belongs to an unexpected process"
                );
            }
        }
    }

    fn evict_terminated_thread(&mut self, thread_object: ThreadObject) {
        let terminated = self
            .threads
            .get(thread_object)
            .is_some_and(|thread| thread.terminated);

        if !terminated {
            return;
        }

        let thread = match self.threads.remove(thread_object) {
            Some(thread) => thread,
            None => {
                debug_assert!(false, "terminated thread must have an entry");
                return;
            }
        };

        tracing::debug!(
            %thread_object,
            process_object = %thread.process,
            "evicting terminated thread"
        );

        if let Some(process) = self.processes.get_mut(thread.process) {
            process.detach_thread(thread_object);
        }
        else {
            debug_assert!(false, "tracked thread must reference a tracked process");
        }
    }

    /// Inserts process and thread values and returns mutable references to both.
    ///
    /// Existing active values are replaced while the process's other threads are
    /// retained. A terminated process and all of its threads are evicted first.
    pub fn insert(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        process_value: P,
        thread_value: T,
    ) -> (&mut P, &mut T) {
        self.evict_terminated_process(process_object);

        let (thread, previous_process_object) =
            self.threads
                .insert(thread_object, process_object, thread_value);

        // If this insert replaces a thread owned by another process, detach it from
        // that process when it is still tracked. This keeps the process-to-thread
        // index consistent with the thread's newly updated owner.
        if let Some(previous_process_object) = previous_process_object
            && previous_process_object != process_object
            && let Some(process) = self.processes.get_mut(previous_process_object)
        {
            process.detach_thread(thread_object);
        }

        let process = self.processes.insert(process_object, process_value);
        process.attach_thread(thread_object);

        (&mut process.value, &mut thread.value)
    }

    /// Returns the process and thread values, inserting them when absent.
    ///
    /// Terminated entries are evicted and initialized as a new generation.
    /// Existing active entries are returned without calling either initializer.
    /// Returns `Err` when initialization fails.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        init_process: impl FnOnce() -> Result<P, E>,
        init_thread: impl FnOnce() -> Result<T, E>,
    ) -> Result<(&mut P, &mut T), E> {
        self.evict_terminated_process(process_object);
        self.evict_terminated_thread(thread_object);

        let process = self
            .processes
            .try_get_or_insert(process_object, init_process)?;

        let thread = self
            .threads
            .try_get_or_insert(thread_object, process_object, init_thread)?;

        debug_assert_eq!(
            process_object, thread.process,
            "tracked thread belongs to an unexpected process"
        );

        if thread.process == process_object {
            process.attach_thread(thread_object);
        }

        Ok((&mut process.value, &mut thread.value))
    }

    /// Returns process and thread values for the expected relationship.
    pub fn get(
        &self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<(&P, &T)> {
        let process = self.processes.get(process_object)?;
        let thread = self.threads.get(thread_object)?;

        debug_assert_eq!(
            process_object, thread.process,
            "tracked thread belongs to an unexpected process"
        );

        Some((&process.value, &thread.value))
    }

    /// Returns mutable process and thread values for the expected relationship.
    pub fn get_mut(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<(&mut P, &mut T)> {
        let process = self.processes.get_mut(process_object)?;
        let thread = self.threads.get_mut(thread_object)?;

        debug_assert_eq!(
            process_object, thread.process,
            "tracked thread belongs to an unexpected process"
        );

        Some((&mut process.value, &mut thread.value))
    }

    /// Marks a process as terminated.
    pub fn mark_process_terminated(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        let process = self.processes.get_mut(process_object)?;
        process.terminated = true;

        Some(&mut process.value)
    }

    /// Marks a thread as terminated.
    pub fn mark_thread_terminated(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<&mut T> {
        self.processes.get(process_object)?;

        let thread = self.threads.get_mut(thread_object)?;

        debug_assert_eq!(
            process_object, thread.process,
            "tracked thread belongs to an unexpected process"
        );

        if thread.process != process_object {
            return None;
        }

        thread.terminated = true;

        Some(&mut thread.value)
    }

    /// Inserts and returns a mutable process value while retaining its tracked threads.
    ///
    /// A terminated process and all of its threads are evicted first.
    pub fn insert_process(&mut self, process_object: ProcessObject, value: P) -> &mut P {
        self.evict_terminated_process(process_object);

        let process = self.processes.insert(process_object, value);
        &mut process.value
    }

    /// Returns the tracked process, inserting one with `init` when absent.
    ///
    /// A terminated process and all of its threads are evicted before `init` is
    /// called. Returns `Err` when initialization fails.
    pub fn try_get_or_insert_process<E>(
        &mut self,
        process_object: ProcessObject,
        init: impl FnOnce() -> Result<P, E>,
    ) -> Result<&mut P, E> {
        self.evict_terminated_process(process_object);

        self.processes
            .try_get_or_insert(process_object, init)
            .map(|process| &mut process.value)
    }

    /// Returns a process value.
    pub fn get_process(&self, process_object: ProcessObject) -> Option<&P> {
        self.processes
            .get(process_object)
            .map(|process| &process.value)
    }

    /// Returns a mutable process value.
    pub fn get_process_mut(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.processes
            .get_mut(process_object)
            .map(|process| &mut process.value)
    }

    /// Returns a thread value.
    pub fn get_thread(&self, thread_object: ThreadObject) -> Option<&T> {
        self.threads.get(thread_object).map(|thread| &thread.value)
    }

    /// Returns a mutable thread value.
    pub fn get_thread_mut(&mut self, thread_object: ThreadObject) -> Option<&mut T> {
        self.threads
            .get_mut(thread_object)
            .map(|thread| &mut thread.value)
    }

    /// Returns the process that owns a tracked thread.
    pub fn process_of(&self, thread_object: ThreadObject) -> Option<ProcessObject> {
        self.threads.get(thread_object).map(|thread| thread.process)
    }

    /// Iterates over the thread identities associated with a process.
    pub fn threads_of(
        &self,
        process_object: ProcessObject,
    ) -> impl Iterator<Item = ThreadObject> + '_ {
        self.processes
            .get(process_object)
            .into_iter()
            .flat_map(|process| process.threads.iter().copied())
    }

    /// Removes a process value and all of its tracked threads.
    pub fn remove_process(&mut self, process_object: ProcessObject) -> Option<P> {
        let process = self.processes.remove(process_object)?;

        for thread_object in process.threads {
            self.threads.remove(thread_object);
        }

        Some(process.value)
    }

    /// Removes a thread value and its process membership.
    pub fn remove_thread(&mut self, thread_object: ThreadObject) -> Option<T> {
        let thread = self.threads.remove(thread_object)?;

        if let Some(process) = self.processes.get_mut(thread.process) {
            process.detach_thread(thread_object);
        }

        Some(thread.value)
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

        let (process_value, thread_value) = tracker.insert(process, thread1, "process", 1);
        assert_eq!((*process_value, *thread_value), ("process", 1));

        let (_, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread2,
                || -> Result<&str, ()> { panic!("initialized an existing process") },
                || Ok(2),
            )
            .unwrap();
        assert_eq!(*thread_value, 2);

        assert_eq!(tracker.process_of(thread1), Some(process));
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.get(process, thread1), Some((&"process", &1)));

        let (process_value, thread_value) = tracker.get_mut(process, thread1).unwrap();
        *process_value = "updated";
        *thread_value = 3;
        assert_eq!(tracker.get(process, thread1), Some((&"updated", &3)));

        let mut threads = tracker.threads_of(process).collect::<Vec<_>>();
        threads.sort_by_key(|object| object.0);
        assert_eq!(threads, [thread1, thread2]);
    }

    #[test]
    fn replacing_active_process_retains_threads() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread = thread(0x2000);
        tracker.insert(process, thread, "old", 7);

        assert_eq!(*tracker.insert_process(process, "new"), "new");
        assert_eq!(tracker.get_thread(thread), Some(&7));
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread]);
    }

    #[test]
    fn replacing_thread_updates_process_membership() {
        let mut tracker = ProcessTracker::<(), u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);
        tracker.insert(process1, thread, (), 1);

        let (_, thread_value) = tracker.insert(process2, thread, (), 2);
        assert_eq!(*thread_value, 2);
        assert_eq!(tracker.process_of(thread), Some(process2));
        assert_eq!(tracker.threads_of(process1).count(), 0);
        assert_eq!(tracker.threads_of(process2).collect::<Vec<_>>(), [thread]);
    }

    #[test]
    fn gets_or_inserts_process() {
        let mut tracker = ProcessTracker::<&str, ()>::default();
        let process = process(0x1000);

        let value = tracker
            .try_get_or_insert_process(process, || Ok::<_, ()>("process"))
            .unwrap();
        assert_eq!(*value, "process");

        let value = tracker
            .try_get_or_insert_process(process, || -> Result<&str, ()> {
                panic!("initialized an existing process")
            })
            .unwrap();
        assert_eq!(*value, "process");
    }

    #[test]
    fn gets_or_inserts_thread_and_process() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread = thread(0x2000);

        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread,
                || Ok::<_, ()>("process"),
                || Ok::<_, ()>(7),
            )
            .unwrap();
        assert_eq!((*process_value, *thread_value), ("process", 7));
        assert_eq!(tracker.get(process, thread), Some((&"process", &7)));

        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread,
                || -> Result<&str, ()> { panic!("initialized an existing process") },
                || -> Result<u32, ()> { panic!("initialized an existing thread") },
            )
            .unwrap();
        assert_eq!((*process_value, *thread_value), ("process", 7));
    }

    #[test]
    fn process_initialization_error_does_not_insert_thread() {
        let mut tracker = ProcessTracker::<(), u32>::default();
        let process = process(0x1000);
        let thread = thread(0x2000);

        let result = tracker.try_get_or_insert(process, thread, || Err("process error"), || Ok(7));

        assert_eq!(result.unwrap_err(), "process error");
        assert!(tracker.get_process(process).is_none());
        assert!(tracker.get_thread(thread).is_none());
    }

    #[test]
    fn inserting_terminated_process_evicts_its_threads() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);
        tracker.insert(process, thread1, "old", 1);
        tracker
            .try_get_or_insert(
                process,
                thread2,
                || -> Result<&str, ()> { panic!("initialized an existing process") },
                || Ok(2),
            )
            .unwrap();

        assert_eq!(
            tracker.mark_process_terminated(process).map(|value| *value),
            Some("old")
        );
        assert_eq!(*tracker.insert_process(process, "new"), "new");

        assert!(tracker.get_thread(thread1).is_none());
        assert!(tracker.get_thread(thread2).is_none());
        assert_eq!(tracker.threads_of(process).count(), 0);
    }

    #[test]
    fn getting_or_inserting_terminated_process_starts_new_generation() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);
        tracker.insert(process, thread1, "old", 1);
        tracker
            .try_get_or_insert(
                process,
                thread2,
                || -> Result<&str, ()> { panic!("initialized an existing process") },
                || Ok(2),
            )
            .unwrap();
        tracker.mark_process_terminated(process).unwrap();

        let (process_value, thread_value) = tracker
            .try_get_or_insert(process, thread1, || Ok::<_, ()>("new"), || Ok::<_, ()>(3))
            .unwrap();

        assert_eq!((*process_value, *thread_value), ("new", 3));
        assert!(tracker.get_thread(thread2).is_none());
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread1]);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn terminated_process_marks_its_threads_for_reuse() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);
        tracker.insert(process1, thread, "process1", 1);
        tracker.insert_process(process2, "process2");
        tracker.mark_process_terminated(process1).unwrap();

        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process2,
                thread,
                || -> Result<&str, ()> { panic!("initialized an existing process") },
                || Ok(2),
            )
            .unwrap();

        assert_eq!((*process_value, *thread_value), ("process2", 2));
        assert_eq!(tracker.process_of(thread), Some(process2));
        assert_eq!(tracker.threads_of(process1).count(), 0);
    }

    #[test]
    fn getting_or_inserting_terminated_thread_replaces_it() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread = thread(0x2000);
        tracker.insert(process, thread, "process", 1);

        assert_eq!(
            tracker
                .mark_thread_terminated(process, thread)
                .map(|value| *value),
            Some(1)
        );

        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread,
                || -> Result<&str, ()> { panic!("initialized an existing process") },
                || Ok(2),
            )
            .unwrap();

        assert_eq!((*process_value, *thread_value), ("process", 2));
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread]);
    }

    #[test]
    fn removing_thread_updates_process_membership() {
        let mut tracker = ProcessTracker::<(), u32>::default();
        let process = process(0x1000);
        let thread = thread(0x2000);
        tracker.insert(process, thread, (), 7);

        assert_eq!(tracker.remove_thread(thread), Some(7));
        assert!(tracker.get_thread(thread).is_none());
        assert_eq!(tracker.threads_of(process).count(), 0);
    }

    #[test]
    fn removing_process_removes_its_threads() {
        let mut tracker = ProcessTracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);
        tracker.insert(process, thread1, "process", 1);
        tracker
            .try_get_or_insert(
                process,
                thread2,
                || -> Result<&str, ()> { panic!("initialized an existing process") },
                || Ok(2),
            )
            .unwrap();

        assert_eq!(tracker.remove_process(process), Some("process"));
        assert!(tracker.get_thread(thread1).is_none());
        assert!(tracker.get_thread(thread2).is_none());
        assert_eq!(tracker.threads_of(process).count(), 0);
    }
}
