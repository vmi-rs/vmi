//! This module tracks process and thread identities with their associated values.

mod process;
mod thread;

use vmi_core::os::{ProcessObject, ThreadObject};

use self::{process::ProcessMap, thread::ThreadMap};

/// A tracker associates values with process and thread relationships.
///
/// Process membership is indexed separately so the common
/// [`Tracker::try_get_or_insert`] path can return mutable process and thread
/// values after one lookup in each primary map.
///
/// # Process generations
///
/// A process remains in its current generation until
/// [`retire_process`](Self::retire_process) retires it. Retiring a process does
/// not remove its value or threads. A successful process initializer or explicit
/// insertion for the same object identity replaces the process value, starts a
/// new active generation, and evicts every thread owned by the previous
/// generation. Inserting a value for an active process replaces only its value
/// and retains its threads.
///
/// # Thread eviction
///
/// Retiring a process or thread does not evict any thread. A process's threads
/// are evicted when its retired generation is replaced or when
/// [`remove_process`](Self::remove_process) removes the process. Calling
/// [`remove_thread`](Self::remove_thread) evicts only that thread.
///
/// # Thread identity reuse
///
/// A thread object identity has one owning process. [`insert`](Self::insert)
/// always replaces the supplied thread value and moves the thread to the
/// supplied process when its owner differs.
/// [`try_get_or_insert`](Self::try_get_or_insert) reuses a thread value only
/// while the thread is active and already belongs to the supplied process. A
/// retired thread or a thread owned by another process is reinitialized and
/// moved after successful initialization. Moving a thread removes its membership
/// from the previous process but does not remove the previous process.
///
/// # Retired values
///
/// Retirement marks lifecycle state without hiding values or relationships. All
/// lookup and membership methods continue to expose retired processes and
/// threads until replacement or explicit removal. Retiring a process does not
/// retire its threads.
///
/// # Cleanup
///
/// Retired entries remain tracked until identity reuse, explicit removal, or a
/// bulk cleanup method removes them. Removing retired processes also removes
/// every thread they own, regardless of each thread's lifecycle state. Removing
/// retired threads alone leaves all processes and their active threads tracked.
pub struct Tracker<P, T> {
    /// This map owns the value and lifecycle state of each process.
    processes: ProcessMap<P>,

    /// This map owns thread values and process membership state.
    threads: ThreadMap<T>,
}

impl<P, T> Default for Tracker<P, T> {
    fn default() -> Self {
        Self {
            processes: ProcessMap::default(),
            threads: ThreadMap::default(),
        }
    }
}

impl<P, T> Tracker<P, T> {
    /// Inserts process and thread values and returns mutable references to both.
    ///
    /// An active process retains its other threads while its value is replaced.
    /// A retired process starts a new generation and evicts all threads from
    /// the previous generation. The supplied thread value always replaces any
    /// value for the same thread identity. A thread owned by another process
    /// moves to `process_object`.
    pub fn insert(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        process_value: P,
        thread_value: T,
    ) -> (&mut P, &mut T) {
        let (process, was_retired) = self.processes.insert(process_object, process_value);

        if was_retired {
            self.threads.remove_process(process_object);
        }

        let thread = self
            .threads
            .insert(process_object, thread_object, thread_value);

        (process, thread)
    }

    /// Returns the process and thread values, inserting them when needed.
    ///
    /// The active-pair path performs one lookup in each primary map and does not
    /// call either initializer. A retired process starts a new generation and
    /// evicts the previous generation's threads. The thread initializer runs
    /// when the thread is absent, retired, or owned by another process. A
    /// successfully reinitialized thread moves to `process_object`.
    ///
    /// # Consistency on error
    ///
    /// A process initialization error leaves the tracker unchanged and does not
    /// call the thread initializer. Process initialization is committed before
    /// thread initialization. If thread initialization fails, any process
    /// insertion or generation replacement remains committed. A generation
    /// replacement also permanently removes the previous generation's threads
    /// before the thread initializer runs.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        init_process: impl FnOnce() -> Result<P, E>,
        init_thread: impl FnOnce() -> Result<T, E>,
    ) -> Result<(&mut P, &mut T), E> {
        let (process, was_retired) = self
            .processes
            .try_get_or_insert(process_object, init_process)?;

        if was_retired {
            self.threads.remove_process(process_object);
        }

        let thread = self
            .threads
            .try_get_or_insert(process_object, thread_object, init_thread)?;

        Ok((process, thread))
    }

    /// Returns process and thread values for the expected relationship.
    ///
    /// Returns `None` if either object is absent. In release builds, also
    /// returns `None` if the thread belongs to another process. Values marked
    /// retired remain visible.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if both objects are present but the thread belongs
    /// to another process.
    pub fn get(
        &self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<(&P, &T)> {
        let process = self.processes.get(process_object)?;
        let thread = self
            .threads
            .get_for_process(process_object, thread_object)?;

        Some((process, thread))
    }

    /// Returns mutable process and thread values for the expected relationship.
    ///
    /// Returns `None` if either object is absent. In release builds, also
    /// returns `None` if the thread belongs to another process. Values marked
    /// retired remain visible.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if both objects are present but the thread belongs
    /// to another process.
    pub fn get_mut(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<(&mut P, &mut T)> {
        let process = self.processes.get_mut(process_object)?;
        let thread = self
            .threads
            .get_for_process_mut(process_object, thread_object)?;

        Some((process, thread))
    }

    /// Retires a process generation and returns its value.
    ///
    /// The process value and all thread relationships remain visible. The next
    /// successful process insertion starts a new generation and evicts the
    /// previous generation's threads. This method does not retire those threads.
    pub fn retire_process(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.processes.retire(process_object)
    }

    /// Retires a thread and returns its value.
    ///
    /// The thread value and process membership remain visible. A later
    /// [`try_get_or_insert`](Self::try_get_or_insert) call reinitializes the
    /// thread.
    ///
    /// Returns `None` if the thread is absent. In release builds, also returns
    /// `None` if the thread belongs to another process.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the thread is present but belongs to another
    /// process.
    pub fn retire_thread(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<&mut T> {
        self.threads.retire(process_object, thread_object)
    }

    /// Inserts and returns a mutable process value.
    ///
    /// An active process retains its threads while its value is replaced. A
    /// retired process starts a new generation and evicts every thread owned
    /// by the previous generation.
    pub fn insert_process(&mut self, process_object: ProcessObject, value: P) -> &mut P {
        let (process, was_retired) = self.processes.insert(process_object, value);

        if was_retired {
            self.threads.remove_process(process_object);
        }

        process
    }

    /// Returns the tracked process, inserting one with `init` when needed.
    ///
    /// An active process is returned without calling `init`. A retired process
    /// starts a new generation and evicts every thread owned by the previous
    /// generation. An initialization error preserves the retired generation and
    /// its threads.
    pub fn try_get_or_insert_process<E>(
        &mut self,
        process_object: ProcessObject,
        init: impl FnOnce() -> Result<P, E>,
    ) -> Result<&mut P, E> {
        let (process, was_retired) = self.processes.try_get_or_insert(process_object, init)?;

        if was_retired {
            self.threads.remove_process(process_object);
        }

        Ok(process)
    }

    /// Returns a process value, including one marked retired.
    pub fn get_process(&self, process_object: ProcessObject) -> Option<&P> {
        self.processes.get(process_object)
    }

    /// Returns a mutable process value, including one marked retired.
    pub fn get_process_mut(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.processes.get_mut(process_object)
    }

    /// Returns a thread value, including one marked retired.
    pub fn get_thread(&self, thread_object: ThreadObject) -> Option<&T> {
        self.threads.get(thread_object)
    }

    /// Returns a mutable thread value, including one marked retired.
    pub fn get_thread_mut(&mut self, thread_object: ThreadObject) -> Option<&mut T> {
        self.threads.get_mut(thread_object)
    }

    /// Returns the process that owns a tracked thread, including a retired thread.
    pub fn process_of(&self, thread_object: ThreadObject) -> Option<ProcessObject> {
        self.threads.process_of(thread_object)
    }

    /// Iterates over all thread identities associated with a process.
    ///
    /// The iterator includes retired threads and threads belonging to a retired
    /// process. Iteration order is unspecified.
    pub fn threads_of(&self, process_object: ProcessObject) -> impl Iterator<Item = ThreadObject> {
        self.threads.threads_of(process_object)
    }

    /// Removes a process value and every thread owned by that process.
    pub fn remove_process(&mut self, process_object: ProcessObject) -> Option<P> {
        let process = self.processes.remove(process_object)?;
        self.threads.remove_process(process_object);

        Some(process)
    }

    /// Removes a thread value and its membership in the owning process.
    pub fn remove_thread(&mut self, thread_object: ThreadObject) -> Option<T> {
        self.threads.remove(thread_object)
    }

    /// Removes all retired processes and every thread they own.
    ///
    /// Threads owned by a retired process are removed regardless of their
    /// lifecycle state.
    pub fn remove_retired_processes(&mut self) {
        for (process_object, _) in self.processes.extract_retired() {
            self.threads.remove_process(process_object);
        }
    }

    /// Removes all retired threads and updates their process memberships.
    ///
    /// Processes and active threads remain tracked.
    pub fn remove_retired_threads(&mut self) {
        self.threads.remove_retired();
    }

    /// Removes all retired processes and threads.
    pub fn remove_retired(&mut self) {
        // Process cleanup must run first because it already removes every owned
        // thread. Running thread cleanup first would repeat membership work for
        // threads that the process pass discards.
        self.remove_retired_processes();
        self.remove_retired_threads();
    }
}

/// Tests public relationship and lifecycle contracts.
#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use vmi_core::{
        Va,
        os::{ProcessObject, ThreadObject},
    };

    use super::Tracker;

    /// Builds a process object from a test address.
    fn process(value: u64) -> ProcessObject {
        ProcessObject(Va(value))
    }

    /// Builds a thread object from a test address.
    fn thread(value: u64) -> ThreadObject {
        ThreadObject(Va(value))
    }

    /// Verifies that an active pair bypasses both initializers.
    #[test]
    fn reuses_active_pair_without_initializing() {
        let mut tracker = Tracker::<u32, u32>::default();
        let process = process(0x1000);
        let thread = thread(0x2000);

        tracker.insert(process, thread, 1, 2);

        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread,
                || -> Result<u32, ()> { panic!("initialized an active process") },
                || -> Result<u32, ()> { panic!("initialized an active thread") },
            )
            .unwrap();

        assert_eq!((*process_value, *thread_value), (1, 2));
    }

    /// Verifies successful replacement of a retired process generation.
    #[test]
    fn replaces_retired_process_generation() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "old", 1);
        tracker.insert(process, thread2, "old", 2);
        tracker.retire_process(process).unwrap();

        let (process_value, thread_value) = tracker
            .try_get_or_insert(process, thread1, || Ok::<_, ()>("new"), || Ok(3))
            .unwrap();

        assert_eq!((*process_value, *thread_value), ("new", 3));
        assert_eq!(tracker.get_thread(thread1), Some(&3));
        assert!(tracker.get_thread(thread2).is_none());
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread1]);
    }

    /// Verifies successful replacement of a retired thread.
    #[test]
    fn replaces_retired_thread() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "process", 1);
        tracker.insert(process, thread2, "process", 2);
        tracker.retire_thread(process, thread1).unwrap();

        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread1,
                || -> Result<&str, ()> { panic!("initialized an active process") },
                || Ok(3),
            )
            .unwrap();

        assert_eq!((*process_value, *thread_value), ("process", 3));
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.threads_of(process).count(), 2);
    }

    /// Verifies that both insertion paths move a reused thread identity.
    #[test]
    fn moves_thread_identity_between_processes() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);

        tracker.insert(process1, thread, "process1", 1);
        tracker.insert_process(process2, "process2");
        tracker.insert(process2, thread, "process2", 2);

        assert_eq!(tracker.process_of(thread), Some(process2));
        assert_eq!(tracker.threads_of(process1).count(), 0);
        assert_eq!(tracker.threads_of(process2).collect::<Vec<_>>(), [thread]);

        let (_, thread_value) = tracker
            .try_get_or_insert(
                process1,
                thread,
                || -> Result<&str, ()> { panic!("initialized an active process") },
                || Ok(3),
            )
            .unwrap();

        assert_eq!(*thread_value, 3);
        assert_eq!(tracker.process_of(thread), Some(process1));
        assert_eq!(tracker.threads_of(process1).collect::<Vec<_>>(), [thread]);
        assert_eq!(tracker.threads_of(process2).count(), 0);
    }

    /// Verifies that active process replacement retains owned threads.
    #[test]
    fn replaces_active_process_without_evicting_threads() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "first", 1);
        tracker.insert(process, thread2, "second", 2);
        tracker.insert_process(process, "third");

        assert_eq!(tracker.get_process(process), Some(&"third"));
        assert_eq!(tracker.get_thread(thread1), Some(&1));
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.threads_of(process).count(), 2);
    }

    /// Verifies that explicit removal updates values and memberships together.
    #[test]
    fn removes_values_and_memberships_explicitly() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "process", 1);
        tracker.insert(process, thread2, "process", 2);

        assert_eq!(tracker.remove_thread(thread1), Some(1));
        assert!(tracker.get_thread(thread1).is_none());
        assert!(tracker.process_of(thread1).is_none());
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread2]);

        assert_eq!(tracker.remove_process(process), Some("process"));
        assert!(tracker.get_process(process).is_none());
        assert!(tracker.get_thread(thread2).is_none());
        assert!(tracker.process_of(thread2).is_none());
        assert_eq!(tracker.threads_of(process).count(), 0);
    }

    /// Verifies the build-mode behavior for mismatched pair lookups.
    #[test]
    fn handles_mismatched_pair_lookup() {
        let mut tracker = Tracker::<u32, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);

        tracker.insert(process1, thread, 1, 2);
        tracker.insert_process(process2, 3);

        let get_result = catch_unwind(AssertUnwindSafe(|| tracker.get(process2, thread).is_none()));
        let get_mut_result = catch_unwind(AssertUnwindSafe(|| {
            tracker.get_mut(process2, thread).is_none()
        }));

        if cfg!(debug_assertions) {
            assert!(get_result.is_err());
            assert!(get_mut_result.is_err());
        }
        else {
            assert!(get_result.unwrap());
            assert!(get_mut_result.unwrap());
        }

        assert_eq!(tracker.get(process1, thread), Some((&1, &2)));
    }

    /// Verifies the build-mode behavior for mismatched thread retirement.
    #[test]
    fn handles_mismatched_thread_retirement() {
        let mut tracker = Tracker::<u32, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);

        tracker.insert(process1, thread, 1, 2);
        tracker.insert_process(process2, 3);

        let result = catch_unwind(AssertUnwindSafe(|| {
            tracker.retire_thread(process2, thread).is_none()
        }));

        if cfg!(debug_assertions) {
            assert!(result.is_err());
        }
        else {
            assert!(result.unwrap());
        }

        assert_eq!(tracker.get(process1, thread), Some((&1, &2)));
    }

    /// Verifies that a thread error retains a newly initialized process.
    #[test]
    fn thread_error_retains_new_process() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread = thread(0x2000);

        let result =
            tracker.try_get_or_insert(process, thread, || Ok("process"), || Err("thread error"));

        assert_eq!(result.unwrap_err(), "thread error");
        assert_eq!(tracker.get_process(process), Some(&"process"));
        assert!(tracker.get_thread(thread).is_none());
        assert_eq!(tracker.threads_of(process).count(), 0);
    }

    /// Verifies that a thread error commits process generation replacement.
    #[test]
    fn thread_error_commits_process_generation_replacement() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "old", 1);
        tracker.insert(process, thread2, "old", 2);
        tracker.retire_process(process).unwrap();

        let result =
            tracker.try_get_or_insert(process, thread1, || Ok("new"), || Err("thread error"));

        assert_eq!(result.unwrap_err(), "thread error");
        assert_eq!(tracker.get_process(process), Some(&"new"));
        assert!(tracker.get_thread(thread1).is_none());
        assert!(tracker.get_thread(thread2).is_none());
        assert_eq!(tracker.threads_of(process).count(), 0);
    }

    /// Verifies that a process error preserves the previous generation.
    #[test]
    fn process_error_preserves_previous_generation() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "old", 1);
        tracker.insert(process, thread2, "old", 2);
        tracker.retire_process(process).unwrap();

        let result = tracker.try_get_or_insert(
            process,
            thread1,
            || Err("process error"),
            || -> Result<u32, &str> {
                panic!("initialized thread after process initialization failed")
            },
        );

        assert_eq!(result.unwrap_err(), "process error");
        assert_eq!(tracker.get_process(process), Some(&"old"));
        assert_eq!(tracker.get_thread(thread1), Some(&1));
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.threads_of(process).count(), 2);
    }

    /// Verifies that process cleanup cascades to all owned threads.
    #[test]
    fn removes_retired_processes_and_owned_threads() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread1 = thread(0x3000);
        let thread2 = thread(0x4000);
        let thread3 = thread(0x5000);

        tracker.insert(process1, thread1, "retired", 1);
        tracker.insert(process1, thread2, "retired", 2);
        tracker.insert(process2, thread3, "active", 3);
        tracker.retire_process(process1).unwrap();
        tracker.retire_thread(process2, thread3).unwrap();

        tracker.remove_retired_processes();

        assert!(tracker.get_process(process1).is_none());
        assert!(tracker.get_thread(thread1).is_none());
        assert!(tracker.get_thread(thread2).is_none());
        assert_eq!(tracker.get_process(process2), Some(&"active"));
        assert_eq!(tracker.get_thread(thread3), Some(&3));
        assert_eq!(tracker.process_of(thread3), Some(process2));
    }

    /// Verifies that thread cleanup leaves processes and active threads tracked.
    #[test]
    fn removes_only_retired_threads() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "process", 1);
        tracker.insert(process, thread2, "process", 2);
        tracker.retire_process(process).unwrap();
        tracker.retire_thread(process, thread1).unwrap();

        tracker.remove_retired_threads();

        assert_eq!(tracker.get_process(process), Some(&"process"));
        assert!(tracker.get_thread(thread1).is_none());
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread2]);
    }

    /// Verifies that combined cleanup removes both retired categories.
    #[test]
    fn removes_all_retired_entries() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread1 = thread(0x3000);
        let thread2 = thread(0x4000);
        let thread3 = thread(0x5000);

        tracker.insert(process1, thread1, "retired", 1);
        tracker.insert(process2, thread2, "active", 2);
        tracker.insert(process2, thread3, "active", 3);
        tracker.retire_process(process1).unwrap();
        tracker.retire_thread(process2, thread2).unwrap();

        tracker.remove_retired();

        assert!(tracker.get_process(process1).is_none());
        assert!(tracker.get_thread(thread1).is_none());
        assert_eq!(tracker.get_process(process2), Some(&"active"));
        assert!(tracker.get_thread(thread2).is_none());
        assert_eq!(tracker.get_thread(thread3), Some(&3));
        assert_eq!(tracker.threads_of(process2).collect::<Vec<_>>(), [thread3]);
    }
}
