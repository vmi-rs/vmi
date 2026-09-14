//! Process and thread tracking.

mod process;
mod thread;

use vmi_core::os::{ProcessObject, ThreadObject};

use self::{process::ProcessMap, thread::ThreadMap};

/// A tracker for process and thread data.
///
/// `P` holds process data. `T` holds thread data. Entries are identified by
/// the addresses of the operating system's process and thread objects, not IDs.
///
/// # Why keep retired entries?
///
/// A process or thread can still cause VMI events while it is exiting. Windows
/// calls `KeTerminateThread` or `MmCleanProcessAddressSpace` before the thread or
/// process object is gone. Later VM exits can still come from that thread or
/// process.
///
/// Removing its entry too early would make a later event add it again, losing
/// the stored data. Retiring means keeping the data but marking it for later
/// removal. Reads and get-or-insert calls keep retired data when the thread
/// still belongs to the same process.
///
/// # When to keep or replace data
///
/// Use [`try_get_or_insert`](Self::try_get_or_insert) for normal events.
/// To update a process ID or other information, change the stored value through
/// a mutable reference.
///
/// Use [`insert_process`](Self::insert_process) or [`insert`](Self::insert) when
/// a new process is created. These replace the old process data and remove all
/// threads still linked to that process object, even if it was not retired.
/// Use [`try_insert_thread`](Self::try_insert_thread) when a new thread is
/// created. It replaces the thread data but keeps existing process data.
///
/// Each thread belongs to one process. Moving a thread to another process
/// removes it from the old process's thread list. Removing the old process will
/// not remove that thread.
pub struct Tracker<P, T> {
    /// Stores process data and whether each entry is retired.
    processes: ProcessMap<P>,

    /// Stores thread data and the process each thread belongs to.
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
    /// Inserts process and thread data, replacing any data at those addresses.
    ///
    /// Removes all threads still linked to `process_object`, even if the process
    /// is not retired. If `thread_object` belonged to another process, it now
    /// belongs to `process_object`.
    pub fn insert(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        process_value: P,
        thread_value: T,
    ) -> (&mut P, &mut T) {
        let process = self.processes.insert(process_object, process_value);
        self.threads.remove_process(process_object);

        let thread = self
            .threads
            .insert(process_object, thread_object, thread_value);

        (process, thread)
    }

    /// Returns saved process and thread data, adding missing data when needed.
    ///
    /// Calls `init_process` only if the process is not stored. Calls `init_thread`
    /// if the thread is not stored or belongs to another process. In the latter
    /// case, replaces the thread data and moves it to `process_object`.
    ///
    /// Keeps existing data even if it is retired, as long as the thread belongs
    /// to the given process.
    ///
    /// # Errors
    ///
    /// If `init_process` fails, nothing changes and `init_thread` is not called.
    /// If `init_thread` fails, any process added by `init_process` stays stored.
    /// Existing thread data and process thread lists stay unchanged.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        init_process: impl FnOnce() -> Result<P, E>,
        init_thread: impl FnOnce() -> Result<T, E>,
    ) -> Result<(&mut P, &mut T), E> {
        let process = self
            .processes
            .try_get_or_insert(process_object, init_process)?;

        let thread = self
            .threads
            .try_get_or_insert(process_object, thread_object, init_thread)?;

        Ok((process, thread))
    }

    /// Returns saved data if the thread belongs to the given process.
    ///
    /// Returns `None` if either entry is missing. In release builds, also returns
    /// `None` if the thread belongs to another process. Includes retired entries.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if both entries exist but the thread belongs to
    /// another process.
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

    /// Returns process and thread data that can be changed.
    ///
    /// Returns `None` if either entry is missing. In release builds, also returns
    /// `None` if the thread belongs to another process. Includes retired entries.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if both entries exist but the thread belongs to
    /// another process.
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

    /// Checks whether both entries are stored and the thread belongs to this process.
    ///
    /// Returns `false` if either entry is missing or the thread belongs to another
    /// process. Retired entries still count as stored.
    pub fn contains(&self, process_object: ProcessObject, thread_object: ThreadObject) -> bool {
        self.contains_process(process_object)
            && self.process_of(thread_object) == Some(process_object)
    }

    /// Inserts process data and removes its old thread entries.
    ///
    /// Replaces any saved value and removes all threads still linked to this
    /// process object, even if the process is not retired. Use
    /// [`get_process_mut`](Self::get_process_mut) to change data for the same
    /// process without removing its threads.
    pub fn insert_process(&mut self, process_object: ProcessObject, value: P) -> &mut P {
        self.threads.remove_process(process_object);
        self.processes.insert(process_object, value)
    }

    /// Returns saved process data, or calls `init` to add it.
    ///
    /// Keeps existing data and its threads, even if the process is retired.
    /// If `init` fails, nothing changes.
    pub fn try_get_or_insert_process<E>(
        &mut self,
        process_object: ProcessObject,
        init: impl FnOnce() -> Result<P, E>,
    ) -> Result<&mut P, E> {
        self.processes.try_get_or_insert(process_object, init)
    }

    /// Returns saved process data, including data for retired processes.
    pub fn get_process(&self, process_object: ProcessObject) -> Option<&P> {
        self.processes.get(process_object)
    }

    /// Returns process data that can be changed, even for retired processes.
    pub fn get_process_mut(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.processes.get_mut(process_object)
    }

    /// Checks whether process data is stored, including retired processes.
    pub fn contains_process(&self, process_object: ProcessObject) -> bool {
        self.processes.get(process_object).is_some()
    }

    /// Marks a process for later removal and keeps its data.
    ///
    /// Keeps all its threads too. Reads and get-or-insert calls still return the
    /// saved data. This does not mark the process's threads as retired.
    pub fn retire_process(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.processes.retire(process_object)
    }

    /// Removes a process entry and all thread entries still linked to it.
    pub fn remove_process(&mut self, process_object: ProcessObject) -> Option<P> {
        let process = self.processes.remove(process_object)?;
        self.threads.remove_process(process_object);

        Some(process)
    }

    /// Inserts thread data, adding process data if needed.
    ///
    /// Always replaces the saved value for `thread_object`, whether retired or
    /// not. Keeps existing process data, its retired flag, and its other threads.
    /// If the thread belonged to another process, updates both thread lists.
    ///
    /// Calls `init_process` only if the process is missing. If it fails, nothing
    /// changes.
    pub fn try_insert_thread<E>(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        init_process: impl FnOnce() -> Result<P, E>,
        thread_value: T,
    ) -> Result<(&mut P, &mut T), E> {
        let process = self
            .processes
            .try_get_or_insert(process_object, init_process)?;
        let thread = self
            .threads
            .insert(process_object, thread_object, thread_value);

        Ok((process, thread))
    }

    /// Returns saved thread data, including data for retired threads.
    pub fn get_thread(&self, thread_object: ThreadObject) -> Option<&T> {
        self.threads.get(thread_object)
    }

    /// Returns thread data that can be changed, even for retired threads.
    pub fn get_thread_mut(&mut self, thread_object: ThreadObject) -> Option<&mut T> {
        self.threads.get_mut(thread_object)
    }

    /// Checks whether thread data is stored, including retired threads.
    pub fn contains_thread(&self, thread_object: ThreadObject) -> bool {
        self.threads.get(thread_object).is_some()
    }

    /// Marks a thread for later removal and keeps its data.
    ///
    /// The thread stays in its process's thread list. Reads still return its
    /// data. Get-or-insert keeps its data while it belongs to the same process.
    ///
    /// Returns `None` if the thread is missing. In release builds, also returns
    /// `None` if the thread belongs to another process.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the thread exists but belongs to another process.
    pub fn retire_thread(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<&mut T> {
        self.threads.retire(process_object, thread_object)
    }

    /// Removes saved thread data and removes it from its process's thread list.
    pub fn remove_thread(&mut self, thread_object: ThreadObject) -> Option<T> {
        self.threads.remove(thread_object)
    }

    /// Returns a stored thread's process, even if the thread is retired.
    pub fn process_of(&self, thread_object: ThreadObject) -> Option<ProcessObject> {
        self.threads.process_of(thread_object)
    }

    /// Lists the threads stored for a process.
    ///
    /// Includes retired threads and threads of a retired process. The order is
    /// not fixed.
    pub fn threads_of(&self, process_object: ProcessObject) -> impl Iterator<Item = ThreadObject> {
        self.threads.threads_of(process_object)
    }

    /// Removes retired process entries and all threads still linked to them.
    ///
    /// Also removes threads that are not retired. Call only when later events no
    /// longer need the saved data.
    pub fn remove_retired_processes(&mut self) {
        for (process_object, _) in self.processes.extract_retired() {
            self.threads.remove_process(process_object);
        }
    }

    /// Removes retired thread entries from the tracker and their process lists.
    ///
    /// Keeps process entries and threads that are not retired. Call only when
    /// later events no longer need the saved data.
    pub fn remove_retired_threads(&mut self) {
        self.threads.remove_retired();
    }

    /// Removes retired process and thread entries.
    ///
    /// Also removes all threads still linked to a retired process. Call only when
    /// later events no longer need the saved data.
    pub fn remove_retired(&mut self) {
        // Remove processes first because this also removes their threads.
        // Then remove any other retired threads.
        self.remove_retired_processes();
        self.remove_retired_threads();
    }
}

/// Checks saved data, retirement, and links between processes and threads.
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

    /// Panics if existing process data is created again.
    fn existing_process() -> Result<&'static str, ()> {
        panic!("initialized an existing process")
    }

    /// Checks which process and thread entries are stored.
    #[test]
    fn checks_containment() {
        let mut tracker = Tracker::<u32, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread1 = thread(0x3000);
        let thread2 = thread(0x4000);
        let missing_process = process(0x5000);
        let missing_thread = thread(0x6000);

        tracker.insert(process1, thread1, 1, 2);
        tracker.insert(process2, thread2, 3, 4);

        assert!(tracker.contains(process1, thread1));
        assert!(tracker.contains_process(process1));
        assert!(tracker.contains_thread(thread1));
        assert!(!tracker.contains(process1, thread2));
        assert!(!tracker.contains(missing_process, thread1));
        assert!(!tracker.contains(process1, missing_thread));
        assert!(!tracker.contains_process(missing_process));
        assert!(!tracker.contains_thread(missing_thread));

        tracker.retire_process(process1).unwrap();
        tracker.retire_thread(process1, thread1).unwrap();

        assert!(tracker.contains(process1, thread1));
        assert!(tracker.contains_process(process1));
        assert!(tracker.contains_thread(thread1));

        assert_eq!(tracker.remove_thread(thread1), Some(2));

        assert!(!tracker.contains(process1, thread1));
        assert!(tracker.contains_process(process1));
        assert!(!tracker.contains_thread(thread1));
    }

    /// Checks that existing data is reused without calling setup functions.
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

    /// Checks that later events keep retired data and other threads.
    #[test]
    fn preserves_retired_context_without_initializing() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);
        let thread3 = thread(0x4000);

        tracker.insert(process, thread1, "old", 1);
        tracker
            .try_insert_thread(process, thread2, existing_process, 2)
            .unwrap();
        tracker.retire_process(process).unwrap();
        tracker.retire_thread(process, thread1).unwrap();

        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread1,
                || -> Result<&str, ()> { panic!("initialized a retired process") },
                || -> Result<u32, ()> { panic!("initialized a retired thread") },
            )
            .unwrap();

        assert_eq!((*process_value, *thread_value), ("old", 1));
        assert_eq!(
            tracker
                .try_get_or_insert_process(process, || -> Result<&str, ()> {
                    panic!("initialized a retired process")
                })
                .unwrap(),
            &"old"
        );
        let (process_value, thread_value) = tracker
            .try_get_or_insert(
                process,
                thread3,
                || -> Result<&str, ()> { panic!("replaced a retired process") },
                || Ok(3),
            )
            .unwrap();
        assert_eq!((*process_value, *thread_value), ("old", 3));
        assert_eq!(tracker.get_thread(thread2), Some(&2));

        tracker.remove_retired_threads();
        assert!(tracker.get_thread(thread1).is_none());
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.get_thread(thread3), Some(&3));
        tracker.remove_retired_processes();
        assert!(tracker.get_process(process).is_none());
        assert!(tracker.get_thread(thread2).is_none());
        assert!(tracker.get_thread(thread3).is_none());
    }

    /// Checks that replacing thread data keeps the retired process's data.
    #[test]
    fn replaces_thread_without_replacing_process() {
        for retired in [false, true] {
            let mut tracker = Tracker::<&str, u32>::default();
            let process = process(0x1000);
            let thread1 = thread(0x2000);
            let thread2 = thread(0x3000);

            tracker.insert(process, thread1, "process", 1);
            tracker
                .try_insert_thread(process, thread2, existing_process, 2)
                .unwrap();
            tracker.retire_process(process).unwrap();
            if retired {
                tracker.retire_thread(process, thread1).unwrap();
            }

            let (process_value, thread_value) = tracker
                .try_insert_thread(process, thread1, existing_process, 3)
                .unwrap();

            assert_eq!((*process_value, *thread_value), ("process", 3));
            tracker.remove_retired_threads();
            assert_eq!(tracker.get(process, thread1), Some((&"process", &3)));
            assert_eq!(tracker.get_thread(thread2), Some(&2));
            assert_eq!(tracker.threads_of(process).count(), 2);

            tracker.remove_retired_processes();
            assert!(!tracker.contains_process(process));
            assert!(!tracker.contains_thread(thread1));
            assert!(!tracker.contains_thread(thread2));
        }
    }

    /// Checks that reused thread objects are linked to the right process.
    #[test]
    fn moves_thread_identity_between_processes() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);

        tracker.insert(process1, thread, "process1", 1);
        let (process_value, thread_value) = tracker
            .try_insert_thread(process2, thread, || Ok::<_, ()>("process2"), 2)
            .unwrap();

        assert_eq!((*process_value, *thread_value), ("process2", 2));

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

        tracker.remove_process(process2).unwrap();
        assert_eq!(tracker.get(process1, thread), Some((&"process1", &3)));
    }

    /// Checks replacement without a retirement call. Moved threads must stay stored.
    #[test]
    fn replaces_process_generation_without_retirement() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread1 = thread(0x3000);
        let thread2 = thread(0x4000);

        tracker.insert(process1, thread1, "old", 1);
        tracker
            .try_insert_thread(process1, thread2, existing_process, 2)
            .unwrap();
        tracker.insert_process(process2, "other");
        tracker
            .try_insert_thread(process2, thread1, existing_process, 3)
            .unwrap();
        tracker.insert_process(process1, "new");

        assert_eq!(tracker.get_process(process1), Some(&"new"));
        assert!(tracker.get_thread(thread2).is_none());
        assert!(tracker.process_of(thread2).is_none());
        assert_eq!(tracker.threads_of(process1).count(), 0);
        assert_eq!(tracker.get(process2, thread1), Some((&"other", &3)));
        assert_eq!(tracker.threads_of(process2).collect::<Vec<_>>(), [thread1]);
    }

    /// Checks that removal clears saved data and links between entries.
    #[test]
    fn removes_values_and_memberships_explicitly() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "process", 1);
        tracker
            .try_insert_thread(process, thread2, existing_process, 2)
            .unwrap();

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

    /// Checks wrong-process reads in debug and release builds.
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

    /// Checks wrong-process retirement in debug and release builds.
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

    /// Checks that new process data is kept if thread setup fails.
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

    /// Checks that failed thread setup leaves saved data and thread lists unchanged.
    #[test]
    fn thread_error_preserves_retired_process_and_threads() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);
        let missing_thread = thread(0x4000);

        tracker.insert(process, thread1, "old", 1);
        tracker
            .try_insert_thread(process, thread2, existing_process, 2)
            .unwrap();
        tracker.retire_process(process).unwrap();

        let result = tracker.try_get_or_insert(
            process,
            missing_thread,
            || -> Result<&str, &str> { panic!("initialized a retired process") },
            || Err("thread error"),
        );

        assert_eq!(result.unwrap_err(), "thread error");
        assert_eq!(tracker.get(process, thread1), Some((&"old", &1)));
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert!(!tracker.contains_thread(missing_thread));
        assert_eq!(tracker.threads_of(process).count(), 2);
    }

    /// Checks that failed process setup leaves all saved data unchanged.
    #[test]
    fn process_error_leaves_tracker_unchanged() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);
        let missing_process = self::process(0x4000);

        tracker.insert(process, thread1, "old", 1);
        tracker
            .try_insert_thread(process, thread2, existing_process, 2)
            .unwrap();
        tracker.retire_process(process).unwrap();

        let result = tracker.try_get_or_insert(
            missing_process,
            thread1,
            || Err("process error"),
            || -> Result<u32, &str> {
                panic!("initialized thread after process initialization failed")
            },
        );

        assert_eq!(result.unwrap_err(), "process error");
        assert!(!tracker.contains_process(missing_process));
        assert_eq!(tracker.get_process(process), Some(&"old"));
        assert_eq!(tracker.get_thread(thread1), Some(&1));
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.threads_of(process).count(), 2);
    }

    /// Checks that new process data replaces retired data and its old threads.
    #[test]
    fn replaces_retired_generation_explicitly() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "old", 1);
        tracker
            .try_insert_thread(process, thread2, existing_process, 2)
            .unwrap();
        tracker.retire_process(process).unwrap();
        let (process_value, thread_value) = tracker.insert(process, thread1, "new", 3);

        assert_eq!((*process_value, *thread_value), ("new", 3));
        tracker.remove_retired_processes();
        assert_eq!(tracker.get(process, thread1), Some((&"new", &3)));
        assert!(!tracker.contains_thread(thread2));
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread1]);
    }

    /// Checks that failed process setup leaves a thread linked to its old process.
    #[test]
    fn thread_insertion_process_error_preserves_previous_owner() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);

        tracker.insert(process1, thread, "process", 1);
        let result = tracker.try_insert_thread(process2, thread, || Err("process error"), 2);

        assert_eq!(result.unwrap_err(), "process error");

        assert!(!tracker.contains_process(process2));
        assert_eq!(tracker.get(process1, thread), Some((&"process", &1)));
        assert_eq!(tracker.process_of(thread), Some(process1));
        assert_eq!(tracker.threads_of(process1).collect::<Vec<_>>(), [thread]);
    }

    /// Checks that failed thread setup keeps the old data and process link.
    #[test]
    fn thread_error_preserves_previous_owner() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread = thread(0x3000);

        tracker.insert(process1, thread, "first", 1);
        tracker.insert_process(process2, "second");
        tracker.retire_thread(process1, thread).unwrap();
        let result = tracker.try_get_or_insert(
            process2,
            thread,
            || -> Result<&str, &str> { panic!("initialized an existing process") },
            || Err("thread error"),
        );

        assert_eq!(result.unwrap_err(), "thread error");
        assert_eq!(tracker.get(process1, thread), Some((&"first", &1)));
        assert_eq!(tracker.get_process(process2), Some(&"second"));
        assert_eq!(tracker.process_of(thread), Some(process1));
        assert_eq!(tracker.threads_of(process1).collect::<Vec<_>>(), [thread]);
        assert_eq!(tracker.threads_of(process2).count(), 0);
        tracker.remove_retired_threads();
        assert!(!tracker.contains_thread(thread));
    }

    /// Checks that removing retired processes also removes all their threads.
    #[test]
    fn removes_retired_processes_and_owned_threads() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process1 = process(0x1000);
        let process2 = process(0x2000);
        let thread1 = thread(0x3000);
        let thread2 = thread(0x4000);
        let thread3 = thread(0x5000);

        tracker.insert(process1, thread1, "retired", 1);
        tracker
            .try_insert_thread(process1, thread2, existing_process, 2)
            .unwrap();
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

    /// Checks that removing retired threads keeps process data and other threads.
    #[test]
    fn removes_only_retired_threads() {
        let mut tracker = Tracker::<&str, u32>::default();
        let process = process(0x1000);
        let thread1 = thread(0x2000);
        let thread2 = thread(0x3000);

        tracker.insert(process, thread1, "process", 1);
        tracker
            .try_insert_thread(process, thread2, existing_process, 2)
            .unwrap();
        tracker.retire_process(process).unwrap();
        tracker.retire_thread(process, thread1).unwrap();

        tracker.remove_retired_threads();

        assert_eq!(tracker.get_process(process), Some(&"process"));
        assert!(tracker.get_thread(thread1).is_none());
        assert_eq!(tracker.get_thread(thread2), Some(&2));
        assert_eq!(tracker.threads_of(process).collect::<Vec<_>>(), [thread2]);
    }

    /// Checks that cleanup removes retired entries and keeps other process data.
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
        tracker
            .try_insert_thread(process2, thread3, existing_process, 3)
            .unwrap();
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
