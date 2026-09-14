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

