//! Process and thread tracking.

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
    /// Stores process values and their lifecycle state.
    processes: ProcessMap<P>,

    /// Stores thread values and their process membership.
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

    /// Checks whether a tracked process owns a tracked thread.
    ///
    /// Returns `false` if either identity is absent or the thread belongs to
    /// another process. Retired processes and threads remain contained until
    /// replacement or removal.
    pub fn contains(&self, process_object: ProcessObject, thread_object: ThreadObject) -> bool {
        self.contains_process(process_object)
            && self.process_of(thread_object) == Some(process_object)
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

    /// Checks whether a process identity is tracked, including one marked retired.
    pub fn contains_process(&self, process_object: ProcessObject) -> bool {
        self.processes.get(process_object).is_some()
    }

    /// Retires a process generation and returns its value.
    ///
    /// The process value and all thread relationships remain visible. The next
    /// successful process insertion starts a new generation and evicts the
    /// previous generation's threads. This method does not retire those threads.
    pub fn retire_process(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.processes.retire(process_object)
    }

    /// Removes a process value and every thread owned by that process.
    pub fn remove_process(&mut self, process_object: ProcessObject) -> Option<P> {
        let process = self.processes.remove(process_object)?;
        self.threads.remove_process(process_object);

        Some(process)
    }

    /// Returns a thread value, including one marked retired.
    pub fn get_thread(&self, thread_object: ThreadObject) -> Option<&T> {
        self.threads.get(thread_object)
    }

    /// Returns a mutable thread value, including one marked retired.
    pub fn get_thread_mut(&mut self, thread_object: ThreadObject) -> Option<&mut T> {
        self.threads.get_mut(thread_object)
    }

    /// Checks whether a thread identity is tracked, including one marked retired.
    pub fn contains_thread(&self, thread_object: ThreadObject) -> bool {
        self.threads.get(thread_object).is_some()
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

    /// Removes a thread value and its membership in the owning process.
    pub fn remove_thread(&mut self, thread_object: ThreadObject) -> Option<T> {
        self.threads.remove(thread_object)
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

