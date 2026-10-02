use std::collections::{HashMap, HashSet, hash_map::Entry};

use foldhash::fast::RandomState;
use vmi_core::os::{ProcessObject, ThreadObject};

/// A tracked thread entry.
struct ThreadEntry<T> {
    /// Value associated with the thread.
    value: T,

    /// Owning process object.
    process: ProcessObject,

    /// Marks the thread as retired.
    retired: bool,
}

impl<T> ThreadEntry<T> {
    /// Creates an active thread entry owned by `process`.
    fn new(value: T, process: ProcessObject) -> Self {
        Self {
            value,
            process,
            retired: false,
        }
    }
}

/// A membership index maps each process to its threads.
#[derive(Default)]
struct ProcessThreads {
    /// Each set contains the threads owned by its process key.
    entries: HashMap<ProcessObject, HashSet<ThreadObject, RandomState>, RandomState>,
}

impl ProcessThreads {
    /// Adds a thread to a process.
    fn attach(&mut self, process_object: ProcessObject, thread_object: ThreadObject) {
        self.entries
            .entry(process_object)
            .or_default()
            .insert(thread_object);
    }

    /// Removes a thread from a process.
    fn detach(&mut self, process_object: ProcessObject, thread_object: ThreadObject) {
        let mut entry = match self.entries.entry(process_object) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => {
                debug_assert!(false, "tracked thread must reference a tracked process");
                return;
            }
        };

        let removed = entry.get_mut().remove(&thread_object);
        debug_assert!(removed, "tracked process must reference its thread");

        if entry.get().is_empty() {
            entry.remove();
        }
    }

    /// Removes and returns all threads belonging to a process.
    fn remove(
        &mut self,
        process_object: ProcessObject,
    ) -> Option<HashSet<ThreadObject, RandomState>> {
        self.entries.remove(&process_object)
    }

    /// Checks a process-to-thread relationship.
    fn contains(&self, process_object: ProcessObject, thread_object: ThreadObject) -> bool {
        self.entries
            .get(&process_object)
            .is_some_and(|threads| threads.contains(&thread_object))
    }

    /// Iterates over the threads belonging to a process.
    fn get(&self, process_object: ProcessObject) -> impl Iterator<Item = ThreadObject> {
        self.entries
            .get(&process_object)
            .into_iter()
            .flat_map(|threads| threads.iter().copied())
    }
}

/// A thread map stores values and their process memberships.
pub struct ThreadMap<T> {
    /// Thread entries indexed by thread object.
    entries: HashMap<ThreadObject, ThreadEntry<T>, RandomState>,

    /// This index supports lookups and removals by process.
    process_threads: ProcessThreads,
}

impl<T> Default for ThreadMap<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::with_hasher(RandomState::default()),
            process_threads: ProcessThreads::default(),
        }
    }
}

impl<T> ThreadMap<T> {
    /// Inserts a thread value and updates its process membership.
    pub fn insert(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        value: T,
    ) -> &mut T {
        let (thread, previous_process_object) = match self.entries.entry(thread_object) {
            Entry::Occupied(mut entry) => {
                let previous_process_object = entry.get().process;
                entry.insert(ThreadEntry::new(value, process_object));
                (entry.into_mut(), Some(previous_process_object))
            }
            Entry::Vacant(entry) => (entry.insert(ThreadEntry::new(value, process_object)), None),
        };

        if let Some(previous_process_object) = previous_process_object
            && previous_process_object != process_object
        {
            self.process_threads
                .detach(previous_process_object, thread_object);
        }

        self.process_threads.attach(process_object, thread_object);

        &mut thread.value
    }

    /// Returns a thread, initializing or replacing it when needed.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        init: impl FnOnce() -> Result<T, E>,
    ) -> Result<&mut T, E> {
        let (thread, previous_process_object, attach_thread) =
            match self.entries.entry(thread_object) {
                Entry::Occupied(mut entry)
                    if entry.get().retired || entry.get().process != process_object =>
                {
                    let previous_process_object = entry.get().process;
                    entry.insert(ThreadEntry::new(init()?, process_object));
                    (
                        entry.into_mut(),
                        (previous_process_object != process_object)
                            .then_some(previous_process_object),
                        previous_process_object != process_object,
                    )
                }
                Entry::Occupied(entry) => (entry.into_mut(), None, false),
                Entry::Vacant(entry) => (
                    entry.insert(ThreadEntry::new(init()?, process_object)),
                    None,
                    true,
                ),
            };

        if let Some(previous_process_object) = previous_process_object {
            self.process_threads
                .detach(previous_process_object, thread_object);
        }

        if attach_thread {
            self.process_threads.attach(process_object, thread_object);
        }
        else {
            debug_assert!(
                self.process_threads.contains(process_object, thread_object),
                "active thread must belong to its tracked process"
            );
        }

        Ok(&mut thread.value)
    }

    /// Removes all threads belonging to a process.
    pub fn remove_process(&mut self, process_object: ProcessObject) {
        let thread_objects = match self.process_threads.remove(process_object) {
            Some(thread_objects) => thread_objects,
            None => return,
        };

        tracing::debug!(
            %process_object,
            stale_threads = thread_objects.len(),
            "evicting process threads"
        );

        for thread_object in thread_objects {
            match self.entries.entry(thread_object) {
                Entry::Occupied(entry) if entry.get().process == process_object => {
                    entry.remove();
                }
                Entry::Occupied(_) => {
                    debug_assert!(false, "tracked thread belongs to an unexpected process");
                }
                Entry::Vacant(_) => {
                    debug_assert!(false, "tracked process thread must have an entry");
                }
            }
        }
    }

    /// Retires a thread for the expected process.
    pub fn retire(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<&mut T> {
        let thread = self.entries.get_mut(&thread_object)?;

        debug_assert_eq!(
            process_object, thread.process,
            "tracked thread belongs to an unexpected process"
        );

        if thread.process != process_object {
            return None;
        }

        thread.retired = true;

        Some(&mut thread.value)
    }

    /// Returns a thread value.
    pub fn get(&self, thread_object: ThreadObject) -> Option<&T> {
        self.entries.get(&thread_object).map(|thread| &thread.value)
    }

    /// Returns a mutable thread value.
    pub fn get_mut(&mut self, thread_object: ThreadObject) -> Option<&mut T> {
        self.entries
            .get_mut(&thread_object)
            .map(|thread| &mut thread.value)
    }

    /// Returns a thread value for the expected process.
    pub fn get_for_process(
        &self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<&T> {
        let thread = self.entries.get(&thread_object)?;

        debug_assert_eq!(
            process_object, thread.process,
            "tracked thread belongs to an unexpected process"
        );

        if thread.process != process_object {
            return None;
        }

        Some(&thread.value)
    }

    /// Returns a mutable thread value for the expected process.
    pub fn get_for_process_mut(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
    ) -> Option<&mut T> {
        let thread = self.entries.get_mut(&thread_object)?;

        debug_assert_eq!(
            process_object, thread.process,
            "tracked thread belongs to an unexpected process"
        );

        if thread.process != process_object {
            return None;
        }

        Some(&mut thread.value)
    }

    /// Returns the process that owns a thread.
    pub fn process_of(&self, thread_object: ThreadObject) -> Option<ProcessObject> {
        self.entries
            .get(&thread_object)
            .map(|thread| thread.process)
    }

    /// Iterates over the threads belonging to a process.
    pub fn threads_of(&self, process_object: ProcessObject) -> impl Iterator<Item = ThreadObject> {
        self.process_threads.get(process_object)
    }

    /// Removes retired threads.
    pub fn remove_retired(&mut self) {
        for (thread_object, thread) in self.entries.extract_if(|_, thread| thread.retired) {
            self.process_threads.detach(thread.process, thread_object);
        }
    }

    /// Removes a thread and its process membership.
    pub fn remove(&mut self, thread_object: ThreadObject) -> Option<T> {
        let thread = self.entries.remove(&thread_object)?;
        self.process_threads.detach(thread.process, thread_object);

        Some(thread.value)
    }
}
