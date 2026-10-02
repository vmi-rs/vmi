use std::collections::{HashMap, HashSet, hash_map::Entry};

use foldhash::fast::RandomState;
use vmi_core::os::{ProcessObject, ThreadObject};

/// Saved data and a process object for one thread.
struct ThreadEntry<T> {
    /// Data saved for this thread.
    value: T,

    /// Owning process object.
    process: ProcessObject,

    /// Marks this entry for later removal.
    retired: bool,
}

impl<T> ThreadEntry<T> {
    /// Creates a thread entry owned by `process`.
    fn new(value: T, process: ProcessObject) -> Self {
        Self {
            value,
            process,
            retired: false,
        }
    }
}

/// Stores a set of thread objects for each process.
#[derive(Default)]
struct ProcessThreads {
    /// Maps each process object to its thread objects.
    entries: HashMap<ProcessObject, HashSet<ThreadObject, RandomState>, RandomState>,
}

impl ProcessThreads {
    /// Adds a thread object to a process's set.
    fn attach(&mut self, process_object: ProcessObject, thread_object: ThreadObject) {
        self.entries
            .entry(process_object)
            .or_default()
            .insert(thread_object);
    }

    /// Removes a thread object from a process's set.
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

    /// Removes a process's set and returns its thread objects.
    fn remove(
        &mut self,
        process_object: ProcessObject,
    ) -> Option<HashSet<ThreadObject, RandomState>> {
        self.entries.remove(&process_object)
    }

    /// Checks whether a process's set includes a thread.
    fn contains(&self, process_object: ProcessObject, thread_object: ThreadObject) -> bool {
        self.entries
            .get(&process_object)
            .is_some_and(|threads| threads.contains(&thread_object))
    }

    /// Lists the thread objects saved for a process.
    fn get(&self, process_object: ProcessObject) -> impl Iterator<Item = ThreadObject> {
        self.entries
            .get(&process_object)
            .into_iter()
            .flat_map(|threads| threads.iter().copied())
    }
}

/// Stores thread data and the process each thread belongs to.
pub struct ThreadMap<T> {
    /// Thread entries indexed by thread object.
    entries: HashMap<ThreadObject, ThreadEntry<T>, RandomState>,

    /// Stores each process's set of thread objects.
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
    /// Inserts thread data and links it to the given process.
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

    /// Returns saved thread data, calling `init` if it is missing or belongs to
    /// another process.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        thread_object: ThreadObject,
        init: impl FnOnce() -> Result<T, E>,
    ) -> Result<&mut T, E> {
        let (thread, previous_process_object, attach_thread) =
            match self.entries.entry(thread_object) {
                Entry::Occupied(mut entry) if entry.get().process != process_object => {
                    let previous_process_object = entry.get().process;
                    entry.insert(ThreadEntry::new(init()?, process_object));
                    (entry.into_mut(), Some(previous_process_object), true)
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
                "tracked thread must belong to its tracked process"
            );
        }

        Ok(&mut thread.value)
    }

    /// Removes all thread entries linked to a process.
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

    /// Marks a thread for later removal if it belongs to the given process.
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

    /// Returns saved thread data.
    pub fn get(&self, thread_object: ThreadObject) -> Option<&T> {
        self.entries.get(&thread_object).map(|thread| &thread.value)
    }

    /// Returns saved thread data that can be changed.
    pub fn get_mut(&mut self, thread_object: ThreadObject) -> Option<&mut T> {
        self.entries
            .get_mut(&thread_object)
            .map(|thread| &mut thread.value)
    }

    /// Returns saved thread data if the thread belongs to this process.
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

    /// Returns thread data that can be changed if the thread belongs to this
    /// process.
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

    /// Returns the process stored for a thread.
    pub fn process_of(&self, thread_object: ThreadObject) -> Option<ProcessObject> {
        self.entries
            .get(&thread_object)
            .map(|thread| thread.process)
    }

    /// Lists the thread objects saved for a process.
    pub fn threads_of(&self, process_object: ProcessObject) -> impl Iterator<Item = ThreadObject> {
        self.process_threads.get(process_object)
    }

    /// Removes retired thread entries and updates their processes' thread sets.
    pub fn remove_retired(&mut self) {
        for (thread_object, thread) in self.entries.extract_if(|_, thread| thread.retired) {
            self.process_threads.detach(thread.process, thread_object);
        }
    }

    /// Removes saved thread data and its address from the process's thread set.
    pub fn remove(&mut self, thread_object: ThreadObject) -> Option<T> {
        let thread = self.entries.remove(&thread_object)?;
        self.process_threads.detach(thread.process, thread_object);

        Some(thread.value)
    }
}
