//! Stores tracked threads and their owning process identities.

use std::collections::{HashMap, hash_map::Entry};

use vmi::os::{ProcessObject, ThreadObject};

/// Thread value and its owning process identity.
pub struct ThreadEntry<T> {
    /// Associated thread value.
    pub value: T,

    /// Owning process identity.
    pub process: ProcessObject,

    /// Whether the thread has terminated.
    pub terminated: bool,
}

impl<T> ThreadEntry<T> {
    /// Creates an active thread entry owned by `process`.
    pub fn new(value: T, process: ProcessObject) -> Self {
        Self {
            value,
            process,
            terminated: false,
        }
    }
}

/// Thread values indexed by their kernel object identities.
pub struct ThreadMap<T> {
    entries: HashMap<ThreadObject, ThreadEntry<T>>,
}

impl<T> Default for ThreadMap<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<T> ThreadMap<T> {
    /// Inserts a thread and returns its entry and previous process identity.
    pub fn insert(
        &mut self,
        thread_object: ThreadObject,
        process_object: ProcessObject,
        value: T,
    ) -> (&mut ThreadEntry<T>, Option<ProcessObject>) {
        match self.entries.entry(thread_object) {
            Entry::Occupied(entry) => {
                let previous_process_object = entry.get().process;
                let entry = entry.into_mut();
                *entry = ThreadEntry::new(value, process_object);
                (entry, Some(previous_process_object))
            }
            Entry::Vacant(entry) => {
                let entry = entry.insert(ThreadEntry::new(value, process_object));
                (entry, None)
            }
        }
    }

    /// Returns a thread entry, inserting one with `init` when absent.
    pub fn try_get_or_insert<E>(
        &mut self,
        thread_object: ThreadObject,
        process_object: ProcessObject,
        init: impl FnOnce() -> Result<T, E>,
    ) -> Result<&mut ThreadEntry<T>, E> {
        match self.entries.entry(thread_object) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => Ok(entry.insert(ThreadEntry::new(init()?, process_object))),
        }
    }

    /// Returns a thread entry.
    pub fn get(&self, thread_object: ThreadObject) -> Option<&ThreadEntry<T>> {
        self.entries.get(&thread_object)
    }

    /// Returns a mutable thread entry.
    pub fn get_mut(&mut self, thread_object: ThreadObject) -> Option<&mut ThreadEntry<T>> {
        self.entries.get_mut(&thread_object)
    }

    /// Removes and returns a thread entry.
    pub fn remove(&mut self, thread_object: ThreadObject) -> Option<ThreadEntry<T>> {
        self.entries.remove(&thread_object)
    }
}
