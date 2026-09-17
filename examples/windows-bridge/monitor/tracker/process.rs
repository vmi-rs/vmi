//! Stores tracked processes and their thread memberships.

use std::collections::{HashMap, HashSet, hash_map::Entry};

use vmi::os::{ProcessObject, ThreadObject};

/// Process value and its tracked thread identities.
pub struct ProcessEntry<P> {
    /// Associated process value.
    pub value: P,

    /// Tracked thread identities.
    pub threads: HashSet<ThreadObject>,

    /// Whether the process has terminated.
    pub terminated: bool,
}

impl<P> ProcessEntry<P> {
    /// Creates an active process entry without tracked threads.
    pub fn new(value: P) -> Self {
        Self {
            value,
            threads: HashSet::new(),
            terminated: false,
        }
    }

    /// Adds a thread identity to the process.
    pub fn attach_thread(&mut self, thread_object: ThreadObject) {
        self.threads.insert(thread_object);
    }

    /// Removes a thread identity from the process.
    pub fn detach_thread(&mut self, thread_object: ThreadObject) {
        self.threads.remove(&thread_object);
    }
}

/// Process values indexed by their kernel object identities.
pub struct ProcessMap<P> {
    entries: HashMap<ProcessObject, ProcessEntry<P>>,
}

impl<P> Default for ProcessMap<P> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<P> ProcessMap<P> {
    /// Inserts and returns a mutable process entry while retaining its tracked threads.
    pub fn insert(&mut self, process_object: ProcessObject, value: P) -> &mut ProcessEntry<P> {
        match self.entries.entry(process_object) {
            Entry::Occupied(entry) => {
                let entry = entry.into_mut();
                entry.value = value;
                entry
            }
            Entry::Vacant(entry) => entry.insert(ProcessEntry::new(value)),
        }
    }

    /// Returns a process entry, inserting one with `init` when absent.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        init: impl FnOnce() -> Result<P, E>,
    ) -> Result<&mut ProcessEntry<P>, E> {
        match self.entries.entry(process_object) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => Ok(entry.insert(ProcessEntry::new(init()?))),
        }
    }

    /// Returns a process entry.
    pub fn get(&self, process_object: ProcessObject) -> Option<&ProcessEntry<P>> {
        self.entries.get(&process_object)
    }

    /// Returns a mutable process entry.
    pub fn get_mut(&mut self, process_object: ProcessObject) -> Option<&mut ProcessEntry<P>> {
        self.entries.get_mut(&process_object)
    }

    /// Removes and returns a process entry.
    pub fn remove(&mut self, process_object: ProcessObject) -> Option<ProcessEntry<P>> {
        self.entries.remove(&process_object)
    }
}
