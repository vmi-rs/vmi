use std::collections::{HashMap, hash_map::Entry};

use foldhash::fast::RandomState;
use vmi_core::os::ProcessObject;

/// Saved data and a retired flag for one process.
struct ProcessEntry<P> {
    /// Data saved for this process.
    value: P,

    /// Marks this entry for later removal.
    retired: bool,
}

impl<P> ProcessEntry<P> {
    /// Creates a process entry.
    fn new(value: P) -> Self {
        Self {
            value,
            retired: false,
        }
    }
}

/// Stores process data indexed by process object.
pub struct ProcessMap<P> {
    /// Maps each process object to its saved entry.
    entries: HashMap<ProcessObject, ProcessEntry<P>, RandomState>,
}

impl<P> Default for ProcessMap<P> {
    fn default() -> Self {
        Self {
            entries: HashMap::with_hasher(RandomState::default()),
        }
    }
}

impl<P> ProcessMap<P> {
    /// Inserts a new value and clears the retired flag.
    pub fn insert(&mut self, process_object: ProcessObject, value: P) -> &mut P {
        match self.entries.entry(process_object) {
            Entry::Occupied(mut entry) => {
                entry.insert(ProcessEntry::new(value));
                &mut entry.into_mut().value
            }
            Entry::Vacant(entry) => &mut entry.insert(ProcessEntry::new(value)).value,
        }
    }

    /// Returns saved process data, or calls `init` if no entry exists.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        init: impl FnOnce() -> Result<P, E>,
    ) -> Result<&mut P, E> {
        match self.entries.entry(process_object) {
            Entry::Occupied(entry) => Ok(&mut entry.into_mut().value),
            Entry::Vacant(entry) => Ok(&mut entry.insert(ProcessEntry::new(init()?)).value),
        }
    }

    /// Returns saved process data.
    pub fn get(&self, process_object: ProcessObject) -> Option<&P> {
        self.entries
            .get(&process_object)
            .map(|process| &process.value)
    }

    /// Returns saved process data that can be changed.
    pub fn get_mut(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.entries
            .get_mut(&process_object)
            .map(|process| &mut process.value)
    }

    /// Marks an entry for later removal without removing its value.
    pub fn retire(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        let process = self.entries.get_mut(&process_object)?;
        process.retired = true;

        Some(&mut process.value)
    }

    /// Removes and returns retired entries during iteration.
    pub fn extract_retired(&mut self) -> impl Iterator<Item = (ProcessObject, P)> {
        self.entries
            .extract_if(|_, process| process.retired)
            .map(|(process_object, process)| (process_object, process.value))
    }

    /// Removes and returns saved process data.
    pub fn remove(&mut self, process_object: ProcessObject) -> Option<P> {
        self.entries
            .remove(&process_object)
            .map(|process| process.value)
    }
}
