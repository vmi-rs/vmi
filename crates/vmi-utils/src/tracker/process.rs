use std::collections::{HashMap, hash_map::Entry};

use foldhash::fast::RandomState;
use vmi_core::os::ProcessObject;

/// A tracked process entry.
struct ProcessEntry<P> {
    /// Value associated with the process.
    value: P,

    /// Marks the process as retired.
    retired: bool,
}

impl<P> ProcessEntry<P> {
    /// Creates an active process entry.
    fn new(value: P) -> Self {
        Self {
            value,
            retired: false,
        }
    }
}

/// A process map indexes values by their kernel object identities.
pub struct ProcessMap<P> {
    /// Each key is a kernel process object identity.
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
    /// Inserts a process value and reports whether it replaced a generation.
    pub fn insert(&mut self, process_object: ProcessObject, value: P) -> (&mut P, bool) {
        match self.entries.entry(process_object) {
            Entry::Occupied(mut entry) if entry.get().retired => {
                entry.insert(ProcessEntry::new(value));
                (&mut entry.into_mut().value, true)
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().value = value;
                (&mut entry.into_mut().value, false)
            }
            Entry::Vacant(entry) => (&mut entry.insert(ProcessEntry::new(value)).value, false),
        }
    }

    /// Returns a process, initializing or replacing its generation when needed.
    pub fn try_get_or_insert<E>(
        &mut self,
        process_object: ProcessObject,
        init: impl FnOnce() -> Result<P, E>,
    ) -> Result<(&mut P, bool), E> {
        match self.entries.entry(process_object) {
            Entry::Occupied(mut entry) if entry.get().retired => {
                entry.insert(ProcessEntry::new(init()?));
                Ok((&mut entry.into_mut().value, true))
            }
            Entry::Occupied(entry) => Ok((&mut entry.into_mut().value, false)),
            Entry::Vacant(entry) => {
                Ok((&mut entry.insert(ProcessEntry::new(init()?)).value, false))
            }
        }
    }

    /// Returns a process value.
    pub fn get(&self, process_object: ProcessObject) -> Option<&P> {
        self.entries
            .get(&process_object)
            .map(|process| &process.value)
    }

    /// Returns a mutable process value.
    pub fn get_mut(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        self.entries
            .get_mut(&process_object)
            .map(|process| &mut process.value)
    }

    /// Retires a process generation.
    pub fn retire(&mut self, process_object: ProcessObject) -> Option<&mut P> {
        let process = self.entries.get_mut(&process_object)?;
        process.retired = true;

        Some(&mut process.value)
    }

    /// Extracts retired process generations.
    pub fn extract_retired(&mut self) -> impl Iterator<Item = (ProcessObject, P)> {
        self.entries
            .extract_if(|_, process| process.retired)
            .map(|(process_object, process)| (process_object, process.value))
    }

    /// Removes and returns a process value.
    pub fn remove(&mut self, process_object: ProcessObject) -> Option<P> {
        self.entries
            .remove(&process_object)
            .map(|process| process.value)
    }
}
