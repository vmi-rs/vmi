use std::collections::HashMap;

use vmi::os::{ProcessId, ProcessObject};

#[derive(Debug)]
pub struct Process {
    pub pid: ProcessId,
    pub ppid: ProcessId,
    pub name: String,
    pub terminated: bool,
}

#[derive(Debug, Default)]
pub struct ProcessTracker {
    processes: HashMap<ProcessObject, Process>,
}

impl ProcessTracker {
    pub fn insert(&mut self, object: ProcessObject, process: Process) -> Option<Process> {
        self.processes.insert(object, process)
    }

    pub fn remove(&mut self, object: ProcessObject) -> Option<Process> {
        self.processes.remove(&object)
    }

    pub fn mark_terminated(&mut self, object: ProcessObject) -> Option<&Process> {
        let process = self.get_mut(object)?;
        process.terminated = true;
        Some(process)
    }

    pub fn get(&self, object: ProcessObject) -> Option<&Process> {
        self.processes.get(&object)
    }

    pub fn get_mut(&mut self, object: ProcessObject) -> Option<&mut Process> {
        self.processes.get_mut(&object)
    }
}

#[cfg(test)]
mod tests {
    use vmi::Va;

    use super::*;

    fn process(pid: u32) -> Process {
        Process {
            pid: ProcessId(pid),
            ppid: ProcessId(42),
            name: format!("process-{pid}"),
            terminated: false,
        }
    }

    #[test]
    fn marking_process_terminated_retains_it() {
        let mut tracker = ProcessTracker::default();
        let object = ProcessObject(Va(0x1000));
        tracker.insert(object, process(100));

        let process = tracker.mark_terminated(object).expect("tracked process");

        assert!(process.terminated);
        assert!(tracker.get(object).expect("retained process").terminated);
    }

    #[test]
    fn removing_process_discards_it() {
        let mut tracker = ProcessTracker::default();
        let object = ProcessObject(Va(0x1000));
        tracker.insert(object, process(100));

        let process = tracker.remove(object).expect("tracked process");

        assert_eq!(process.pid, ProcessId(100));
        assert!(tracker.get(object).is_none());
    }
}
