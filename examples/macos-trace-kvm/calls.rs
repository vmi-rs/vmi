//! Matches observed call entries and returns within one process and thread.

use std::collections::HashMap;

use crate::{
    encoding::AbiType,
    ipc::{HookContext, PendingIpc, ProcessIdentity},
    taps::TapKey,
};

/// Bounds pending calls when recursion or missing returns prevent completion.
const FRAME_LIMIT: usize = 256;

/// Identifies a thread within its address-space lifetime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadKey {
    /// Translation root selected for the process.
    pub root: u64,

    /// Stable 64-bit kernel thread ID, independent of the executing vCPU.
    pub thread: u64,
}

/// Captures call inputs before the callee can modify their backing memory.
pub struct PendingCall {
    /// Entry instruction address retained for incomplete-call diagnostics.
    pub entry_pc: u64,

    /// Canonical caller continuation captured before the callee executes.
    pub return_pc: u64,

    /// Stack pointer that the callee must restore on an ordinary return.
    pub sp: u64,

    /// Entry time in seconds since tracing started.
    pub timestamp: f64,

    /// Formatted entry snapshot, absent for internal correlation-only hooks.
    pub body: Option<String>,

    /// Declared result ABI, absent when a signature is unavailable.
    pub result: Option<AbiType>,

    /// Entry `x8`, used for ABI results returned through caller-owned storage.
    pub result_buffer: u64,

    /// Post-call IPC observation associated with this same invocation.
    pub ipc: Option<PendingIpc>,

    /// Entry process and thread lifetime for post-call correlation.
    pub ipc_context: Option<HookContext>,

    /// Parent observed at cloneproc entry, resolved to a child only on success.
    pub child_of: Option<ProcessIdentity>,

    /// Temporary ownership of the exact caller continuation tap.
    pub tap: Option<TapKey>,

    /// Requests a fresh runtime snapshot after a mutator completes.
    pub invalidate: bool,
}

/// Stores independent pending stacks while allowing thread migration.
#[derive(Default)]
pub struct Calls {
    /// Empty stacks remain allocated so successive calls reuse their capacity.
    stacks: HashMap<ThreadKey, Vec<PendingCall>>,
}

impl Calls {
    /// Records an entry or merges a tap observing the same entry instruction.
    ///
    /// Returns a rejected frame or duplicate tap ownership for the caller to
    /// release.
    pub fn enter(
        &mut self,
        key: ThreadKey,
        mut call: PendingCall,
    ) -> (Option<PendingCall>, Option<TapKey>) {
        let stack = self.stacks.entry(key).or_default();
        if let Some(existing) = stack.last_mut()
            && existing.return_pc == call.return_pc
            && existing.sp == call.sp
            && !(existing.ipc.is_some() && call.ipc.is_some())
        {
            if existing.body.is_none() {
                existing.body = call.body.take();
                existing.result = call.result;
                existing.result_buffer = call.result_buffer;
            }
            if call.ipc.is_some() {
                existing.ipc = call.ipc.take();
                existing.ipc_context = call.ipc_context.take();
            }
            if call.child_of.is_some() {
                existing.child_of = call.child_of;
            }
            let redundant = if existing.tap.is_some() {
                call.tap
            }
            else {
                existing.tap = call.tap;
                None
            };
            existing.invalidate |= call.invalidate;
            return (None, redundant);
        }
        if stack.len() >= FRAME_LIMIT {
            return (Some(call), None);
        }
        stack.push(call);
        (None, None)
    }

    /// Reports whether a continuation already owns a formatted entry snapshot.
    pub fn has_body(&self, key: ThreadKey, return_pc: u64, sp: u64) -> bool {
        self.stacks
            .get(&key)
            .and_then(|stack| stack.last())
            .is_some_and(|call| call.return_pc == return_pc && call.sp == sp && call.body.is_some())
    }

    /// Removes the matching continuation without mistaking a callback for it.
    ///
    /// Returns bypassed frames so their taps and execution scopes are retired.
    pub fn returning(
        &mut self,
        key: ThreadKey,
        pc: u64,
        sp: u64,
    ) -> Option<(PendingCall, Vec<PendingCall>)> {
        let stack = self.stacks.get_mut(&key)?;
        let position = stack
            .iter()
            .rposition(|call| call.return_pc == pc && call.sp == sp)?;
        let abandoned = if stack.len() > position + 1 {
            stack.split_off(position + 1)
        }
        else {
            Vec::new()
        };
        stack.pop().map(|call| (call, abandoned))
    }

    /// Removes pending calls for a thread whose lifetime has ended.
    pub fn remove_thread(&mut self, key: ThreadKey) -> Vec<PendingCall> {
        self.stacks.remove(&key).unwrap_or_default()
    }

    /// Removes pending calls whose translation root belongs to an ended
    /// process.
    pub fn remove_process(&mut self, root: u64) -> Vec<PendingCall> {
        let mut removed = Vec::new();
        self.stacks.retain(|key, stack| {
            if key.root == root {
                removed.append(stack);
                false
            }
            else {
                true
            }
        });
        removed
    }

    /// Removes remaining calls when tracing stops before their returns.
    pub fn drain(&mut self) -> impl Iterator<Item = (ThreadKey, PendingCall)> + '_ {
        self.stacks
            .drain()
            .flat_map(|(key, stack)| stack.into_iter().map(move |call| (key, call)))
    }
}

#[cfg(test)]
mod tests {
    use super::{Calls, PendingCall, ThreadKey};

    /// Creates a frame with an observable entry snapshot and no IPC state.
    fn call(entry_pc: u64, return_pc: u64, sp: u64, body: &str) -> PendingCall {
        PendingCall {
            entry_pc,
            return_pc,
            sp,
            timestamp: 0.0,
            body: Some(body.to_string()),
            result: None,
            result_buffer: 0,
            ipc: None,
            ipc_context: None,
            child_of: None,
            tap: None,
            invalidate: false,
        }
    }

    /// Creates a thread identity without binding it to any vCPU.
    fn key(root: u64, thread: u64) -> ThreadKey {
        ThreadKey { root, thread }
    }

    /// Rejects callback entries and pairs concurrent callers independently.
    #[test]
    fn callbacks_and_concurrent_threads_do_not_consume_returns() {
        let mut calls = Calls::default();
        let first = key(1, 7);
        let second = key(1, 8);
        calls.enter(first, call(100, 200, 1000, "first"));
        calls.enter(second, call(100, 200, 1000, "second"));
        assert!(calls.returning(first, 250, 1000).is_none());
        assert!(calls.returning(first, 200, 900).is_none());
        assert_eq!(
            calls
                .returning(second, 200, 1000)
                .unwrap()
                .0
                .body
                .as_deref(),
            Some("second")
        );
        assert_eq!(
            calls.returning(first, 200, 1000).unwrap().0.body.as_deref(),
            Some("first")
        );
    }

    /// Keeps recursive calls at the same continuation distinct by their stack.
    #[test]
    fn recursion_matches_stack_and_reports_bypassed_frames() {
        let mut calls = Calls::default();
        let thread = key(1, 7);
        calls.enter(thread, call(100, 200, 1000, "outer"));
        calls.enter(thread, call(100, 200, 900, "inner"));
        let (completed, abandoned) = calls.returning(thread, 200, 1000).unwrap();
        assert_eq!(completed.body.as_deref(), Some("outer"));
        assert_eq!(abandoned.len(), 1);
        assert!(calls.returning(thread, 200, 900).is_none());
    }

    /// Clears ended address spaces without consuming another process's frame.
    #[test]
    fn process_lifetime_removal_is_isolated() {
        let mut calls = Calls::default();
        calls.enter(key(1, 7), call(100, 200, 1000, "ended"));
        calls.enter(key(2, 7), call(100, 200, 1000, "live"));
        assert_eq!(
            calls.remove_process(1).pop().unwrap().body.as_deref(),
            Some("ended")
        );
        assert!(calls.returning(key(1, 7), 200, 1000).is_none());
        assert_eq!(
            calls
                .returning(key(2, 7), 200, 1000)
                .unwrap()
                .0
                .body
                .as_deref(),
            Some("live")
        );
    }
}
