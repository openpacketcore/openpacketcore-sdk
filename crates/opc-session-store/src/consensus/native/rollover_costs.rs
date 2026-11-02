//! Test-only structural accounting, scoped to one real rollover invocation.

use std::cell::Cell;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Costs {
    pub(crate) serializations: u64,
    pub(crate) read_calls: u64,
    pub(crate) read_blocks: u64,
    pub(crate) empty_reads: u64,
    pub(crate) output_blocks: u64,
    pub(crate) authenticated_output_blocks: u64,
    pub(crate) metadata: u64,
    pub(crate) cache_locks: u64,
    pub(crate) state_locks: u64,
    pub(crate) repairs: u64,
}

thread_local! {
    static CURRENT: Cell<Option<Costs>> = const { Cell::new(None) };
}

pub(crate) fn record(update: impl FnOnce(&mut Costs)) {
    CURRENT.with(|current| {
        if let Some(mut costs) = current.get() {
            update(&mut costs);
            current.set(Some(costs));
        }
    });
}

pub(crate) struct Scope(Option<Arc<Mutex<Vec<Costs>>>>);

impl Scope {
    pub(crate) fn begin(output: Option<Arc<Mutex<Vec<Costs>>>>) -> Self {
        if output.is_some() {
            CURRENT.with(|current| {
                assert!(current.replace(Some(Costs::default())).is_none());
            });
        }
        Self(output)
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if let Some(output) = &self.0 {
            let costs = CURRENT.with(|current| current.take()).unwrap();
            output.lock().unwrap().push(costs);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Adapter {
    BaseBlock,
    ExtentRead,
}
type AdapterHook = Arc<dyn Fn(Adapter) + Send + Sync>;
thread_local! {
    static ADAPTER: std::cell::RefCell<Option<AdapterHook>> = const { std::cell::RefCell::new(None) };
}
pub(crate) struct AdapterScope;
impl AdapterScope {
    pub(crate) fn begin(hook: AdapterHook) -> Self {
        ADAPTER.with(|current| assert!(current.replace(Some(hook)).is_none()));
        Self
    }
}
impl Drop for AdapterScope {
    fn drop(&mut self) {
        ADAPTER.with(|current| {
            current.take();
        });
    }
}
pub(crate) fn adapter(point: Adapter) {
    let hook = ADAPTER.with(|current| current.borrow().clone());
    if let Some(hook) = hook {
        hook(point);
    }
}
