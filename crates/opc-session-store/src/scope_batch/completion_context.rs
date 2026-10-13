//! Opaque adapter facts and receipt retention; neither alone grants authority.
use std::{
    any::Any,
    fmt,
    sync::{Arc, Mutex},
};

/// Adapter-specific completion facts. Public ports may supply arbitrary facts;
/// a capability consumer must authenticate its concrete adapter's private type,
/// complete request/outcome binding and this completion's retention identity.
#[derive(Clone)]
pub struct ScopeBatchCompletionContext(Arc<dyn Any + Send + Sync>);
impl ScopeBatchCompletionContext {
    /// Retain adapter facts without adding a serialization or authority codec.
    pub fn new<T: Any + Send + Sync>(facts: T) -> Self {
        Self(Arc::new(facts))
    }
    /// Inspect only the concrete type owned by the authenticating adapter.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }
}

#[derive(Default)]
struct RetentionState {
    acknowledged: bool,
    readers: usize,
}

/// Process-local identity of one coordinator completion's retained receipt.
/// Only the coordinator constructs it. Copies cannot reopen an acknowledged
/// receipt, even when a caller retains the completion after lane reuse.
#[derive(Clone)]
pub struct ScopeBatchCompletionRetention(Arc<Mutex<RetentionState>>);
impl ScopeBatchCompletionRetention {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(RetentionState::default())))
    }
    /// Whether both values name the same supervised completion retention.
    pub fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Hold acknowledgement until this readback finishes. This does not prove
    /// application; the concrete transport must verify provenance separately.
    /// An early-acknowledged completion cannot acquire a new guard.
    pub fn acquire(&self) -> Option<ScopeBatchCompletionReadGuard> {
        let mut state = self.0.lock().ok()?;
        if state.acknowledged {
            return None;
        }
        state.readers = state.readers.checked_add(1)?;
        Some(ScopeBatchCompletionReadGuard(self.clone()))
    }
    pub(super) fn acknowledge(&self) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if state.acknowledged || state.readers != 0 {
            return false;
        }
        state.acknowledged = true;
        true
    }
}

/// Affine readback pin. Dropping every pin allows exact coordinator ack; the
/// resulting effect capability must not retain a pin for its later rechecks.
pub struct ScopeBatchCompletionReadGuard(ScopeBatchCompletionRetention);
impl Drop for ScopeBatchCompletionReadGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0 .0.lock() {
            state.readers = state.readers.saturating_sub(1);
        }
    }
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => {$(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+};
}
redacted!(
    ScopeBatchCompletionContext,
    ScopeBatchCompletionRetention,
    ScopeBatchCompletionReadGuard
);
