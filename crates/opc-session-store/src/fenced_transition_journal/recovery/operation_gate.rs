use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::recovery_unavailable;
use crate::{scope_scheduler::ScopeWorkClass, StoreError};

pub(super) struct RecoveryOperationGate {
    heads: [Arc<Semaphore>; ScopeWorkClass::ALL.len()],
    state: Mutex<AdmissionState>,
    changed: Notify,
}

#[derive(Default)]
struct AdmissionState {
    running: bool,
    registrations: [usize; ScopeWorkClass::ALL.len()],
    #[cfg(any(test, feature = "test-control"))]
    admissions: [usize; ScopeWorkClass::ALL.len()],
}

// One FIFO head per existing work class keeps waiter storage in caller futures.
// Register before the class-head await, and retain a separate registration for
// each consecutive local journal sequence. Lower-ranked work cannot enter
// between its steps; higher-ranked work can proceed and same-class operations
// remain FIFO. Callers release sequence registrations before remote I/O or
// sleeps. No growing collection, background worker or timer belongs to this gate.
pub(super) struct RecoveryOperationRegistration {
    gate: Arc<RecoveryOperationGate>,
    class: ScopeWorkClass,
}

impl Drop for RecoveryOperationRegistration {
    fn drop(&mut self) {
        self.gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .registrations[self.class.index()] -= 1;
        self.gate.changed.notify_waiters();
    }
}

pub(super) struct RecoveryOperationPermit {
    gate: Arc<RecoveryOperationGate>,
    _class_head: OwnedSemaphorePermit,
}

impl Drop for RecoveryOperationPermit {
    fn drop(&mut self) {
        self.gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .running = false;
        self.gate.changed.notify_waiters();
    }
}

impl RecoveryOperationGate {
    pub(super) fn new() -> Self {
        Self {
            heads: std::array::from_fn(|_| Arc::new(Semaphore::new(1))),
            state: Mutex::new(AdmissionState::default()),
            changed: Notify::new(),
        }
    }

    #[cfg(any(test, feature = "test-control"))]
    pub(super) fn admissions(&self, class: ScopeWorkClass) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admissions[class.index()]
    }

    pub(super) fn register(
        self: &Arc<Self>,
        class: ScopeWorkClass,
    ) -> RecoveryOperationRegistration {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .registrations[class.index()] += 1;
        RecoveryOperationRegistration {
            gate: Arc::clone(self),
            class,
        }
    }

    pub(super) async fn acquire(
        self: &Arc<Self>,
        class: ScopeWorkClass,
    ) -> Result<RecoveryOperationPermit, StoreError> {
        let _registration = self.register(class);
        let class_head = Arc::clone(&self.heads[class.index()])
            .acquire_owned()
            .await
            .map_err(|_| recovery_unavailable())?;
        loop {
            // Register before checking the state: neither completion nor
            // cancellation may be lost between checking and awaiting.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let higher_waiting = ScopeWorkClass::ALL.iter().any(|other| {
                    other.priority_rank() < class.priority_rank()
                        && state.registrations[other.index()] != 0
                });
                if !state.running && !higher_waiting {
                    state.running = true;
                    #[cfg(any(test, feature = "test-control"))]
                    {
                        let admitted = &mut state.admissions[class.index()];
                        *admitted = admitted.saturating_add(1);
                    }
                    return Ok(RecoveryOperationPermit {
                        gate: Arc::clone(self),
                        _class_head: class_head,
                    });
                }
            }
            changed.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ScopeWorkClass::{Emergency as Urgent, Normal as Ordinary};

    #[tokio::test]
    async fn call_registration_excludes_lower_work_between_operations_until_drop() {
        let gate = Arc::new(RecoveryOperationGate::new());
        let call = gate.register(Urgent);
        let mut ordinary = Box::pin(gate.acquire(Ordinary));
        assert!(futures_util::poll!(&mut ordinary).is_pending());
        drop(gate.acquire(Urgent).await.expect("first call step"));
        assert!(futures_util::poll!(&mut ordinary).is_pending());
        drop(gate.acquire(Urgent).await.expect("second call step"));
        assert!(futures_util::poll!(&mut ordinary).is_pending());
        drop(call);
        drop(ordinary.await.expect("call cancellation releases priority"));
    }

    #[tokio::test]
    async fn call_priority_blocks_only_lower_ranks_and_cancellation_releases_them() {
        for class in ScopeWorkClass::ALL {
            let gate = Arc::new(RecoveryOperationGate::new());
            let call = gate.register(class);
            let mut lower = Vec::new();
            for other in ScopeWorkClass::ALL {
                if other.priority_rank() < class.priority_rank() {
                    drop(
                        gate.acquire(other)
                            .await
                            .expect("higher rank can preempt a call gap"),
                    );
                } else if other.priority_rank() > class.priority_rank() {
                    let mut operation = Box::pin(gate.acquire(other));
                    assert!(futures_util::poll!(&mut operation).is_pending());
                    lower.push(operation);
                }
            }
            drop(
                gate.acquire(class)
                    .await
                    .expect("the call can run its own step"),
            );
            for operation in &mut lower {
                assert!(futures_util::poll!(operation.as_mut()).is_pending());
            }
            drop(call);
            for operation in lower {
                drop(
                    operation
                        .await
                        .expect("cancelled call releases lower ranks"),
                );
            }
        }
    }

    #[tokio::test]
    async fn scope_rank_orders_classes_and_preserves_fifo_within_each_class() {
        let gate = Arc::new(RecoveryOperationGate::new());
        let running = gate.acquire(Ordinary).await.expect("running operation");
        let mut classes = ScopeWorkClass::ALL;
        classes.sort_by_key(|class| class.priority_rank());
        let mut waiting = Vec::new();
        // Lower-ranked work arrives first, with several callers in each class.
        for class in classes.into_iter().rev() {
            for ordinal in 0..3 {
                let mut operation = Box::pin(gate.acquire(class));
                assert!(futures_util::poll!(&mut operation).is_pending());
                waiting.push((class, ordinal, Some(operation)));
            }
        }
        drop(running);
        for class in classes {
            for ordinal in 0..3 {
                for (other_class, other_ordinal, operation) in &mut waiting {
                    if (*other_class, *other_ordinal) != (class, ordinal) {
                        if let Some(operation) = operation {
                            assert!(
                                futures_util::poll!(operation.as_mut()).is_pending(),
                                "only the oldest caller at the highest waiting rank may run"
                            );
                        }
                    }
                }
                let (_, _, operation) = waiting
                    .iter_mut()
                    .find(|(candidate, position, _)| (*candidate, *position) == (class, ordinal))
                    .expect("queued class member");
                let permit = operation
                    .take()
                    .expect("one admission per caller")
                    .await
                    .expect("next ranked operation");
                for (_, _, operation) in &mut waiting {
                    if let Some(operation) = operation {
                        assert!(futures_util::poll!(operation.as_mut()).is_pending());
                    }
                }
                drop(permit);
            }
        }
    }

    #[tokio::test]
    async fn urgent_operation_precedes_every_queued_ordinary_operation() {
        let gate = Arc::new(RecoveryOperationGate::new());
        let running = gate.acquire(Ordinary).await.expect("running operation");
        let mut first = Box::pin(gate.acquire(Ordinary));
        let mut second = Box::pin(gate.acquire(Ordinary));
        let mut third = Box::pin(gate.acquire(Ordinary));
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut second).is_pending());
        assert!(futures_util::poll!(&mut third).is_pending());
        let mut urgent = Box::pin(gate.acquire(Urgent));
        let mut later_urgent = Box::pin(gate.acquire(Urgent));
        assert!(futures_util::poll!(&mut urgent).is_pending());
        assert!(futures_util::poll!(&mut later_urgent).is_pending());
        drop(running);

        // Poll the earlier routine work first: priority must not depend on
        // executor polling order after the running operation releases.
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut second).is_pending());
        assert!(futures_util::poll!(&mut third).is_pending());
        assert!(futures_util::poll!(&mut later_urgent).is_pending());
        let urgent = urgent.await.expect("urgent runs next");
        assert!(futures_util::poll!(&mut first).is_pending());
        drop(urgent);
        assert!(futures_util::poll!(&mut first).is_pending());
        drop(later_urgent.await.expect("urgent FIFO"));
        drop(first.await.expect("ordinary first"));
        drop(second.await.expect("ordinary second"));
        drop(third.await.expect("ordinary third"));
    }

    #[tokio::test]
    async fn ordinary_default_preserves_fifo_order() {
        let gate = Arc::new(RecoveryOperationGate::new());
        let running = gate.acquire(Ordinary).await.expect("running operation");
        let mut first = Box::pin(gate.acquire(Ordinary));
        let mut second = Box::pin(gate.acquire(Ordinary));
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut second).is_pending());
        drop(running);
        assert!(futures_util::poll!(&mut second).is_pending());
        let first = first.await.expect("first ordinary");
        assert!(futures_util::poll!(&mut second).is_pending());
        drop(first);
        drop(second.await.expect("second ordinary"));
    }

    #[tokio::test]
    async fn cancelled_waiter_releases_its_place_in_both_classes() {
        for class in ScopeWorkClass::ALL {
            let gate = Arc::new(RecoveryOperationGate::new());
            let running = gate.acquire(Ordinary).await.expect("running operation");
            let mut cancelled_head = Box::pin(gate.acquire(class));
            let mut survivor = Box::pin(gate.acquire(class));
            let mut cancelled_tail = Box::pin(gate.acquire(class));
            assert!(futures_util::poll!(&mut cancelled_head).is_pending());
            assert!(futures_util::poll!(&mut survivor).is_pending());
            assert!(futures_util::poll!(&mut cancelled_tail).is_pending());
            drop(cancelled_head);
            drop(cancelled_tail);
            drop(running);
            let survivor = survivor.await.expect("remaining waiter");
            let mut ordinary = Box::pin(gate.acquire(Ordinary));
            assert!(futures_util::poll!(&mut ordinary).is_pending());
            drop(survivor);
            drop(ordinary.await.expect("no cancelled reservation remains"));
        }
    }

    #[tokio::test]
    async fn cancelling_all_urgent_waiters_restores_ordinary_progress() {
        let gate = Arc::new(RecoveryOperationGate::new());
        let running = gate.acquire(Ordinary).await.expect("running operation");
        let mut ordinary = Box::pin(gate.acquire(Ordinary));
        let mut urgent = Box::pin(gate.acquire(Urgent));
        assert!(futures_util::poll!(&mut ordinary).is_pending());
        assert!(futures_util::poll!(&mut urgent).is_pending());
        drop(urgent);
        drop(running);
        drop(
            ordinary
                .await
                .expect("cancelled urgent cannot block routine work"),
        );
    }
}
