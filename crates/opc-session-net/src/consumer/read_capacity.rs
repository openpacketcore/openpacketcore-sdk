//! Bound extended read occupancy within the existing shared request pool.

use super::{Arc, OwnedSemaphorePermit, Semaphore, SessionConsumerClientError};

pub(super) struct PersistentReadCapacity {
    lanes: Arc<Semaphore>,
    pending: Arc<Semaphore>,
}

pub(super) struct PersistentReadReservation {
    _lane: OwnedSemaphorePermit,
    _pending: OwnedSemaphorePermit,
}

impl PersistentReadCapacity {
    pub(super) fn new(request_connections: usize, pending_calls: usize) -> Self {
        // A one-lane configuration remains usable. Wider pools reserve one
        // existing lane and one total-admission slot for other operations.
        let reserved = usize::from(request_connections > 1);
        Self {
            lanes: Arc::new(Semaphore::new(request_connections.saturating_sub(reserved))),
            pending: Arc::new(Semaphore::new(
                request_connections
                    .saturating_add(pending_calls)
                    .saturating_sub(reserved),
            )),
        }
    }

    pub(super) fn try_pending(&self) -> Result<OwnedSemaphorePermit, SessionConsumerClientError> {
        Arc::clone(&self.pending)
            .try_acquire_owned()
            .map_err(|_| SessionConsumerClientError::Overloaded)
    }

    pub(super) async fn acquire(
        &self,
        pending: Option<OwnedSemaphorePermit>,
    ) -> Result<Option<Arc<PersistentReadReservation>>, SessionConsumerClientError> {
        let Some(pending) = pending else {
            return Ok(None);
        };
        let lane = Arc::clone(&self.lanes)
            .acquire_owned()
            .await
            .map_err(|_| SessionConsumerClientError::ShuttingDown)?;
        Ok(Some(Arc::new(PersistentReadReservation {
            _lane: lane,
            _pending: pending,
        })))
    }

    pub(super) fn close(&self) {
        self.pending.close();
        self.lanes.close();
    }
}
