//! Explicitly volatile, process-local fenced transitions for call-development labs.
//!
//! One mutex is the linearization point for the lease, record, and receipt.
//! No file, SQLite database, consensus peer, or network client is constructed.
//! Dropping the backend loses every record and fence; this is not HA storage.

use super::*;
use crate::{
    fenced_transition::{PreparedFencedTransitionProtection, FENCED_TRANSITION_OUTCOME_RETENTION},
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionOutcome, FencedTransitionRequest, FencedTransitionStatus,
    PreparedFencedTransition,
};

mod restore;
#[cfg(test)]
mod tests;

pub(super) struct RestoreAuthority {
    epoch: [u8; 16],
    key: opc_key::Zeroizing<[u8; 32]>,
}

#[derive(Clone)]
pub(super) struct Receipt {
    request: FencedTransitionRequest,
    result: Result<FencedTransitionOutcome, StoreError>,
    retained_until: Timestamp,
}

impl Receipt {
    fn status(&self, request: &FencedTransitionRequest, now: Timestamp) -> FencedTransitionStatus {
        if &self.request != request {
            FencedTransitionStatus::RequestConflict
        } else if self.retained_until <= now {
            FencedTransitionStatus::Expired
        } else {
            FencedTransitionStatus::Recorded(Box::new(self.result.clone()))
        }
    }
}

impl FakeSessionBackend {
    /// Construct volatile lab storage with process-local atomic transitions.
    ///
    /// Records, leases, preparation tokens and receipts never survive restart.
    /// The returned allocation must be shared by all consumers in this process.
    /// It cannot coordinate other workers or grant production HA authority.
    /// Opaque restore cursors use the SDK's authenticated seek format, scoped
    /// to this volatile allocation and invalidated by record mutation/expiry.
    pub fn in_memory_lab() -> Self {
        let mut backend = Self::with_limits(FakeBackendLimits {
            max_tracked_keys: 100_000,
            max_replication_entries: 65_536,
        });
        backend.lab_identity = Some(rand::random());
        backend.lab_restore_authority = Some(Arc::new(RestoreAuthority::new()));
        backend
    }

    pub(super) fn require_lab_identity(&self) -> Result<[u8; 32], StoreError> {
        self.lab_identity.ok_or_else(|| {
            StoreError::CapabilityNotSupported("lab_memory_fenced_transition".into())
        })
    }

    pub(super) fn lab_request(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionRequest, StoreError> {
        prepared
            .without_outer_protection(PreparedFencedTransitionProtection::LabMemoryPhysicalV1 {
                instance_commitment: self.require_lab_identity()?,
            })?
            .request_for_unprotected_backend()
    }

    pub(super) async fn lab_status(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionStatus, StoreError> {
        let request = self.lab_request(prepared)?;
        let state = self.inner.lock().await;
        Ok(match state.lab_transitions.get(&request.request_id()) {
            Some(receipt) => receipt.status(&request, self.clock.now_utc()),
            None if state.lab_transitions.len() >= self.limits.max_replication_entries => {
                FencedTransitionStatus::HistoryFull
            }
            None => FencedTransitionStatus::NotFound,
        })
    }

    pub(super) async fn lab_execute(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        let request = self.lab_request(prepared)?;
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        if let Some(receipt) = state.lab_transitions.get(&request.request_id()) {
            return match receipt.status(&request, now) {
                FencedTransitionStatus::Recorded(result) => *result,
                FencedTransitionStatus::RequestConflict => {
                    Err(StoreError::FencedTransitionRequestConflict)
                }
                _ => Err(StoreError::FencedTransitionRequestExpired),
            };
        }
        if state.lab_transitions.len() >= self.limits.max_replication_entries {
            return Err(StoreError::FencedTransitionHistoryFull);
        }
        let retained_until = checked_session_deadline(now, FENCED_TRANSITION_OUTCOME_RETENTION)
            .map_err(|_| StoreError::FencedTransitionRetentionExhausted)?;
        // Stage both lease and record. A failed record condition cannot leak a
        // newly minted fence or a renewed lease into the authoritative map.
        let key = Self::map_key(request.lease().key());
        Self::ensure_key_capacity(&state, &key, self.limits.max_tracked_keys)?;
        let mut staged = FakeBackendState::empty();
        staged.next_fence = state.next_fence;
        staged.next_credential_id = state.next_credential_id;
        if let Some(record) = state.records.get(&key) {
            staged.records.insert(key.clone(), record.clone());
        }
        if let Some(lease) = state.leases.get(&key) {
            staged.leases.insert(key.clone(), lease.clone());
        }
        if let Some(fence) = state.key_fences.get(&key) {
            staged.key_fences.insert(key.clone(), *fence);
        }
        let result = self.lab_apply(&mut staged, &request, now);
        if let Ok((outcome, replication)) = &result {
            let sequence = self.next_direct_replication_sequence(&state)?;
            state.invalidate_lab_restore_snapshot();
            match staged.records.remove(&key) {
                Some(record) => {
                    state.records.insert(key.clone(), record);
                }
                None => {
                    state.records.remove(&key);
                }
            }
            match staged.leases.remove(&key) {
                Some(lease) => {
                    state.leases.insert(key.clone(), lease);
                }
                None => {
                    state.leases.remove(&key);
                }
            }
            if let Some(fence) = staged.key_fences.remove(&key) {
                state.key_fences.insert(key, fence);
            }
            state.next_fence = staged.next_fence;
            state.next_credential_id = staged.next_credential_id;
            self.append_direct_replication_entry(&mut state, sequence, replication.clone(), now);
            state.lab_transitions.insert(
                request.request_id(),
                Receipt {
                    request,
                    result: Ok(outcome.clone()),
                    retained_until,
                },
            );
            return Ok(outcome.clone());
        }
        let result = result.map(|(outcome, _)| outcome);
        state.lab_transitions.insert(
            request.request_id(),
            Receipt {
                request,
                result: result.clone(),
                retained_until,
            },
        );
        result
    }

    fn lab_apply(
        &self,
        state: &mut FakeBackendState,
        request: &FencedTransitionRequest,
        now: Timestamp,
    ) -> Result<(FencedTransitionOutcome, ReplicationOp), StoreError> {
        request.validate_at(now)?;
        let key = request.lease().key();
        let mk = Self::map_key(key);
        Self::ensure_key_capacity(state, &mk, self.limits.max_tracked_keys)?;
        let expires_at = checked_session_deadline(now, request.lease().ttl())?;
        let (lease, lease_op) = match request.lease() {
            FencedTransitionLease::Acquire {
                owner,
                expected_fence,
                ttl,
                ..
            } => {
                if Self::current_fence(state, &mk) != *expected_fence {
                    return Err(StoreError::StaleFence);
                }
                if state.leases.get(&mk).is_some_and(|entry| {
                    entry.active && entry.expires_at > now && entry.owner != *owner
                }) {
                    return Err(StoreError::LeaseHeld);
                }
                let fence = request.lease().committed_fence()?;
                let credential_id = state.next_credential_id;
                state.next_credential_id = credential_id
                    .checked_add(1)
                    .ok_or(StoreError::FencedTransitionStorageExhausted)?;
                state.next_fence = state.next_fence.max(fence.get().saturating_add(1));
                state.key_fences.insert(mk.clone(), fence);
                state.leases.insert(
                    mk.clone(),
                    LeaseEntry {
                        active: true,
                        credential_id,
                        owner: owner.clone(),
                        fence,
                        acquired_at: now,
                        expires_at,
                        guard_expires_at: expires_at,
                    },
                );
                (
                    LeaseGuard::new(
                        key.clone(),
                        owner.clone(),
                        fence,
                        now,
                        expires_at,
                        credential_id,
                    ),
                    ReplicationOp::AcquireLease {
                        key: key.clone(),
                        owner: owner.clone(),
                        fence,
                        credential_id,
                        ttl: *ttl,
                        expires_at,
                    },
                )
            }
            FencedTransitionLease::Renew { lease, ttl } => {
                Self::validate_fenced_mutation(state, lease, now)?;
                let entry = state.leases.get_mut(&mk).ok_or(StoreError::StaleFence)?;
                entry.expires_at = expires_at;
                entry.guard_expires_at = expires_at;
                (
                    LeaseGuard::new(
                        key.clone(),
                        lease.owner().clone(),
                        lease.fence(),
                        lease.acquired_at(),
                        expires_at,
                        lease.credential_id(),
                    ),
                    ReplicationOp::RenewLease {
                        key: key.clone(),
                        owner: lease.owner().clone(),
                        fence: lease.fence(),
                        credential_id: lease.credential_id(),
                        ttl: *ttl,
                        expires_at,
                    },
                )
            }
        };
        let (generation, mutation, mutation_op) = match request.mutation() {
            FencedTransitionMutation::Create { record }
            | FencedTransitionMutation::Update { record, .. } => {
                let expected_generation = match request.mutation() {
                    FencedTransitionMutation::Update {
                        expected_generation,
                        ..
                    } => Some(*expected_generation),
                    _ => None,
                };
                let cas = CompareAndSet {
                    key: key.clone(),
                    lease: lease.clone(),
                    expected_generation,
                    new_record: record.as_ref().clone(),
                };
                if self.compare_and_set_with_state(state, cas, now)? != CompareAndSetResult::Success
                {
                    return Err(StoreError::CasConflict);
                }
                (
                    record.generation,
                    if expected_generation.is_some() {
                        FencedTransitionMutationResult::Updated
                    } else {
                        FencedTransitionMutationResult::Created
                    },
                    ReplicationOp::CompareAndSet {
                        key: key.clone(),
                        expected_generation,
                        credential_id: lease.credential_id(),
                        guard_expires_at: lease.expires_at(),
                        new_record: record.as_ref().clone(),
                    },
                )
            }
            FencedTransitionMutation::Delete {
                expected_generation,
            } => {
                if Self::get_with_state(state, key, now)
                    .as_ref()
                    .map(|record| record.generation)
                    != Some(*expected_generation)
                {
                    return Err(StoreError::CasConflict);
                }
                self.delete_fenced_with_state(state, &lease, now)?;
                (
                    *expected_generation,
                    FencedTransitionMutationResult::Deleted,
                    ReplicationOp::DeleteFenced {
                        key: key.clone(),
                        owner: lease.owner().clone(),
                        fence: lease.fence(),
                    },
                )
            }
            FencedTransitionMutation::RefreshTtl {
                expected_generation,
                ttl,
            } => {
                if Self::get_with_state(state, key, now)
                    .as_ref()
                    .map(|record| record.generation)
                    != Some(*expected_generation)
                {
                    return Err(StoreError::CasConflict);
                }
                let expires_at = self.refresh_ttl_with_state(state, &lease, *ttl, now)?;
                (
                    *expected_generation,
                    FencedTransitionMutationResult::TtlRefreshed { expires_at },
                    ReplicationOp::RefreshTtl {
                        key: key.clone(),
                        owner: lease.owner().clone(),
                        fence: lease.fence(),
                        ttl: *ttl,
                        expires_at,
                    },
                )
            }
        };
        let outcome = FencedTransitionOutcome::new(lease, generation, mutation, now)?;
        Ok((
            outcome,
            ReplicationOp::Batch {
                ops: vec![lease_op, mutation_op],
            },
        ))
    }
}
