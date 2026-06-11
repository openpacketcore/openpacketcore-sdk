//! Generic handover storage state machine (RFC 004 §10).
//!
//! `HandoverManager` drives a session record through
//! `Stable → Preparing → Prepared → Activating → Active` (or
//! `Aborting → Stable` on rollback) using a fenced compare-and-set for every
//! transition, so a stale source NF can never reclaim a session after the
//! target has been fenced in. All steps are idempotent by `HandoverTxId`:
//! re-running a step that already happened for the same transaction returns
//! `Ok` without writing, which makes the procedure safe to retry after NF
//! restarts. NF-specific AMF/SMF/UPF logic maps 3GPP procedure messages onto
//! these generic transitions.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    backend::{CompareAndSet, CompareAndSetResult, SessionBackend},
    clock::Clock,
    error::StoreError,
    lease::LeaseGuard,
    model::{FenceToken, Generation, HandoverPhase, HandoverTxId, OwnerId, SessionKey},
    record::{EncryptedSessionPayload, StoredSessionRecord},
};

/// Errors from handover state transitions.
///
/// The conflict variants (`PhaseRegression`, `TransactionConflict`,
/// `OwnerConflict`, `FencingMismatch`) mean this caller lost a race for the
/// transition: blind retries cannot succeed — re-read the record to learn the
/// surviving phase and decide whether to continue, abort, or stand down.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandoverError {
    /// The attempted transition would move the state machine backwards or
    /// skip a phase (e.g. activating a session that was never prepared). The
    /// record was not modified.
    #[error("handover phase regression: cannot transition from {current:?} to {attempted:?}")]
    PhaseRegression {
        /// Phase the record was actually in when the step ran.
        current: HandoverPhase,
        /// Phase the caller tried to move to.
        attempted: HandoverPhase,
    },

    /// A different handover transaction owns the in-flight phase. Two
    /// concurrent handover attempts collided; the one holding `active` wins
    /// and the `received` transaction should be abandoned or aborted.
    #[error("handover transaction conflict: active transaction is {active:?}, but received {received:?}")]
    TransactionConflict {
        /// Transaction recorded in the stored phase.
        active: HandoverTxId,
        /// Transaction the caller presented.
        received: HandoverTxId,
    },

    /// The step was attempted by a replica that is not the one the current
    /// phase designates (e.g. a non-target trying to mark itself prepared).
    #[error(
        "owner conflict: expected owner {expected:?}, but operation was initiated by {actual:?}"
    )]
    OwnerConflict {
        /// Owner the stored phase says may perform this step.
        expected: OwnerId,
        /// Owner that actually attempted it.
        actual: OwnerId,
    },

    /// The caller's lease fence is not high enough relative to the fence the
    /// record was last written under — a newer owner has been fenced in.
    /// The caller must stop writing this session; acquiring a fresh lease
    /// (and re-reading) is the only way forward.
    #[error("fencing token mismatch: provided fence {provided} is lower than or equal to current fence {current}")]
    FencingMismatch {
        /// Fence token from the caller's lease.
        provided: FenceToken,
        /// Fence token currently recorded on the stored record.
        current: FenceToken,
    },

    /// The caller's lease had already expired (by the manager's clock) before
    /// the step ran, so no fenced write was attempted. Re-acquire the lease —
    /// which mints a higher fence — before retrying.
    #[error("lease expired or invalid for owner {owner:?}")]
    InvalidLease {
        /// Owner whose lease was expired or invalid.
        owner: OwnerId,
    },

    /// The underlying session store failed. Notably wraps
    /// `StoreError::CasConflict` when `expected_generation` no longer matches
    /// (another write landed first — re-read and retry with the new
    /// generation) and `StoreError::NotFound` when the session record does
    /// not exist.
    #[error("underlying store error: {0}")]
    Store(#[from] crate::error::StoreError),
}

/// Pairing of a handover phase header with the NF's session payload, stored
/// together inside the session record's payload bytes.
///
/// The packed wire form is a 4-byte big-endian length prefix, the
/// JSON-encoded `HandoverPhase`, then the payload bytes. Keeping the phase
/// inside the (encrypted) payload means every phase transition is itself a
/// fenced, generation-checked CAS — there is no side channel a stale owner
/// could update without going through fencing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoverEnvelope<P> {
    /// Current position in the handover state machine for this session.
    pub phase: HandoverPhase,
    /// The NF's own session state, opaque to the handover layer.
    pub payload: P,
}

impl<P> HandoverEnvelope<P> {
    /// Encode as the length-prefixed wire form with the payload's bytes
    /// appended verbatim (no payload serialization). Fails only if the phase
    /// header cannot be JSON-encoded.
    pub fn pack_raw(&self) -> Result<Vec<u8>, serde_json::Error>
    where
        P: AsRef<[u8]>,
    {
        let phase_bytes = serde_json::to_vec(&self.phase)?;
        let n = phase_bytes.len() as u32;
        let mut out = Vec::with_capacity(4 + phase_bytes.len() + self.payload.as_ref().len());
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&phase_bytes);
        out.extend_from_slice(self.payload.as_ref());
        Ok(out)
    }

    /// Decode the wire form produced by `pack_raw`.
    ///
    /// Infallible by design: bytes that do not parse as an envelope are
    /// treated as a bare payload in phase `Stable`, so records written before
    /// handover support (or by NFs that never hand over) remain readable.
    pub fn unpack_raw(bytes: &[u8]) -> Self
    where
        P: From<Vec<u8>>,
    {
        if bytes.len() >= 4 {
            let mut prefix = [0u8; 4];
            prefix.copy_from_slice(&bytes[0..4]);
            let n = u32::from_be_bytes(prefix) as usize;
            if n + 4 <= bytes.len() {
                let phase_slice = &bytes[4..4 + n];
                if let Ok(phase) = serde_json::from_slice::<HandoverPhase>(phase_slice) {
                    let payload = bytes[4 + n..].to_vec().into();
                    return Self { phase, payload };
                }
            }
        }
        Self {
            phase: HandoverPhase::Stable,
            payload: bytes.to_vec().into(),
        }
    }

    /// Encode as the length-prefixed wire form with the payload
    /// JSON-serialized, for typed (non-byte-slice) payloads. Pair with
    /// `unpack_json`; the two byte formats are otherwise identical.
    pub fn pack_json(&self) -> Result<Vec<u8>, serde_json::Error>
    where
        P: Serialize,
    {
        let phase_bytes = serde_json::to_vec(&self.phase)?;
        let n = phase_bytes.len() as u32;
        let payload_bytes = serde_json::to_vec(&self.payload)?;
        let mut out = Vec::with_capacity(4 + phase_bytes.len() + payload_bytes.len());
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&phase_bytes);
        out.extend_from_slice(&payload_bytes);
        Ok(out)
    }

    /// Decode the wire form produced by `pack_json`.
    ///
    /// Bytes without a parseable phase header are interpreted as a bare
    /// JSON payload in phase `Stable` (pre-handover compatibility); the
    /// error case is payload JSON that fails to deserialize as `P`.
    pub fn unpack_json(bytes: &[u8]) -> Result<Self, serde_json::Error>
    where
        P: for<'de> Deserialize<'de>,
    {
        if bytes.len() >= 4 {
            let mut prefix = [0u8; 4];
            prefix.copy_from_slice(&bytes[0..4]);
            let n = u32::from_be_bytes(prefix) as usize;
            if n + 4 <= bytes.len() {
                let phase_slice = &bytes[4..4 + n];
                if let Ok(phase) = serde_json::from_slice::<HandoverPhase>(phase_slice) {
                    let payload = serde_json::from_slice(&bytes[4 + n..])?;
                    return Ok(Self { phase, payload });
                }
            }
        }
        let payload = serde_json::from_slice(bytes)?;
        Ok(Self {
            phase: HandoverPhase::Stable,
            payload,
        })
    }
}

/// A stored session record together with its decoded handover envelope.
///
/// Gives callers the storage metadata (generation, owner, fence) needed to
/// drive the next fenced CAS alongside the decoded phase and payload, without
/// re-parsing the payload bytes.
pub struct HandoverSessionRecord<P> {
    /// The record as read from the backend, including the `generation` to
    /// pass as `expected_generation` for the next transition and the `fence`
    /// it was written under.
    pub record: StoredSessionRecord,
    /// Handover phase decoded from the record's payload envelope.
    pub phase: HandoverPhase,
    /// The NF payload decoded from the record's envelope.
    pub payload: P,
}

impl<P> HandoverSessionRecord<P> {
    /// Decode a fetched record whose payload was packed with
    /// `HandoverEnvelope::pack_raw`. Non-envelope payload bytes are reported
    /// as phase `Stable` rather than failing.
    pub fn unpack_raw(record: StoredSessionRecord) -> Self
    where
        P: From<Vec<u8>>,
    {
        let envelope = HandoverEnvelope::<P>::unpack_raw(record.payload.as_bytes());
        Self {
            record,
            phase: envelope.phase,
            payload: envelope.payload,
        }
    }

    /// Decode a fetched record whose payload was packed with
    /// `HandoverEnvelope::pack_json`; fails if the payload JSON does not
    /// deserialize as `P`.
    pub fn unpack_json(record: StoredSessionRecord) -> Result<Self, serde_json::Error>
    where
        P: for<'de> Deserialize<'de>,
    {
        let envelope = HandoverEnvelope::<P>::unpack_json(record.payload.as_bytes())?;
        Ok(Self {
            record,
            phase: envelope.phase,
            payload: envelope.payload,
        })
    }
}

/// Coordinator for handover phase transitions over a `SessionBackend`.
///
/// Every step follows the same recipe: check the caller's lease has not
/// expired, read the current record, validate phase / transaction / owner /
/// fence, then perform a generation-checked fenced CAS that bumps the
/// record's generation. The manager never bypasses fencing, so it is safe to
/// run concurrently from source and target NFs.
pub struct HandoverManager<B> {
    /// Store the session records live in; all transitions go through its
    /// fenced compare-and-set.
    pub backend: Arc<B>,
    /// Clock used to test lease expiry before each step. Must agree with the
    /// lease manager's clock or unexpired leases may be falsely rejected
    /// (and vice versa).
    pub clock: Arc<dyn Clock>,
}

impl<B: SessionBackend> HandoverManager<B> {
    /// Build a manager from a backend and the clock used for lease-expiry
    /// checks.
    pub fn new(backend: Arc<B>, clock: Arc<dyn Clock>) -> Self {
        Self { backend, clock }
    }

    /// Fetch and decode the session's record and raw-packed handover
    /// envelope. Returns `Ok(None)` when no live record exists for the key.
    pub async fn get_record<P>(
        &self,
        key: &SessionKey,
    ) -> Result<Option<HandoverSessionRecord<P>>, HandoverError>
    where
        P: From<Vec<u8>>,
    {
        let record = self.backend.get(key).await?;
        match record {
            Some(record) => {
                let unpacked = HandoverSessionRecord::unpack_raw(record);
                Ok(Some(unpacked))
            }
            None => Ok(None),
        }
    }

    /// Fetch and decode the session's record and JSON-packed handover
    /// envelope. Returns `Ok(None)` for a missing record and a
    /// `Serialization` store error if the payload does not deserialize.
    pub async fn get_record_json<P>(
        &self,
        key: &SessionKey,
    ) -> Result<Option<HandoverSessionRecord<P>>, HandoverError>
    where
        P: for<'de> Deserialize<'de>,
    {
        let record = self.backend.get(key).await?;
        match record {
            Some(record) => {
                let unpacked = HandoverSessionRecord::unpack_json(record)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                Ok(Some(unpacked))
            }
            None => Ok(None),
        }
    }

    /// Source-owner step: transition `Stable`/`Active` into
    /// `Preparing { tx, target }` (RFC 004 §10.3 step 2).
    ///
    /// The caller must hold an unexpired lease, be the session's current
    /// owner, and present the record's current generation; the CAS bumps the
    /// generation while keeping the payload intact. Idempotent: if the record
    /// is already `Preparing` for the same `tx` and `target`, returns `Ok`
    /// without writing. A `Preparing` phase under a different transaction
    /// yields `TransactionConflict`.
    pub async fn prepare_handover(
        &self,
        lease: &LeaseGuard,
        expected_generation: Generation,
        tx: HandoverTxId,
        target: OwnerId,
    ) -> Result<(), HandoverError> {
        if lease.expires_at() <= self.clock.now_utc() {
            return Err(HandoverError::InvalidLease {
                owner: lease.owner().clone(),
            });
        }

        let record = self
            .backend
            .get(lease.key())
            .await?
            .ok_or(StoreError::NotFound)?;

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes());

        match &envelope.phase {
            HandoverPhase::Stable | HandoverPhase::Active { .. } => {
                // Compatible phases
            }
            HandoverPhase::Preparing {
                tx: cur_tx,
                target: cur_target,
            } => {
                if cur_tx == &tx && cur_target == &target {
                    return Ok(());
                } else {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
            }
            _ => {
                return Err(HandoverError::PhaseRegression {
                    current: envelope.phase.clone(),
                    attempted: HandoverPhase::Preparing { tx, target },
                });
            }
        }

        let current_owner = match &envelope.phase {
            HandoverPhase::Stable => &record.owner,
            HandoverPhase::Active { owner } => owner,
            _ => unreachable!(),
        };

        if lease.owner() != current_owner {
            return Err(HandoverError::OwnerConflict {
                expected: current_owner.clone(),
                actual: lease.owner().clone(),
            });
        }

        if record.generation != expected_generation {
            return Err(HandoverError::Store(StoreError::CasConflict));
        }

        let new_envelope = HandoverEnvelope {
            phase: HandoverPhase::Preparing {
                tx,
                target: target.clone(),
            },
            payload: envelope.payload.clone(),
        };

        let payload_bytes = new_envelope
            .pack_raw()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let new_record = StoredSessionRecord {
            key: record.key.clone(),
            generation: record
                .generation
                .next()
                .ok_or_else(|| StoreError::Serialization("generation overflow".to_string()))?,
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: record.state_class,
            state_type: record.state_type.clone(),
            expires_at: record.expires_at,
            payload: EncryptedSessionPayload::new(payload_bytes),
        };

        let result = self
            .backend
            .compare_and_set(CompareAndSet {
                key: lease.key().clone(),
                lease: lease.clone(),
                expected_generation: Some(expected_generation),
                new_record,
            })
            .await?;

        match result {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => {
                Err(HandoverError::Store(StoreError::CasConflict))
            }
        }
    }

    /// Target step: transition `Preparing` into `Prepared` for the same `tx`
    /// (RFC 004 §10.3 step 4).
    ///
    /// Must be called by the designated target with its own lease, and that
    /// lease's fence must be *strictly greater* than the fence the record was
    /// last written under — this is where the target's higher fence enters
    /// the record, after which the source's old fence can no longer win CAS
    /// races. Idempotent if already `Prepared` for the same `tx` and target.
    pub async fn mark_prepared(
        &self,
        lease: &LeaseGuard,
        expected_generation: Generation,
        tx: HandoverTxId,
    ) -> Result<(), HandoverError> {
        if lease.expires_at() <= self.clock.now_utc() {
            return Err(HandoverError::InvalidLease {
                owner: lease.owner().clone(),
            });
        }

        let record = self
            .backend
            .get(lease.key())
            .await?
            .ok_or(StoreError::NotFound)?;

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes());

        let target = match &envelope.phase {
            HandoverPhase::Preparing {
                tx: cur_tx,
                target: cur_target,
            } => {
                if cur_tx != &tx {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
                cur_target
            }
            HandoverPhase::Prepared {
                tx: cur_tx,
                target: cur_target,
            } => {
                if cur_tx == &tx {
                    if lease.owner() != cur_target {
                        return Err(HandoverError::OwnerConflict {
                            expected: cur_target.clone(),
                            actual: lease.owner().clone(),
                        });
                    }
                    return Ok(());
                } else {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
            }
            _ => {
                return Err(HandoverError::PhaseRegression {
                    current: envelope.phase.clone(),
                    attempted: HandoverPhase::Prepared {
                        tx,
                        target: lease.owner().clone(),
                    },
                });
            }
        };

        if lease.owner() != target {
            return Err(HandoverError::OwnerConflict {
                expected: target.clone(),
                actual: lease.owner().clone(),
            });
        }

        if lease.fence().get() <= record.fence.get() {
            return Err(HandoverError::FencingMismatch {
                provided: lease.fence(),
                current: record.fence,
            });
        }

        if record.generation != expected_generation {
            return Err(HandoverError::Store(StoreError::CasConflict));
        }

        let new_envelope = HandoverEnvelope {
            phase: HandoverPhase::Prepared {
                tx,
                target: lease.owner().clone(),
            },
            payload: envelope.payload.clone(),
        };

        let payload_bytes = new_envelope
            .pack_raw()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let new_record = StoredSessionRecord {
            key: record.key.clone(),
            generation: record
                .generation
                .next()
                .ok_or_else(|| StoreError::Serialization("generation overflow".to_string()))?,
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: record.state_class,
            state_type: record.state_type.clone(),
            expires_at: record.expires_at,
            payload: EncryptedSessionPayload::new(payload_bytes),
        };

        let result = self
            .backend
            .compare_and_set(CompareAndSet {
                key: lease.key().clone(),
                lease: lease.clone(),
                expected_generation: Some(expected_generation),
                new_record,
            })
            .await?;

        match result {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => {
                Err(HandoverError::Store(StoreError::CasConflict))
            }
        }
    }

    /// Target step: transition `Prepared` into `Activating` for the same
    /// `tx` (RFC 004 §10.3 step 5, first half).
    ///
    /// Requires the target's unexpired lease with a fence at least as high
    /// as the record's. Idempotent if already `Activating` for the same
    /// transaction, so a target that crashes mid-activation can simply rerun
    /// the step after restart.
    pub async fn activate_handover(
        &self,
        lease: &LeaseGuard,
        expected_generation: Generation,
        tx: HandoverTxId,
    ) -> Result<(), HandoverError> {
        if lease.expires_at() <= self.clock.now_utc() {
            return Err(HandoverError::InvalidLease {
                owner: lease.owner().clone(),
            });
        }

        let record = self
            .backend
            .get(lease.key())
            .await?
            .ok_or(StoreError::NotFound)?;

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes());

        match &envelope.phase {
            HandoverPhase::Prepared {
                tx: cur_tx,
                target: cur_target,
            } => {
                if cur_tx != &tx {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
                if lease.owner() != cur_target {
                    return Err(HandoverError::OwnerConflict {
                        expected: cur_target.clone(),
                        actual: lease.owner().clone(),
                    });
                }
            }
            HandoverPhase::Activating {
                tx: cur_tx,
                target: cur_target,
            } => {
                if cur_tx == &tx {
                    if lease.owner() != cur_target {
                        return Err(HandoverError::OwnerConflict {
                            expected: cur_target.clone(),
                            actual: lease.owner().clone(),
                        });
                    }
                    return Ok(());
                } else {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
            }
            _ => {
                return Err(HandoverError::PhaseRegression {
                    current: envelope.phase.clone(),
                    attempted: HandoverPhase::Activating {
                        tx,
                        target: lease.owner().clone(),
                    },
                });
            }
        }

        if lease.fence().get() < record.fence.get() {
            return Err(HandoverError::FencingMismatch {
                provided: lease.fence(),
                current: record.fence,
            });
        }

        if record.generation != expected_generation {
            return Err(HandoverError::Store(StoreError::CasConflict));
        }

        let new_envelope = HandoverEnvelope {
            phase: HandoverPhase::Activating {
                tx,
                target: lease.owner().clone(),
            },
            payload: envelope.payload.clone(),
        };

        let payload_bytes = new_envelope
            .pack_raw()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let new_record = StoredSessionRecord {
            key: record.key.clone(),
            generation: record
                .generation
                .next()
                .ok_or_else(|| StoreError::Serialization("generation overflow".to_string()))?,
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: record.state_class,
            state_type: record.state_type.clone(),
            expires_at: record.expires_at,
            payload: EncryptedSessionPayload::new(payload_bytes),
        };

        let result = self
            .backend
            .compare_and_set(CompareAndSet {
                key: lease.key().clone(),
                lease: lease.clone(),
                expected_generation: Some(expected_generation),
                new_record,
            })
            .await?;

        match result {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => {
                Err(HandoverError::Store(StoreError::CasConflict))
            }
        }
    }

    /// Target step: transition `Activating` into `Active { owner: target }`,
    /// completing the handover (RFC 004 §10.3 steps 5–6).
    ///
    /// After this commits, the target is the authoritative owner and any
    /// write the old source attempts under its lower fence is rejected by
    /// the backend as stale. Idempotent if the record is already `Active`
    /// for this caller; `Active` under a different owner is an
    /// `OwnerConflict`.
    pub async fn complete_handover(
        &self,
        lease: &LeaseGuard,
        expected_generation: Generation,
        tx: HandoverTxId,
    ) -> Result<(), HandoverError> {
        if lease.expires_at() <= self.clock.now_utc() {
            return Err(HandoverError::InvalidLease {
                owner: lease.owner().clone(),
            });
        }

        let record = self
            .backend
            .get(lease.key())
            .await?
            .ok_or(StoreError::NotFound)?;

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes());

        match &envelope.phase {
            HandoverPhase::Activating {
                tx: cur_tx,
                target: cur_target,
            } => {
                if cur_tx != &tx {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
                if lease.owner() != cur_target {
                    return Err(HandoverError::OwnerConflict {
                        expected: cur_target.clone(),
                        actual: lease.owner().clone(),
                    });
                }
            }
            HandoverPhase::Active { owner: cur_owner } => {
                if cur_owner == lease.owner() {
                    return Ok(());
                } else {
                    return Err(HandoverError::OwnerConflict {
                        expected: cur_owner.clone(),
                        actual: lease.owner().clone(),
                    });
                }
            }
            _ => {
                return Err(HandoverError::PhaseRegression {
                    current: envelope.phase.clone(),
                    attempted: HandoverPhase::Active {
                        owner: lease.owner().clone(),
                    },
                });
            }
        }

        if lease.fence().get() < record.fence.get() {
            return Err(HandoverError::FencingMismatch {
                provided: lease.fence(),
                current: record.fence,
            });
        }

        if record.generation != expected_generation {
            return Err(HandoverError::Store(StoreError::CasConflict));
        }

        let new_envelope = HandoverEnvelope {
            phase: HandoverPhase::Active {
                owner: lease.owner().clone(),
            },
            payload: envelope.payload.clone(),
        };

        let payload_bytes = new_envelope
            .pack_raw()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let new_record = StoredSessionRecord {
            key: record.key.clone(),
            generation: record
                .generation
                .next()
                .ok_or_else(|| StoreError::Serialization("generation overflow".to_string()))?,
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: record.state_class,
            state_type: record.state_type.clone(),
            expires_at: record.expires_at,
            payload: EncryptedSessionPayload::new(payload_bytes),
        };

        let result = self
            .backend
            .compare_and_set(CompareAndSet {
                key: lease.key().clone(),
                lease: lease.clone(),
                expected_generation: Some(expected_generation),
                new_record,
            })
            .await?;

        match result {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => {
                Err(HandoverError::Store(StoreError::CasConflict))
            }
        }
    }

    /// Begin rolling back an incomplete handover: any in-flight phase
    /// (`Preparing`, `Prepared`, or `Activating`) for the same `tx` moves to
    /// `Aborting { tx }` (RFC 004 §10.3 step 7).
    ///
    /// `Stable` returns `Ok` immediately (nothing to abort), and `Aborting`
    /// for the same transaction is idempotent. An already-`Active` record
    /// cannot be aborted — that is a `PhaseRegression` — and a different
    /// in-flight transaction is a `TransactionConflict`.
    pub async fn abort_handover(
        &self,
        lease: &LeaseGuard,
        expected_generation: Generation,
        tx: HandoverTxId,
    ) -> Result<(), HandoverError> {
        if lease.expires_at() <= self.clock.now_utc() {
            return Err(HandoverError::InvalidLease {
                owner: lease.owner().clone(),
            });
        }

        let record = self
            .backend
            .get(lease.key())
            .await?
            .ok_or(StoreError::NotFound)?;

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes());

        match &envelope.phase {
            HandoverPhase::Preparing { tx: cur_tx, .. }
            | HandoverPhase::Prepared { tx: cur_tx, .. }
            | HandoverPhase::Activating { tx: cur_tx, .. } => {
                if cur_tx != &tx {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
            }
            HandoverPhase::Aborting { tx: cur_tx } => {
                if cur_tx == &tx {
                    return Ok(());
                } else {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
            }
            HandoverPhase::Stable => {
                return Ok(());
            }
            _ => {
                return Err(HandoverError::PhaseRegression {
                    current: envelope.phase.clone(),
                    attempted: HandoverPhase::Aborting { tx },
                });
            }
        }

        if lease.fence().get() < record.fence.get() {
            return Err(HandoverError::FencingMismatch {
                provided: lease.fence(),
                current: record.fence,
            });
        }

        if record.generation != expected_generation {
            return Err(HandoverError::Store(StoreError::CasConflict));
        }

        let new_envelope = HandoverEnvelope {
            phase: HandoverPhase::Aborting { tx },
            payload: envelope.payload.clone(),
        };

        let payload_bytes = new_envelope
            .pack_raw()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let new_record = StoredSessionRecord {
            key: record.key.clone(),
            generation: record
                .generation
                .next()
                .ok_or_else(|| StoreError::Serialization("generation overflow".to_string()))?,
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: record.state_class,
            state_type: record.state_type.clone(),
            expires_at: record.expires_at,
            payload: EncryptedSessionPayload::new(payload_bytes),
        };

        let result = self
            .backend
            .compare_and_set(CompareAndSet {
                key: lease.key().clone(),
                lease: lease.clone(),
                expected_generation: Some(expected_generation),
                new_record,
            })
            .await?;

        match result {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => {
                Err(HandoverError::Store(StoreError::CasConflict))
            }
        }
    }

    /// Finish a rollback: transition `Aborting { tx }` back to `Stable`,
    /// restoring `rollback_owner` (normally the original source) as the
    /// record's owner.
    ///
    /// The caller's lease must belong to `rollback_owner` and carry a fence
    /// at least as high as the record's. Idempotent if the record is already
    /// `Stable`, or `Active` under `rollback_owner`; any other phase is a
    /// `PhaseRegression` and a different aborting transaction is a
    /// `TransactionConflict`.
    pub async fn finalize_abort(
        &self,
        lease: &LeaseGuard,
        expected_generation: Generation,
        tx: HandoverTxId,
        rollback_owner: OwnerId,
    ) -> Result<(), HandoverError> {
        if lease.expires_at() <= self.clock.now_utc() {
            return Err(HandoverError::InvalidLease {
                owner: lease.owner().clone(),
            });
        }

        let record = self
            .backend
            .get(lease.key())
            .await?
            .ok_or(StoreError::NotFound)?;

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes());

        match &envelope.phase {
            HandoverPhase::Aborting { tx: cur_tx } => {
                if cur_tx != &tx {
                    return Err(HandoverError::TransactionConflict {
                        active: *cur_tx,
                        received: tx,
                    });
                }
            }
            HandoverPhase::Stable => {
                return Ok(());
            }
            HandoverPhase::Active { owner: cur_owner } => {
                if cur_owner == &rollback_owner {
                    return Ok(());
                } else {
                    return Err(HandoverError::OwnerConflict {
                        expected: rollback_owner.clone(),
                        actual: cur_owner.clone(),
                    });
                }
            }
            _ => {
                return Err(HandoverError::PhaseRegression {
                    current: envelope.phase.clone(),
                    attempted: HandoverPhase::Stable,
                });
            }
        }

        if lease.owner() != &rollback_owner {
            return Err(HandoverError::OwnerConflict {
                expected: rollback_owner.clone(),
                actual: lease.owner().clone(),
            });
        }

        if lease.fence().get() < record.fence.get() {
            return Err(HandoverError::FencingMismatch {
                provided: lease.fence(),
                current: record.fence,
            });
        }

        if record.generation != expected_generation {
            return Err(HandoverError::Store(StoreError::CasConflict));
        }

        let new_envelope = HandoverEnvelope {
            phase: HandoverPhase::Stable,
            payload: envelope.payload.clone(),
        };

        let payload_bytes = new_envelope
            .pack_raw()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let new_record = StoredSessionRecord {
            key: record.key.clone(),
            generation: record
                .generation
                .next()
                .ok_or_else(|| StoreError::Serialization("generation overflow".to_string()))?,
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: record.state_class,
            state_type: record.state_type.clone(),
            expires_at: record.expires_at,
            payload: EncryptedSessionPayload::new(payload_bytes),
        };

        let result = self
            .backend
            .compare_and_set(CompareAndSet {
                key: lease.key().clone(),
                lease: lease.clone(),
                expected_generation: Some(expected_generation),
                new_record,
            })
            .await?;

        match result {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => {
                Err(HandoverError::Store(StoreError::CasConflict))
            }
        }
    }
}
