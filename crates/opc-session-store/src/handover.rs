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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandoverError {
    #[error("handover phase regression: cannot transition from {current:?} to {attempted:?}")]
    PhaseRegression {
        current: HandoverPhase,
        attempted: HandoverPhase,
    },

    #[error("handover transaction conflict: active transaction is {active:?}, but received {received:?}")]
    TransactionConflict {
        active: HandoverTxId,
        received: HandoverTxId,
    },

    #[error(
        "owner conflict: expected owner {expected:?}, but operation was initiated by {actual:?}"
    )]
    OwnerConflict { expected: OwnerId, actual: OwnerId },

    #[error("fencing token mismatch: provided fence {provided} is lower than or equal to current fence {current}")]
    FencingMismatch {
        provided: FenceToken,
        current: FenceToken,
    },

    #[error("lease expired or invalid for owner {owner:?}")]
    InvalidLease { owner: OwnerId },

    #[error("underlying store error: {0}")]
    Store(#[from] crate::error::StoreError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoverEnvelope<P> {
    pub phase: HandoverPhase,
    pub payload: P,
}

impl<P> HandoverEnvelope<P> {
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

pub struct HandoverSessionRecord<P> {
    pub record: StoredSessionRecord,
    pub phase: HandoverPhase,
    pub payload: P,
}

impl<P> HandoverSessionRecord<P> {
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

pub struct HandoverManager<B> {
    pub backend: Arc<B>,
    pub clock: Arc<dyn Clock>,
}

impl<B: SessionBackend> HandoverManager<B> {
    pub fn new(backend: Arc<B>, clock: Arc<dyn Clock>) -> Self {
        Self { backend, clock }
    }

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
