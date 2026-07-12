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
//!
//! The versioned envelope is a one-way persisted-format migration: an SDK that
//! predates the `OPCH` header treats it as an opaque legacy `Stable` payload.
//! Upgrade every reader and writer together, and do not roll back after an
//! `OPCH` write without restoring a pre-upgrade snapshot or reverse-migrating
//! every affected payload while the fleet is drained.

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

/// Magic prefix written by the versioned handover-envelope format.
pub const HANDOVER_ENVELOPE_MAGIC: [u8; 4] = *b"OPCH";

/// Current version of the handover-envelope header written by this SDK.
pub const HANDOVER_ENVELOPE_VERSION: u8 = 1;

/// Maximum encoded JSON phase-header size accepted from persisted state.
pub const HANDOVER_PHASE_HEADER_MAX_BYTES: usize = 1_024;

const VERSIONED_ENVELOPE_PREFIX_BYTES: usize = HANDOVER_ENVELOPE_MAGIC.len() + 1 + 4;

/// Syntactic format selected while decoding a handover payload.
///
/// This is migration evidence, not provenance evidence. In a snapshot known to
/// predate `OPCH`, [`HandoverEnvelopeFormat::VersionedV1`] means a bare-payload
/// prefix collision and requires product-owned migration. Likewise, a value
/// classified as [`HandoverEnvelopeFormat::OriginalLengthPrefixed`] can still
/// be historical bare data that happens to contain a valid-looking phase; the
/// product must verify that classification against its payload semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandoverEnvelopeFormat {
    /// Current `OPCH` envelope with format version 1.
    VersionedV1,
    /// Original untagged four-byte-length-prefixed envelope.
    OriginalLengthPrefixed,
    /// Untagged payload interpreted as legacy `Stable` state.
    Bare,
}

/// Redaction-safe failure to decode a typed handover envelope.
///
/// The error deliberately carries no submitted phase, owner, transaction, or
/// payload text. Some bare payloads written before handover-envelope support
/// remain readable as `Stable` under the exact compatibility classifier on
/// [`HandoverEnvelope::unpack_raw`]; ambiguous bytes fail closed instead of
/// allowing corrupted typed state to become legacy state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandoverEnvelopeDecodeError {
    /// A claimed envelope prefix, version, length, or header bound was invalid.
    #[error("handover envelope header is invalid")]
    InvalidHeader,
    /// Phase JSON was malformed or violated the handover model.
    #[error("handover envelope phase header is invalid")]
    InvalidPhase,
    /// A JSON-packed envelope contained an invalid payload.
    #[error("handover envelope payload is invalid")]
    InvalidPayload,
}

/// Errors from handover state transitions.
///
/// The conflict variants (`PhaseRegression`, `TransactionConflict`,
/// `OwnerConflict`, `FencingMismatch`) mean this caller lost a race for the
/// transition: blind retries cannot succeed — re-read the record to learn the
/// surviving phase and decide whether to continue, abort, or stand down.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandoverError {
    /// A stored payload looked like a typed handover envelope but its phase or
    /// JSON payload failed validation. The record was not modified.
    #[error(transparent)]
    InvalidEnvelope(#[from] HandoverEnvelopeDecodeError),

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
/// The current packed form is [`HANDOVER_ENVELOPE_MAGIC`], one version byte, a
/// 4-byte big-endian phase length, the JSON-encoded `HandoverPhase`, then the
/// payload bytes. Decoding also accepts the original length-prefixed format
/// and unframed legacy payloads under the explicit compatibility rules on
/// [`HandoverEnvelope::unpack_raw`]. Keeping the phase inside the (encrypted)
/// payload means every transition is a fenced, generation-checked CAS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoverEnvelope<P> {
    /// Current position in the handover state machine for this session.
    pub phase: HandoverPhase,
    /// The NF's own session state, opaque to the handover layer.
    pub payload: P,
}

impl<P> HandoverEnvelope<P> {
    /// Encode as the versioned `OPCH` form with the payload's bytes appended
    /// verbatim (no payload serialization). Fails only if the phase header
    /// cannot be JSON-encoded.
    pub fn pack_raw(&self) -> Result<Vec<u8>, serde_json::Error>
    where
        P: AsRef<[u8]>,
    {
        let phase_bytes = serde_json::to_vec(&self.phase)?;
        let n = phase_bytes.len() as u32;
        let mut out = Vec::with_capacity(
            VERSIONED_ENVELOPE_PREFIX_BYTES + phase_bytes.len() + self.payload.as_ref().len(),
        );
        out.extend_from_slice(&HANDOVER_ENVELOPE_MAGIC);
        out.push(HANDOVER_ENVELOPE_VERSION);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&phase_bytes);
        out.extend_from_slice(self.payload.as_ref());
        Ok(out)
    }

    /// Decode the wire form produced by `pack_raw`.
    ///
    /// Versioned envelopes are always decoded strictly. For non-`OPCH` input,
    /// the first four bytes are interpreted as a potential original-format
    /// big-endian phase length. Fewer than four bytes are bare `Stable` data.
    /// A zero length or a length from 1 through
    /// [`HANDOVER_PHASE_HEADER_MAX_BYTES`] that exceeds the remaining bytes is
    /// an invalid header. A complete in-bound slice is an original envelope
    /// when it decodes as `HandoverPhase`; a JSON-looking but invalid slice is
    /// an invalid phase, while a non-JSON-looking slice falls back to bare
    /// `Stable` data. A larger length is invalid when the bytes after its
    /// prefix look like JSON and otherwise falls back to bare `Stable` data.
    ///
    /// This classifier deliberately rejects ambiguous historical bare bytes.
    /// Products must preflight their decrypted payload population before an
    /// upgrade and explicitly re-pack any authoritatively identified bare
    /// value that the classifier rejects.
    pub fn unpack_raw(bytes: &[u8]) -> Result<Self, HandoverEnvelopeDecodeError>
    where
        P: From<Vec<u8>>,
    {
        Self::unpack_raw_with_format(bytes).map(|(_, envelope)| envelope)
    }

    /// Decode raw payload bytes and return the syntactic source format.
    ///
    /// Products should use this variant for legacy preflight. A successful
    /// classification is not proof of provenance: apply the rules documented
    /// on [`HandoverEnvelopeFormat`] before accepting or migrating old state.
    pub fn unpack_raw_with_format(
        bytes: &[u8],
    ) -> Result<(HandoverEnvelopeFormat, Self), HandoverEnvelopeDecodeError>
    where
        P: From<Vec<u8>>,
    {
        if let Some((format, phase, payload_start)) = decode_envelope_header(bytes)? {
            let payload = bytes[payload_start..].to_vec().into();
            return Ok((format, Self { phase, payload }));
        }
        Ok((
            HandoverEnvelopeFormat::Bare,
            Self {
                phase: HandoverPhase::Stable,
                payload: bytes.to_vec().into(),
            },
        ))
    }

    /// Encode as the versioned `OPCH` form with the payload JSON-serialized,
    /// for typed (non-byte-slice) payloads. Pair with `unpack_json`; the two
    /// byte formats are otherwise identical.
    pub fn pack_json(&self) -> Result<Vec<u8>, serde_json::Error>
    where
        P: Serialize,
    {
        let phase_bytes = serde_json::to_vec(&self.phase)?;
        let n = phase_bytes.len() as u32;
        let payload_bytes = serde_json::to_vec(&self.payload)?;
        let mut out = Vec::with_capacity(
            VERSIONED_ENVELOPE_PREFIX_BYTES + phase_bytes.len() + payload_bytes.len(),
        );
        out.extend_from_slice(&HANDOVER_ENVELOPE_MAGIC);
        out.push(HANDOVER_ENVELOPE_VERSION);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&phase_bytes);
        out.extend_from_slice(&payload_bytes);
        Ok(out)
    }

    /// Decode the wire form produced by `pack_json`.
    ///
    /// A bare legacy JSON value accepted by the exact classifier documented on
    /// [`HandoverEnvelope::unpack_raw`] remains readable as phase `Stable`.
    /// Versioned envelopes and plausible original-format envelope claims are
    /// decoded strictly; an invalid phase or payload returns a fieldless error.
    pub fn unpack_json(bytes: &[u8]) -> Result<Self, HandoverEnvelopeDecodeError>
    where
        P: for<'de> Deserialize<'de>,
    {
        Self::unpack_json_with_format(bytes).map(|(_, envelope)| envelope)
    }

    /// Decode a JSON payload and return the syntactic source format.
    ///
    /// Use the returned [`HandoverEnvelopeFormat`] together with snapshot
    /// provenance and product payload semantics; format detection alone cannot
    /// distinguish every historical bare-prefix collision.
    pub fn unpack_json_with_format(
        bytes: &[u8],
    ) -> Result<(HandoverEnvelopeFormat, Self), HandoverEnvelopeDecodeError>
    where
        P: for<'de> Deserialize<'de>,
    {
        if let Some((format, phase, payload_start)) = decode_envelope_header(bytes)? {
            let payload = serde_json::from_slice(&bytes[payload_start..])
                .map_err(|_| HandoverEnvelopeDecodeError::InvalidPayload)?;
            return Ok((format, Self { phase, payload }));
        }
        let payload = serde_json::from_slice(bytes)
            .map_err(|_| HandoverEnvelopeDecodeError::InvalidPayload)?;
        Ok((
            HandoverEnvelopeFormat::Bare,
            Self {
                phase: HandoverPhase::Stable,
                payload,
            },
        ))
    }
}

fn decode_envelope_header(
    bytes: &[u8],
) -> Result<Option<(HandoverEnvelopeFormat, HandoverPhase, usize)>, HandoverEnvelopeDecodeError> {
    if bytes.starts_with(&HANDOVER_ENVELOPE_MAGIC) {
        if bytes.len() < VERSIONED_ENVELOPE_PREFIX_BYTES
            || bytes[HANDOVER_ENVELOPE_MAGIC.len()] != HANDOVER_ENVELOPE_VERSION
        {
            return Err(HandoverEnvelopeDecodeError::InvalidHeader);
        }
        let length_start = HANDOVER_ENVELOPE_MAGIC.len() + 1;
        let phase_len = read_phase_length(&bytes[length_start..length_start + 4])?;
        let phase_start = VERSIONED_ENVELOPE_PREFIX_BYTES;
        let phase_end = checked_phase_end(phase_start, phase_len, bytes.len())?;
        let phase = serde_json::from_slice(&bytes[phase_start..phase_end])
            .map_err(|_| HandoverEnvelopeDecodeError::InvalidPhase)?;
        return Ok(Some((
            HandoverEnvelopeFormat::VersionedV1,
            phase,
            phase_end,
        )));
    }

    if bytes.len() < 4 {
        return Ok(None);
    }
    let phase_len = read_phase_length(&bytes[..4])?;
    if phase_len > HANDOVER_PHASE_HEADER_MAX_BYTES {
        return if looks_like_json(bytes.get(4..).unwrap_or_default()) {
            Err(HandoverEnvelopeDecodeError::InvalidHeader)
        } else {
            Ok(None)
        };
    }
    let phase_end = checked_phase_end(4, phase_len, bytes.len())?;
    let phase_bytes = &bytes[4..phase_end];
    match serde_json::from_slice::<HandoverPhase>(phase_bytes) {
        Ok(phase) => Ok(Some((
            HandoverEnvelopeFormat::OriginalLengthPrefixed,
            phase,
            phase_end,
        ))),
        Err(_) if looks_like_json(phase_bytes) => Err(HandoverEnvelopeDecodeError::InvalidPhase),
        Err(_) => Ok(None),
    }
}

fn read_phase_length(bytes: &[u8]) -> Result<usize, HandoverEnvelopeDecodeError> {
    let prefix: [u8; 4] = bytes
        .try_into()
        .map_err(|_| HandoverEnvelopeDecodeError::InvalidHeader)?;
    let phase_len = u32::from_be_bytes(prefix) as usize;
    if phase_len == 0 {
        return Err(HandoverEnvelopeDecodeError::InvalidHeader);
    }
    Ok(phase_len)
}

fn checked_phase_end(
    phase_start: usize,
    phase_len: usize,
    total_len: usize,
) -> Result<usize, HandoverEnvelopeDecodeError> {
    if phase_len > HANDOVER_PHASE_HEADER_MAX_BYTES {
        return Err(HandoverEnvelopeDecodeError::InvalidHeader);
    }
    phase_start
        .checked_add(phase_len)
        .filter(|end| *end <= total_len)
        .ok_or(HandoverEnvelopeDecodeError::InvalidHeader)
}

fn looks_like_json(bytes: &[u8]) -> bool {
    matches!(
        bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace()),
        Some(b'{' | b'[' | b'"' | b't' | b'f' | b'n' | b'-' | b'0'..=b'9')
    )
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
    /// `HandoverEnvelope::pack_raw`. Legacy non-envelope payload bytes accepted
    /// by [`HandoverEnvelope::unpack_raw`]'s exact classifier are reported as
    /// phase `Stable`; ambiguous or malformed claimed envelopes fail closed.
    pub fn unpack_raw(record: StoredSessionRecord) -> Result<Self, HandoverEnvelopeDecodeError>
    where
        P: From<Vec<u8>>,
    {
        let envelope = HandoverEnvelope::<P>::unpack_raw(record.payload.as_bytes())?;
        Ok(Self {
            record,
            phase: envelope.phase,
            payload: envelope.payload,
        })
    }

    /// Decode a fetched record whose payload was packed with
    /// `HandoverEnvelope::pack_json`; fails with a fieldless error when a
    /// claimed envelope or its payload is invalid.
    pub fn unpack_json(record: StoredSessionRecord) -> Result<Self, HandoverEnvelopeDecodeError>
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
                let unpacked = HandoverSessionRecord::unpack_raw(record)?;
                Ok(Some(unpacked))
            }
            None => Ok(None),
        }
    }

    /// Fetch and decode the session's record and JSON-packed handover
    /// envelope. Returns `Ok(None)` for a missing record and
    /// [`HandoverError::InvalidEnvelope`] if a claimed envelope or its JSON
    /// payload is invalid.
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
                let unpacked = HandoverSessionRecord::unpack_json(record)?;
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

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes())?;

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

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes())?;

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

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes())?;

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

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes())?;

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

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes())?;

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

        let envelope = HandoverEnvelope::<Vec<u8>>::unpack_raw(record.payload.as_bytes())?;

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
