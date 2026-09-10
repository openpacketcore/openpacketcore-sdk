//! Explicit ownership copies from closed native decoders. Model Clone may
//! share Bytes or encrypted payload backing, so those fields are reconstructed
//! independently. These helpers neither admit input nor change its semantics.

use super::*;
use crate::fenced_transition::{FencedTransitionLease, FencedTransitionMutation};

pub(crate) fn key(value: &SessionKey) -> io::Result<SessionKey> {
    Ok(SessionKey {
        tenant: value.tenant.clone(),
        nf_kind: value.nf_kind.clone(),
        key_type: value.key_type.clone(),
        // Exact independent Box backing matches the existing key allocation
        // accounting, including Bytes' possible three-word shared promotion.
        stable_id: crate::model::StableId::new(bytes::Bytes::from(Box::<[u8]>::from(
            value.stable_id.as_bytes(),
        )))
        .map_err(|_| invalid("native owned identifier copy invalid"))?,
    })
}

pub(crate) fn lease(value: &LeaseGuard) -> io::Result<LeaseGuard> {
    Ok(LeaseGuard::new(
        key(value.key())?,
        value.owner().clone(),
        value.fence(),
        value.acquired_at(),
        value.expires_at(),
        value.credential_id(),
    ))
}

pub(crate) fn record(value: &StoredSessionRecord) -> io::Result<StoredSessionRecord> {
    let payload = value.payload.copy_for_native_read();
    Ok(StoredSessionRecord {
        key: key(&value.key)?,
        generation: value.generation,
        owner: value.owner.clone(),
        fence: value.fence,
        state_class: value.state_class,
        state_type: value.state_type.clone(),
        expires_at: value.expires_at,
        payload,
    })
}

pub(crate) fn transition_lease(value: &FencedTransitionLease) -> io::Result<FencedTransitionLease> {
    Ok(match value {
        FencedTransitionLease::Acquire {
            key: session_key,
            owner,
            expected_fence,
            ttl,
        } => FencedTransitionLease::Acquire {
            key: key(session_key)?,
            owner: owner.clone(),
            expected_fence: *expected_fence,
            ttl: *ttl,
        },
        FencedTransitionLease::Renew { lease: guard, ttl } => FencedTransitionLease::Renew {
            lease: lease(guard)?,
            ttl: *ttl,
        },
    })
}

pub(crate) fn transition_mutation(
    value: &FencedTransitionMutation,
) -> io::Result<FencedTransitionMutation> {
    Ok(match value {
        FencedTransitionMutation::Create { record: value } => FencedTransitionMutation::Create {
            record: Box::new(record(value)?),
        },
        FencedTransitionMutation::Update {
            expected_generation,
            record: value,
        } => FencedTransitionMutation::Update {
            expected_generation: *expected_generation,
            record: Box::new(record(value)?),
        },
        FencedTransitionMutation::Delete {
            expected_generation,
        } => FencedTransitionMutation::Delete {
            expected_generation: *expected_generation,
        },
        FencedTransitionMutation::RefreshTtl {
            expected_generation,
            ttl,
        } => FencedTransitionMutation::RefreshTtl {
            expected_generation: *expected_generation,
            ttl: *ttl,
        },
    })
}

fn request_v1(
    value: &crate::FencedTransitionRequest,
) -> io::Result<crate::FencedTransitionRequest> {
    crate::FencedTransitionRequest::new(
        value.request_id(),
        transition_lease(value.lease())?,
        transition_mutation(value.mutation())?,
    )
    .map_err(|_| invalid("native owned V1 request invalid"))
}

fn intent(
    value: &SessionMutationIntent,
    allow_authorized: bool,
) -> io::Result<SessionMutationIntent> {
    Ok(match value {
        SessionMutationIntent::AdvanceLogicalTime => SessionMutationIntent::AdvanceLogicalTime,
        SessionMutationIntent::MaintainFencedTransitionV2History {
            expected_generation,
            expected_active_epoch,
            expected_retired_through,
            expected_bound_entries,
        } if allow_authorized => SessionMutationIntent::MaintainFencedTransitionV2History {
            expected_generation: *expected_generation,
            expected_active_epoch: *expected_active_epoch,
            expected_retired_through: *expected_retired_through,
            expected_bound_entries: *expected_bound_entries,
        },
        SessionMutationIntent::BindConsumerRequest { request_commitment } => {
            SessionMutationIntent::BindConsumerRequest {
                request_commitment: *request_commitment,
            }
        }
        SessionMutationIntent::ReadConsumerRecord { key: value } => {
            SessionMutationIntent::ReadConsumerRecord { key: key(value)? }
        }
        SessionMutationIntent::CompareAndSet(value) => SessionMutationIntent::CompareAndSet(
            std::sync::Arc::new(crate::backend::CompareAndSet {
                key: key(&value.key)?,
                expected_generation: value.expected_generation,
                lease: lease(&value.lease)?,
                new_record: record(&value.new_record)?,
            }),
        ),
        SessionMutationIntent::DeleteFenced(value) => {
            SessionMutationIntent::DeleteFenced(lease(value)?)
        }
        SessionMutationIntent::RefreshTtl { lease: value, ttl } => {
            SessionMutationIntent::RefreshTtl {
                lease: lease(value)?,
                ttl: *ttl,
            }
        }
        SessionMutationIntent::AcquireLease {
            key: value,
            owner,
            ttl,
        } => SessionMutationIntent::AcquireLease {
            key: key(value)?,
            owner: owner.clone(),
            ttl: *ttl,
        },
        SessionMutationIntent::RenewLease { lease: value, ttl } => {
            SessionMutationIntent::RenewLease {
                lease: lease(value)?,
                ttl: *ttl,
            }
        }
        SessionMutationIntent::ReleaseLease(value) => {
            SessionMutationIntent::ReleaseLease(lease(value)?)
        }
        SessionMutationIntent::FencedTransition(value) => {
            SessionMutationIntent::FencedTransition(Box::new(request_v1(value)?))
        }
        SessionMutationIntent::ActivateFencedTransition {
            request,
            scope_identity,
            voter_set_digest,
        } => SessionMutationIntent::ActivateFencedTransition {
            request: Box::new(request_v1(request)?),
            scope_identity: *scope_identity,
            voter_set_digest: *voter_set_digest,
        },
        SessionMutationIntent::ActivateFencedTransitionCapability {
            schema_version,
            scope_identity,
            voter_set_digest,
        } => SessionMutationIntent::ActivateFencedTransitionCapability {
            schema_version: *schema_version,
            scope_identity: *scope_identity,
            voter_set_digest: *voter_set_digest,
        },
        SessionMutationIntent::ActivateProtectedRosterProfileV2 {
            schema_version,
            consumer_revision,
            scope_identity,
            voter_set_digest,
            profile_digest,
        } => SessionMutationIntent::ActivateProtectedRosterProfileV2 {
            schema_version: *schema_version,
            consumer_revision: *consumer_revision,
            scope_identity: *scope_identity,
            voter_set_digest: *voter_set_digest,
            profile_digest: *profile_digest,
        },
        SessionMutationIntent::RosterAdmission(value) if !allow_authorized => {
            SessionMutationIntent::RosterAdmission(Box::new(value.copy_for_native_read()?))
        }
        SessionMutationIntent::RosterAdmissionV2(value) if !allow_authorized => {
            SessionMutationIntent::RosterAdmissionV2(Box::new(value.copy_for_native_read()?))
        }
        SessionMutationIntent::RosterTerminal(value) if !allow_authorized => {
            SessionMutationIntent::RosterTerminal(Box::new(value.copy_for_native_read()?))
        }
        SessionMutationIntent::RosterTerminalV2(value) if !allow_authorized => {
            SessionMutationIntent::RosterTerminalV2(Box::new(value.copy_for_native_read()?))
        }
        SessionMutationIntent::FencedTransitionV2(request) => {
            SessionMutationIntent::FencedTransitionV2(Box::new(request.copy_for_native_read()?))
        }
        SessionMutationIntent::ActivateFencedTransitionV2 {
            request,
            scope_identity,
            voter_set_digest,
            profile_digest,
        } => SessionMutationIntent::ActivateFencedTransitionV2 {
            request: Box::new(request.copy_for_native_read()?),
            scope_identity: *scope_identity,
            voter_set_digest: *voter_set_digest,
            profile_digest: *profile_digest,
        },
        SessionMutationIntent::FencedTransitionV2Batch(requests) => {
            if requests.len()
                > crate::consensus::types::MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS
            {
                return Err(invalid("native owned log batch exceeds profile"));
            }
            let mut copied = Vec::new();
            copied
                .try_reserve_exact(requests.len())
                .map_err(|_| invalid("native owned log batch allocation failed"))?;
            for request in requests {
                copied.push(request.copy_for_native_read()?);
            }
            SessionMutationIntent::FencedTransitionV2Batch(copied)
        }
        SessionMutationIntent::Authorized {
            origin,
            authority_identity,
            mutation,
        } if allow_authorized => SessionMutationIntent::Authorized {
            origin: *origin,
            authority_identity: *authority_identity,
            mutation: Box::new(intent(mutation, false)?),
        },
        _ => return Err(invalid("native owned log requires its command codec")),
    })
}

pub(super) fn entry(
    value: &Entry<SessionRaftTypeConfig>,
) -> io::Result<Entry<SessionRaftTypeConfig>> {
    let payload = match &value.payload {
        EntryPayload::Blank => EntryPayload::Blank,
        // Membership owns BTree containers of scalar node IDs and EmptyNode.
        EntryPayload::Membership(value) => EntryPayload::Membership(value.clone()),
        EntryPayload::Normal(value) => EntryPayload::Normal(SessionConsensusCommand {
            schema_version: value.schema_version,
            identity: value.identity,
            request_id: value.request_id,
            logical_time: value.logical_time,
            intent: intent(&value.intent, true)?,
        }),
    };
    Ok(Entry {
        log_id: value.log_id,
        payload,
    })
}

pub(super) fn notification(value: &ReplicationEntry) -> io::Result<ReplicationEntry> {
    use crate::backend::ReplicationOp;
    changes::notification_payload(value)?;
    fn effect(op: &ReplicationOp) -> io::Result<ReplicationOp> {
        Ok(match op {
            ReplicationOp::AcquireLease {
                key: session_key,
                owner,
                fence,
                credential_id,
                ttl,
                expires_at,
            } => ReplicationOp::AcquireLease {
                key: key(session_key)?,
                owner: owner.clone(),
                fence: *fence,
                credential_id: *credential_id,
                ttl: *ttl,
                expires_at: *expires_at,
            },
            ReplicationOp::RenewLease {
                key: session_key,
                owner,
                fence,
                credential_id,
                ttl,
                expires_at,
            } => ReplicationOp::RenewLease {
                key: key(session_key)?,
                owner: owner.clone(),
                fence: *fence,
                credential_id: *credential_id,
                ttl: *ttl,
                expires_at: *expires_at,
            },
            ReplicationOp::CompareAndSet {
                key: session_key,
                expected_generation,
                credential_id,
                guard_expires_at,
                new_record,
            } => ReplicationOp::CompareAndSet {
                key: key(session_key)?,
                expected_generation: *expected_generation,
                credential_id: *credential_id,
                guard_expires_at: *guard_expires_at,
                new_record: record(new_record)?,
            },
            ReplicationOp::DeleteFenced {
                key: session_key,
                owner,
                fence,
            } => ReplicationOp::DeleteFenced {
                key: key(session_key)?,
                owner: owner.clone(),
                fence: *fence,
            },
            ReplicationOp::RefreshTtl {
                key: session_key,
                owner,
                fence,
                ttl,
                expires_at,
            } => ReplicationOp::RefreshTtl {
                key: key(session_key)?,
                owner: owner.clone(),
                fence: *fence,
                ttl: *ttl,
                expires_at: *expires_at,
            },
            ReplicationOp::ReleaseLease {
                key: session_key,
                owner,
                fence,
                credential_id,
            } => ReplicationOp::ReleaseLease {
                key: key(session_key)?,
                owner: owner.clone(),
                fence: *fence,
                credential_id: *credential_id,
            },
            ReplicationOp::ProtectedRosterEstablished {
                key: session_key,
                expected_record,
                successor,
                owner,
                fence,
                credential_id,
                guard_acquired_at,
                guard_expires_at,
            } => {
                use crate::backend::ProtectedRosterEstablishedSuccessor as Successor;
                let successor = match &**successor {
                    Successor::Put { record: value } => Successor::Put {
                        record: Box::new(record(value)?),
                    },
                    Successor::Delete => Successor::Delete,
                    Successor::NoOp => Successor::NoOp,
                };
                ReplicationOp::ProtectedRosterEstablished {
                    key: key(session_key)?,
                    expected_record: record(expected_record)?,
                    successor: Box::new(successor),
                    owner: owner.clone(),
                    fence: *fence,
                    credential_id: *credential_id,
                    guard_acquired_at: *guard_acquired_at,
                    guard_expires_at: *guard_expires_at,
                }
            }
            ReplicationOp::ProtectedRosterEstablishedCreate {
                key: session_key,
                record: value,
                owner,
                fence,
                credential_id,
                guard_acquired_at,
                guard_expires_at,
            } => ReplicationOp::ProtectedRosterEstablishedCreate {
                key: key(session_key)?,
                record: record(value)?,
                owner: owner.clone(),
                fence: *fence,
                credential_id: *credential_id,
                guard_acquired_at: *guard_acquired_at,
                guard_expires_at: *guard_expires_at,
            },
            _ => {
                return Err(invalid(
                    "native owned notification requires its effect codec",
                ))
            }
        })
    }
    let op = if let ReplicationOp::Batch { ops } = &value.op {
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(2)
            .map_err(|_| invalid("native owned notification allocation failed"))?;
        for op in ops {
            copied.push(effect(op)?);
        }
        ReplicationOp::Batch { ops: copied }
    } else {
        effect(&value.op)?
    };
    Ok(ReplicationEntry {
        sequence: value.sequence,
        tx_id: value.tx_id.clone(),
        op,
        timestamp: value.timestamp,
    })
}

pub(super) fn ordinary_response(
    value: &SessionConsensusResponse,
) -> io::Result<SessionConsensusResponse> {
    use crate::backend::CompareAndSetResult;
    let result = match &value.result {
        Ok(SessionMutationOutcome::Unit) => Ok(SessionMutationOutcome::Unit),
        Ok(SessionMutationOutcome::Lease(value)) => {
            Ok(SessionMutationOutcome::Lease(lease(value)?))
        }
        Ok(SessionMutationOutcome::ConsumerRecord(value)) => Ok(
            SessionMutationOutcome::ConsumerRecord(value.as_ref().map(record).transpose()?),
        ),
        Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success)) => Ok(
            SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success),
        ),
        Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict { current })) => Ok(
            SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                current: current.as_ref().map(record).transpose()?,
            }),
        ),
        Err(error) if business::deterministic(error) => Err(error.clone()),
        _ => {
            return Err(invalid(
                "native owned generic receipt requires its response codec",
            ))
        }
    };
    Ok(SessionConsensusResponse {
        result,
        sequence: value.sequence,
        digest: value.digest,
        logical_time: value.logical_time,
        raft_log_index: value.raft_log_index,
    })
}
