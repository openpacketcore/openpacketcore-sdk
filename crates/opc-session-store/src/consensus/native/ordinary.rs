//! Ordinary commands preserve the established savepoint contract: deterministic
//! rejection discards the whole business effect, including global expiry
//! pruning, while binding the response and advancing the application clock.
//! A successful CAS conflict commits pruning and emits no watch event.

use super::*;
use crate::backend::{CompareAndSet, CompareAndSetResult, ReplicationOp};
use crate::ttl::checked_session_deadline;

struct Transaction<'a, 'state> {
    base: &'a NativeDelta<'state>,
    frontiers: NativeFrontiers,
    keys: HashMap<SessionKey, NativeKeyState>,
    expiry: expiry::ExpiryIndex,
    now: Timestamp,
}

impl NativeDelta<'_> {
    pub(super) fn ordinary(
        &mut self,
        command: &SessionConsensusCommand,
        intent: &SessionMutationIntent,
        authorized: bool,
        now: Timestamp,
        index: u64,
    ) -> io::Result<SessionConsensusResponse> {
        let payload_digest = crate::sqlite::consensus::payload_digest(self.base.identity, command)?;
        if let Some(receipt) = self.request_receipt(&command.request_id) {
            let NativeGenericReceipt::Ordinary(receipt) = receipt else {
                return Ok(self.response(index, Err(StoreError::CasIdempotencyConflict)));
            };
            return Ok(if receipt.payload_digest == payload_digest {
                receipt.response.clone()
            } else {
                self.response(index, Err(StoreError::CasIdempotencyConflict))
            });
        }
        let sequence = self
            .frontiers
            .sequence
            .checked_add(1)
            .filter(|next| *next <= COUNTER_MAX)
            .ok_or_else(|| invalid("native application sequence exhausted"))?;
        let digest = command
            .calculate_applied_digest(sequence, self.frontiers.digest, now)
            .map_err(|_| invalid("native ordinary command digest failed"))?;
        let mut transaction = Transaction {
            base: self,
            frontiers: self.frontiers.clone(),
            keys: HashMap::new(),
            expiry: self.expiry.clone(),
            now,
        };
        let executed = if authorized {
            transaction.execute(intent)
        } else {
            Err(StoreError::TopologyAuthorityRevoked)
        };
        let (result, replication) = match executed {
            Ok((outcome, replication)) => {
                let Transaction {
                    frontiers,
                    keys,
                    expiry,
                    ..
                } = transaction;
                self.frontiers = frontiers;
                self.expiry = expiry;
                self.keys.extend(keys);
                (Ok(outcome), replication)
            }
            Err(error) if business::deterministic(&error) => (Err(error), None),
            Err(_) => return Err(invalid("native ordinary business infrastructure fault")),
        };
        self.frontiers.sequence = sequence;
        self.frontiers.digest = digest;
        self.frontiers.logical_time = Some(now);
        if let Some(op) = replication {
            let sequence = self
                .frontiers
                .watch_sequence
                .checked_add(1)
                .filter(|next| *next <= COUNTER_MAX)
                .ok_or_else(|| invalid("native ordinary watch sequence exhausted"))?;
            let notification = ReplicationEntry {
                sequence,
                tx_id: ReplicationTxId::from_request_bytes(*command.request_id.as_bytes()),
                op,
                timestamp: now,
            };
            notification
                .validate()
                .map_err(|_| invalid("native ordinary notification invalid"))?;
            self.frontiers.watch_sequence = sequence;
            self.notifications.push(notification);
        }
        let response = self.response(index, result);
        self.generic_receipts.insert(
            command.request_id,
            NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
                payload_digest,
                response: response.clone(),
            }),
        );
        self.compact_one_v1(now)?;
        Ok(response)
    }
}

impl Transaction<'_, '_> {
    fn key(&self, key: &SessionKey) -> NativeKeyState {
        self.keys
            .get(key)
            .cloned()
            .unwrap_or_else(|| self.base.key(key))
    }

    fn set_key(&mut self, key: SessionKey, row: NativeKeyState) {
        self.expiry.replace(&key, Some(&self.key(&key)), Some(&row));
        self.keys.insert(key, row);
    }

    fn revision(&mut self) -> Result<(), StoreError> {
        self.frontiers.restore_revision = self
            .frontiers
            .restore_revision
            .checked_add(1)
            .filter(|next| *next <= COUNTER_MAX)
            .ok_or_else(unavailable)?;
        Ok(())
    }

    fn prune(&mut self) -> Result<(), StoreError> {
        let mut records_removed = false;
        while let Some(key) = self.expiry.due_record(self.now) {
            let mut row = self.key(&key);
            if row
                .record
                .as_ref()
                .and_then(|record| record.expires_at)
                .is_none_or(|until| until > self.now)
            {
                return Err(unavailable());
            }
            row.record = None;
            self.set_key(key, row);
            records_removed = true;
        }
        if records_removed {
            self.revision()?;
        }
        while let Some(key) = self.expiry.due_lease(self.now) {
            let mut row = self.key(&key);
            if row
                .lease
                .as_ref()
                .is_none_or(|lease| lease.active && lease.guard_expires_at > self.now)
            {
                return Err(unavailable());
            }
            row.lease = None;
            self.set_key(key, row);
        }
        Ok(())
    }

    fn unreserved(&self, key: &SessionKey) -> Result<(), StoreError> {
        if self.key(key).reserved {
            Err(StoreError::SessionRecordReserved)
        } else {
            Ok(())
        }
    }

    fn mutation_guard(&self, guard: &LeaseGuard) -> Result<NativeKeyState, StoreError> {
        if guard.expires_at() <= self.now {
            return Err(StoreError::LeaseExpired);
        }
        let row = self.key(guard.key());
        if !row.lease.as_ref().is_some_and(|lease| lease.matches(guard))
            || guard.fence().get() < row.fence
        {
            return Err(StoreError::StaleFence);
        }
        Ok(row)
    }

    fn lease_guard(&self, guard: &LeaseGuard) -> Result<NativeKeyState, StoreError> {
        let row = self.key(guard.key());
        let Some(lease) = &row.lease else {
            return Err(if guard.fence().get() <= row.fence {
                StoreError::StaleFence
            } else {
                StoreError::NotFound
            });
        };
        if !lease.active || lease.credential_id != guard.credential_id() {
            return Err(StoreError::StaleFence);
        }
        if lease.owner != *guard.owner() {
            return Err(StoreError::LeaseHeld);
        }
        if !lease.matches(guard) {
            return Err(StoreError::StaleFence);
        }
        Ok(row)
    }

    fn execute(
        &mut self,
        intent: &SessionMutationIntent,
    ) -> Result<(SessionMutationOutcome, Option<ReplicationOp>), StoreError> {
        match intent {
            SessionMutationIntent::AdvanceLogicalTime
            | SessionMutationIntent::BindConsumerRequest { .. }
            | SessionMutationIntent::ActivateFencedTransitionCapability { .. } => {
                Ok((SessionMutationOutcome::Unit, None))
            }
            SessionMutationIntent::ActivateProtectedRosterProfileV2 {
                schema_version,
                consumer_revision,
                scope_identity,
                voter_set_digest,
                profile_digest,
            } => {
                let profile = crate::fenced_mutation_roster::Profile::v2();
                if *schema_version != profile.schema()
                    || *consumer_revision != profile.consumer_revision()
                    || *scope_identity != self.base.base.identity
                    || *voter_set_digest
                        != super::super::types::protected_roster_profile_v2_voter_set_digest(
                            self.base.base.identity,
                            &self.base.base.members,
                        )
                    || *profile_digest != profile.digest()
                {
                    return Err(StoreError::CapabilityNotSupported(
                        "protected_roster_profile_v2_activation_rejected".into(),
                    ));
                }
                self.frontiers.roster_v2_activation = Some(NativeActivation {
                    identity: *scope_identity,
                    voters: *voter_set_digest,
                    profile: *profile_digest,
                });
                Ok((SessionMutationOutcome::Unit, None))
            }
            SessionMutationIntent::ReadConsumerRecord { key } => {
                let record = self
                    .key(key)
                    .record
                    .filter(|record| record.expires_at.is_none_or(|until| until > self.now));
                if let Some(record) = &record {
                    crate::sqlite::validate_consensus_record(record)?;
                }
                Ok((SessionMutationOutcome::ConsumerRecord(record), None))
            }
            SessionMutationIntent::AcquireLease { key, owner, ttl } => {
                let expires_at = checked_session_deadline(self.now, *ttl)?;
                self.prune()?;
                let mut row = self.key(key);
                if row.lease.as_ref().is_some_and(|lease| {
                    lease.active && lease.owner != *owner && lease.guard_expires_at > self.now
                }) {
                    return Err(StoreError::LeaseHeld);
                }
                let fence = self
                    .frontiers
                    .next_fence
                    .max(row.fence.checked_add(1).ok_or_else(unavailable)?);
                let next_fence = fence
                    .checked_add(1)
                    .filter(|next| *next <= COUNTER_MAX)
                    .ok_or_else(unavailable)?;
                let credential = self.frontiers.next_credential;
                let next_credential = credential
                    .checked_add(1)
                    .filter(|next| *next <= COUNTER_MAX)
                    .ok_or_else(unavailable)?;
                if fence == 0 || credential == 0 {
                    return Err(unavailable());
                }
                let guard = LeaseGuard::new(
                    key.clone(),
                    owner.clone(),
                    crate::FenceToken::new(fence),
                    self.now,
                    expires_at,
                    credential,
                );
                row.lease = Some(NativeLease::from_guard(&guard)?);
                row.fence = fence;
                self.frontiers.next_fence = next_fence;
                self.frontiers.next_credential = next_credential;
                self.set_key(key.clone(), row);
                Ok((
                    SessionMutationOutcome::Lease(guard.clone()),
                    Some(ReplicationOp::AcquireLease {
                        key: key.clone(),
                        owner: owner.clone(),
                        fence: guard.fence(),
                        credential_id: credential,
                        ttl: *ttl,
                        expires_at,
                    }),
                ))
            }
            SessionMutationIntent::RenewLease { lease: guard, ttl } => {
                let expires_at = checked_session_deadline(self.now, *ttl)?;
                if guard.expires_at() <= self.now {
                    return Err(StoreError::LeaseExpired);
                }
                self.prune()?;
                let mut row = self.lease_guard(guard)?;
                let renewed = LeaseGuard::new(
                    guard.key().clone(),
                    guard.owner().clone(),
                    guard.fence(),
                    guard.acquired_at(),
                    expires_at,
                    guard.credential_id(),
                );
                row.lease = Some(NativeLease::from_guard(&renewed)?);
                self.set_key(guard.key().clone(), row);
                Ok((
                    SessionMutationOutcome::Lease(renewed),
                    Some(ReplicationOp::RenewLease {
                        key: guard.key().clone(),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                        credential_id: guard.credential_id(),
                        ttl: *ttl,
                        expires_at,
                    }),
                ))
            }
            SessionMutationIntent::ReleaseLease(guard) => {
                self.prune()?;
                let mut row = self.lease_guard(guard)?;
                let lease = row.lease.as_mut().ok_or_else(unavailable)?;
                lease.active = false;
                // The released row retains its original physical expiry column.
                lease.guard_expires_at = self.now;
                self.set_key(guard.key().clone(), row);
                Ok((
                    SessionMutationOutcome::Unit,
                    Some(ReplicationOp::ReleaseLease {
                        key: guard.key().clone(),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                        credential_id: guard.credential_id(),
                    }),
                ))
            }
            SessionMutationIntent::CompareAndSet(op) => self.compare_and_set(op),
            SessionMutationIntent::DeleteFenced(guard) => {
                self.unreserved(guard.key())?;
                self.prune()?;
                let mut row = self.mutation_guard(guard)?;
                if row.record.take().is_some() {
                    self.revision()?;
                }
                row.fence = guard.fence().get();
                self.set_key(guard.key().clone(), row);
                Ok((
                    SessionMutationOutcome::Unit,
                    Some(ReplicationOp::DeleteFenced {
                        key: guard.key().clone(),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                    }),
                ))
            }
            SessionMutationIntent::RefreshTtl { lease: guard, ttl } => {
                self.unreserved(guard.key())?;
                let expires_at = checked_session_deadline(self.now, *ttl)?;
                self.prune()?;
                let mut row = self.mutation_guard(guard)?;
                row.record.as_mut().ok_or(StoreError::NotFound)?.expires_at = Some(expires_at);
                self.revision()?;
                row.fence = guard.fence().get();
                self.set_key(guard.key().clone(), row);
                Ok((
                    SessionMutationOutcome::Unit,
                    Some(ReplicationOp::RefreshTtl {
                        key: guard.key().clone(),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                        ttl: *ttl,
                        expires_at,
                    }),
                ))
            }
            _ => Err(unavailable()),
        }
    }

    fn compare_and_set(
        &mut self,
        op: &CompareAndSet,
    ) -> Result<(SessionMutationOutcome, Option<ReplicationOp>), StoreError> {
        self.unreserved(&op.key)?;
        if op.new_record.payload.encoding() != crate::record::SessionPayloadEncoding::EnvelopeV1 {
            return Err(StoreError::Serialization(
                "session consensus requires a sealed record payload".into(),
            ));
        }
        crate::ttl::validate_stored_record_expiry_at(&op.new_record, self.now)?;
        self.prune()?;
        if op.lease.key() != &op.key {
            return Err(StoreError::InvalidKey(
                "compare-and-set key does not match lease key".into(),
            ));
        }
        if op.new_record.key != op.key {
            return Err(StoreError::InvalidKey(
                "compare-and-set key does not match record key".into(),
            ));
        }
        if op.new_record.owner != *op.lease.owner() || op.new_record.fence != op.lease.fence() {
            return Err(StoreError::StaleFence);
        }
        if op.new_record.payload.len() > crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES {
            return Err(StoreError::PayloadTooLarge {
                actual: op.new_record.payload.len(),
                max: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            });
        }
        let mut row = self.mutation_guard(&op.lease)?;
        let success = match (op.expected_generation, row.record.as_ref()) {
            (None, None) => true,
            (Some(expected), Some(current)) => {
                current.generation == expected
                    && (!(current.state_class.requires_monotonic_generation()
                        || op.new_record.state_class.requires_monotonic_generation())
                        || op.new_record.generation > current.generation)
            }
            _ => false,
        };
        if !success {
            return Ok((
                SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                    current: row.record,
                }),
                None,
            ));
        }
        crate::sqlite::validate_consensus_record(&op.new_record)?;
        if op.new_record.generation.get() > COUNTER_MAX || op.new_record.fence.get() > COUNTER_MAX {
            return Err(unavailable());
        }
        row.record = Some(op.new_record.clone());
        row.fence = op.lease.fence().get();
        self.revision()?;
        self.set_key(op.key.clone(), row);
        Ok((
            SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success),
            Some(ReplicationOp::CompareAndSet {
                key: op.key.clone(),
                expected_generation: op.expected_generation,
                credential_id: op.lease.credential_id(),
                guard_expires_at: op.lease.expires_at(),
                new_record: op.new_record.clone(),
            }),
        ))
    }
}
