//! The original 16-byte request namespace and permanent V1 tombstones. The
//! shared binding map makes an ordinary/V1 collision impossible to publish.
//! Only the scalar capability certificate lives in the generation header.

use super::*;
use crate::fenced_transition::FENCED_TRANSITION_MAX_HISTORY_ENTRIES;
use crate::sqlite::consensus as sql;
use crate::{FencedTransitionRequest, FencedTransitionStatus};

#[cfg(test)]
#[path = "v1_tests.rs"]
pub(super) mod tests;

impl NativeGenericReceipt {
    pub(super) fn response(&self) -> Option<&SessionConsensusResponse> {
        match self {
            Self::Ordinary(row) => Some(&row.response),
            Self::FencedV1(row) => row.response.as_deref(),
        }
    }

    pub(super) fn validate_replacement(
        &self,
        before: &Self,
        now: Option<Timestamp>,
    ) -> io::Result<()> {
        let valid = match (before, self) {
            (Self::Ordinary(before), Self::Ordinary(after)) => {
                before.payload_digest == after.payload_digest && before.response == after.response
            }
            (Self::FencedV1(before), Self::FencedV1(after)) => {
                before.payload_digest == after.payload_digest
                    && before.retained_until == after.retained_until
                    && (before.response == after.response
                        || (before.response.is_some()
                            && after.response.is_none()
                            && now.is_some_and(|now| after.retained_until <= now)))
            }
            _ => false,
        };
        if !valid {
            return Err(invalid(
                "native request receipt changes its immutable binding",
            ));
        }
        Ok(())
    }

    pub(super) fn owned_copy(&self) -> io::Result<Self> {
        Ok(match self {
            Self::Ordinary(row) => Self::Ordinary(NativeOrdinaryReceipt {
                payload_digest: row.payload_digest,
                response: Box::new(owned::ordinary_response(&row.response)?),
            }),
            Self::FencedV1(row) => Self::FencedV1(NativeV1Receipt {
                payload_digest: row.payload_digest,
                retained_until: row.retained_until,
                response: row
                    .response
                    .as_deref()
                    .map(cold::copy_response)
                    .transpose()?
                    .map(Box::new),
            }),
        })
    }
}

pub(super) fn activation_matches(
    activation: &NativeV1Activation,
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    activation.identity == identity
        && (activation.voters == fenced_transition_voter_set_digest(identity, members)
            || activation.voters
                == super::super::types::protected_roster_profile_voter_set_digest(
                    identity, members,
                ))
}

pub(super) fn validate_activation_transition(
    before: &NativeFrontiers,
    after: &NativeFrontiers,
) -> io::Result<()> {
    if let Some(before) = &before.v1_activation {
        let next = after
            .v1_activation
            .as_ref()
            .ok_or_else(|| invalid("native V1 activation cleared"))?;
        if before.identity != next.identity {
            return Err(invalid("native V1 activation identity changed"));
        }
        if before != next {
            let members = after.membership.membership().voter_ids().collect();
            if next.voters
                != super::super::types::protected_roster_profile_voter_set_digest(
                    next.identity,
                    &members,
                )
            {
                return Err(invalid("native V1 activation downgraded"));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_receipt(
    id: &SessionConsensusRequestId,
    row: &NativeV1Receipt,
    frontiers: &NativeFrontiers,
) -> io::Result<()> {
    if id.as_bytes().iter().all(|byte| *byte == 0) || frontiers.v1_activation.is_none() {
        return Err(invalid(
            "native V1 receipt lacks its request identity or activation",
        ));
    }
    sql::fenced_transition_receipt_binding_digest(
        frontiers
            .v1_activation
            .as_ref()
            .ok_or_else(|| invalid("native V1 activation absent"))?
            .identity,
        *id,
        row.payload_digest,
        &crate::sqlite::ops::format_rfc3339_normalized(row.retained_until),
    )?;
    if let Some(response) = &row.response {
        sql::validate_fenced_transition_receipt(row.retained_until, response)?;
        let _memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(
            4 * sql::FENCED_TRANSITION_RECEIPT_MAX_RESPONSE_BYTES + 64 * 1024,
        )?;
        let encoded = serde_json::to_vec(response)
            .map_err(|_| invalid("native V1 response cannot encode"))?;
        if encoded.len() > sql::FENCED_TRANSITION_RECEIPT_MAX_RESPONSE_BYTES {
            return Err(invalid("native V1 response exceeds original bound"));
        }
    } else if frontiers
        .logical_time
        .is_none_or(|now| row.retained_until > now)
    {
        return Err(invalid("native V1 response compacted before expiry"));
    }
    Ok(())
}

impl NativeState {
    pub(crate) fn v1_activation_matches(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> bool {
        identity == self.identity
            && members == &self.members
            && self
                .frontiers
                .v1_activation
                .as_ref()
                .is_some_and(|activation| activation_matches(activation, identity, members))
    }

    pub(crate) fn protected_roster_activation_matches(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> bool {
        self.v1_activation_matches(identity, members)
            && self
                .frontiers
                .v1_activation
                .as_ref()
                .is_some_and(|activation| {
                    activation.voters
                        == super::super::types::protected_roster_profile_voter_set_digest(
                            identity, members,
                        )
                })
    }

    pub(crate) fn status_v1(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<FencedTransitionStatus, StoreError> {
        request.validate()?;
        let id = SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes());
        let digest = sql::fenced_transition_payload_digest(self.identity, request)
            .map_err(|_| unavailable())?;
        if let Some(receipt) = self.generic_receipts.get(&id) {
            let NativeGenericReceipt::FencedV1(row) = &**receipt else {
                return Ok(FencedTransitionStatus::RequestConflict);
            };
            validation::validate_generic(&id, receipt, &self.frontiers)
                .map_err(|_| unavailable())?;
            if row.payload_digest != digest {
                return Ok(FencedTransitionStatus::RequestConflict);
            }
            if let Some(response) = &row.response {
                sql::validate_fenced_transition_response_for_request(request, response)
                    .map_err(|_| unavailable())?;
            }
            if row.response.is_none()
                || self
                    .frontiers
                    .logical_time
                    .is_some_and(|now| row.retained_until <= now)
            {
                return Ok(FencedTransitionStatus::Expired);
            }
            return Ok(FencedTransitionStatus::Recorded(Box::new(
                match &row.response.as_ref().ok_or_else(unavailable)?.result {
                    Ok(SessionMutationOutcome::FencedTransition(outcome)) => {
                        Ok(cold::copy_outcome(outcome).map_err(|_| unavailable())?)
                    }
                    Err(error) => Err(error.clone()),
                    _ => return Err(unavailable()),
                },
            )));
        }
        if self
            .require_business_proof()
            .map_err(|_| unavailable())?
            .expiry
            .v1_count()
            >= FENCED_TRANSITION_MAX_HISTORY_ENTRIES
        {
            return Ok(FencedTransitionStatus::HistoryFull);
        }
        if self.frontiers.logical_time.is_some_and(|now| {
            crate::ttl::checked_session_deadline(now, FENCED_TRANSITION_OUTCOME_RETENTION).is_err()
        }) {
            return Ok(FencedTransitionStatus::RetentionExhausted);
        }
        Ok(FencedTransitionStatus::NotFound)
    }
}

impl NativeDelta<'_> {
    pub(super) fn request_receipt(
        &self,
        id: &SessionConsensusRequestId,
    ) -> Option<&NativeGenericReceipt> {
        self.generic_receipts
            .get(id)
            .or_else(|| self.base.generic_receipts.get(id).map(|row| &**row))
    }

    fn put_request_receipt(
        &mut self,
        id: SessionConsensusRequestId,
        row: NativeGenericReceipt,
    ) -> io::Result<()> {
        let before = self.request_receipt(&id).cloned();
        self.expiry
            .replace_request(id, before.as_ref(), Some(&row))?;
        self.generic_receipts.insert(id, row);
        Ok(())
    }

    fn compact_v1(&mut self, id: SessionConsensusRequestId, now: Timestamp) -> io::Result<()> {
        let Some(NativeGenericReceipt::FencedV1(row)) = self.request_receipt(&id) else {
            return Ok(());
        };
        if row.response.is_some() && row.retained_until <= now {
            let row = NativeV1Receipt {
                payload_digest: row.payload_digest,
                retained_until: row.retained_until,
                response: None,
            };
            self.put_request_receipt(id, NativeGenericReceipt::FencedV1(row))?;
        }
        Ok(())
    }

    pub(super) fn compact_one_v1(&mut self, now: Timestamp) -> io::Result<()> {
        if let Some(id) = self.expiry.due_v1(now) {
            self.compact_v1(id, now)?;
        }
        Ok(())
    }

    pub(super) fn activate_v1(
        &mut self,
        activation: NativeV1Activation,
        allow_protected: bool,
    ) -> io::Result<()> {
        if !activation_matches(&activation, self.base.identity, &self.base.members)
            || (!allow_protected
                && activation.voters
                    != fenced_transition_voter_set_digest(self.base.identity, &self.base.members))
        {
            return Err(invalid("native V1 activation scope differs"));
        }
        let protected = super::super::types::protected_roster_profile_voter_set_digest(
            self.base.identity,
            &self.base.members,
        );
        if !self
            .frontiers
            .v1_activation
            .as_ref()
            .is_some_and(|existing| existing.voters == protected)
        {
            self.frontiers.v1_activation = Some(activation);
        }
        Ok(())
    }

    pub(super) fn fenced_v1(
        &mut self,
        command: &SessionConsensusCommand,
        request: &FencedTransitionRequest,
        activation: Option<NativeV1Activation>,
        authorized: bool,
        now: Timestamp,
        index: u64,
    ) -> io::Result<SessionConsensusResponse> {
        if !authorized && self.frontiers.v1_activation.is_none() {
            return Ok(self.clock_response(now, index, StoreError::TopologyAuthorityRevoked));
        }
        if authorized {
            if let Some(activation) = activation {
                self.activate_v1(activation, false)?;
            } else if self.frontiers.v1_activation.is_none() {
                return Err(invalid("native V1 transition lacks exact activation"));
            }
        }
        let payload_digest = sql::payload_digest(self.base.identity, command)?;
        if let Some(receipt) = self.request_receipt(&command.request_id) {
            let replayed = match receipt {
                NativeGenericReceipt::Ordinary(_) => {
                    self.response(index, Err(StoreError::FencedTransitionRequestConflict))
                }
                NativeGenericReceipt::FencedV1(row) => {
                    if row.payload_digest != payload_digest {
                        self.response(index, Err(StoreError::FencedTransitionRequestConflict))
                    } else {
                        if let Some(response) = &row.response {
                            sql::validate_fenced_transition_response_for_request(
                                request, response,
                            )?;
                        }
                        if row.response.is_none() || row.retained_until <= now {
                            let response = self
                                .response(index, Err(StoreError::FencedTransitionRequestExpired));
                            self.compact_v1(command.request_id, now)?;
                            response
                        } else {
                            row.response
                                .as_deref()
                                .ok_or_else(|| invalid("native V1 retained response absent"))?
                                .clone()
                        }
                    }
                }
            };
            self.frontiers.logical_time = Some(now);
            return Ok(if authorized {
                replayed
            } else {
                self.response(index, Err(StoreError::TopologyAuthorityRevoked))
            });
        }
        if self.expiry.v1_count() >= FENCED_TRANSITION_MAX_HISTORY_ENTRIES {
            self.compact_one_v1(now)?;
            return Ok(self.clock_response(
                now,
                index,
                if authorized {
                    StoreError::FencedTransitionHistoryFull
                } else {
                    StoreError::TopologyAuthorityRevoked
                },
            ));
        }
        let Ok(retained_until) =
            crate::ttl::checked_session_deadline(now, FENCED_TRANSITION_OUTCOME_RETENTION)
        else {
            self.compact_one_v1(now)?;
            return Ok(self.clock_response(
                now,
                index,
                if authorized {
                    StoreError::FencedTransitionRetentionExhausted
                } else {
                    StoreError::TopologyAuthorityRevoked
                },
            ));
        };
        let terminal = self.frontiers.sequence >= COUNTER_MAX;
        let sequence = if terminal {
            self.frontiers.sequence
        } else {
            self.frontiers.sequence + 1
        };
        let digest = if terminal {
            self.frontiers.digest
        } else {
            command
                .calculate_applied_digest(sequence, self.frontiers.digest, now)
                .map_err(|_| invalid("native V1 applied digest invalid"))?
        };
        let executed = if authorized {
            business::transition_v1(
                request,
                &self.key(request.lease().key()),
                &self.frontiers,
                now,
            )
        } else {
            Err(StoreError::TopologyAuthorityRevoked)
        };
        let result = match executed {
            Ok(_) if terminal => Err(StoreError::FencedTransitionStorageExhausted),
            Ok(effect) => {
                let watch = self
                    .frontiers
                    .watch_sequence
                    .checked_add(1)
                    .filter(|next| *next <= COUNTER_MAX)
                    .ok_or_else(|| invalid("native V1 watch exhausted"))?;
                let notification = ReplicationEntry {
                    sequence: watch,
                    tx_id: ReplicationTxId::from_request_bytes(*command.request_id.as_bytes()),
                    op: effect.replication,
                    timestamp: now,
                };
                notification
                    .validate()
                    .map_err(|_| invalid("native V1 notification invalid"))?;
                self.set_key(effect.key, effect.value);
                self.frontiers.next_fence = effect.next_fence;
                self.frontiers.next_credential = effect.next_credential;
                self.frontiers.restore_revision += 1;
                self.frontiers.watch_sequence = watch;
                self.notifications.push(notification);
                Ok(SessionMutationOutcome::FencedTransition(effect.outcome))
            }
            Err(error) if sql::is_persistable_fenced_transition_error(&error) => Err(error),
            Err(_) => return Err(invalid("native V1 business infrastructure fault")),
        };
        self.frontiers.sequence = sequence;
        self.frontiers.digest = digest;
        self.frontiers.logical_time = Some(now);
        let response = self.response(index, result);
        sql::validate_fenced_transition_receipt(retained_until, &response)?;
        self.put_request_receipt(
            command.request_id,
            NativeGenericReceipt::FencedV1(NativeV1Receipt {
                payload_digest,
                retained_until,
                response: Some(Box::new(response.clone())),
            }),
        )?;
        self.compact_one_v1(now)?;
        Ok(response)
    }
}
