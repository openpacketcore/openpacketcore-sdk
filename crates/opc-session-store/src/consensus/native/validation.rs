//! Shared business predicates. Cold admission still visits every retained row;
//! live transitions validate every changed row with these same functions.

use super::*;

pub(super) const MAX_ITEMS: usize = 1_048_576;

pub(super) fn validate_key(
    key: &SessionKey,
    value: &NativeKeyState,
    frontiers: &NativeFrontiers,
) -> io::Result<()> {
    if value.fence > COUNTER_MAX || value.fence >= frontiers.next_fence {
        return Err(invalid("native key floor invalid"));
    }
    if let Some(lease) = &value.lease {
        let expires = crate::sqlite::ops::timestamp_unix_millis(lease.guard_expires_at)
            .map_err(|_| invalid("native image lease expiry invalid"))?;
        if lease.fence.get() == 0
            || lease.fence.get() > value.fence
            || lease.credential_id == 0
            || lease.credential_id >= frontiers.next_credential
            || lease
                .acquired_at
                .is_some_and(|time| time > lease.guard_expires_at)
            || (lease.active && lease.expires_at_unix_ms != expires)
            || (!lease.active && lease.expires_at_unix_ms < expires)
        {
            return Err(invalid(
                "native image lease frontier or stored expiry differs",
            ));
        }
    }
    if let Some(record) = &value.record {
        crate::sqlite::validate_consensus_record(record)
            .map_err(|_| invalid("native image record invalid"))?;
        if &record.key != key || record.fence.get() > value.fence {
            return Err(invalid("native image record key or fence differs"));
        }
    }
    Ok(())
}

pub(super) fn validate_receipt(
    identity: SessionConsensusIdentity,
    id: &FencedTransitionV2RequestId,
    receipt: &NativeReceipt,
    frontiers: &NativeFrontiers,
    history: FencedTransitionV2HistoryState,
) -> io::Result<()> {
    lifecycle::validate_ordinal(history, *id, receipt.ordinal)?;
    if !fenced_transition_v2_timestamp_is_in_range(receipt.retained_until) {
        return Err(invalid("native image receipt ordinal or epoch invalid"));
    }
    let canonical = crate::sqlite::consensus::fenced_transition_v2_payload_digest_for_request_id(
        identity,
        id.to_bytes(),
    )?;
    if canonical != receipt.payload_digest
        || history
            .active_epoch()
            .is_none_or(|active| id.epoch().get() > active.get())
    {
        return Err(invalid(
            "native image receipt key digest or represented epoch differs",
        ));
    }
    validate_receipt_frontier(receipt, frontiers)?;
    if let Some(response) = receipt.response_facts()? {
        if retention_deadline(response.logical_time) != Some(receipt.retained_until) {
            return Err(invalid("native image receipt retention differs"));
        }
    }
    if let Some(response) = &receipt.response {
        crate::sqlite::consensus::encode_fenced_transition_v2_response(response)?;
    }
    if receipt.cold.is_some() {
        use resident::RowFingerprint;
        receipt.row_fingerprint(1, id)?;
    }
    Ok(())
}

pub(super) fn validate_generic(
    id: &SessionConsensusRequestId,
    receipt: &NativeGenericReceipt,
    frontiers: &NativeFrontiers,
) -> io::Result<()> {
    if let NativeGenericReceipt::FencedV1(row) = receipt {
        v1::validate_receipt(id, row, frontiers)?;
    }
    if let Some(response) = receipt.response() {
        if response.sequence == 0
            || response.sequence > frontiers.sequence
            || response.digest.is_none()
            || response
                .logical_time
                .is_none_or(|time| frontiers.logical_time.is_none_or(|current| time > current))
            || frontiers
                .applied
                .is_none_or(|applied| response.raft_log_index > applied.index)
        {
            return Err(invalid("native request receipt frontier invalid"));
        }
    }
    let NativeGenericReceipt::Ordinary(receipt) = receipt else {
        return Ok(());
    };
    if receipt.response.sequence == 0
        || receipt.response.sequence > frontiers.sequence
        || receipt.response.digest.is_none()
        || receipt
            .response
            .logical_time
            .is_none_or(|time| frontiers.logical_time.is_none_or(|current| time > current))
        || frontiers
            .applied
            .is_none_or(|applied| receipt.response.raft_log_index > applied.index)
    {
        return Err(invalid("native generic receipt frontier invalid"));
    }
    changes::ordinary_payload(receipt)?;
    match &receipt.response.result {
        Ok(SessionMutationOutcome::Lease(guard)) => guard
            .validate_profile()
            .map_err(|_| invalid("native generic lease invalid"))?,
        Ok(
            SessionMutationOutcome::ConsumerRecord(Some(record))
            | SessionMutationOutcome::CompareAndSet(crate::backend::CompareAndSetResult::Conflict {
                current: Some(record),
            }),
        ) => {
            crate::sqlite::validate_consensus_record(record)
                .map_err(|_| invalid("native generic retained record invalid"))?;
            if record.payload.len() > crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES {
                return Err(invalid(
                    "native generic retained payload exceeds materialized bound",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn validate_notification(
    notification: &ReplicationEntry,
    sequence: u64,
    frontiers: &NativeFrontiers,
) -> io::Result<()> {
    notification
        .validate()
        .map_err(|_| invalid("native image notification invalid"))?;
    if notification.sequence != sequence
        || frontiers
            .logical_time
            .is_none_or(|now| notification.timestamp > now)
    {
        return Err(invalid("native notification frontier differs"));
    }
    Ok(())
}

pub(super) fn validate_frontiers(
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    frontiers: &NativeFrontiers,
    counts: [usize; 4],
    origin: Option<&NativeSnapshotAuthority>,
) -> io::Result<()> {
    let [keys, receipts, generic, notifications] = counts;
    if !matches!(members.len(), 3 | 5)
        || [keys, generic, notifications]
            .into_iter()
            .any(|count| count > MAX_ITEMS)
        || logically_invalid_membership(members, frontiers)
        || frontiers.sequence > COUNTER_MAX
        || frontiers.watch_sequence > COUNTER_MAX
        || frontiers.restore_revision > COUNTER_MAX
        || !(1..=COUNTER_MAX).contains(&frontiers.next_fence)
        || !(1..=COUNTER_MAX).contains(&frontiers.next_credential)
        || (frontiers.sequence == 0 && frontiers.digest != SessionConsensusEntryDigest::GENESIS)
        || (frontiers.sequence > 0 && frontiers.logical_time.is_none())
    {
        return Err(invalid("native image frontiers invalid"));
    }
    match (frontiers.history, &frontiers.activation) {
        (None, None) if receipts == 0 => {}
        (Some(history), Some(activation)) => {
            FencedTransitionV2HistoryState::new(
                history.active_epoch(),
                history.retired_through(),
                history.reclaim_epoch(),
                history.reclaim_remaining(),
                history.generation(),
                history.bound_entries(),
                history.reclaimed_entries(),
            )
            .map_err(|_| invalid("native image history invalid"))?;
            if activation.identity != identity
                || activation.voters != fenced_transition_voter_set_digest(identity, members)
                || activation.profile != fenced_transition_v2_profile_digest()
                || lifecycle::receipt_count(Some(history))? != receipts
            {
                return Err(invalid("native image activation or receipt count differs"));
            }
        }
        _ => return Err(invalid("native image history and activation differ")),
    }
    if frontiers
        .v1_activation
        .as_ref()
        .is_some_and(|activation| !v1::activation_matches(activation, identity, members))
    {
        return Err(invalid("native V1 capability certificate differs"));
    }
    roster::validate_activation(identity, members, frontiers)?;
    if notifications as u64 != frontiers.watch_sequence {
        return Err(invalid("native image watch count differs"));
    }
    if let Some(snapshot) = &frontiers.current_snapshot {
        validate_snapshot(snapshot, frontiers, origin)?;
    }
    Ok(())
}

pub(super) fn validate_snapshot_metadata(
    snapshot: &crate::sqlite::consensus::CurrentSnapshot,
) -> io::Result<()> {
    let (meta, name, _, length) = snapshot;
    validate_snapshot_metadata_parts(&meta.snapshot_id, name, *length)
}

pub(super) fn validate_snapshot_metadata_parts(
    snapshot_id: &str,
    name: &str,
    length: u64,
) -> io::Result<()> {
    crate::sqlite::consensus::validate_published_snapshot_file_name(name)?;
    if length == 0
        || length > crate::consensus::snapshot::SNAPSHOT_ENVELOPE_MAX_BYTES
        || snapshot_id.len() > 256
    {
        return Err(invalid("native current snapshot metadata invalid"));
    }
    Ok(())
}

pub(super) fn validate_snapshot(
    snapshot: &crate::sqlite::consensus::CurrentSnapshot,
    frontiers: &NativeFrontiers,
    origin: Option<&NativeSnapshotAuthority>,
) -> io::Result<()> {
    validate_snapshot_metadata(snapshot)?;
    let meta = &snapshot.0;
    let installed = origin.is_some_and(|origin| origin.matches_snapshot(snapshot));
    if !installed && meta.last_membership != frontiers.membership {
        return Err(invalid("native current snapshot membership differs"));
    }
    match meta.last_log_id {
        Some(applied) => crate::sqlite::consensus::ensure_log_id_not_after(
            &applied,
            &frontiers
                .applied
                .ok_or_else(|| invalid("native state applied missing"))?,
            "native snapshot is ahead of applied state",
        ),
        None if installed && meta.last_membership == StoredMembership::default() => Ok(()),
        None => Err(invalid(
            "native empty snapshot lacks its original installed authority",
        )),
    }
}

fn logically_invalid_membership(
    members: &BTreeSet<SessionConsensusNodeId>,
    frontiers: &NativeFrontiers,
) -> bool {
    let membership = &frontiers.membership;
    match (frontiers.applied, membership.log_id()) {
        (None, None) => false,
        (Some(applied), Some(membership_id)) => {
            membership_id.index > applied.index
                || membership.membership().get_joint_config().len() != 1
                || membership.membership().voter_ids().collect::<BTreeSet<_>>() != *members
                || membership
                    .membership()
                    .nodes()
                    .map(|(id, _)| *id)
                    .collect::<BTreeSet<_>>()
                    != *members
        }
        _ => true,
    }
}

impl NativeState {
    pub(super) fn validate_full_business(&self) -> io::Result<history_order::ReceiptOrder> {
        let order = self.validate_full_business_rows()?;
        self.admit_full_roster(&|| Ok(()))?;
        Ok(order)
    }

    pub(super) fn validate_full_business_rows(&self) -> io::Result<history_order::ReceiptOrder> {
        let frontiers = &self.frontiers;
        validate_frontiers(
            self.identity,
            &self.members,
            frontiers,
            [
                self.keys.len(),
                self.receipts.len(),
                self.generic_receipts.len(),
                self.notifications.len(),
            ],
            self.snapshot_origin.as_deref(),
        )?;
        for (key, row) in &self.keys {
            validate_key(key, row, frontiers)?;
        }
        // Cold admission clears the proof before entering this validator and
        // must construct the complete independent ordinal index. An already
        // published image can share its immutable paths, but still validates
        // every row below and the complete index/row bijection afterward.
        let admitted = self
            .proof
            .as_ref()
            .and_then(|_| self.require_business_proof().ok());
        let mut receipt_order = match admitted {
            Some(proof) => proof.receipt_order.clone(),
            None => history_order::ReceiptOrder::preparing(frontiers.history)?,
        };
        if let Some(history) = frontiers.history {
            for (id, row) in &self.receipts {
                validate_receipt(self.identity, id, row, frontiers, history)?;
                if admitted.is_none() {
                    receipt_order.insert_cold(*id, row.ordinal, row.retained_until)?;
                }
            }
        }
        receipt_order.validate(frontiers.history)?;
        if admitted.is_some() {
            receipt_order.validate_rows(&self.receipts)?;
        }
        let mut v1_count = 0usize;
        for (id, row) in &self.generic_receipts {
            validate_generic(id, row, frontiers)?;
            v1_count += usize::from(matches!(&**row, NativeGenericReceipt::FencedV1(_)));
        }
        if v1_count > crate::fenced_transition::FENCED_TRANSITION_MAX_HISTORY_ENTRIES {
            return Err(invalid("native V1 receipt count exceeds lifetime bound"));
        }
        for (ordinal, row) in self.notifications.iter().enumerate() {
            row.validate(ordinal as u64 + 1, frontiers)?;
        }
        Ok(receipt_order)
    }
}
