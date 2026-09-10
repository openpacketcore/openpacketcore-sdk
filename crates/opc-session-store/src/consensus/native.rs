//! Private native committed state. The WAL adapter is the sole producer of
//! committed input; this module has no database connection. Selected reads
//! and application preparation use explicit captures outside the WAL mutex.
//!
//! A delta borrows one published state and overlays only touched keys and
//! receipts. Infrastructure failure discards it. Publication is owned by the
//! same mutex as every physical read; an unwind poisons/fences that owner.

mod application;
mod business;
mod changes;
mod expiry;
mod export;
mod history_order;
mod image;
mod lifecycle;
#[cfg(test)]
pub(crate) mod lifecycle_tests;
pub(crate) mod log;
mod ordinary;
pub(crate) mod roster;
mod shared;
mod v1;
mod validation;
pub(crate) use application::ApplicationCapture;
mod capture;
mod cold;
mod notification;
mod public_reads;
mod public_restore;
mod resident;
mod scratch;
use notification::NativeNotification;
pub(crate) mod owned;
mod reads;
pub(crate) use reads::{ReceiptCopies, ReceiptReads, ResolvedReceipts};
pub(crate) mod generation;
pub(crate) use capture::NativeChanges;
pub(crate) use changes::SnapshotSelection;
pub(crate) mod prefix;
use crate::sqlite::consensus::wal::snapshot::NativeSnapshotAuthority;
pub(crate) use image::snapshot_prefix;
use shared::SharedRow;

use im::{HashMap as ResidentMap, Vector as ResidentVector};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::sync::Arc;

use opc_consensus::engine::{EmptyNode, Entry, EntryPayload, LogId, StoredMembership};
use opc_types::Timestamp;
use serde::{Deserialize, Serialize};

use super::types::{
    fenced_transition_voter_set_digest, validate_fenced_transition_v2_batch,
    validate_fenced_transition_v2_batch_outcomes,
};
use super::{
    SessionConsensusCommand, SessionConsensusEntryDigest, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusRequestId, SessionConsensusResponse,
    SessionMutationIntent, SessionMutationOutcome, SessionRaftTypeConfig,
};
use crate::backend::{ReplicationEntry, ReplicationTxId};
use crate::fenced_transition::{
    fenced_transition_v2_outer_request_id, fenced_transition_v2_profile_digest,
    fenced_transition_v2_timestamp_is_in_range, FencedTransitionOutcome,
    FencedTransitionV2HistoryState, FencedTransitionV2Request, FencedTransitionV2RequestId,
    FencedTransitionV2Status, FENCED_TRANSITION_OUTCOME_RETENTION,
    FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
};
use crate::lease::LeaseGuard;
use crate::model::SessionKey;
use crate::{StoreError, StoredSessionRecord};

const COUNTER_MAX: u64 = i64::MAX as u64;
const LOG_RPC_ENTRIES: usize = opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeLease {
    owner: crate::OwnerId,
    fence: crate::FenceToken,
    credential_id: u64,
    acquired_at: Option<Timestamp>,
    expires_at_unix_ms: i64,
    guard_expires_at: Timestamp,
    active: bool,
}

impl NativeLease {
    fn from_guard(guard: &LeaseGuard) -> Result<Self, StoreError> {
        Ok(Self {
            owner: guard.owner().clone(),
            fence: guard.fence(),
            credential_id: guard.credential_id(),
            acquired_at: Some(guard.acquired_at()),
            expires_at_unix_ms: crate::sqlite::ops::timestamp_unix_millis(guard.expires_at())?,
            guard_expires_at: guard.expires_at(),
            active: true,
        })
    }

    fn matches(&self, guard: &LeaseGuard) -> bool {
        self.active
            && self.owner == *guard.owner()
            && self.fence == guard.fence()
            && self.credential_id == guard.credential_id()
            && self.acquired_at == Some(guard.acquired_at())
            && self.guard_expires_at == guard.expires_at()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeKeyState {
    record: Option<StoredSessionRecord>,
    lease: Option<NativeLease>,
    fence: u64,
    reserved: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeReceipt {
    ordinal: u64,
    payload_digest: [u8; 32],
    retained_until: Timestamp,
    response: Option<Box<SessionConsensusResponse>>,
    #[serde(skip)]
    cold: Option<Box<resident::ColdReceipt>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeOrdinaryReceipt {
    payload_digest: [u8; 32],
    response: SessionConsensusResponse,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeV1Receipt {
    payload_digest: [u8; 32],
    retained_until: Timestamp,
    response: Option<Box<SessionConsensusResponse>>,
}

#[derive(Clone)]
enum NativeGenericReceipt {
    Ordinary(NativeOrdinaryReceipt),
    FencedV1(NativeV1Receipt),
}

// Ordinary bindings keep their original JSON content commitment. The new
// postcard vocabulary has an explicit variant; older formats decode their
// original struct before conversion and never accept that variant implicitly.
impl Serialize for NativeGenericReceipt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        enum Wire<'a> {
            Ordinary(&'a NativeOrdinaryReceipt),
            FencedV1(&'a NativeV1Receipt),
        }
        if serializer.is_human_readable() {
            if let Self::Ordinary(row) = self {
                return row.serialize(serializer);
            }
        }
        match self {
            Self::Ordinary(row) => Wire::Ordinary(row).serialize(serializer),
            Self::FencedV1(row) => Wire::FencedV1(row).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for NativeGenericReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        enum Wire {
            Ordinary(NativeOrdinaryReceipt),
            FencedV1(NativeV1Receipt),
        }
        if decoder.is_human_readable() {
            #[derive(Deserialize)]
            enum V1 {
                FencedV1(NativeV1Receipt),
            }
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Human {
                Ordinary(NativeOrdinaryReceipt),
                Fenced(V1),
            }
            return Ok(match Human::deserialize(decoder)? {
                Human::Ordinary(row) => Self::Ordinary(row),
                Human::Fenced(V1::FencedV1(row)) => Self::FencedV1(row),
            });
        }
        Ok(match Wire::deserialize(decoder)? {
            Wire::Ordinary(row) => Self::Ordinary(row),
            Wire::FencedV1(row) => Self::FencedV1(row),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeV1Activation {
    identity: SessionConsensusIdentity,
    voters: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeActivation {
    identity: SessionConsensusIdentity,
    voters: [u8; 32],
    profile: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeFrontiers {
    applied: Option<LogId<SessionConsensusNodeId>>,
    membership: StoredMembership<SessionConsensusNodeId, EmptyNode>,
    sequence: u64,
    digest: SessionConsensusEntryDigest,
    logical_time: Option<Timestamp>,
    watch_sequence: u64,
    next_fence: u64,
    next_credential: u64,
    restore_revision: u64,
    history: Option<FencedTransitionV2HistoryState>,
    activation: Option<NativeActivation>,
    #[serde(default)]
    v1_activation: Option<NativeV1Activation>,
    #[serde(default)]
    roster_v1_namespace: bool,
    #[serde(default)]
    roster_v2_activation: Option<NativeActivation>,
    current_snapshot: Option<crate::sqlite::consensus::CurrentSnapshot>,
}

impl Serialize for NativeFrontiers {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // Only JSON can omit a named field without shifting following data.
        // Preserve old JSON commitments while positional postcard always
        // carries the option marker, including an absent V1 certificate.
        let include_v1 = !serializer.is_human_readable() || self.v1_activation.is_some();
        let include_roster_v1 = !serializer.is_human_readable() || self.roster_v1_namespace;
        let include_roster_v2 =
            !serializer.is_human_readable() || self.roster_v2_activation.is_some();
        let mut value = serializer.serialize_struct(
            "NativeFrontiers",
            12 + usize::from(include_v1)
                + usize::from(include_roster_v1)
                + usize::from(include_roster_v2),
        )?;
        value.serialize_field("applied", &self.applied)?;
        value.serialize_field("membership", &self.membership)?;
        value.serialize_field("sequence", &self.sequence)?;
        value.serialize_field("digest", &self.digest)?;
        value.serialize_field("logical_time", &self.logical_time)?;
        value.serialize_field("watch_sequence", &self.watch_sequence)?;
        value.serialize_field("next_fence", &self.next_fence)?;
        value.serialize_field("next_credential", &self.next_credential)?;
        value.serialize_field("restore_revision", &self.restore_revision)?;
        value.serialize_field("history", &self.history)?;
        value.serialize_field("activation", &self.activation)?;
        if include_v1 {
            value.serialize_field("v1_activation", &self.v1_activation)?;
        }
        if include_roster_v1 {
            value.serialize_field("roster_v1_namespace", &self.roster_v1_namespace)?;
        }
        if include_roster_v2 {
            value.serialize_field("roster_v2_activation", &self.roster_v2_activation)?;
        }
        value.serialize_field("current_snapshot", &self.current_snapshot)?;
        value.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeState {
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    frontiers: NativeFrontiers,
    keys: ResidentMap<SessionKey, SharedRow<NativeKeyState>>,
    receipts: ResidentMap<FencedTransitionV2RequestId, SharedRow<NativeReceipt>>,
    generic_receipts: ResidentMap<SessionConsensusRequestId, SharedRow<NativeGenericReceipt>>,
    notifications: ResidentVector<SharedRow<NativeNotification>>,
    #[serde(skip, default = "roster::Ledger::empty")]
    roster: roster::Ledger,
    // Configuration comes from the independently validated opener. No
    // serialized native context is allowed to choose its verifier root.
    #[serde(skip)]
    roster_root:
        Option<std::sync::Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>>,
    #[serde(skip)]
    snapshot_origin: Option<Arc<NativeSnapshotAuthority>>,
    // The original local restore choice is loaded once by the cold opener.
    // Installed generations use the choice bound to their admitted origin.
    // Neither is business authority or encoded in the portable comparison.
    #[serde(skip)]
    local_restore: Option<Arc<crate::sqlite::ops::RestoreScanIncarnation>>,
    // A decoded object is not certified. Only complete admission or one
    // checked publication can construct this process-local proof.
    #[serde(skip)]
    proof: Option<std::sync::Arc<changes::BusinessProof>>,
    #[serde(skip)]
    changes: Option<changes::BusinessChanges>,
}

impl Serialize for NativeState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The historical full-image codec has no roster vocabulary. Reject
        // a configured roster instead of silently dropping its state/root.
        self.require_legacy_roster_absent()
            .map_err(serde::ser::Error::custom)?;
        #[derive(Serialize)]
        struct Legacy<'a> {
            identity: SessionConsensusIdentity,
            members: &'a BTreeSet<SessionConsensusNodeId>,
            frontiers: &'a NativeFrontiers,
            keys: &'a ResidentMap<SessionKey, SharedRow<NativeKeyState>>,
            receipts: &'a ResidentMap<FencedTransitionV2RequestId, SharedRow<NativeReceipt>>,
            generic_receipts:
                &'a ResidentMap<SessionConsensusRequestId, SharedRow<NativeGenericReceipt>>,
            notifications: &'a ResidentVector<SharedRow<NativeNotification>>,
        }
        Legacy {
            identity: self.identity,
            members: &self.members,
            frontiers: &self.frontiers,
            keys: &self.keys,
            receipts: &self.receipts,
            generic_receipts: &self.generic_receipts,
            notifications: &self.notifications,
        }
        .serialize(serializer)
    }
}

impl Clone for NativeState {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity,
            members: self.members.clone(),
            frontiers: self.frontiers.clone(),
            keys: self.keys.clone(),
            receipts: self.receipts.clone(),
            generic_receipts: self.generic_receipts.clone(),
            notifications: self.notifications.clone(),
            roster: self.roster.clone(),
            roster_root: self.roster_root.clone(),
            snapshot_origin: self.snapshot_origin.clone(),
            local_restore: self.local_restore.clone(),
            proof: self.proof.clone(),
            changes: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct NativeStorage {
    pub(crate) business: NativeState,
    pub(crate) log: log::NativeLog,
}

impl NativeStorage {
    pub(crate) fn empty(
        identity: SessionConsensusIdentity,
        members: BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<Self> {
        Self::empty_with_roster_root(identity, members, None)
    }

    pub(crate) fn empty_with_roster_root(
        identity: SessionConsensusIdentity,
        members: BTreeSet<SessionConsensusNodeId>,
        roster_root: Option<Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>>,
    ) -> io::Result<Self> {
        let business = NativeState::empty_with_roster_root(identity, members, roster_root)?;
        let mut log = log::NativeLog::default();
        log.admit(&business)?;
        Ok(Self { business, log })
    }

    pub(crate) fn replay_committed(&mut self) -> io::Result<()> {
        let Some(committed) = self.log.committed else {
            return Ok(());
        };
        let mut next = self
            .business
            .applied()
            .map_or(0, |applied| applied.index + 1);
        while next <= committed.index {
            let end = (next + LOG_RPC_ENTRIES as u64).min(committed.index + 1);
            // Recovery holds exclusive NativeStorage ownership before a WAL
            // writer exists. The same detached codec still supplies complete
            // independently owned log and receipt results for cold rows.
            let capture = self.capture_log_read()?;
            let rows = capture.resolve(next, Some(end), Some(LOG_RPC_ENTRIES), &|| Ok(()))?;
            capture.require_current_authority(self)?;
            let entries = rows.entries();
            if entries.len() != (end - next) as usize {
                return Err(invalid("native committed recovery contains a hole"));
            }
            self.log
                .require_committed_entries(&self.business, self.log.committed, entries)?;
            let reads = self
                .business
                .capture_apply_reads(entries)?
                .resolve(&|| Ok(()))?;
            let copies = reads.copy_current(&self.business)?;
            self.business.apply_with_receipts(entries, &copies)?;
            next = end;
        }
        Ok(())
    }
}

pub(crate) struct NativeApplied {
    pub(crate) responses: Vec<SessionConsensusResponse>,
    pub(crate) notifications: Vec<ReplicationEntry>,
}

struct NativeDelta<'a> {
    base: &'a NativeState,
    resolved: Option<&'a ReceiptCopies>,
    frontiers: NativeFrontiers,
    roster: roster::Ledger,
    roster_changes: roster::changes::Journal,
    keys: HashMap<SessionKey, NativeKeyState>,
    expiry: expiry::ExpiryIndex,
    receipts: HashMap<FencedTransitionV2RequestId, NativeReceipt>,
    receipt_removals: HashSet<FencedTransitionV2RequestId>,
    receipt_order: history_order::ReceiptOrder,
    generic_receipts: HashMap<SessionConsensusRequestId, NativeGenericReceipt>,
    responses: Vec<SessionConsensusResponse>,
    notifications: Vec<ReplicationEntry>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unavailable() -> StoreError {
    StoreError::BackendUnavailable("native committed state unavailable".into())
}

impl NativeState {
    pub(crate) fn empty(
        identity: SessionConsensusIdentity,
        members: BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<Self> {
        Self::empty_with_roster_root(identity, members, None)
    }

    fn empty_with_roster_root(
        identity: SessionConsensusIdentity,
        members: BTreeSet<SessionConsensusNodeId>,
        roster_root: Option<Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>>,
    ) -> io::Result<Self> {
        if members.is_empty() {
            return Err(invalid("native fixed membership is empty"));
        }
        let mut state = Self {
            identity,
            members,
            frontiers: NativeFrontiers {
                applied: None,
                membership: StoredMembership::default(),
                sequence: 0,
                digest: SessionConsensusEntryDigest::GENESIS,
                logical_time: None,
                watch_sequence: 0,
                next_fence: 1,
                next_credential: 1,
                restore_revision: 0,
                history: None,
                activation: None,
                v1_activation: None,
                roster_v1_namespace: false,
                roster_v2_activation: None,
                current_snapshot: None,
            },
            keys: ResidentMap::new(),
            receipts: ResidentMap::new(),
            generic_receipts: ResidentMap::new(),
            notifications: ResidentVector::new(),
            roster: roster::Ledger::empty(),
            roster_root,
            snapshot_origin: None,
            local_restore: None,
            proof: None,
            changes: None,
        };
        state.admit_business()?;
        Ok(state)
    }

    pub(crate) fn applied(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.frontiers.applied
    }

    pub(crate) fn members(&self) -> &BTreeSet<SessionConsensusNodeId> {
        &self.members
    }

    pub(crate) fn roster_root(
        &self,
    ) -> Option<&std::sync::Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>> {
        self.roster_root.as_ref()
    }

    pub(crate) fn membership(&self) -> StoredMembership<SessionConsensusNodeId, EmptyNode> {
        self.frontiers.membership.clone()
    }

    pub(crate) fn logical_time(&self) -> Option<Timestamp> {
        self.frontiers.logical_time
    }

    pub(crate) fn history(&self) -> Option<FencedTransitionV2HistoryState> {
        self.frontiers.history
    }

    pub(crate) fn identity(&self) -> SessionConsensusIdentity {
        self.identity
    }

    pub(crate) fn current_snapshot(&self) -> Option<crate::sqlite::consensus::CurrentSnapshot> {
        self.frontiers.current_snapshot.clone()
    }

    pub(crate) fn retained_snapshots(&self) -> Vec<crate::sqlite::consensus::CurrentSnapshot> {
        let mut retained = self
            .snapshot_origin
            .as_ref()
            .map(|origin| origin.candidate().clone())
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(current) = &self.frontiers.current_snapshot {
            if !retained.contains(current) {
                retained.push(current.clone());
            }
        }
        retained
    }

    pub(crate) fn set_current_snapshot(
        &mut self,
        current: crate::sqlite::consensus::CurrentSnapshot,
    ) -> io::Result<()> {
        self.publish_snapshot_metadata(current)
    }

    pub(crate) fn history_state(&self) -> io::Result<FencedTransitionV2HistoryState> {
        self.frontiers.history.map(Ok).unwrap_or_else(|| {
            FencedTransitionV2HistoryState::new(
                Some(
                    crate::FencedTransitionV2HistoryEpoch::new(
                        FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH,
                    )
                    .map_err(|_| invalid("native initial epoch invalid"))?,
                ),
                None,
                None,
                0,
                0,
                0,
                0,
            )
            .map_err(|_| invalid("native initial history invalid"))
        })
    }

    pub(crate) fn v2_activation_matches(
        &self,
        identity: SessionConsensusIdentity,
        voters: &BTreeSet<SessionConsensusNodeId>,
        profile: [u8; 32],
    ) -> bool {
        identity == self.identity
            && voters == &self.members
            && profile == fenced_transition_v2_profile_digest()
            && self.frontiers.history.is_some()
            && self
                .frontiers
                .activation
                .as_ref()
                .is_some_and(|activation| {
                    activation.identity == identity
                        && activation.voters == fenced_transition_voter_set_digest(identity, voters)
                        && activation.profile == profile
                })
    }

    pub(crate) fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    pub(crate) fn get_at(
        &self,
        key: &SessionKey,
        logical_time: Timestamp,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.require_business_proof().map_err(|_| unavailable())?;
        let _memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(
            4 * crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 64 * 1024,
        )
        .map_err(|_| unavailable())?;
        let record = self
            .keys
            .get(key)
            .and_then(|state| state.record.as_ref())
            .filter(|record| record.expires_at.is_none_or(|until| until > logical_time));
        if let Some(record) = record {
            crate::sqlite::validate_consensus_record(record)?;
        }
        record
            .map(owned::record)
            .transpose()
            .map_err(|_| unavailable())
    }

    pub(crate) fn observe_at(
        &self,
        key: &SessionKey,
        logical_time: Timestamp,
    ) -> Result<crate::FencedTransitionObservation, StoreError> {
        let record = self.get_at(key, logical_time)?;
        crate::FencedTransitionObservation::new(
            record,
            crate::FenceToken::new(self.keys.get(key).map_or(0, |state| state.fence)),
        )
    }

    pub(crate) fn get(&self, key: &SessionKey) -> Option<StoredSessionRecord> {
        self.keys
            .get(key)?
            .record
            .as_ref()
            .filter(|record| {
                record
                    .expires_at
                    .is_none_or(|until| self.frontiers.logical_time.is_none_or(|now| until > now))
            })
            .cloned()
    }

    pub(crate) fn status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        self.status_using(request, None)
    }

    fn status_using(
        &self,
        request: &FencedTransitionV2Request,
        resolved: Option<&ReceiptCopies>,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        match request.validate() {
            Ok(()) => {}
            Err(StoreError::FencedTransitionRequestConflict) => {
                return Ok(FencedTransitionV2Status::RequestConflict)
            }
            Err(error) => return Err(error),
        }
        let Some(history) = self.frontiers.history else {
            return Ok(
                if request.request_id().epoch().get() != FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH
                {
                    FencedTransitionV2Status::EpochNotActive
                } else if retention_exhausted(self.frontiers.logical_time) {
                    FencedTransitionV2Status::RetentionExhausted
                } else {
                    FencedTransitionV2Status::NotFound
                },
            );
        };
        if history
            .retired_through()
            .is_some_and(|floor| request.request_id().epoch().get() <= floor.get())
        {
            return Ok(FencedTransitionV2Status::Retired);
        }
        if let Some(receipt) = resolved
            .and_then(|resolved| resolved.get(&request.request_id()))
            .or_else(|| self.receipts.get(&request.request_id()).map(|row| &**row))
        {
            let digest = crate::sqlite::consensus::fenced_transition_v2_payload_digest(
                self.identity,
                request,
            )
            .map_err(|_| unavailable())?;
            if digest != receipt.payload_digest {
                return Ok(FencedTransitionV2Status::RequestConflict);
            }
            validate_receipt_frontier(receipt, &self.frontiers).map_err(|_| unavailable())?;
            if !receipt.retained()
                || self
                    .frontiers
                    .logical_time
                    .is_some_and(|now| receipt.retained_until <= now)
            {
                return Ok(FencedTransitionV2Status::Expired);
            }
            let response = receipt.response.as_ref().ok_or_else(unavailable)?;
            match &response.result {
                Ok(SessionMutationOutcome::FencedTransition(outcome))
                    if outcome.matches_v2_request(request) =>
                {
                    return Ok(FencedTransitionV2Status::Recorded(Box::new(Ok(
                        cold::copy_outcome(outcome).map_err(|_| unavailable())?,
                    ))))
                }
                Err(error) if business::deterministic(error) => {
                    return Ok(FencedTransitionV2Status::Recorded(Box::new(Err(
                        error.clone()
                    ))))
                }
                _ => return Err(unavailable()),
            }
        }
        Ok(
            if history.active_epoch() != Some(request.request_id().epoch()) {
                FencedTransitionV2Status::EpochNotActive
            } else if history.bound_entries() >= FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
                FencedTransitionV2Status::HistoryFull
            } else if retention_exhausted(self.frontiers.logical_time) {
                FencedTransitionV2Status::RetentionExhausted
            } else {
                FencedTransitionV2Status::NotFound
            },
        )
    }

    fn prepare(&self, entries: &[Entry<SessionRaftTypeConfig>]) -> io::Result<NativeDelta<'_>> {
        self.prepare_using(entries, None)
    }

    fn prepare_using<'a>(
        &'a self,
        entries: &[Entry<SessionRaftTypeConfig>],
        resolved: Option<&'a ReceiptCopies>,
    ) -> io::Result<NativeDelta<'a>> {
        self.prepare_using_checked(entries, resolved, &|| Ok(()))
    }

    fn prepare_using_checked<'a>(
        &'a self,
        entries: &[Entry<SessionRaftTypeConfig>],
        resolved: Option<&'a ReceiptCopies>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<NativeDelta<'a>> {
        self.require_business_proof()?;
        if let Some(resolved) = resolved {
            resolved.require_current(self)?;
        }
        // Live OpenRaft apply may combine multiple 64-entry RPC batches. Its
        // complete committed delivery is one atomic delta, with no RPC cap.
        let mut delta = NativeDelta {
            base: self,
            resolved,
            frontiers: self.frontiers.clone(),
            keys: HashMap::new(),
            roster: self.roster.clone(),
            roster_changes: roster::changes::Journal::empty(&self.roster)?,
            expiry: self.require_business_proof()?.expiry.clone(),
            receipts: HashMap::new(),
            receipt_removals: HashSet::new(),
            receipt_order: self.require_business_proof()?.receipt_order.clone(),
            generic_receipts: HashMap::new(),
            responses: Vec::with_capacity(entries.len()),
            notifications: Vec::new(),
        };
        for entry in entries {
            check()?;
            delta.entry(entry, check)?;
        }
        check()?;
        Ok(delta)
    }

    // Only the owning adapter can use this after validating exact durable
    // committed inputs. All allocation needed by publication is reserved
    // first; a poisoned enclosing owner can never return a partial image.
    pub(crate) fn apply(
        &mut self,
        entries: &[Entry<SessionRaftTypeConfig>],
    ) -> io::Result<NativeApplied> {
        let delta = self.prepare(entries)?;
        changes::Publication::prepare(delta)?.publish(self)
    }
}

impl NativeDelta<'_> {
    fn key(&self, key: &SessionKey) -> NativeKeyState {
        self.keys
            .get(key)
            .or_else(|| self.base.keys.get(key).map(|row| &**row))
            .cloned()
            .unwrap_or_default()
    }

    fn set_key(&mut self, key: SessionKey, value: NativeKeyState) {
        self.expiry
            .replace(&key, Some(&self.key(&key)), Some(&value));
        self.keys.insert(key, value);
    }

    fn receipt(&self, id: &FencedTransitionV2RequestId) -> Option<&NativeReceipt> {
        if self.receipt_removals.contains(id) {
            return None;
        }
        self.receipts
            .get(id)
            .or_else(|| self.resolved.and_then(|resolved| resolved.get(id)))
            .or_else(|| self.base.receipts.get(id).map(|row| &**row))
    }

    fn entry(
        &mut self,
        entry: &Entry<SessionRaftTypeConfig>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let next = self
            .frontiers
            .applied
            .map(|id| {
                id.index
                    .checked_add(1)
                    .ok_or_else(|| invalid("native applied index exhausted"))
            })
            .transpose()?
            .unwrap_or(0);
        if entry.log_id.index != next
            || entry.log_id.index > COUNTER_MAX
            || entry.log_id.leader_id.term > COUNTER_MAX
            || self
                .frontiers
                .applied
                .is_some_and(|prior| entry.log_id.leader_id < prior.leader_id)
        {
            return Err(invalid(
                "native apply position is not contiguous and monotonic",
            ));
        }
        let response = match &entry.payload {
            EntryPayload::Blank => empty_response(entry.log_id.index),
            EntryPayload::Membership(membership) => {
                if membership.get_joint_config().len() != 1
                    || membership.voter_ids().collect::<BTreeSet<_>>() != self.base.members
                    || membership
                        .nodes()
                        .map(|(id, _)| *id)
                        .collect::<BTreeSet<_>>()
                        != self.base.members
                {
                    return Err(invalid("native fixed membership differs"));
                }
                self.frontiers.membership =
                    StoredMembership::new(Some(entry.log_id), membership.clone());
                empty_response(entry.log_id.index)
            }
            EntryPayload::Normal(command) => self.command(command, entry.log_id.index, check)?,
        };
        if let EntryPayload::Normal(command) = &entry.payload {
            if !crate::sqlite::consensus::contains_protected_roster_command(&command.intent) {
                if let Some(now) = response.logical_time {
                    self.maintain_roster(now, check)?;
                }
            }
        }
        self.frontiers.applied = Some(entry.log_id);
        self.responses.push(response);
        Ok(())
    }

    fn command(
        &mut self,
        command: &SessionConsensusCommand,
        index: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<SessionConsensusResponse> {
        crate::sqlite::consensus::validate_command_for_log(command, self.base.identity)?;
        if command.schema_version != super::SESSION_CONSENSUS_SCHEMA_VERSION
            || command.identity != self.base.identity
        {
            return Err(invalid("native command schema or storage identity differs"));
        }
        if let Some(roster) = crate::sqlite::consensus::protected_roster_command_for_scope(
            &command.intent,
            &roster::fixed_scope(self.base.identity, &self.base.members),
            self.base.identity,
            index,
            crate::sqlite::consensus::ProtectedRosterCommandAuthorityValidation::CurrentOnly,
        )? {
            return self.roster_command(command, roster, index, check);
        }
        let (intent, authorized) = match &command.intent {
            SessionMutationIntent::Authorized {
                origin,
                authority_identity,
                mutation,
            } => {
                if matches!(mutation.as_ref(), SessionMutationIntent::Authorized { .. }) {
                    return Err(invalid("native nested authority envelope"));
                }
                (
                    mutation.as_ref(),
                    *authority_identity == self.base.identity && self.base.members.contains(origin),
                )
            }
            intent => (intent, true),
        };
        let now = self
            .frontiers
            .logical_time
            .map_or(command.logical_time, |prior| {
                prior.max(command.logical_time)
            });
        match intent {
            SessionMutationIntent::FencedTransition(request) => {
                self.fenced_v1(command, request, None, authorized, now, index)
            }
            SessionMutationIntent::ActivateFencedTransition {
                request,
                scope_identity,
                voter_set_digest,
            } => self.fenced_v1(
                command,
                request,
                Some(NativeV1Activation {
                    identity: *scope_identity,
                    voters: *voter_set_digest,
                }),
                authorized,
                now,
                index,
            ),
            SessionMutationIntent::ActivateFencedTransitionCapability {
                scope_identity,
                voter_set_digest,
                ..
            } => {
                if authorized {
                    self.activate_v1(
                        NativeV1Activation {
                            identity: *scope_identity,
                            voters: *voter_set_digest,
                        },
                        true,
                    )?;
                }
                self.ordinary(command, intent, authorized, now, index)
            }
            SessionMutationIntent::FencedTransitionV2(request) => {
                self.singleton(command, request, None, authorized, now, index)
            }
            SessionMutationIntent::ActivateFencedTransitionV2 {
                request,
                scope_identity,
                voter_set_digest,
                profile_digest,
            } => self.singleton(
                command,
                request,
                Some(NativeActivation {
                    identity: *scope_identity,
                    voters: *voter_set_digest,
                    profile: *profile_digest,
                }),
                authorized,
                now,
                index,
            ),
            SessionMutationIntent::FencedTransitionV2Batch(requests) => {
                self.batch(command, requests, authorized, now, index)
            }
            SessionMutationIntent::MaintainFencedTransitionV2History { .. } => {
                self.maintain_history(command, now, index)
            }
            SessionMutationIntent::AdvanceLogicalTime
            | SessionMutationIntent::BindConsumerRequest { .. }
            | SessionMutationIntent::ActivateProtectedRosterProfileV2 { .. }
            | SessionMutationIntent::ReadConsumerRecord { .. }
            | SessionMutationIntent::CompareAndSet(_)
            | SessionMutationIntent::DeleteFenced(_)
            | SessionMutationIntent::RefreshTtl { .. }
            | SessionMutationIntent::AcquireLease { .. }
            | SessionMutationIntent::RenewLease { .. }
            | SessionMutationIntent::ReleaseLease(_) => {
                self.ordinary(command, intent, authorized, now, index)
            }
            _ => Err(invalid(
                "native private slice does not yet implement this command",
            )),
        }
    }

    fn clock_response(
        &mut self,
        now: Timestamp,
        index: u64,
        error: StoreError,
    ) -> SessionConsensusResponse {
        self.frontiers.logical_time = Some(now);
        self.response(index, Err(error))
    }

    fn response(
        &self,
        index: u64,
        result: Result<SessionMutationOutcome, StoreError>,
    ) -> SessionConsensusResponse {
        SessionConsensusResponse {
            result,
            sequence: self.frontiers.sequence,
            digest: Some(self.frontiers.digest),
            logical_time: self.frontiers.logical_time,
            raft_log_index: index,
        }
    }

    fn activation_exact(&self) -> bool {
        self.frontiers
            .activation
            .as_ref()
            .is_some_and(|activation| {
                activation.identity == self.base.identity
                    && activation.voters
                        == fenced_transition_voter_set_digest(
                            self.base.identity,
                            &self.base.members,
                        )
                    && activation.profile == fenced_transition_v2_profile_digest()
            })
    }

    fn singleton(
        &mut self,
        command: &SessionConsensusCommand,
        request: &FencedTransitionV2Request,
        activation: Option<NativeActivation>,
        authorized: bool,
        now: Timestamp,
        index: u64,
    ) -> io::Result<SessionConsensusResponse> {
        if !fenced_transition_v2_timestamp_is_in_range(command.logical_time) {
            return Err(invalid("native V2 command time outside profile"));
        }
        match request.validate() {
            Ok(()) => {}
            Err(StoreError::FencedTransitionRequestConflict) => {
                return Ok(self.clock_response(
                    now,
                    index,
                    StoreError::FencedTransitionRequestConflict,
                ))
            }
            Err(_) => return Err(invalid("native V2 request invalid")),
        }
        if !authorized {
            return Ok(self.clock_response(now, index, StoreError::TopologyAuthorityRevoked));
        }
        if self.frontiers.history.is_none()
            && request.request_id().epoch().get() != FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH
        {
            return Ok(self.clock_response(
                now,
                index,
                StoreError::FencedTransitionHistoryEpochNotActive,
            ));
        }
        if let Some(activation) = activation {
            if activation.identity != self.base.identity
                || activation.voters
                    != fenced_transition_voter_set_digest(self.base.identity, &self.base.members)
                || activation.profile != fenced_transition_v2_profile_digest()
            {
                return Err(invalid("native V2 activation differs"));
            }
            if self.frontiers.history.is_none() {
                self.frontiers.history = Some(
                    FencedTransitionV2HistoryState::new(
                        Some(request.request_id().epoch()),
                        None,
                        None,
                        0,
                        0,
                        0,
                        0,
                    )
                    .map_err(|_| invalid("native initial history invalid"))?,
                );
            }
            let history = self
                .frontiers
                .history
                .ok_or_else(|| invalid("native history absent"))?;
            if history
                .retired_through()
                .is_none_or(|floor| request.request_id().epoch().get() > floor.get())
                && history
                    .active_epoch()
                    .is_some_and(|active| request.request_id().epoch().get() <= active.get())
            {
                self.frontiers.activation = Some(activation);
            }
        } else if !self.activation_exact() {
            return Err(invalid("native V2 activation missing"));
        }
        let history = self
            .frontiers
            .history
            .ok_or_else(|| invalid("native history absent"))?;
        if history
            .retired_through()
            .is_some_and(|floor| request.request_id().epoch().get() <= floor.get())
        {
            return Ok(self.clock_response(
                now,
                index,
                StoreError::FencedTransitionHistoryEpochRetired,
            ));
        }
        let digest = crate::sqlite::consensus::fenced_transition_v2_payload_digest(
            self.base.identity,
            request,
        )?;
        if let Some(receipt) = self.receipt(&request.request_id()) {
            let response = if receipt.payload_digest != digest {
                self.response(index, Err(StoreError::FencedTransitionRequestConflict))
            } else if !receipt.retained() || receipt.retained_until <= now {
                let expired = NativeReceipt {
                    ordinal: receipt.ordinal,
                    payload_digest: receipt.payload_digest,
                    retained_until: receipt.retained_until,
                    response: None,
                    cold: None,
                };
                self.receipts.insert(request.request_id(), expired);
                self.response(index, Err(StoreError::FencedTransitionRequestExpired))
            } else {
                cold::copy_response(
                    receipt
                        .response
                        .as_deref()
                        .ok_or_else(|| invalid("native retained response absent"))?,
                )?
            };
            self.frontiers.logical_time = Some(now);
            return Ok(response);
        }
        if history.active_epoch() != Some(request.request_id().epoch()) {
            return Ok(self.clock_response(
                now,
                index,
                StoreError::FencedTransitionHistoryEpochNotActive,
            ));
        }
        if history.bound_entries() >= FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
            return Ok(self.clock_response(now, index, StoreError::FencedTransitionHistoryFull));
        }
        let Some(until) = retention_deadline(now) else {
            return Ok(self.clock_response(
                now,
                index,
                StoreError::FencedTransitionRetentionExhausted,
            ));
        };
        let result = self.effect(request, now, self.frontiers.sequence >= COUNTER_MAX)?;
        if self.frontiers.sequence < COUNTER_MAX {
            self.frontiers.sequence += 1;
            self.frontiers.digest = command
                .calculate_applied_digest(self.frontiers.sequence, self.frontiers.digest, now)
                .map_err(|_| invalid("native command digest failed"))?;
        }
        self.frontiers.logical_time = Some(now);
        let response = self.response(index, result.map(SessionMutationOutcome::FencedTransition));
        self.bind(request, digest, until, response.clone())?;
        Ok(response)
    }

    fn batch(
        &mut self,
        command: &SessionConsensusCommand,
        requests: &[FencedTransitionV2Request],
        authorized: bool,
        now: Timestamp,
        index: u64,
    ) -> io::Result<SessionConsensusResponse> {
        validate_fenced_transition_v2_batch(requests)
            .map_err(|_| invalid("native V2 batch invalid"))?;
        if !fenced_transition_v2_timestamp_is_in_range(command.logical_time) {
            return Err(invalid("native V2 batch time outside profile"));
        }
        let mut outcomes = vec![None; requests.len()];
        if !authorized {
            for (slot, request) in requests.iter().enumerate() {
                outcomes[slot] = Some(Err(
                    if matches!(
                        request.validate(),
                        Err(StoreError::FencedTransitionRequestConflict)
                    ) {
                        StoreError::FencedTransitionRequestConflict
                    } else {
                        StoreError::TopologyAuthorityRevoked
                    },
                ));
            }
        } else {
            if !self.activation_exact() {
                return Err(invalid("native V2 batch activation missing"));
            }
            let history = self
                .frontiers
                .history
                .ok_or_else(|| invalid("native history absent"))?;
            let mut fresh = Vec::new();
            for (slot, request) in requests.iter().enumerate() {
                if matches!(
                    request.validate(),
                    Err(StoreError::FencedTransitionRequestConflict)
                ) {
                    outcomes[slot] = Some(Err(StoreError::FencedTransitionRequestConflict));
                    continue;
                }
                let digest = crate::sqlite::consensus::fenced_transition_v2_payload_digest(
                    self.base.identity,
                    request,
                )?;
                if history
                    .retired_through()
                    .is_some_and(|floor| request.request_id().epoch().get() <= floor.get())
                {
                    outcomes[slot] = Some(Err(StoreError::FencedTransitionHistoryEpochRetired));
                } else if let Some(receipt) = self.receipt(&request.request_id()) {
                    outcomes[slot] = Some(replay_outcome(receipt, digest, now)?);
                } else if history.active_epoch() != Some(request.request_id().epoch()) {
                    outcomes[slot] = Some(Err(StoreError::FencedTransitionHistoryEpochNotActive));
                } else {
                    fresh.push((slot, digest));
                }
            }
            let remaining = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                .checked_sub(history.bound_entries())
                .ok_or_else(|| invalid("native history count exceeds profile"))?;
            let until = retention_deadline(now);
            let binds = remaining > 0 && until.is_some() && !fresh.is_empty();
            let terminal = self.frontiers.sequence >= COUNTER_MAX;
            let sequence = if binds && !terminal {
                self.frontiers.sequence + 1
            } else {
                self.frontiers.sequence
            };
            let digest = if binds && !terminal {
                command
                    .calculate_applied_digest(sequence, self.frontiers.digest, now)
                    .map_err(|_| invalid("native batch digest failed"))?
            } else {
                self.frontiers.digest
            };
            for (position, (slot, payload_digest)) in fresh.into_iter().enumerate() {
                let result = if remaining == 0 {
                    Err(StoreError::FencedTransitionHistoryFull)
                } else if until.is_none() {
                    Err(StoreError::FencedTransitionRetentionExhausted)
                } else if position >= remaining {
                    Err(StoreError::FencedTransitionHistoryFull)
                } else {
                    let result = if terminal {
                        Err(StoreError::FencedTransitionStorageExhausted)
                    } else {
                        self.effect(&requests[slot], now, false)?
                    };
                    let response = SessionConsensusResponse {
                        result: result.clone().map(SessionMutationOutcome::FencedTransition),
                        sequence,
                        digest: Some(digest),
                        logical_time: Some(now),
                        raft_log_index: index,
                    };
                    self.bind(
                        &requests[slot],
                        payload_digest,
                        until.ok_or_else(|| invalid("native retention absent"))?,
                        response,
                    )?;
                    result
                };
                outcomes[slot] = Some(result);
            }
            self.frontiers.sequence = sequence;
            self.frontiers.digest = digest;
        }
        let outcomes = outcomes
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| invalid("native batch outcome missing"))?;
        validate_fenced_transition_v2_batch_outcomes(&outcomes)
            .map_err(|_| invalid("native batch outcomes invalid"))?;
        self.frontiers.logical_time = Some(now);
        Ok(self.response(
            index,
            Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)),
        ))
    }

    fn effect(
        &mut self,
        request: &FencedTransitionV2Request,
        now: Timestamp,
        terminal: bool,
    ) -> io::Result<Result<FencedTransitionOutcome, StoreError>> {
        let current = self.key(request.lease().key());
        match business::transition(request, &current, &self.frontiers, now) {
            Ok(_) if terminal => Ok(Err(StoreError::FencedTransitionStorageExhausted)),
            Ok(effect) => {
                let watch_sequence = self
                    .frontiers
                    .watch_sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("native watch sequence exhausted"))?;
                let notification = ReplicationEntry {
                    sequence: watch_sequence,
                    tx_id: ReplicationTxId::from_request_bytes(
                        fenced_transition_v2_outer_request_id(request.request_id()),
                    ),
                    op: effect.replication,
                    timestamp: now,
                };
                notification
                    .validate()
                    .map_err(|_| invalid("native notification invalid"))?;
                self.set_key(effect.key, effect.value);
                self.frontiers.next_fence = effect.next_fence;
                self.frontiers.next_credential = effect.next_credential;
                self.frontiers.restore_revision += 1;
                self.frontiers.watch_sequence = watch_sequence;
                self.notifications.push(notification);
                Ok(Ok(effect.outcome))
            }
            Err(error) if business::deterministic(&error) => Ok(Err(error)),
            Err(_) => Err(invalid("native business state infrastructure fault")),
        }
    }

    fn bind(
        &mut self,
        request: &FencedTransitionV2Request,
        payload_digest: [u8; 32],
        until: Timestamp,
        response: SessionConsensusResponse,
    ) -> io::Result<()> {
        let history = self
            .frontiers
            .history
            .ok_or_else(|| invalid("native receipt history absent"))?;
        let ordinal = history
            .bound_entries()
            .checked_add(1)
            .ok_or_else(|| invalid("native receipt ordinal exhausted"))?;
        let updated = FencedTransitionV2HistoryState::new(
            history.active_epoch(),
            history.retired_through(),
            history.reclaim_epoch(),
            history.reclaim_remaining(),
            history.generation(),
            ordinal,
            history.reclaimed_entries(),
        )
        .map_err(|_| invalid("native bound history invalid"))?;
        // Reuse the fixed response codec as an independent schema/error-profile
        // validator before a receipt can become visible or enter a snapshot.
        crate::sqlite::consensus::encode_fenced_transition_v2_response(&response)?;
        if self.receipt(&request.request_id()).is_some() {
            return Err(invalid("native duplicate receipt binding"));
        }
        self.receipt_order
            .append(request.request_id(), ordinal as u64, until)?;
        self.receipts.insert(
            request.request_id(),
            NativeReceipt {
                ordinal: ordinal as u64,
                payload_digest,
                retained_until: until,
                response: Some(Box::new(response)),
                cold: None,
            },
        );
        self.frontiers.history = Some(updated);
        Ok(())
    }
}

fn retention_deadline(now: Timestamp) -> Option<Timestamp> {
    crate::ttl::checked_session_deadline(now, FENCED_TRANSITION_OUTCOME_RETENTION)
        .ok()
        .filter(|until| {
            fenced_transition_v2_timestamp_is_in_range(now)
                && fenced_transition_v2_timestamp_is_in_range(*until)
        })
}

fn retention_exhausted(now: Option<Timestamp>) -> bool {
    now.is_some_and(|now| retention_deadline(now).is_none())
}

fn replay_outcome(
    receipt: &NativeReceipt,
    digest: [u8; 32],
    now: Timestamp,
) -> io::Result<Result<FencedTransitionOutcome, StoreError>> {
    if receipt.payload_digest != digest {
        return Ok(Err(StoreError::FencedTransitionRequestConflict));
    }
    if !receipt.retained() || receipt.retained_until <= now {
        return Ok(Err(StoreError::FencedTransitionRequestExpired));
    }
    match &receipt
        .response
        .as_ref()
        .ok_or_else(|| invalid("native retained response absent"))?
        .result
    {
        Ok(SessionMutationOutcome::FencedTransition(outcome)) => {
            Ok(Ok(cold::copy_outcome(outcome)?))
        }
        Err(error) if business::deterministic(error) => Ok(Err(error.clone())),
        _ => Err(invalid("native retained response invalid")),
    }
}

fn validate_receipt_frontier(
    receipt: &NativeReceipt,
    frontiers: &NativeFrontiers,
) -> io::Result<()> {
    if let Some(response) = receipt.response_facts()? {
        response
            .validate(frontiers)
            .map_err(|_| invalid("native receipt exceeds published frontiers"))?;
    } else if frontiers
        .logical_time
        .is_none_or(|now| receipt.retained_until > now)
    {
        return Err(invalid("native receipt compacted before expiry"));
    }
    Ok(())
}

fn empty_response(index: u64) -> SessionConsensusResponse {
    SessionConsensusResponse {
        result: Ok(SessionMutationOutcome::Unit),
        sequence: 0,
        digest: None,
        logical_time: None,
        raft_log_index: index,
    }
}
