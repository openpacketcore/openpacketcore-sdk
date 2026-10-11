//! Complete consumer row image, projected only through public SDK accessors.
//! It is data, never an acknowledgement, a completion token or an epoch owner.

use super::{
    envelope::Error,
    store::{RowKey, Version},
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CbcEpochInputs, Ikev2CbcEpochRecord, Ikev2CbcRecoveryProfile as Cbc,
        Ikev2CommittedExchangeRecord as Exchange, Ikev2CommittedWindowDomain as Domain,
        Ikev2CommittedWindowRecord as Record, Ikev2PersistedProfileSync as ProfileSync,
        Ikev2ReservationRetryPolicy as RetryPolicy, Ikev2ReservationRetryRecord as RetryRecord,
        Ikev2SyncAttemptRecord as Attempt, Ikev2SyncDisposition as Disposition,
        Ikev2SyncRecoveryPolicy as Policy, Ikev2SyncRecoveryRecord as Recovery,
        Ikev2SyncRecoveryStatus as Status, Ikev2SyncResponderRecord as SyncRecord,
    },
    Ikev2AesGcmEpochInputs, Ikev2AesGcmIvLimits as Limits, Ikev2AesGcmIvRecord as IvRecord,
    Ikev2DhGroup as Group, Ikev2MessageIdSyncAgreement as Agreement,
    Ikev2MessageIdSyncMode as Mode, Ikev2MessageIdSyncPending as Pending,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeKind {
    NewChild,
    ChildRekey,
    IkeRekey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Success,
    CrossedLoss,
    RetryBudget,
    Abandoned,
    Uncertain,
    Teardown,
    PeerKeRejected,
    PeerKeDeleted,
    InvalidSyntax,
}

#[derive(Clone)]
pub struct Operation {
    pub id: u64,
    pub kind: KeKind,
    pub initiated_here: bool,
    pub group: Group,
    pub public: Vec<u8>,
    pub nonce_i: Vec<u8>,
    pub nonce_r: Vec<u8>,
    pub spis: (u64, u64),
    pub first_payload: u8,
    pub transcript: Bytes,
    pub checkpoint: Option<Zeroizing<Vec<u8>>>,
    pub outcome: Outcome,
    pub derived: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operation")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl Operation {
    pub fn validate(&self) -> Result<(), Error> {
        if self.id == 0
            || self.public.len() != self.group.public_value_len()
            || self.nonce_i.len() < 16
            || self.transcript.is_empty()
            || (self.outcome == Outcome::Pending) != self.checkpoint.is_some()
            || (self.outcome == Outcome::Pending && !self.initiated_here)
            || (self.outcome == Outcome::Success) != self.derived.is_some()
            || (!self.initiated_here && self.checkpoint.is_some())
        {
            return Err(Error::Format);
        }
        if let Some(checkpoint) = &self.checkpoint {
            if checkpoint.len() != self.group.shared_secret_len() + 3
                || checkpoint[0] != 1
                || u16::from_be_bytes([checkpoint[1], checkpoint[2]]) != self.group.transform_id()
            {
                return Err(Error::Format);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Row {
    pub key: RowKey,
    pub version: Version,
    pub sealed_stamp: u64,
    pub spis: (u64, u64),
    pub direction: Direction,
    pub profile: Profile,
    pub keys: Keys,
    pub agreement: Agreement,
    pub mode: Mode,
    pub marker: Option<u8>,
    pub iv: Option<IvImage>,
    pub window: WindowImage,
    pub operations: BTreeMap<u64, Operation>,
    pub sync_intents: [Option<SyncIntent>; 2],
    pub identity: u64,
    pub namespace: u64,
    pub endpoint: Option<(u32, u16)>,
    pub challenge: Option<Challenge>,
    pub contact_cleanup: Vec<ContactVictim>,
    pub contact_auth: Option<Bytes>,
    pub closed: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ContactVictim {
    pub key: RowKey,
    pub birth: u64,
    pub identity: u64,
    pub namespace: u64,
}

#[derive(Clone)]
pub struct Challenge {
    pub destination: (u32, u16),
    pub request: Bytes,
}

#[derive(Clone)]
pub struct SyncIntent {
    pub policy: Policy,
    pub observed: u64,
    pub pending: bool,
}

#[derive(Clone)]
pub struct IvImage {
    pub limits: Limits,
    pub end: u64,
    pub retries: BTreeMap<u64, RetryImage>,
}

#[derive(Clone)]
pub struct RetryImage {
    pub operation: u64,
    pub policy: RetryPolicy,
    pub attempts: u8,
    pub last_attempt: Option<u64>,
}

#[derive(Clone)]
pub struct WindowImage {
    pub generation: u64,
    pub next_send: Option<u32>,
    pub next_receive: Option<u32>,
    pub outbound: Option<Exchange>,
    pub inbound: Option<Exchange>,
    pub sync: Option<SyncImage>,
    pub recovery: Option<RecoveryImage>,
}

#[derive(Clone)]
pub struct SyncImage {
    pub agreement: Agreement,
    pub local_request: Option<u32>,
    pub peer_request: Option<u32>,
    pub local_proposal: Option<u32>,
    pub peer_proposal: Option<u32>,
    pub disposition: Disposition,
    pub minimum_iv_end: Option<u64>,
}

#[derive(Clone)]
pub struct RecoveryImage {
    pub policy: Policy,
    pub observed: u64,
    pub attempts: Vec<AttemptImage>,
    pub status: Status,
}

#[derive(Clone)]
pub struct AttemptImage {
    pub pending: Pending,
    pub prepared: u64,
    pub request: Bytes,
}

macro_rules! capture {
    ($record:expr, $minimum:expr) => {{
        let record = $record;
        WindowImage {
            generation: record.generation(),
            next_send: record.next_send(),
            next_receive: record.next_receive(),
            outbound: record.outbound().cloned(),
            inbound: record.inbound().cloned(),
            sync: record.sync_state().map(|s| SyncImage {
                agreement: s.agreement(),
                local_request: s.highest_local_request(),
                peer_request: s.highest_peer_request(),
                local_proposal: s.highest_local_proposal(),
                peer_proposal: s.highest_peer_proposal(),
                disposition: s.disposition(),
                minimum_iv_end: ($minimum)(s),
            }),
            recovery: record.sync_recovery().map(|r| RecoveryImage {
                policy: r.policy(),
                observed: r.last_observed_unix_ms(),
                status: r.status(),
                attempts: r
                    .attempts()
                    .iter()
                    .map(|a| AttemptImage {
                        pending: a.pending(),
                        prepared: a.prepared_unix_ms(),
                        request: Bytes::copy_from_slice(a.request_bytes()),
                    })
                    .collect(),
            }),
        }
    }};
}

impl WindowImage {
    pub fn gcm(record: &Record) -> Self {
        capture!(record, |s: &SyncRecord| Some(s.minimum_send_iv_end()))
    }
    pub fn cbc(record: &Record<Cbc>) -> Self {
        capture!(record, |_s: &SyncRecord<Cbc>| None)
    }
}

macro_rules! recovery {
    ($image:expr, $attempt:ident, $record:ident) => {
        $image
            .as_ref()
            .map(|r| {
                let attempts = r
                    .attempts
                    .iter()
                    .map(|a| {
                        Attempt::$attempt(a.pending, a.prepared, a.request.clone())
                            .map_err(|_| Error::Format)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Recovery::$record(r.policy, r.observed, attempts, r.status)
                    .map_err(|_| Error::Format)
            })
            .transpose()?
    };
}

impl Row {
    pub fn validate(&self) -> Result<(), Error> {
        let role = match self.direction {
            Direction::InitiatorToResponder => Role::Initiator,
            Direction::ResponderToInitiator => Role::Responder,
        };
        let sa = Sa::new(self.spis.0, self.spis.1, role).map_err(|_| Error::Format)?;
        if self.agreement.sa() != sa
            || self.agreement.mode() != self.mode
            || self.profile.encryption().is_aead() != self.iv.is_some()
            || (self.mode == Mode::Negotiated) != self.window.sync.is_some()
            || (self.mode == Mode::BaseFallback && self.window.recovery.is_some())
            || self.version.generation == 0
        {
            return Err(Error::Format);
        }
        if let Some(challenge) = &self.challenge {
            if self
                .window
                .outbound
                .as_ref()
                .is_none_or(|entry| entry.request() != challenge.request)
            {
                return Err(Error::Format);
            }
        }
        if !self.contact_cleanup.is_empty() && self.contact_auth.is_none() {
            return Err(Error::Format);
        }
        for intent in self.sync_intents.iter().flatten() {
            if self.mode != Mode::Negotiated || intent.observed < intent.policy.started().unix_ms()
            {
                return Err(Error::Format);
            }
        }
        for (&id, operation) in &self.operations {
            operation.validate()?;
            if id != operation.id {
                return Err(Error::Format);
            }
            if operation.outcome == Outcome::Pending
                && (self.closed
                    || self
                        .window
                        .outbound
                        .as_ref()
                        .is_none_or(|outbound| outbound.response().is_some()))
            {
                return Err(Error::Format);
            }
        }
        Ok(())
    }

    /// A genuinely new rekey epoch starts at zero in both directions. This is
    /// proposed row data; the runtime factory must acquire an owner after CAS.
    pub fn fresh(
        key: RowKey,
        stamp: u64,
        profile: Profile,
        keys: Keys,
        spis: (u64, u64),
        direction: Direction,
        mode: Mode,
    ) -> Self {
        let role = match direction {
            Direction::InitiatorToResponder => Role::Initiator,
            Direction::ResponderToInitiator => Role::Responder,
        };
        let agreement = Agreement::from_persisted(Sa::new(spis.0, spis.1, role).unwrap(), mode);
        let is_gcm = profile.encryption().is_aead();
        Self {
            key,
            version: Version {
                birth: key.0 + 100,
                generation: 1,
            },
            sealed_stamp: stamp,
            spis,
            direction,
            profile,
            keys,
            agreement,
            mode,
            marker: Some(1),
            iv: is_gcm.then(|| IvImage {
                limits: Limits::new(1024, 2, 1, 2).unwrap(),
                end: 0,
                retries: BTreeMap::new(),
            }),
            window: WindowImage {
                generation: 0,
                next_send: Some(0),
                next_receive: Some(0),
                outbound: None,
                inbound: None,
                sync: (mode == Mode::Negotiated).then_some(SyncImage {
                    agreement,
                    local_request: None,
                    peer_request: None,
                    local_proposal: None,
                    peer_proposal: None,
                    disposition: Disposition::Continue,
                    minimum_iv_end: is_gcm.then_some(0),
                }),
                recovery: None,
            },
            operations: BTreeMap::new(),
            sync_intents: [None, None],
            identity: 11,
            namespace: 1,
            endpoint: None,
            challenge: None,
            contact_cleanup: Vec::new(),
            contact_auth: None,
            closed: false,
        }
    }

    pub fn gcm(&self) -> Result<(Record, IvRecord, Vec<RetryRecord>), Error> {
        self.validate()?;
        let image = self.iv.as_ref().ok_or(Error::Format)?;
        let iv = IvRecord::from_persisted(
            Ikev2AesGcmEpochInputs {
                initiator_spi: self.spis.0,
                responder_spi: self.spis.1,
                sending_direction: self.direction,
                profile: self.profile,
                keys: &self.keys,
            },
            image.limits,
            image.end,
            self.marker,
        )
        .map_err(|_| Error::Format)?;
        let domain = Domain::from_iv_record(&iv);
        let synchronization = match self.mode {
            Mode::BaseFallback => ProfileSync::Base {
                agreement: self.agreement,
            },
            Mode::Negotiated => {
                let s = self.window.sync.as_ref().ok_or(Error::Format)?;
                let state = SyncRecord::from_persisted(
                    s.agreement,
                    s.local_request,
                    s.peer_request,
                    s.local_proposal,
                    s.peer_proposal,
                    s.disposition,
                    s.minimum_iv_end.ok_or(Error::Format)?,
                )
                .map_err(|_| Error::Format)?;
                let recovery = recovery!(self.window.recovery, from_persisted, from_persisted);
                ProfileSync::Negotiated {
                    agreement: self.agreement,
                    state,
                    recovery,
                }
            }
        };
        let record = Record::from_profile_persisted(
            domain,
            self.window.generation,
            self.window.next_send,
            self.window.next_receive,
            self.window.outbound.clone(),
            self.window.inbound.clone(),
            synchronization,
        )
        .map_err(|_| Error::Format)?;
        let retry = image
            .retries
            .iter()
            .map(|(&id, r)| {
                if id != r.operation {
                    return Err(Error::Format);
                }
                RetryRecord::from_persisted(
                    iv.domain().clone(),
                    r.operation,
                    r.policy,
                    r.attempts,
                    r.last_attempt,
                )
                .map_err(|_| Error::Format)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((record, iv, retry))
    }

    pub fn cbc(&self) -> Result<(Record<Cbc>, Ikev2CbcEpochRecord), Error> {
        self.validate()?;
        if self.iv.is_some() {
            return Err(Error::Format);
        }
        let epoch = Ikev2CbcEpochRecord::from_persisted(
            Ikev2CbcEpochInputs {
                initiator_spi: self.spis.0,
                responder_spi: self.spis.1,
                sending_direction: self.direction,
                profile: self.profile,
                keys: &self.keys,
            },
            self.marker,
        )
        .map_err(|_| Error::Format)?;
        let domain = Domain::from_cbc_epoch(&epoch);
        let synchronization = match self.mode {
            Mode::BaseFallback => ProfileSync::Base {
                agreement: self.agreement,
            },
            Mode::Negotiated => {
                let s = self.window.sync.as_ref().ok_or(Error::Format)?;
                if s.minimum_iv_end.is_some() {
                    return Err(Error::Format);
                }
                let state = SyncRecord::from_persisted_cbc(
                    s.agreement,
                    s.local_request,
                    s.peer_request,
                    s.local_proposal,
                    s.peer_proposal,
                    s.disposition,
                )
                .map_err(|_| Error::Format)?;
                let recovery =
                    recovery!(self.window.recovery, from_persisted_cbc, from_persisted_cbc);
                ProfileSync::Negotiated {
                    agreement: self.agreement,
                    state,
                    recovery,
                }
            }
        };
        let record = Record::from_profile_persisted(
            domain,
            self.window.generation,
            self.window.next_send,
            self.window.next_receive,
            self.window.outbound.clone(),
            self.window.inbound.clone(),
            synchronization,
        )
        .map_err(|_| Error::Format)?;
        Ok((record, epoch))
    }

    /// Every row write begins from the complete latest acknowledged image. A
    /// window, inbound result or IV-only update therefore carries pending KE
    /// checkpoints and independent retry histories through the same child CAS.
    pub fn next_write(&self, stamp: u64, update: impl FnOnce(&mut Self)) -> Result<Self, Error> {
        let mut candidate = self.clone();
        candidate.version = self.version.next();
        candidate.sealed_stamp = stamp;
        update(&mut candidate);
        if candidate.challenge.as_ref().is_some_and(|challenge| {
            candidate.window.outbound.as_ref().is_none_or(|entry| {
                entry.response().is_some() || entry.request() != challenge.request
            })
        }) {
            candidate.challenge = None;
        }
        candidate.validate()?;
        Ok(candidate)
    }
}
