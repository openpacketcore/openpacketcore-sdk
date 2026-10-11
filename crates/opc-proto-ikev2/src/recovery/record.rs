use bytes::Bytes;

use super::profile::{
    DirectionBinding, Ikev2CbcRecoveryProfile as Cbc, Ikev2GcmRecoveryProfile as Gcm,
    RecoveryProfile,
};
use super::{Ikev2SyncResponderRecord, Ikev2WindowError as Error};
use crate::{
    Header, HeaderFlags, Ikev2AesGcmIvDomain, Ikev2ExchangeKind,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
    PayloadType,
};

/// Established profile-bound key epoch and local original role for committed windows.
///
/// GCM binds both directional key/salt pairs, algorithm and nonzero SPIs. CBC
/// additionally binds SK_d, PRF, INTEG and both integrity keys. This descriptor
/// establishes neither fresh-key provenance nor authenticated peers. Persist its
/// inputs atomically with the epoch's keys and window. Derive it with
/// `from_iv_record` for GCM or `from_cbc_epoch` for CBC, never from mutable fields.
///
/// ```compile_fail
/// use opc_proto_ikev2::{Ikev2AesGcmEpochInputs, recovery::Ikev2CommittedWindowDomain};
/// fn assemble(i: Ikev2AesGcmEpochInputs<'_>) {
///     let _ = Ikev2CommittedWindowDomain::new(i.initiator_spi, i.responder_spi,
///         i.sending_direction, i.profile, i.keys);
/// }
/// ```
///
/// Only SDK-defined profiles can name a domain; dispatch is sealed:
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2CommittedWindowDomain;
/// struct UncheckedProfile;
/// let _: Option<Ikev2CommittedWindowDomain<UncheckedProfile>> = None;
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CommittedWindowDomain<P: RecoveryProfile = Gcm> {
    pub(crate) send: P::Direction,
    pub(crate) receive: P::Direction,
    pub(crate) canonical_format: Option<u8>,
}

impl Ikev2CommittedWindowDomain<Gcm> {
    /// Bind both key directions to an established SA and local sending direction.
    ///
    /// # Errors
    /// Rejects invalid SPIs, GCM profiles or directional key/salt material.
    pub(crate) fn new(
        initiator_spi: u64,
        responder_spi: u64,
        sending_direction: Direction,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
    ) -> Result<Self, Error> {
        let receive = match sending_direction {
            Direction::InitiatorToResponder => Direction::ResponderToInitiator,
            Direction::ResponderToInitiator => Direction::InitiatorToResponder,
        };
        Ok(Self {
            canonical_format: None,
            send: Ikev2AesGcmIvDomain::new(
                initiator_spi,
                responder_spi,
                sending_direction,
                profile,
                keys,
            )
            .map_err(|_| Error::DomainMismatch)?,
            receive: Ikev2AesGcmIvDomain::new(initiator_spi, responder_spi, receive, profile, keys)
                .map_err(|_| Error::DomainMismatch)?,
        })
    }

    /// Derive both directions and the immutable marker from the single IV record.
    ///
    /// Replaces independent SPI/key assembly. This is a descriptor only; window
    /// restoration must still cross-check the same atomic persisted records.
    pub fn from_iv_record(record: &crate::Ikev2AesGcmIvRecord) -> Self {
        Self {
            send: record.domain().clone(),
            receive: record.receive_domain().clone(),
            canonical_format: record.canonical_format(),
        }
    }

    /// Descriptor to use with the single local sending-IV allocator.
    pub const fn send_iv_domain(&self) -> &Ikev2AesGcmIvDomain {
        &self.send
    }
}

impl Ikev2CommittedWindowDomain<Cbc> {
    /// Derive both directions and the exact marker from the immutable CBC epoch.
    /// This descriptor grants no persistence acknowledgement or send permission.
    pub fn from_cbc_epoch(record: &super::Ikev2CbcEpochRecord) -> Self {
        let receive = match record.direction() {
            Direction::InitiatorToResponder => Direction::ResponderToInitiator,
            Direction::ResponderToInitiator => Direction::InitiatorToResponder,
        };
        Self {
            send: super::cbc_epoch::CbcDirection::new(record, record.direction()),
            receive: super::cbc_epoch::CbcDirection::new(record, receive),
            canonical_format: record.canonical_format(),
        }
    }
}

impl<P: RecoveryProfile> Ikev2CommittedWindowDomain<P> {
    pub(super) fn check(
        &self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
    ) -> Result<(), Error> {
        P::check_domain(self, profile, keys)
    }

    pub(super) fn header(&self, exchange: Ikev2ExchangeKind, id: u32, response: bool) -> Header {
        Header::new(
            self.send.initiator_spi(),
            self.send.responder_spi(),
            PayloadType::Encrypted,
            exchange.as_u8(),
            HeaderFlags::from_bits(
                self.send.direction() == Direction::InitiatorToResponder,
                response,
                false,
            ),
            id,
        )
    }
}

/// Exact ordinary request and optional authenticated response plus opaque outcome.
///
/// Accessors are serialization inputs, not send/effect permission. Outcomes are
/// consumer-defined durable state, not automatically inferred protocol success.
/// They must be committed atomically with the window and applied idempotently.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CommittedExchangeRecord {
    pub(super) request: Bytes,
    pub(super) response: Option<Bytes>,
    pub(super) outcome: Option<Bytes>,
}

impl Ikev2CommittedExchangeRecord {
    /// Rebuild trusted persisted fields; window restoration authenticates packets.
    ///
    /// A pending outbound request has neither response nor outcome. An inbound
    /// record always has both; its window constructor enforces that requirement.
    /// # Errors
    /// Rejects an absent request or an unpaired response/outcome.
    pub fn from_persisted(
        request: Bytes,
        response: Option<Bytes>,
        outcome: Option<Bytes>,
    ) -> Result<Self, Error> {
        if request.is_empty() || response.is_some() != outcome.is_some() {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            request,
            response,
            outcome,
        })
    }

    /// Exact request bytes to persist, never an uncommitted transmit permission.
    pub fn request(&self) -> &[u8] {
        &self.request
    }
    /// Exact response, present only together with the corresponding outcome.
    pub fn response(&self) -> Option<&[u8]> {
        self.response.as_deref()
    }
    /// Opaque durable outcome; reading historical state does not repeat an effect.
    pub fn outcome(&self) -> Option<&[u8]> {
        self.outcome.as_deref()
    }
}

/// Mandatory recovery-profile metadata from the same atomic authenticated SA row.
///
/// There is deliberately no default. The immutable agreement must be decoded
/// independently of the mutable synchronization history, never inferred from
/// missing fields. An explicit `None` recovery event is valid only if no local
/// sync proposal has been recorded. Neither variant proves authentication,
/// exclusive ownership or the freshness of the stored row.
#[derive(Clone, PartialEq, Eq)]
pub enum Ikev2PersistedProfileSync<P: RecoveryProfile = Gcm> {
    /// The authenticated SA did not negotiate synchronization.
    Base {
        /// Explicit immutable base-mode agreement, including SPIs and original role.
        agreement: Agreement,
    },
    /// Both peers negotiated synchronization; retain all history and event fields.
    Negotiated {
        /// Immutable negotiated agreement decoded with the SA's keys and identity.
        agreement: Agreement,
        /// Complete responder history, including dispositions and proposal floors.
        state: Ikev2SyncResponderRecord<P>,
        /// Explicit event presence or absence; retain completed/closed events too.
        recovery: Option<super::Ikev2SyncRecoveryRecord<P>>,
    },
}

/// Consumer-owned durable ordinary state for one fenced IKE key epoch.
///
/// No storage format or authentication of the storage acknowledgement is defined.
/// Persist every field atomically with the intended SA and its outcome. Never
/// restore an arbitrary legacy Message-ID snapshot or a rolled-back record.
/// CBC cannot attach GCM sync evidence:
/// ```compile_fail
/// use opc_proto_ikev2::recovery::{Ikev2CbcRecoveryProfile, Ikev2CommittedWindowRecord,
///     Ikev2SyncResponderRecord};
/// fn mix(record: Ikev2CommittedWindowRecord<Ikev2CbcRecoveryProfile>,
///        gcm: Ikev2SyncResponderRecord) {
///     let _ = record.with_sync_state(gcm);
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CommittedWindowRecord<P: RecoveryProfile = Gcm> {
    pub(super) domain: Ikev2CommittedWindowDomain<P>,
    pub(super) generation: u64,
    pub(super) next_send: Option<u32>,
    pub(super) next_receive: Option<u32>,
    pub(super) outbound: Option<Ikev2CommittedExchangeRecord>,
    pub(super) inbound: Option<Ikev2CommittedExchangeRecord>,
    pub(super) sync: Option<Ikev2SyncResponderRecord<P>>,
    pub(super) recovery: Option<super::Ikev2SyncRecoveryRecord<P>>,
}

impl<P: RecoveryProfile> Ikev2CommittedWindowRecord<P> {
    /// Initial fields to commit with a genuinely new durable key epoch.
    ///
    /// Floors must account for all completed handshake messages. Zero means no
    /// request has been used in that direction, not an unknown history. Neither
    /// this constructor nor cloning a record proves persistence or fresh keys.
    pub const fn initial(
        domain: Ikev2CommittedWindowDomain<P>,
        next_send: u32,
        next_receive: u32,
    ) -> Self {
        Self {
            domain,
            generation: 0,
            next_send: Some(next_send),
            next_receive: Some(next_receive),
            outbound: None,
            inbound: None,
            sync: None,
            recovery: None,
        }
    }

    /// Rebuild fields from the latest trusted fenced atomic record.
    ///
    /// `None` is exhausted, distinct from ID zero. Complete restoration additionally
    /// authenticates every cached packet, correlates its response, checks floors
    /// and, for GCM, cross-checks locally sent IVs against its reservation record.
    /// CBC authenticates stored random-IV packets without counter interpretation.
    /// # Errors
    /// Rejects an incomplete inbound result or exhausted direction with no history.
    pub fn from_persisted(
        domain: Ikev2CommittedWindowDomain<P>,
        generation: u64,
        next_send: Option<u32>,
        next_receive: Option<u32>,
        outbound: Option<Ikev2CommittedExchangeRecord>,
        inbound: Option<Ikev2CommittedExchangeRecord>,
    ) -> Result<Self, Error> {
        if inbound
            .as_ref()
            .is_some_and(|entry| entry.response.is_none())
            || (next_send.is_none() && outbound.is_none())
            || (next_receive.is_none() && inbound.is_none())
            || (generation == 0 && (outbound.is_some() || inbound.is_some()))
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            domain,
            generation,
            next_send,
            next_receive,
            outbound,
            inbound,
            sync: None,
            recovery: None,
        })
    }

    /// Rebuild the supported recovery profile with mandatory synchronization mode.
    ///
    /// Obtain every argument from one latest, fenced atomic record. The codec must
    /// reject omitted mode, history or event-presence fields before calling this
    /// function. In particular it must not synthesize `Base` or an absent event.
    /// This checks structural completeness and the immutable agreement binding;
    /// [`super::Ikev2CommittedWindow::restore`] must still authenticate cached
    /// packets and validate key/IV state. Construction grants no effect authority.
    ///
    /// # Errors
    /// Rejects invalid ordinary fields, a foreign SA/original role, disagreement
    /// between the explicit mode and immutable agreement, inconsistent sync
    /// history, or missing event history after any local synchronization proposal.
    pub fn from_profile_persisted(
        domain: Ikev2CommittedWindowDomain<P>,
        generation: u64,
        next_send: Option<u32>,
        next_receive: Option<u32>,
        outbound: Option<Ikev2CommittedExchangeRecord>,
        inbound: Option<Ikev2CommittedExchangeRecord>,
        synchronization: Ikev2PersistedProfileSync<P>,
    ) -> Result<Self, Error> {
        let record = Self::from_persisted(
            domain,
            generation,
            next_send,
            next_receive,
            outbound,
            inbound,
        )?;
        let agreement = match &synchronization {
            Ikev2PersistedProfileSync::Base { agreement }
            | Ikev2PersistedProfileSync::Negotiated { agreement, .. } => *agreement,
        };
        let binding = &record.domain.send;
        let role = match binding.direction() {
            Direction::InitiatorToResponder => Role::Initiator,
            Direction::ResponderToInitiator => Role::Responder,
        };
        let sa = Sa::new(binding.initiator_spi(), binding.responder_spi(), role)
            .map_err(|_| Error::DomainMismatch)?;
        if agreement.sa() != sa {
            return Err(Error::DomainMismatch);
        }
        match synchronization {
            Ikev2PersistedProfileSync::Base { .. } => {
                if agreement.mode() != Mode::BaseFallback {
                    return Err(Error::InvalidRecord);
                }
                Ok(record)
            }
            Ikev2PersistedProfileSync::Negotiated {
                state, recovery, ..
            } => {
                if agreement.mode() != Mode::Negotiated
                    || state.agreement() != agreement
                    || state.highest_local_proposal().is_some() != recovery.is_some()
                {
                    return Err(Error::InvalidRecord);
                }
                let record = record.with_sync_state(state)?;
                match recovery {
                    Some(recovery) => record.with_sync_recovery(recovery),
                    None => Ok(record),
                }
            }
        }
    }

    /// Attach the same atomic record's persisted synchronization metadata.
    ///
    /// Use after `initial` or `from_persisted`; never omit existing sync state on
    /// readback or replace an active SA's immutable agreement. This is a trusted
    /// record constructor, not negotiation, persistence or cutover authority.
    /// # Errors
    /// Rejects an already attached state, a foreign agreement or history that
    /// contradicts this record's floors, generation or cached ordinary requests.
    pub fn with_sync_state(mut self, state: Ikev2SyncResponderRecord<P>) -> Result<Self, Error> {
        if self.sync.is_some() {
            return Err(Error::InvalidRecord);
        }
        state.validate(&self)?;
        self.sync = Some(state);
        Ok(self)
    }

    /// Persist this optional metadata atomically with all ordinary window fields.
    pub const fn sync_state(&self) -> Option<&Ikev2SyncResponderRecord<P>> {
        self.sync.as_ref()
    }

    /// Attach the same atomic record's initiating-event history after sync metadata.
    ///
    /// Never omit existing recovery fields on readback or reset an unfinished event.
    /// This constructor does not mint runtime send or response-completion permission.
    /// # Errors
    /// Rejects an already attached event, foreign SA, inconsistent floors or disposition.
    pub fn with_sync_recovery(
        mut self,
        recovery: super::Ikev2SyncRecoveryRecord<P>,
    ) -> Result<Self, Error> {
        if self.recovery.is_some() {
            return Err(Error::InvalidRecord);
        }
        recovery.validate(&self)?;
        self.recovery = Some(recovery);
        Ok(self)
    }

    /// Initiating-event fields to persist atomically with the complete window.
    pub const fn sync_recovery(&self) -> Option<&super::Ikev2SyncRecoveryRecord<P>> {
        self.recovery.as_ref()
    }

    /// Key/role binding that must be rebuilt from the same durable SA.
    pub const fn domain(&self) -> &Ikev2CommittedWindowDomain<P> {
        &self.domain
    }
    /// Monotonic ordinary commit generation; it never wraps.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Next unused local request ID, or exhausted. MAX is the final usable ID.
    pub const fn next_send(&self) -> Option<u32> {
        self.next_send
    }
    /// Committed peer receive floor, or exhausted. Empty replies advance only the
    /// runtime's [`super::Ikev2CommittedWindow::next_receive`] until ordinary inbound
    /// work or synchronization commits a new boundary.
    pub const fn next_receive(&self) -> Option<u32> {
        self.next_receive
    }
    /// Last locally initiated request, either pending or settled.
    pub const fn outbound(&self) -> Option<&Ikev2CommittedExchangeRecord> {
        self.outbound.as_ref()
    }
    /// Last committed peer request, exact response and outcome.
    pub const fn inbound(&self) -> Option<&Ikev2CommittedExchangeRecord> {
        self.inbound.as_ref()
    }
}
