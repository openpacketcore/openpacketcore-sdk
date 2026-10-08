use bytes::Bytes;

use super::{Ikev2SyncResponderRecord, Ikev2WindowError as Error};
use crate::{
    Header, HeaderFlags, Ikev2AesGcmIvDomain, Ikev2ExchangeKind,
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
    PayloadType,
};

/// Established GCM key epoch and local original role for committed windows.
///
/// Both directional key/salt pairs, algorithm and nonzero SPIs are bound. This
/// descriptor establishes neither fresh-key provenance nor authenticated peers.
/// Persist its inputs atomically with keys, IV reservations and window records.
/// Derive it with [`Self::from_iv_record`], never separately from mutable fields.
///
/// ```compile_fail
/// use opc_proto_ikev2::{Ikev2AesGcmEpochInputs, recovery::Ikev2CommittedWindowDomain};
/// fn assemble(i: Ikev2AesGcmEpochInputs<'_>) {
///     let _ = Ikev2CommittedWindowDomain::new(i.initiator_spi, i.responder_spi,
///         i.sending_direction, i.profile, i.keys);
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CommittedWindowDomain {
    pub(crate) send: Ikev2AesGcmIvDomain,
    pub(crate) receive: Ikev2AesGcmIvDomain,
    pub(crate) canonical_format: Option<u8>,
}

impl Ikev2CommittedWindowDomain {
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

    pub(super) fn check(
        &self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
    ) -> Result<(), Error> {
        let mut actual = Self::new(
            self.send.initiator_spi(),
            self.send.responder_spi(),
            self.send.direction(),
            profile,
            keys,
        )?;
        actual.canonical_format = self.canonical_format;
        if self != &actual {
            return Err(Error::DomainMismatch);
        }
        Ok(())
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

/// Consumer-owned durable ordinary state for one fenced IKE key epoch.
///
/// No storage format or authentication of the storage acknowledgement is defined.
/// Persist every field atomically with the intended SA and its outcome. Never
/// restore an arbitrary legacy Message-ID snapshot or a rolled-back record.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CommittedWindowRecord {
    pub(super) domain: Ikev2CommittedWindowDomain,
    pub(super) generation: u64,
    pub(super) next_send: Option<u32>,
    pub(super) next_receive: Option<u32>,
    pub(super) outbound: Option<Ikev2CommittedExchangeRecord>,
    pub(super) inbound: Option<Ikev2CommittedExchangeRecord>,
    pub(super) sync: Option<Ikev2SyncResponderRecord>,
    pub(super) recovery: Option<super::Ikev2SyncRecoveryRecord>,
}

impl Ikev2CommittedWindowRecord {
    // Preserve locally sent packet evidence before caches/history are retired.
    pub(super) fn retain_local_iv_floor(&mut self) -> Result<(), Error> {
        let Some(sync) = &mut self.sync else {
            return Ok(());
        };
        let ordinary = self
            .outbound
            .as_ref()
            .map(|entry| entry.request.as_ref())
            .into_iter()
            .chain(
                self.inbound
                    .as_ref()
                    .and_then(|entry| entry.response.as_deref()),
            );
        let attempts = self.recovery.iter().flat_map(|recovery| {
            recovery
                .attempts()
                .iter()
                .map(|attempt| attempt.request_bytes())
        });
        for wire in ordinary.chain(attempts) {
            sync.minimum_send_iv_end = sync
                .minimum_send_iv_end
                .max(super::packet::sending_iv_end(wire)?);
        }
        Ok(())
    }

    /// Initial fields to commit with a genuinely new durable key epoch.
    ///
    /// Floors must account for all completed handshake messages. Zero means no
    /// request has been used in that direction, not an unknown history. Neither
    /// this constructor nor cloning a record proves persistence or fresh keys.
    pub const fn initial(
        domain: Ikev2CommittedWindowDomain,
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
    /// and cross-checks locally sent IVs against the sending-IV reservation record.
    /// # Errors
    /// Rejects an incomplete inbound result or exhausted direction with no history.
    pub fn from_persisted(
        domain: Ikev2CommittedWindowDomain,
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

    /// Attach the same atomic record's persisted synchronization metadata.
    ///
    /// Use after `initial` or `from_persisted`; never omit existing sync state on
    /// readback or replace an active SA's immutable agreement. This is a trusted
    /// record constructor, not negotiation, persistence or cutover authority.
    /// # Errors
    /// Rejects an already attached state, a foreign agreement or history that
    /// contradicts this record's floors, generation or cached ordinary requests.
    pub fn with_sync_state(mut self, state: Ikev2SyncResponderRecord) -> Result<Self, Error> {
        if self.sync.is_some() {
            return Err(Error::InvalidRecord);
        }
        state.validate(&self)?;
        self.sync = Some(state);
        Ok(self)
    }

    /// Persist this optional metadata atomically with all ordinary window fields.
    pub const fn sync_state(&self) -> Option<&Ikev2SyncResponderRecord> {
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
        recovery: super::Ikev2SyncRecoveryRecord,
    ) -> Result<Self, Error> {
        if self.recovery.is_some() {
            return Err(Error::InvalidRecord);
        }
        recovery.validate(&self)?;
        self.recovery = Some(recovery);
        Ok(self)
    }

    /// Initiating-event fields to persist atomically with the complete window.
    pub const fn sync_recovery(&self) -> Option<&super::Ikev2SyncRecoveryRecord> {
        self.recovery.as_ref()
    }

    /// Key/role binding that must be rebuilt from the same durable SA.
    pub const fn domain(&self) -> &Ikev2CommittedWindowDomain {
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
