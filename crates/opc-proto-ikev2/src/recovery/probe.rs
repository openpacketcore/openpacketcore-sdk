//! Volatile empty-INFORMATIONAL probes: liveness requests without durable work.
//!
//! An empty INFORMATIONAL request is the RFC 7296 §2.4 liveness probe. This
//! module seals and retains one in memory only: no window record, IV record,
//! outcome or completion is persisted. The send Message ID advances volatilely
//! and is written by the next committed operation; the probe itself issues no
//! store command. A crash may therefore lose the advanced IDs as a bounded lead
//! ([RFC 6311 §5.1]): the restored window expects its durable floor and treats
//! any probe ID not covered by the durable record as unobserved state. The
//! consumer either advances the floor with an ordinary commit or resolves the
//! lead through the RFC 6311 message-ID synchronization hooks before relying on
//! the peer's receive expectation.
//!
//! Retransmission replays the exact sealed bytes: no new Message ID and no new
//! IV. The caller owns the retransmission budget and the complete idleness
//! decision; this primitive never decides that a peer is idle. RFC 7296 §2.4
//! and 3GPP TS 24.302 §7.4.1A require the liveness period to cover both IKE and
//! IPsec, so the caller must establish that no authenticated protected IKEv2 or
//! IPsec (ESP) message was received for the period from the IKE SA or any Child
//! SA under it. NAT keepalives ([RFC 3948 §4]) and unauthenticated traffic never
//! count. A matching response is liveness evidence for the caller's current SA
//! fence only: it authorizes no endpoint, key, bearer, lifetime or application
//! outcome mutation.
//!
//! GCM sealing requires a [`crate::Ikev2AesGcmIvAllocation`] taken from an
//! already committed reservation block. Because the probe performs no durable
//! write, it must not allocate from an uncommitted block tail: a crash restores
//! the allocator to the durable `exclusive_end` and could otherwise reuse a
//! probe IV. CBC uses its admitted random IV and needs no allocation.
//!
//! [RFC 6311 §5.1]: https://www.rfc-editor.org/rfc/rfc6311.html#section-5.1
//! [RFC 3948 §4]: https://www.rfc-editor.org/rfc/rfc3948.html#section-4

use std::marker::PhantomData;

use bytes::Bytes;

use super::profile::{Ikev2GcmRecoveryProfile as Gcm, RecoveryProfile};
use super::{
    Ikev2AuthenticatedOrdinary as Request, Ikev2CommittedWindow as Window,
    Ikev2WindowError as Error,
};
use crate::{Ikev2ExchangeKind, PayloadChain, PayloadType};

pub(super) struct PendingEmptyRequest {
    message_id: u32,
    wire: Bytes,
}

/// Volatile send state for empty INFORMATIONAL probes.
///
/// `next_send` is the in-memory high-water mark: the ID after the last probe
/// sealed in this runtime, whether or not that probe is still pending. It is
/// folded into the next committed window record, never persisted on its own.
#[derive(Default)]
pub(super) struct ProbeState {
    pub(super) pending: Option<PendingEmptyRequest>,
    pub(super) next_send: Option<u32>,
}

/// Sealed liveness request holding an exclusive borrow of its admitted window.
///
/// Transmit these exact bytes while retaining this value and the external
/// fenced SA/send authority; the borrow prevents an SDK lifecycle transition
/// before submission. Dropping the value does not transmit, discard or settle
/// the probe: it remains pending until a matching response is admitted or the
/// caller abandons it. This type performs no transport operation.
#[must_use = "transmit the exact retained bytes while this window borrow lives"]
pub struct Ikev2EmptyRequest<'a, P: RecoveryProfile = Gcm> {
    wire: Bytes,
    message_id: u32,
    window: PhantomData<&'a mut Window<P>>,
}

impl<P: RecoveryProfile> Ikev2EmptyRequest<'_, P> {
    /// Complete immutable IKE packet without transport framing.
    pub fn bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Message ID of the retained request; retransmissions reuse it.
    pub const fn message_id(&self) -> u32 {
        self.message_id
    }
}

impl<P: RecoveryProfile> std::fmt::Debug for Ikev2EmptyRequest<'_, P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ikev2EmptyRequest")
            .finish_non_exhaustive()
    }
}

/// Evidence that the peer answered one outstanding empty INFORMATIONAL request.
///
/// This is liveness evidence for the caller's current SA fence. It grants no
/// endpoint, key, bearer, lifetime or application-outcome authority and is not
/// proof that later traffic from the peer will arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ikev2EmptyRequestCompletion {
    message_id: u32,
}

impl Ikev2EmptyRequestCompletion {
    /// Message ID of the answered request.
    pub const fn message_id(self) -> u32 {
        self.message_id
    }
}

impl<P: RecoveryProfile> Window<P> {
    /// Seal one empty INFORMATIONAL request at the volatile next send ID.
    ///
    /// No store command is issued and no durable record changes. The request
    /// occupies the single local request slot until [`Self::complete_empty_request`]
    /// or [`Self::abandon_empty_request`]; ordinary preparation and sync
    /// initiation are refused with [`Error::RequestOutstanding`] meanwhile.
    /// Peer requests in the independent receive direction remain admissible.
    ///
    /// The caller must have established the full liveness period, including
    /// authenticated ESP traffic under this IKE SA (module docs), and owns the
    /// retransmission budget. Start the caller's deadline before the first
    /// transmission and abandon the probe when it expires.
    ///
    /// # Errors
    /// Refuses an unresolved lifecycle, pending ordinary work, an already
    /// pending probe, an exhausted send-ID space, or sealing/admission failure.
    /// A failed seal burns its supplied allocation but changes no Message-ID
    /// state and creates no pending probe.
    pub fn send_empty_request(
        &mut self,
        profile: crate::Ikev2SaInitCryptoProfile,
        keys: &crate::Ikev2SaInitKeyMaterial,
        sealing: P::Sealing<'_>,
    ) -> Result<Ikev2EmptyRequest<'_, P>, Error> {
        self.ready()?;
        if self
            .record
            .outbound
            .as_ref()
            .is_some_and(|entry| entry.response.is_none())
            || self.probe.pending.is_some()
        {
            return Err(Error::RequestOutstanding);
        }
        let id = self.effective_next_send().ok_or(Error::Exhausted)?;
        let sealed = super::packet::seal(
            &self.record.domain,
            profile,
            keys,
            sealing,
            self.record
                .domain
                .header(Ikev2ExchangeKind::Informational, id, false),
            PayloadChain::new(PayloadType::NoNext, &[]),
        )?;
        let wire = sealed.into_wire();
        self.probe.pending = Some(PendingEmptyRequest {
            message_id: id,
            wire: wire.clone(),
        });
        self.probe.next_send = id.checked_add(1);
        Ok(Ikev2EmptyRequest {
            wire,
            message_id: id,
            window: PhantomData,
        })
    }

    /// Return the exact retained probe bytes for retransmission.
    ///
    /// `None` when no probe is pending. Retransmission reuses the original IV
    /// and Message ID and requires no allocation. The caller stops
    /// retransmitting at its own budget and then abandons the probe.
    /// # Errors
    /// Quiescent runtimes must resolve readback first; other lifecycle blocks
    /// keep refusing new work.
    pub fn retransmit_empty_request(&self) -> Result<Option<&[u8]>, Error> {
        self.ready()?;
        Ok(self
            .probe
            .pending
            .as_ref()
            .map(|pending| pending.wire.as_ref()))
    }

    /// Admit the authenticated response to the pending probe and complete it.
    ///
    /// The caller authenticates the peer packet with [`Self::open_peer`] first.
    /// The response must be an empty INFORMATIONAL response with the pending
    /// Message ID; every other shape, a duplicate after completion, a late
    /// response after abandonment or a response for a restored/fenced probe is
    /// [`Error::Drop`]. No durable state changes.
    /// # Errors
    /// Rejects unresolved lifecycle, unknown or mismatched responses, and
    /// non-empty response payloads.
    pub fn complete_empty_request(
        &mut self,
        response: &Request<P>,
    ) -> Result<Ikev2EmptyRequestCompletion, Error> {
        self.ready()?;
        let Some(pending) = self.probe.pending.as_ref() else {
            return Err(Error::Drop);
        };
        if response.domain != self.record.domain
            || !response.header.flags.response()
            || response.header.exchange_type != Ikev2ExchangeKind::Informational.as_u8()
            || response.header.message_id != pending.message_id
            || !response.payloads().is_empty()
        {
            return Err(Error::Drop);
        }
        let completion = Ikev2EmptyRequestCompletion {
            message_id: pending.message_id,
        };
        self.probe.pending = None;
        Ok(completion)
    }

    /// End the caller's retransmission budget and release the request slot.
    ///
    /// Returns the abandoned Message ID, or `None` when no probe is pending.
    /// The ID stays consumed in this runtime and the next committed operation
    /// persists the advance. A late response is then an unknown ID and drops.
    /// # Errors
    /// Quiescent runtimes must resolve readback first.
    pub fn abandon_empty_request(&mut self) -> Result<Option<u32>, Error> {
        self.ready()?;
        Ok(self.probe.pending.take().map(|pending| pending.message_id))
    }

    /// Message ID of the pending probe, when one is outstanding.
    pub fn pending_empty_request_message_id(&self) -> Option<u32> {
        self.probe
            .pending
            .as_ref()
            .map(|pending| pending.message_id)
    }

    /// Next local request Message ID including volatile empty-probe advances.
    ///
    /// This is not a persistence input. The committed record's `next_send`
    /// advances only when the next durable operation commits.
    pub fn next_send_message_id(&self) -> Option<u32> {
        self.effective_next_send()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::canonical_test_fixtures::{Fixture, delete, empty};
    use crate::recovery::{
        Ikev2CommittedWindowDomain as Domain, Ikev2OrdinaryRequestDisposition as Disposition,
        cbc_test_fixtures,
    };
    use crate::{
        Ikev2AesGcmIvPurpose as Purpose, Ikev2EncryptionAlgorithm as Encryption,
        Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitProtectedPayloadProvider, Message,
        ProtectedPayloadKind, decode_header, open_protected_payloads,
    };
    use opc_protocol::{BorrowDecode, DecodeContext};

    fn fixture(tag: u64) -> Fixture {
        crate::test_support::ensure_ike_crypto();
        Fixture::new(
            tag,
            Encryption::AesGcm16_128,
            Direction::InitiatorToResponder,
        )
    }

    fn send_probe(f: &mut Fixture) -> (u32, Vec<u8>) {
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        let request = f
            .window
            .send_empty_request(f.profile, &f.keys, allocation)
            .unwrap();
        let id = request.message_id();
        let bytes = request.bytes().to_vec();
        drop(request);
        (id, bytes)
    }

    #[test]
    fn seals_an_authenticated_empty_informational_request() {
        let mut f = fixture(91_001);
        let (id, bytes) = send_probe(&mut f);
        assert_eq!(id, 0);

        let (payload_region, header) = decode_header(&bytes, DecodeContext::default()).unwrap();
        assert_eq!(payload_region.len(), bytes.len() - crate::HEADER_LEN);
        assert_eq!(
            header.exchange_type,
            Ikev2ExchangeKind::Informational.as_u8()
        );
        assert_eq!(header.message_id, id);
        assert!(!header.flags.response());
        assert_eq!(header.next_payload, PayloadType::Encrypted.as_u8());

        // The peer opens the exact same authenticated empty chain.
        let (rest, message) = Message::decode(&bytes, DecodeContext::default()).unwrap();
        assert!(rest.is_empty());
        let provider = Ikev2SaInitProtectedPayloadProvider::new(f.profile, &f.keys, f.direction);
        let opened =
            open_protected_payloads(&message, &bytes, DecodeContext::default(), &provider).unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].kind, ProtectedPayloadKind::Encrypted);
        assert_eq!(opened[0].first_inner_payload, PayloadType::NoNext);
        assert!(opened[0].cleartext.is_empty());
    }

    #[test]
    fn a_matching_authenticated_response_completes_the_probe() {
        let mut f = fixture(91_002);
        let (id, _) = send_probe(&mut f);
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));

        let wire = f.peer(
            id,
            true,
            Ikev2ExchangeKind::Informational.as_u8(),
            empty(),
            0,
            0x2000,
        );
        let response = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let completion = f.window.complete_empty_request(&response).unwrap();
        assert_eq!(completion.message_id(), id);
        assert_eq!(f.window.pending_empty_request_message_id(), None);
        assert!(f.window.retransmit_empty_request().unwrap().is_none());
        // A duplicate response after completion is an unknown exchange.
        assert_eq!(f.window.complete_empty_request(&response), Err(Error::Drop));
    }

    #[test]
    fn unknown_ids_nonempty_shapes_and_failed_integrity_do_not_complete() {
        let mut f = fixture(91_003);
        let (id, _) = send_probe(&mut f);

        let wrong_id = f.peer(
            id.wrapping_add(1),
            true,
            Ikev2ExchangeKind::Informational.as_u8(),
            empty(),
            0,
            0x2100,
        );
        let opened = f.window.open_peer(f.profile, &f.keys, &wrong_id).unwrap();
        assert_eq!(f.window.complete_empty_request(&opened), Err(Error::Drop));
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));

        // The right Message ID with inner payloads is not a liveness response.
        let nonempty = f.peer(
            id,
            true,
            Ikev2ExchangeKind::Informational.as_u8(),
            delete(),
            0,
            0x2101,
        );
        let opened = f.window.open_peer(f.profile, &f.keys, &nonempty).unwrap();
        assert_eq!(f.window.complete_empty_request(&opened), Err(Error::Drop));
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));

        // A tampered response never authenticates, so it cannot complete.
        let mut tampered = f
            .peer(
                id,
                true,
                Ikev2ExchangeKind::Informational.as_u8(),
                empty(),
                0,
                0x2102,
            )
            .to_vec();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(f.window.open_peer(f.profile, &f.keys, &tampered).is_err());
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));
    }

    #[test]
    fn caller_budget_retransmits_exact_bytes_and_abandons_without_a_write() {
        let mut f = fixture(91_004);
        let (id, first) = send_probe(&mut f);
        let durable_before = f.window.record().clone();
        const CALLER_BUDGET: usize = 3;
        for _ in 0..CALLER_BUDGET {
            assert_eq!(
                f.window.retransmit_empty_request().unwrap(),
                Some(first.as_slice())
            );
        }
        assert_eq!(f.window.record(), &durable_before);

        assert_eq!(f.window.abandon_empty_request().unwrap(), Some(id));
        assert!(f.window.retransmit_empty_request().unwrap().is_none());
        assert_eq!(f.window.record(), &durable_before);
        assert_eq!(f.window.next_send_message_id(), Some(id + 1));

        // A late response after abandonment is an unknown ID.
        let late = f.peer(
            id,
            true,
            Ikev2ExchangeKind::Informational.as_u8(),
            empty(),
            0,
            0x2200,
        );
        let opened = f.window.open_peer(f.profile, &f.keys, &late).unwrap();
        assert_eq!(f.window.complete_empty_request(&opened), Err(Error::Drop));
    }

    #[test]
    fn ordinary_work_is_refused_until_the_probe_is_abandoned() {
        let mut f = fixture(91_005);
        let (id, _) = send_probe(&mut f);
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        assert_eq!(
            f.window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    allocation,
                    Ikev2ExchangeKind::Informational,
                    delete(),
                )
                .err(),
            Some(Error::RequestOutstanding)
        );

        assert_eq!(f.window.abandon_empty_request().unwrap(), Some(id));
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                allocation,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        // The abandoned probe ID is consumed; ordinary work starts after it.
        assert_eq!(prepared.record().next_send(), Some(id + 2));
    }

    #[test]
    fn the_next_committed_operation_persists_the_probe_lead() {
        let Fixture {
            profile,
            keys,
            direction: _,
            spis: _,
            iv,
            allocator,
            window,
        } = fixture(91_006);
        let mut allocator = allocator;
        let mut window = window;
        let (probe_id, _) = {
            let allocation = allocator.allocate(Purpose::Ordinary).unwrap();
            let request = window
                .send_empty_request(profile, &keys, allocation)
                .unwrap();
            let id = request.message_id();
            drop(request);
            (id, ())
        };
        assert_eq!(window.abandon_empty_request().unwrap(), Some(probe_id));

        let allocation = allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = window
            .prepare_request(
                profile,
                &keys,
                allocation,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        let candidate = prepared.record().clone();
        assert_eq!(candidate.next_send(), Some(probe_id + 2));
        let commit = prepared.commit_after_durable(&candidate).unwrap();
        assert!(window.apply_committed(commit).unwrap().is_none());

        // Restart from the committed record observes the folded lead.
        drop(window);
        let restored: Window<Gcm> = Window::restore(
            &Domain::<Gcm>::from_iv_record(&iv),
            profile,
            &keys,
            &candidate,
            &iv,
        )
        .unwrap();
        assert_eq!(restored.record().next_send(), Some(probe_id + 2));
        assert_eq!(restored.next_send_message_id(), Some(probe_id + 2));
        assert_eq!(restored.pending_empty_request_message_id(), None);
    }

    #[test]
    fn restart_without_a_commit_loses_the_lead_as_a_bounded_reuse() {
        let Fixture {
            profile,
            keys,
            direction: _,
            spis: _,
            iv,
            allocator,
            window,
        } = fixture(91_007);
        let mut allocator = allocator;
        let mut window = window;
        let allocation = allocator.allocate(Purpose::Ordinary).unwrap();
        let request = window
            .send_empty_request(profile, &keys, allocation)
            .unwrap();
        let id = request.message_id();
        drop(request);
        assert_eq!(id, 0);
        let durable_before = window.record().clone();

        // Crash with the probe outstanding: nothing was persisted.
        drop(window);
        let mut restored: Window<Gcm> = Window::restore(
            &Domain::<Gcm>::from_iv_record(&iv),
            profile,
            &keys,
            &durable_before,
            &iv,
        )
        .unwrap();
        assert_eq!(restored.record().next_send(), Some(id));
        assert_eq!(restored.next_send_message_id(), Some(id));
        assert_eq!(restored.pending_empty_request_message_id(), None);

        // The bounded lead permits reusing the unrecoverable ID. When the peer
        // may have observed the lost probe, the consumer must synchronize the
        // Message IDs first instead of reusing it for different content.
        let allocation = allocator.allocate(Purpose::Ordinary).unwrap();
        let second = restored
            .send_empty_request(profile, &keys, allocation)
            .unwrap();
        assert_eq!(second.message_id(), id);
    }

    #[test]
    fn peer_work_in_the_receive_direction_remains_admissible() {
        let mut f = fixture(91_008);
        let (probe_id, _) = send_probe(&mut f);

        let wire = f.peer(
            0,
            false,
            Ikev2ExchangeKind::Informational.as_u8(),
            delete(),
            0,
            0x2300,
        );
        let peer_request = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        assert_eq!(
            f.window.request_disposition(&peer_request).unwrap(),
            Disposition::New
        );

        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = f
            .window
            .prepare_response(
                f.profile,
                &f.keys,
                allocation,
                &peer_request,
                empty(),
                bytes::Bytes::from_static(b"accepted"),
            )
            .unwrap();
        let candidate = prepared.record().clone();
        // The inbound commit also persists the volatile probe send-ID advance.
        assert_eq!(candidate.next_send(), Some(probe_id + 1));
        assert_eq!(candidate.next_receive(), Some(1));
        let commit = prepared.commit_after_durable(&candidate).unwrap();
        assert!(f.window.apply_committed(commit).unwrap().is_some());
        assert_eq!(f.window.pending_empty_request_message_id(), Some(probe_id));
    }

    #[test]
    fn empty_peer_requests_are_answered_while_the_probe_is_outstanding() {
        let mut f = fixture(91_009);
        f.window
            .enable_empty_replies(crate::canonical::Ikev2CanonicalPolicy::default())
            .unwrap();
        let (probe_id, _) = send_probe(&mut f);

        let peer_request = f.request(0);
        let reply = f.window.reply_empty(&peer_request).unwrap();
        // The fixture is a restored window, so its first stateless prefix is
        // reconstruction-uncertain; the outstanding probe does not change that.
        assert_eq!(
            reply.observation(),
            crate::recovery::Ikev2EmptyReplyObservation::Uncertain
        );
        assert!(!reply.bytes().is_empty());
        drop(reply);
        assert_eq!(f.window.pending_empty_request_message_id(), Some(probe_id));
    }

    #[test]
    fn cbc_profile_seals_and_completes_with_a_random_iv() {
        let f = cbc_test_fixtures::Fixture::new(
            cbc_test_fixtures::profiles().next().unwrap(),
            cbc_test_fixtures::DIRECTIONS[0],
            91_010,
        );
        let mut window = f.window();
        let request = window.send_empty_request(f.profile, &f.keys, ()).unwrap();
        assert_eq!(request.message_id(), 1);
        drop(request);

        let response = f.peer_packet(
            1,
            true,
            crate::PayloadChain::new(crate::PayloadType::NoNext, &[]),
            0,
        );
        let opened = window.open_peer(f.profile, &f.keys, &response).unwrap();
        let completion = window.complete_empty_request(&opened).unwrap();
        assert_eq!(completion.message_id(), 1);
        assert_eq!(window.pending_empty_request_message_id(), None);
    }

    fn settle_outbound(f: &mut Fixture) {
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                allocation,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        f.window.apply_committed(commit).unwrap();
        let wire = f.peer(0, true, 37, empty(), 0, 0x9000);
        let response = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = f
            .window
            .prepare_completion(&response, Bytes::from_static(b"settled"))
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        assert_eq!(
            f.window.apply_committed(commit).unwrap(),
            Some(Bytes::from_static(b"settled"))
        );
    }

    fn commit_peer_work_after_probe(
        f: &mut Fixture,
    ) -> super::super::Ikev2CommittedWindowRecord<Gcm> {
        let wire = f.peer(0, false, 37, delete(), 0, 0x9001);
        let request = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = f
            .window
            .prepare_response(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                &request,
                empty(),
                Bytes::from_static(b"peer-work"),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        assert_eq!(
            f.window.apply_committed(commit).unwrap(),
            Some(Bytes::from_static(b"peer-work"))
        );
        row
    }

    #[test]
    fn settled_outbound_cache_and_newer_probe_survive_inbound_commit_and_restore() {
        let mut f = fixture(92_001);
        settle_outbound(&mut f);
        let (id, _) = send_probe(&mut f);
        assert_eq!(id, 1);
        let row = commit_peer_work_after_probe(&mut f);
        assert_eq!(row.next_send(), Some(2));
        let restored: Window<Gcm> = Window::restore(
            &Domain::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &row,
            &f.iv,
        )
        .expect("retained older settled exchange is valid");
        assert_eq!(
            restored.record().outbound().unwrap().outcome(),
            Some(b"settled".as_slice())
        );
    }

    #[test]
    fn settled_outbound_cache_and_newer_probe_survive_inbound_readback() {
        let mut f = fixture(92_002);
        settle_outbound(&mut f);
        send_probe(&mut f);
        let row = commit_peer_work_after_probe(&mut f);
        f.window
            .reconcile(f.profile, &f.keys, &row, &f.iv)
            .expect("authenticated settled/probe history reconciles");
        assert_eq!(f.window.record(), &row);
    }

    #[test]
    fn cbc_settled_outbound_cache_and_newer_probe_survive_inbound_commit() {
        let f = cbc_test_fixtures::Fixture::new(
            cbc_test_fixtures::profiles().next().unwrap(),
            cbc_test_fixtures::DIRECTIONS[0],
            92_003,
        );
        let mut window = f.window();
        let prepared = window
            .prepare_request(
                f.profile,
                &f.keys,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        window.apply_committed(commit).unwrap();
        let wire = f.peer_packet(1, true, empty(), 0);
        let response = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = window
            .prepare_completion(&response, Bytes::from_static(b"settled"))
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        window.apply_committed(commit).unwrap();
        let probe = window.send_empty_request(f.profile, &f.keys, ()).unwrap();
        assert_eq!(probe.message_id(), 2);
        drop(probe);
        let wire = f.peer_packet(1, false, delete(), 0);
        let request = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = window
            .prepare_response(
                f.profile,
                &f.keys,
                &request,
                empty(),
                Bytes::from_static(b"peer-work"),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        window.apply_committed(commit).unwrap();
        let restored = f.restore(&row);
        assert_eq!(restored.record().next_send(), Some(3));
        assert_eq!(
            restored.record().outbound().unwrap().outcome(),
            Some(b"settled".as_slice())
        );
    }

    #[test]
    fn the_last_message_id_is_reserved_for_rekey_or_closure() {
        let mut f = fixture(92_004);
        let row = super::super::Ikev2CommittedWindowRecord::initial(
            Domain::from_iv_record(&f.iv),
            u32::MAX,
            0,
        );
        f.window = Window::restore(
            &Domain::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &row,
            &f.iv,
        )
        .unwrap();
        assert_eq!(
            f.window
                .send_empty_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap()
                )
                .err(),
            Some(Error::Exhausted)
        );
    }

    #[test]
    fn an_answered_probe_cannot_be_reused_for_a_delete_after_restart() {
        let mut f = fixture(92_005);
        let (id, _) = send_probe(&mut f);
        let response = f.peer(id, true, 37, empty(), 0, 0x9002);
        let opened = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
        f.window.complete_empty_request(&opened).unwrap();
        let row = f.window.record().clone();
        let mut restored: Window<Gcm> = Window::restore(
            &Domain::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &row,
            &f.iv,
        )
        .unwrap();
        assert!(
            restored
                .prepare_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    Ikev2ExchangeKind::Informational,
                    delete()
                )
                .is_err(),
            "restart must synchronize or retire before reusing the probe's ID for durable work"
        );
    }

    #[test]
    fn a_failed_probe_cannot_release_the_sa_for_another_request() {
        let mut f = fixture(92_006);
        send_probe(&mut f);
        f.window.abandon_empty_request().unwrap();
        assert!(
            f.window.ready().is_err(),
            "exhausted liveness must retire the scoped SA"
        );
    }

    #[test]
    fn probe_origination_requires_a_durable_positive_bound() {
        let mut f = fixture(92_007);
        assert!(
            f.window
                .send_empty_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap()
                )
                .is_err(),
            "an unconfigured SA has no safe crash bound for unwritten probes"
        );
    }
}
