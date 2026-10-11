//! Independent RFC 7296 §§2.1–2.3 and RFC 6311 §§5.1, 8.1, 9 peer.
//!
//! Only authenticated packets enter transitions. No recovery/window/SDK counter
//! type supplies expected IDs, cache decisions, outcomes or sync calculations.
//! Strict window-one policy drops ordinary traffic while local sync is pending.

use std::collections::BTreeMap;

use bytes::Bytes;
use opc_proto_ikev2::{PayloadChain, PayloadType};

use super::wire::{Packet, Wire, WireError};

pub const CACHE_RETENTION_MS: u64 = 180_000;
pub const REQUEST_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    Wire(WireError),
    ChangedRequest(u32),
    ChangedResponse(u32),
    RequestOutsideWindow {
        received: u32,
        expected: Option<u32>,
    },
    OutstandingRequest,
    ResponseMismatch,
    Exhausted,
    InvalidSync,
    SyncRegression,
    SyncExhausted,
    NotNegotiated,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    NewRequest(u32),
    Replay(Bytes),
    Completed(u32),
    Ignored,
    SyncReply { wire: Bytes, abandoned: Option<u32> },
    Synchronized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sync {
    pub nonce: [u8; 4],
    pub send: u32,
    pub receive: u32,
}

impl Sync {
    /// Literal RFC 6311 §6.3 framing, independent of the SDK sync codec.
    pub fn bytes(self) -> Bytes {
        let mut bytes = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26];
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.send.to_be_bytes());
        bytes.extend_from_slice(&self.receive.to_be_bytes());
        bytes.into()
    }

    fn from_packet(packet: &Packet) -> Result<Option<Self>, Violation> {
        // Inspect every generic payload: a sync notification after another
        // payload must not fall through to the ordinary Message-ID window.
        let mut kind = packet.first.as_u8();
        let mut offset = 0;
        let mut found = false;
        while kind != 0 {
            let payload = &packet.body[offset..];
            if kind == 41 && payload.get(6..8) == Some(&[0x40, 0x26][..]) {
                found = true;
            }
            kind = payload[0];
            offset += usize::from(u16::from_be_bytes([payload[2], payload[3]]));
        }
        if !found {
            return Ok(None);
        }
        if packet.first != PayloadType::Notify
            || packet.header.exchange_type != 37
            || packet.header.message_id != 0
            || packet.body.len() != 20
            || packet.body[..8] != [0, 0, 0, 20, 0, 0, 0x40, 0x26]
        {
            return Err(Violation::InvalidSync);
        }
        Ok(Some(Self {
            nonce: packet.body[8..12].try_into().unwrap(),
            send: u32::from_be_bytes(packet.body[12..16].try_into().unwrap()),
            receive: u32::from_be_bytes(packet.body[16..20].try_into().unwrap()),
        }))
    }
}

struct Sent {
    id: u32,
    exchange: u8,
    wire: Bytes,
    at: u64,
}

struct Received {
    exchange: u8,
    wire: Bytes,
    response: Option<(Bytes, u64)>,
}

pub struct PeerModel<'a> {
    pub wire: Wire<'a>,
    next_send: Option<u32>,
    next_receive: Option<u32>,
    highest_received: Option<u32>,
    highest_peer_proposal: Option<u32>,
    highest_local_proposal: Option<u32>,
    sent: Option<Sent>,
    receiving: Option<u32>,
    received: BTreeMap<u32, Received>,
    responses: BTreeMap<u32, Bytes>,
    sync: Option<Sync>,
    sync_started: Option<u64>,
    sync_attempts: u8,
    negotiated: bool,
    now: u64,
    closed: bool,
}

impl<'a> PeerModel<'a> {
    pub fn new(wire: Wire<'a>, next_send: u32, next_receive: u32, negotiated: bool) -> Self {
        Self {
            wire,
            next_send: Some(next_send),
            next_receive: Some(next_receive),
            highest_received: next_receive.checked_sub(1),
            highest_peer_proposal: None,
            highest_local_proposal: None,
            sent: None,
            receiving: None,
            received: BTreeMap::new(),
            responses: BTreeMap::new(),
            sync: None,
            sync_started: None,
            sync_attempts: 0,
            negotiated,
            now: 0,
            closed: false,
        }
    }

    pub fn counters(&self) -> (Option<u32>, Option<u32>) {
        (self.next_send, self.next_receive)
    }

    pub fn advance(&mut self, milliseconds: u64) {
        self.now = self.now.checked_add(milliseconds).unwrap();
        if self
            .sent
            .as_ref()
            .is_some_and(|sent| self.now - sent.at >= REQUEST_TIMEOUT_MS)
            || self
                .sync_started
                .is_some_and(|at| self.now - at >= REQUEST_TIMEOUT_MS)
        {
            self.closed = true;
        }
    }

    pub fn alive(&self) -> bool {
        !self.closed
    }

    pub fn forget_expired_responses(&mut self) {
        for entry in self.received.values_mut() {
            if entry
                .response
                .as_ref()
                .is_some_and(|(_, at)| self.now - at >= CACHE_RETENTION_MS)
            {
                entry.response = None;
            }
        }
    }

    pub fn request(&mut self, exchange: u8, payload: PayloadChain<'_>) -> Result<Bytes, Violation> {
        if self.closed {
            return Err(Violation::Closed);
        }
        if self.sent.is_some() || self.sync.is_some() {
            return Err(Violation::OutstandingRequest);
        }
        let id = self.next_send.ok_or(Violation::Exhausted)?;
        let wire = self.wire.seal(id, false, exchange, payload);
        self.sent = Some(Sent {
            id,
            exchange,
            wire: wire.clone(),
            at: self.now,
        });
        self.next_send = id.checked_add(1);
        Ok(wire)
    }

    pub fn retransmit(&self) -> Option<&[u8]> {
        if self.closed {
            return None;
        }
        self.sent.as_ref().map(|sent| sent.wire.as_ref())
    }

    pub fn respond(&mut self, id: u32, payload: PayloadChain<'_>) -> Result<Bytes, Violation> {
        if self.closed {
            return Err(Violation::Closed);
        }
        if self.receiving != Some(id) {
            return Err(Violation::ResponseMismatch);
        }
        let entry = self.received.get_mut(&id).unwrap();
        let wire = self.wire.seal(id, true, entry.exchange, payload);
        entry.response = Some((wire.clone(), self.now));
        self.receiving = None;
        Ok(wire)
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<Event, Violation> {
        if self.closed {
            return Ok(Event::Ignored);
        }
        let packet = self.wire.open(wire).map_err(Violation::Wire)?;
        if let Some(sync) = Sync::from_packet(&packet)? {
            return self.receive_sync(packet.header.flags.response(), sync);
        }
        // RFC 6311 §8.1 explicitly permits this strict policy for either party.
        if self.sync.is_some() {
            return Ok(Event::Ignored);
        }
        let id = packet.header.message_id;
        if packet.header.flags.response() {
            if let Some(previous) = self.responses.get(&id) {
                return if previous == &packet.wire {
                    Ok(Event::Ignored)
                } else {
                    Err(Violation::ChangedResponse(id))
                };
            }
            let Some(sent) = &self.sent else {
                return Ok(Event::Ignored);
            };
            // An abandoned exchange may still have a response in flight while
            // a post-sync request occupies the new window.
            if id < sent.id {
                return Ok(Event::Ignored);
            }
            if (id, packet.header.exchange_type) != (sent.id, sent.exchange) {
                return Err(Violation::ResponseMismatch);
            }
            self.responses.insert(id, packet.wire);
            self.sent = None;
            return Ok(Event::Completed(id));
        }
        if let Some(previous) = self.received.get(&id) {
            if previous.wire != packet.wire {
                return Err(Violation::ChangedRequest(id));
            }
            return Ok(previous
                .response
                .as_ref()
                .map_or(Event::Ignored, |(bytes, _)| Event::Replay(bytes.clone())));
        }
        if self.next_receive.is_none_or(|next| id < next) {
            return Ok(Event::Ignored);
        }
        if self.receiving.is_some() || self.next_receive != Some(id) {
            return Err(Violation::RequestOutsideWindow {
                received: id,
                expected: self.next_receive,
            });
        }
        // Window one permits forgetting older replies on the next new request.
        for old in self.received.values_mut() {
            old.response = None;
        }
        self.received.insert(
            id,
            Received {
                exchange: packet.header.exchange_type,
                wire: packet.wire,
                response: None,
            },
        );
        self.receiving = Some(id);
        self.highest_received = Some(id);
        self.next_receive = id.checked_add(1);
        Ok(Event::NewRequest(id))
    }

    pub fn begin_sync(&mut self, proposal: Sync) -> Result<Bytes, Violation> {
        if self.closed {
            return Err(Violation::Closed);
        }
        if !self.negotiated {
            return Err(Violation::NotNegotiated);
        }
        let send = self.next_send.ok_or(Violation::Exhausted)?;
        let receive = self.next_receive.ok_or(Violation::Exhausted)?;
        if proposal.send < send
            || self
                .highest_local_proposal
                .is_some_and(|old| proposal.send <= old)
            || proposal.receive < receive
        {
            return Err(Violation::SyncRegression);
        }
        if self.sync_attempts >= 3 {
            self.closed = true;
            return Err(Violation::SyncExhausted);
        }
        self.sync_attempts += 1;
        self.sync_started.get_or_insert(self.now);
        self.highest_local_proposal = Some(proposal.send);
        self.next_send = Some(proposal.send);
        self.next_receive = Some(proposal.receive);
        self.sync = Some(proposal);
        // This model permits a peer failover to abandon its old operations.
        // The SDK profile's own initiation admission is deliberately stricter.
        self.sent = None;
        self.receiving = None;
        for old in self.received.values_mut() {
            old.response = None;
        }
        Ok(self.wire.seal(
            0,
            false,
            37,
            PayloadChain::new(PayloadType::Notify, &proposal.bytes()),
        ))
    }

    fn receive_sync(&mut self, response: bool, value: Sync) -> Result<Event, Violation> {
        if !self.negotiated {
            return Err(Violation::NotNegotiated);
        }
        if response {
            let Some(proposal) = self.sync else {
                return Ok(Event::Ignored);
            };
            if proposal.nonce != value.nonce {
                return Ok(Event::Ignored);
            }
            if value.receive < proposal.send || value.send < proposal.receive {
                return Err(Violation::SyncRegression);
            }
            self.next_send = Some(
                self.next_send
                    .ok_or(Violation::Exhausted)?
                    .max(value.receive),
            );
            self.next_receive = Some(
                self.next_receive
                    .ok_or(Violation::Exhausted)?
                    .max(value.send),
            );
            self.sync = None;
            self.sync_started = None;
            self.sync_attempts = 0;
            return Ok(Event::Synchronized);
        }
        // The normative §5.1 replay rule takes precedence over the illustrative
        // Appendix A.2/A.3 exchanges, whose old M1 would otherwise be accepted.
        if self
            .highest_received
            .into_iter()
            .chain(self.highest_peer_proposal)
            .any(|old| value.send <= old)
        {
            return Ok(Event::Ignored);
        }
        let send = self
            .next_send
            .ok_or(Violation::Exhausted)?
            .max(value.receive);
        let receive = self
            .next_receive
            .ok_or(Violation::Exhausted)?
            .max(value.send);
        self.highest_peer_proposal = Some(value.send);
        self.next_send = Some(send);
        self.next_receive = Some(receive);
        let abandoned = self.sent.take().map(|sent| sent.id);
        self.receiving = None;
        for old in self.received.values_mut() {
            old.response = None;
        }
        let reply = Sync {
            nonce: value.nonce,
            send,
            receive,
        };
        Ok(Event::SyncReply {
            wire: self.wire.seal(
                0,
                true,
                37,
                PayloadChain::new(PayloadType::Notify, &reply.bytes()),
            ),
            abandoned,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_proto_ikev2::{
        Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption, Ikev2PrfAlgorithm,
        Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
        Ikev2SaInitKeyMaterial as Keys,
    };

    fn keys(tag: u8) -> (Profile, Keys) {
        crate::support::ensure_ike_crypto();
        let profile = Profile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2DhGroup::Ecp256,
            Encryption::AesGcm16_128,
        )
        .unwrap();
        let keys = Keys::from_established_keys(
            profile,
            false,
            &[tag; 32],
            &[],
            &[],
            &[tag; 20],
            &[tag + 1; 20],
            &[tag + 2; 32],
            &[tag + 3; 32],
        )
        .unwrap();
        (profile, keys)
    }

    fn pair(
        profile: Profile,
        keys: &Keys,
        a: (u32, u32),
        b: (u32, u32),
    ) -> (PeerModel<'_>, PeerModel<'_>) {
        (
            PeerModel::new(
                Wire::new(profile, keys, (101, 202), Direction::InitiatorToResponder),
                a.0,
                a.1,
                true,
            ),
            PeerModel::new(
                Wire::new(profile, keys, (101, 202), Direction::ResponderToInitiator),
                b.0,
                b.1,
                true,
            ),
        )
    }

    fn empty() -> PayloadChain<'static> {
        PayloadChain::new(PayloadType::NoNext, &[])
    }

    #[test]
    fn independent_directions_cache_and_exact_retransmission() {
        let (profile, keys) = keys(1);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let ar = a.request(37, empty()).unwrap();
        let br = b.request(37, empty()).unwrap();
        assert_eq!(a.retransmit(), Some(ar.as_ref()));
        assert_eq!(a.receive(&br), Ok(Event::NewRequest(0)));
        assert_eq!(b.receive(&ar), Ok(Event::NewRequest(0)));
        let a_reply = a.respond(0, empty()).unwrap();
        let b_reply = b.respond(0, empty()).unwrap();
        assert_eq!(a.receive(&b_reply), Ok(Event::Completed(0)));
        assert_eq!(b.receive(&a_reply), Ok(Event::Completed(0)));
        assert_eq!(a.retransmit(), None);
        assert_eq!(b.receive(&ar), Ok(Event::Replay(b_reply.clone())));
        assert_eq!(a.receive(&b_reply), Ok(Event::Ignored));
        assert_eq!(a.counters(), (Some(1), Some(1)));
        assert_eq!(b.counters(), (Some(1), Some(1)));
    }

    #[test]
    fn changed_request_and_response_are_violations() {
        let (profile, keys) = keys(5);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let request = a.request(37, empty()).unwrap();
        assert_eq!(b.receive(&request), Ok(Event::NewRequest(0)));
        // Same plaintext and ID, different IV: retransmission must be bitwise exact.
        let changed = a.wire.seal(0, false, 37, empty());
        assert_eq!(b.receive(&changed), Err(Violation::ChangedRequest(0)));
        let response = b.respond(0, empty()).unwrap();
        assert_eq!(a.receive(&response), Ok(Event::Completed(0)));
        assert_eq!(
            a.receive(&b.wire.seal(0, true, 37, empty())),
            Err(Violation::ChangedResponse(0))
        );
    }

    #[test]
    fn live_peer_may_forget_response_and_ignore_settled_replay() {
        let (profile, keys) = keys(9);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let request = a.request(37, empty()).unwrap();
        assert_eq!(b.receive(&request), Ok(Event::NewRequest(0)));
        let response = b.respond(0, empty()).unwrap();
        assert_eq!(a.receive(&response), Ok(Event::Completed(0)));
        b.advance(CACHE_RETENTION_MS - 1);
        b.forget_expired_responses();
        assert_eq!(b.receive(&request), Ok(Event::Replay(response)));
        b.advance(1);
        b.forget_expired_responses();
        assert_eq!(b.receive(&request), Ok(Event::Ignored));
        assert!(b.alive());
    }

    #[test]
    fn new_request_retires_cache_and_outside_window_is_detected() {
        let (profile, keys) = keys(13);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let request = a.request(37, empty()).unwrap();
        assert_eq!(b.receive(&request), Ok(Event::NewRequest(0)));
        let response = b.respond(0, empty()).unwrap();
        assert_eq!(a.receive(&response), Ok(Event::Completed(0)));
        assert_eq!(
            b.receive(&a.request(37, empty()).unwrap()),
            Ok(Event::NewRequest(1))
        );
        assert_eq!(b.receive(&request), Ok(Event::Ignored));
        assert_eq!(
            b.receive(&a.wire.seal(2, false, 37, empty())),
            Err(Violation::RequestOutsideWindow {
                received: 2,
                expected: Some(2)
            })
        );
        assert_eq!(a.request(37, empty()), Err(Violation::OutstandingRequest));
    }

    #[test]
    fn max_id_exhausts_without_wrapping() {
        let (profile, keys) = keys(17);
        let (mut a, mut b) = pair(profile, &keys, (u32::MAX, 0), (0, u32::MAX));
        assert_eq!(
            b.receive(&a.request(37, empty()).unwrap()),
            Ok(Event::NewRequest(u32::MAX))
        );
        assert_eq!(
            a.receive(&b.respond(u32::MAX, empty()).unwrap()),
            Ok(Event::Completed(u32::MAX))
        );
        assert_eq!(a.request(37, empty()), Err(Violation::Exhausted));
        assert_eq!(b.counters().1, None);
    }

    #[test]
    fn authentication_failure_changes_no_model_state() {
        let (profile, keys) = keys(21);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let request = a.request(37, empty()).unwrap();
        let mut forged = request.to_vec();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            b.receive(&forged),
            Err(Violation::Wire(WireError::AuthenticationOrFraming))
        );
        assert_eq!(b.counters(), (Some(0), Some(0)));
        assert_eq!(b.receive(&request), Ok(Event::NewRequest(0)));
    }

    #[test]
    fn rfc6311_zero_history_and_normative_old_m1_drop_vectors() {
        let (profile, keys) = keys(25);
        let (mut a, mut b) = pair(profile, &keys, (0, 5), (5, 0));
        let request = a
            .begin_sync(Sync {
                nonce: [1, 2, 3, 4],
                send: 0,
                receive: 5,
            })
            .unwrap();
        let Event::SyncReply { wire, abandoned } = b.receive(&request).unwrap() else {
            panic!("sync response")
        };
        assert_eq!(abandoned, None);
        assert_eq!(
            Sync::from_packet(&a.wire.open(&wire).unwrap()).unwrap(),
            Some(Sync {
                nonce: [1, 2, 3, 4],
                send: 5,
                receive: 0
            })
        );
        assert_eq!(a.receive(&wire), Ok(Event::Synchronized));
        // Appendix A.2 is illustrative; normative §5.1 rejects M1=2 after ID4.
        let (profile, keys) = self::keys(26);
        let (mut a, mut b) = pair(profile, &keys, (2, 3), (4, 5));
        let stale = a
            .begin_sync(Sync {
                nonce: [9; 4],
                send: 2,
                receive: 3,
            })
            .unwrap();
        assert_eq!(b.receive(&stale), Ok(Event::Ignored));
        assert_eq!(b.counters(), (Some(4), Some(5)));
    }

    #[test]
    fn sync_maxima_abandonment_and_higher_retry() {
        let (profile, keys) = keys(29);
        let (mut a, mut b) = pair(profile, &keys, (10, 2), (6, 3));
        let abandoned = b.request(36, empty()).unwrap();
        assert_eq!(b.retransmit(), Some(abandoned.as_ref()));
        let proposal = Sync {
            nonce: [1; 4],
            send: 10,
            receive: 2,
        };
        let request = a.begin_sync(proposal).unwrap();
        let Event::SyncReply { wire, abandoned } = b.receive(&request).unwrap() else {
            panic!("sync response")
        };
        assert_eq!(abandoned, Some(6));
        assert_eq!(
            Sync::from_packet(&a.wire.open(&wire).unwrap()).unwrap(),
            Some(Sync {
                nonce: [1; 4],
                send: 7,
                receive: 10
            })
        );
        assert_eq!(b.receive(&request), Ok(Event::Ignored));
        assert_eq!(a.begin_sync(proposal), Err(Violation::SyncRegression));
        let retry = a
            .begin_sync(Sync {
                nonce: [2; 4],
                send: 11,
                receive: 2,
            })
            .unwrap();
        let Event::SyncReply { wire, .. } = b.receive(&retry).unwrap() else {
            panic!("higher reply")
        };
        assert_eq!(a.receive(&wire), Ok(Event::Synchronized));
        assert_eq!(a.counters(), (Some(11), Some(7)));
        assert_eq!(b.counters(), (Some(7), Some(11)));
    }

    #[test]
    fn sync_nonce_floors_and_strict_pending_window() {
        let (profile, keys) = keys(33);
        let (mut a, b) = pair(profile, &keys, (0, 0), (0, 0));
        a.begin_sync(Sync {
            nonce: [1; 4],
            send: 10,
            receive: 20,
        })
        .unwrap();
        for id in [19, 20, 21] {
            assert_eq!(
                a.receive(&b.wire.seal(id, false, 37, empty())),
                Ok(Event::Ignored)
            );
        }
        let bad_nonce = Sync {
            nonce: [2; 4],
            send: 20,
            receive: 10,
        }
        .bytes();
        assert_eq!(
            a.receive(&b.wire.seal(
                0,
                true,
                37,
                PayloadChain::new(PayloadType::Notify, &bad_nonce)
            )),
            Ok(Event::Ignored)
        );
        assert_eq!(a.request(37, empty()), Err(Violation::OutstandingRequest));
        let regression = Sync {
            nonce: [1; 4],
            send: 19,
            receive: 10,
        }
        .bytes();
        assert_eq!(
            a.receive(&b.wire.seal(
                0,
                true,
                37,
                PayloadChain::new(PayloadType::Notify, &regression)
            )),
            Err(Violation::SyncRegression)
        );
        let valid = Sync {
            nonce: [1; 4],
            send: 21,
            receive: 11,
        }
        .bytes();
        assert_eq!(
            a.receive(
                &b.wire
                    .seal(0, true, 37, PayloadChain::new(PayloadType::Notify, &valid))
            ),
            Ok(Event::Synchronized)
        );
        assert_eq!(a.counters(), (Some(11), Some(21)));
    }

    #[test]
    fn crossed_sync_merges_without_regression() {
        let (profile, keys) = keys(37);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let ar = a
            .begin_sync(Sync {
                nonce: [1; 4],
                send: 4,
                receive: 4,
            })
            .unwrap();
        let br = b
            .begin_sync(Sync {
                nonce: [2; 4],
                send: 5,
                receive: 5,
            })
            .unwrap();
        let Event::SyncReply {
            wire: a_response, ..
        } = a.receive(&br).unwrap()
        else {
            panic!("crossed response")
        };
        let Event::SyncReply {
            wire: b_response, ..
        } = b.receive(&ar).unwrap()
        else {
            panic!("crossed response")
        };
        assert_eq!(a.receive(&b_response), Ok(Event::Synchronized));
        assert_eq!(b.receive(&a_response), Ok(Event::Synchronized));
        assert_eq!(a.counters(), (Some(5), Some(5)));
        assert_eq!(b.counters(), (Some(5), Some(5)));
    }

    #[test]
    fn unanswered_new_request_times_out_and_late_response_cannot_revive_sa() {
        let (profile, keys) = keys(41);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let request = a.request(37, empty()).unwrap();
        assert_eq!(b.receive(&request), Ok(Event::NewRequest(0)));
        a.advance(REQUEST_TIMEOUT_MS - 1);
        assert!(a.alive());
        a.advance(1);
        assert!(!a.alive());
        let response = b.respond(0, empty()).unwrap();
        assert_eq!(a.receive(&response), Ok(Event::Ignored));
        a.advance(REQUEST_TIMEOUT_MS);
        assert!(!a.alive());
        assert_eq!(a.receive(&response), Ok(Event::Ignored));
        assert_eq!(a.request(37, empty()), Err(Violation::Closed));
        assert_eq!(a.retransmit(), None);
    }

    #[test]
    fn local_failover_abandons_pending_work_and_ignores_its_late_response() {
        let (profile, keys) = keys(45);
        let (mut a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let old = a.request(37, empty()).unwrap();
        assert_eq!(b.receive(&old), Ok(Event::NewRequest(0)));
        let late = b.respond(0, empty()).unwrap();
        let request = a
            .begin_sync(Sync {
                nonce: [1; 4],
                send: 1,
                receive: 0,
            })
            .unwrap();
        assert_eq!(a.retransmit(), None);
        let Event::SyncReply { wire, .. } = b.receive(&request).unwrap() else {
            panic!("sync response")
        };
        assert_eq!(a.receive(&wire), Ok(Event::Synchronized));
        let new = a.request(37, empty()).unwrap();
        assert_eq!(a.receive(&late), Ok(Event::Ignored));
        assert_eq!(a.retransmit(), Some(new.as_ref()));
        assert_eq!(b.receive(&new), Ok(Event::NewRequest(1)));
        assert_eq!(
            a.receive(&b.respond(1, empty()).unwrap()),
            Ok(Event::Completed(1))
        );
        a.advance(REQUEST_TIMEOUT_MS);
        assert!(a.alive());
    }

    #[test]
    fn sync_must_be_negotiated_and_alone_at_informational_id_zero() {
        let (profile, keys) = keys(49);
        let (a, mut b) = pair(profile, &keys, (0, 0), (0, 0));
        let sync = Sync {
            nonce: [1; 4],
            send: 0,
            receive: 0,
        }
        .bytes();
        let mut before = vec![41, 0, 0, 8, 1, 0, 0, 0];
        before.extend_from_slice(&sync);
        let mut after = sync.to_vec();
        after[0] = 42;
        after.extend_from_slice(&[0, 0, 0, 8, 1, 0, 0, 0]);
        for (id, exchange, first, body) in [
            (1, 37, PayloadType::Notify, sync.as_ref()),
            (0, 36, PayloadType::Notify, sync.as_ref()),
            (0, 37, PayloadType::Delete, before.as_slice()),
            (0, 37, PayloadType::Notify, after.as_slice()),
        ] {
            let wire = a
                .wire
                .seal(id, false, exchange, PayloadChain::new(first, body));
            assert_eq!(b.receive(&wire), Err(Violation::InvalidSync));
            assert_eq!(b.counters(), (Some(0), Some(0)));
        }
        b.negotiated = false;
        assert_eq!(
            b.begin_sync(Sync {
                nonce: [1; 4],
                send: 0,
                receive: 0
            }),
            Err(Violation::NotNegotiated)
        );
        assert_eq!(
            b.receive(
                &a.wire
                    .seal(0, false, 37, PayloadChain::new(PayloadType::Notify, &sync))
            ),
            Err(Violation::NotNegotiated)
        );
    }

    #[test]
    fn sync_retry_budget_and_original_deadline_bound_a_silent_peer() {
        let (profile, keys) = keys(53);
        let (mut a, _) = pair(profile, &keys, (0, 0), (0, 0));
        for n in 1..=3 {
            a.begin_sync(Sync {
                nonce: [n as u8; 4],
                send: n,
                receive: 0,
            })
            .unwrap();
        }
        assert_eq!(
            a.begin_sync(Sync {
                nonce: [4; 4],
                send: 4,
                receive: 0
            }),
            Err(Violation::SyncExhausted)
        );
        assert!(!a.alive());
        let (mut a, _) = pair(profile, &keys, (0, 0), (0, 0));
        a.begin_sync(Sync {
            nonce: [1; 4],
            send: 1,
            receive: 0,
        })
        .unwrap();
        a.advance(REQUEST_TIMEOUT_MS - 1);
        a.begin_sync(Sync {
            nonce: [2; 4],
            send: 2,
            receive: 0,
        })
        .unwrap();
        assert!(a.alive());
        a.advance(1);
        assert!(!a.alive());
        assert_eq!(
            a.begin_sync(Sync {
                nonce: [3; 4],
                send: 3,
                receive: 0
            }),
            Err(Violation::Closed)
        );
    }
}
