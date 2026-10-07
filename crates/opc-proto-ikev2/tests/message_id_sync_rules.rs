//! Pure RFC 6311 negotiation and counter decisions, with synthetic inputs.
//! Authentication, persistence, entropy and transmission are not exercised.

use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload,
    decode_ike_auth_cleartext_payloads, Header, HeaderFlags, Ikev2IkeAuthPayloadBuild,
    Ikev2MessageIdSync as Sync, Ikev2MessageIdSyncAgreement as Agreement,
    Ikev2MessageIdSyncCounters as Counters, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncNegotiation as Negotiation, Ikev2MessageIdSyncPending as Pending,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncRuleError as RuleError,
    Ikev2MessageIdSyncSa as Sa, Ikev2NotifyPayloadBuild, PayloadChain, PayloadType,
    EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_INFORMATIONAL,
};

const NONCE: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

fn sa(role: Role) -> Sa {
    Sa::new(0x101, 0x202, role).unwrap()
}

fn header(role: Role, response: bool, exchange_type: u8) -> Header {
    Header::new(
        0x101,
        0x202,
        PayloadType::Encrypted,
        exchange_type,
        HeaderFlags::from_bits(role == Role::Responder, response, false),
        0,
    )
}

fn observe(negotiation: &mut Negotiation, role: Role, bodies: &[&[u8]]) {
    let payloads = bodies
        .iter()
        .map(|body| Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: body.to_vec(),
        })
        .collect::<Vec<_>>();
    let (first, bytes) = if payloads.is_empty() {
        (PayloadType::NoNext, bytes::Bytes::new())
    } else {
        build_ike_auth_cleartext_payload_chain(&payloads).unwrap()
    };
    let opened = decode_ike_auth_cleartext_payloads(first, &bytes).unwrap();
    let mut auth = header(role, role == Role::Initiator, EXCHANGE_TYPE_IKE_AUTH);
    auth.message_id = 7; // A later EAP round is allowed.
    negotiation
        .observe_peer_offer(&auth, opened.message_id_sync_supported())
        .unwrap();
}

const OFFER: &[u8] = &[0, 0, 0x40, 0x24];
const BAD_OFFER: &[u8] = &[0, 0, 0x40, 0x24, 1];

fn agreement(role: Role) -> Agreement {
    let mut negotiation = Negotiation::new(sa(role), true);
    if role == Role::Initiator {
        assert!(negotiation.record_local_offer());
    }
    observe(&mut negotiation, role, &[OFFER]);
    assert!(negotiation.record_local_offer());
    negotiation.finish(true).unwrap()
}

fn counts(send: u32, receive: u32) -> Counters {
    Counters::new(send, receive)
}

fn wire(value: Sync) -> bytes::Bytes {
    let body =
        build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::message_id_sync(value)).unwrap();
    build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body,
    }])
    .unwrap()
    .1
}

fn request(
    role: Role,
    counters: Counters,
    pending: Option<&Pending>,
    value: Sync,
) -> Result<(Counters, Sync), RuleError> {
    let bytes = wire(value);
    agreement(role).evaluate_request(
        &header(role, false, EXCHANGE_TYPE_INFORMATIONAL),
        PayloadChain::new(PayloadType::Notify, &bytes),
        counters,
        pending,
    )
}

fn response(
    role: Role,
    counters: Counters,
    pending: &Pending,
    value: Sync,
) -> Result<Counters, RuleError> {
    let bytes = wire(value);
    agreement(role).evaluate_response(
        &header(role, true, EXCHANGE_TYPE_INFORMATIONAL),
        PayloadChain::new(PayloadType::Notify, &bytes),
        counters,
        pending,
    )
}

#[test]
fn eap_offers_accumulate_but_only_successful_authentication_finishes() {
    for role in [Role::Initiator, Role::Responder] {
        let mut negotiation = Negotiation::new(sa(role), true);
        assert_eq!(negotiation.record_local_offer(), role == Role::Initiator);
        for bodies in [vec![], vec![BAD_OFFER], vec![OFFER, OFFER]] {
            observe(&mut negotiation, role, &bodies);
            assert_eq!(
                negotiation.clone().finish(true).unwrap().mode(),
                Mode::BaseFallback
            );
        }
        observe(&mut negotiation, role, &[OFFER]);
        assert!(negotiation.record_local_offer());
        for bodies in [vec![OFFER], vec![], vec![BAD_OFFER], vec![OFFER, OFFER]] {
            observe(&mut negotiation, role, &bodies);
            assert_eq!(
                negotiation.clone().finish(true).unwrap().mode(),
                Mode::Negotiated
            );
        }
        assert!(negotiation.finish(false).is_none());
    }
}

#[test]
fn unsolicited_or_unready_offers_cannot_negotiate_and_sa_binding_is_checked() {
    let role = Role::Initiator;
    let mut negotiation = Negotiation::new(sa(role), true);
    observe(&mut negotiation, role, &[OFFER]); // No prior local offer.
    assert!(negotiation.record_local_offer());
    assert_eq!(
        negotiation.clone().finish(true).unwrap().mode(),
        Mode::BaseFallback
    );
    observe(&mut negotiation, role, &[OFFER]);
    assert_eq!(negotiation.finish(true).unwrap().mode(), Mode::Negotiated);
    for role in [Role::Initiator, Role::Responder] {
        let mut negotiation = Negotiation::new(sa(role), false);
        observe(&mut negotiation, role, &[OFFER]);
        assert!(!negotiation.record_local_offer());
        let fallback = negotiation.finish(true).unwrap();
        assert_eq!(fallback.mode(), Mode::BaseFallback);
        assert_eq!(fallback.propose(counts(0, 0), NONCE), Err(RuleError::Drop));
        let bytes = wire(Sync::new(NONCE, 0, 0));
        let payloads = PayloadChain::new(PayloadType::Notify, &bytes);
        let pending = agreement(role).propose(counts(0, 0), NONCE).unwrap();
        assert_eq!(
            fallback.evaluate_request(
                &header(role, false, EXCHANGE_TYPE_INFORMATIONAL),
                payloads,
                counts(0, 0),
                None
            ),
            Err(RuleError::Drop)
        );
        assert_eq!(
            fallback.evaluate_response(
                &header(role, true, EXCHANGE_TYPE_INFORMATIONAL),
                payloads,
                counts(0, 0),
                &pending
            ),
            Err(RuleError::Drop)
        );
    }
    for (initiator, responder) in [(0, 1), (1, 0), (0, 0)] {
        assert_eq!(Sa::new(initiator, responder, role), Err(RuleError::Drop));
    }
    let mut negotiation = Negotiation::new(sa(role), true);
    let mut wrong_sa = header(role, true, EXCHANGE_TYPE_IKE_AUTH);
    wrong_sa.responder_spi += 1;
    assert_eq!(
        negotiation.observe_peer_offer(&wrong_sa, Ok(None)),
        Err(RuleError::Drop)
    );
}

#[test]
fn authenticated_rekey_inherits_only_mode_with_new_spi_binding_and_role() {
    for role in [Role::Initiator, Role::Responder] {
        for negotiated in [false, true] {
            let old = if negotiated {
                agreement(role)
            } else {
                Negotiation::new(sa(role), false).finish(true).unwrap()
            };
            let new_role = if role == Role::Initiator {
                Role::Responder
            } else {
                Role::Initiator
            };
            let new_sa = Sa::new(0x303, 0x404, new_role).unwrap();
            assert!(old.inherit_rekey(new_sa, false).is_none()); // Failed/uncertain.
            assert!(old.inherit_rekey(sa(role), true).is_none());
            for (initiator, responder) in [(0x303, 0x202), (0x101, 0x404)] {
                let partially_changed = Sa::new(initiator, responder, new_role).unwrap();
                assert!(old.inherit_rekey(partially_changed, true).is_none());
            }
            let new = old.inherit_rekey(new_sa, true).unwrap();
            assert_eq!(new.mode(), old.mode());
            assert_eq!(new.sa(), new_sa);
            if negotiated {
                let pending = old.propose(counts(9, 8), NONCE).unwrap();
                let bytes = wire(Sync::new(NONCE, 8, 9));
                let mut reply = header(new_role, true, EXCHANGE_TYPE_INFORMATIONAL);
                reply.initiator_spi = 0x303;
                reply.responder_spi = 0x404;
                assert_eq!(
                    new.evaluate_response(
                        &reply,
                        PayloadChain::new(PayloadType::Notify, &bytes),
                        counts(0, 0),
                        &pending
                    ),
                    Err(RuleError::Drop)
                );
                assert_eq!(
                    new.propose(counts(0, 0), NONCE).unwrap().notification(),
                    Sync::new(NONCE, 0, 0)
                );
            }
        }
    }
}

#[test]
fn ike_auth_message_id_zero_drops_without_recording_a_valid_offer() {
    let opened =
        decode_ike_auth_cleartext_payloads(PayloadType::Notify, &[0, 0, 0, 8, 0, 0, 0x40, 0x24])
            .unwrap();
    for role in [Role::Initiator, Role::Responder] {
        let mut negotiation = Negotiation::new(sa(role), true);
        negotiation.record_local_offer();
        assert_eq!(
            negotiation.observe_peer_offer(
                &header(role, role == Role::Initiator, EXCHANGE_TYPE_IKE_AUTH),
                opened.message_id_sync_supported()
            ),
            Err(RuleError::Drop)
        );
        assert_eq!(negotiation.record_local_offer(), role == Role::Initiator);
        assert_eq!(negotiation.finish(true).unwrap().mode(), Mode::BaseFallback);
    }
}

#[test]
fn highest_used_local_id_alone_sets_the_next_proposal_and_response_send_floor() {
    for role in [Role::Initiator, Role::Responder] {
        let mut history = counts(0, 0);
        history.highest_local_request = Some(7);
        let pending = agreement(role).propose(history, NONCE).unwrap();
        assert_eq!(pending.notification(), Sync::new(NONCE, 8, 0));
        let (next, reply) = request(role, history, None, Sync::new(NONCE, 1, 3)).unwrap();
        assert_eq!(reply, Sync::new(NONCE, 8, 1));
        assert_eq!((next.next_send, next.next_receive), (8, 1));
    }
}

#[test]
fn appendix_arithmetic_and_normative_admission_are_separate() {
    for role in [Role::Initiator, Role::Responder] {
        // A.1, A.2 and A.3 counter-selection fixtures without history.
        for (m1, p1, send, receive, p2, m2) in
            [(0, 5, 5, 0, 5, 0), (2, 3, 4, 5, 4, 5), (2, 5, 2, 4, 5, 4)]
        {
            let (next, reply) =
                request(role, counts(send, receive), None, Sync::new(NONCE, m1, p1)).unwrap();
            assert_eq!(reply, Sync::new(NONCE, p2, m2));
            assert_eq!((next.next_send, next.next_receive), (p2, m2));
            assert_eq!(next.highest_peer_proposal, Some(m1));
        }
        let mut history = counts(5, 0);
        history.highest_local_request = Some(4);
        // A.1 admits M1=0 because no peer request has been received.
        assert!(request(role, history, None, Sync::new(NONCE, 0, 5)).is_ok());
        // A.2 and A.3's stated histories violate the normative §5.1 MUST drop.
        for (send, receive, highest_sent, highest_received, p1) in
            [(4, 5, 3, 4, 3), (2, 4, 1, 3, 5)]
        {
            let mut history = counts(send, receive);
            history.highest_local_request = Some(highest_sent);
            history.highest_peer_request = Some(highest_received);
            assert_eq!(
                request(role, history, None, Sync::new(NONCE, 2, p1)),
                Err(RuleError::Drop)
            );
        }
    }
}

#[test]
fn fresh_proposals_exceed_all_known_local_ids_and_duplicates_drop() {
    for role in [Role::Initiator, Role::Responder] {
        let mut history = counts(1, 2);
        history.highest_local_request = Some(7);
        history.highest_local_proposal = Some(9);
        history.highest_peer_request = Some(12);
        let pending = agreement(role).propose(history, NONCE).unwrap();
        assert_eq!(pending.notification(), Sync::new(NONCE, 10, 13));
        history.highest_peer_proposal = Some(15);
        for m1 in [0, 12, 14, 15] {
            assert_eq!(
                request(role, history, None, Sync::new(NONCE, m1, 2)),
                Err(RuleError::Drop)
            );
        }
        let (next, _) = request(role, history, Some(&pending), Sync::new(NONCE, 16, 2)).unwrap();
        assert_eq!((next.next_send, next.next_receive), (10, 16));
        assert_eq!(
            request(role, next, Some(&pending), Sync::new(NONCE, 16, 2)),
            Err(RuleError::Drop)
        );
        let mut seen_zero = counts(0, 0);
        seen_zero.highest_peer_request = Some(0);
        assert_eq!(
            request(role, seen_zero, None, Sync::new(NONCE, 0, 0)),
            Err(RuleError::Drop)
        );
    }
}

#[test]
fn nonce_and_proposal_bounds_are_checked_before_monotonic_response_merge() {
    for role in [Role::Initiator, Role::Responder] {
        let pending = agreement(role).propose(counts(4, 7), NONCE).unwrap();
        for value in [
            Sync::new([9; 4], 7, 4),
            Sync::new(NONCE, 6, 4),
            Sync::new(NONCE, 7, 3),
        ] {
            assert_eq!(
                response(role, counts(4, 7), &pending, value),
                Err(RuleError::Drop)
            );
        }
        let mut current = counts(12, 13); // A concurrently committed peer sync.
        current.highest_peer_proposal = Some(10);
        let next = response(role, current, &pending, Sync::new(NONCE, 9, 8)).unwrap();
        assert_eq!((next.next_send, next.next_receive), (12, 13));
        assert_eq!(next.highest_peer_proposal, Some(10));
        assert_eq!(next.highest_local_proposal, Some(4));
        let next = response(role, counts(0, 0), &pending, Sync::new(NONCE, 9, 8)).unwrap();
        assert_eq!((next.next_send, next.next_receive), (8, 9));
        // Pending declared floors participate even if counters predate them.
        let (next, reply) =
            request(role, counts(1, 2), Some(&pending), Sync::new([9; 4], 3, 1)).unwrap();
        assert_eq!((next.next_send, next.next_receive), (4, 7));
        assert_eq!(reply, Sync::new([9; 4], 4, 7));
    }
}

#[test]
fn superseded_proposals_cannot_accept_late_replies_or_supply_pending_floors() {
    for role in [Role::Initiator, Role::Responder] {
        let old = agreement(role).propose(counts(4, 7), NONCE).unwrap();
        let mut counters = counts(4, 7);
        counters.highest_local_proposal = Some(4);
        let retry = agreement(role).propose(counters, [9; 4]).unwrap();
        assert_eq!(retry.notification(), Sync::new([9; 4], 5, 7));
        counters.highest_local_proposal = Some(5);
        assert_eq!(
            response(role, counters, &retry, Sync::new(NONCE, 7, 5)),
            Err(RuleError::Drop)
        );
        assert_eq!(
            response(role, counters, &old, Sync::new(NONCE, 7, 5)),
            Err(RuleError::Drop)
        );
        assert_eq!(
            request(role, counters, Some(&old), Sync::new([9; 4], 8, 6)),
            Err(RuleError::Drop)
        );
        assert!(response(role, counters, &retry, Sync::new([9; 4], 7, 5)).is_ok());
    }
}

#[test]
fn simultaneous_sync_converges_in_both_orders_and_with_one_request_dropped() {
    for reverse in [false, true] {
        let roles = if reverse {
            [Role::Responder, Role::Initiator]
        } else {
            [Role::Initiator, Role::Responder]
        };
        let mut a = counts(4, 4);
        let mut b = counts(5, 5);
        a.highest_peer_request = Some(3);
        b.highest_peer_request = Some(3); // Admits M1=4, unlike a default P1=last+1 history.
        let pa = agreement(roles[0]).propose(a, NONCE).unwrap();
        let pb = agreement(roles[1]).propose(b, [9; 4]).unwrap();
        let (a_cutover, to_b) = request(roles[0], a, Some(&pa), pb.notification()).unwrap();
        let (b_cutover, to_a) = request(roles[1], b, Some(&pb), pa.notification()).unwrap();
        for reply_first in [false, true] {
            let (a_end, b_end) = if reply_first {
                let a_replied = response(roles[0], a, &pa, to_a).unwrap();
                let b_replied = response(roles[1], b, &pb, to_b).unwrap();
                (
                    request(roles[0], a_replied, Some(&pa), pb.notification())
                        .unwrap()
                        .0,
                    request(roles[1], b_replied, Some(&pb), pa.notification())
                        .unwrap()
                        .0,
                )
            } else {
                (
                    response(roles[0], a_cutover, &pa, to_a).unwrap(),
                    response(roles[1], b_cutover, &pb, to_b).unwrap(),
                )
            };
            assert_eq!((a_end.next_send, a_end.next_receive), (5, 5));
            assert_eq!((b_end.next_send, b_end.next_receive), (5, 5));
        }
        b.highest_peer_request = Some(4); // Now M1=4 must drop, but B's request completes.
        assert_eq!(
            request(roles[1], b, Some(&pb), pa.notification()),
            Err(RuleError::Drop)
        );
        let (a_end, to_b) = request(roles[0], a, Some(&pa), pb.notification()).unwrap();
        let b_end = response(roles[1], b, &pb, to_b).unwrap();
        assert_eq!((a_end.next_send, a_end.next_receive), (5, 5));
        assert_eq!((b_end.next_send, b_end.next_receive), (5, 5));
    }
}

#[test]
fn opened_exchange_requires_correct_spi_role_class_and_exactly_one_sync() {
    for role in [Role::Initiator, Role::Responder] {
        let agreed = agreement(role);
        let pending = agreed.propose(counts(2, 3), NONCE).unwrap();
        for is_response in [false, true] {
            let good = header(role, is_response, EXCHANGE_TYPE_INFORMATIONAL);
            let bytes = wire(Sync::new(NONCE, 3, 2));
            let evaluate = |h: &Header, first, clear: &[u8]| {
                let chain = PayloadChain::new(first, clear);
                if is_response {
                    agreed
                        .evaluate_response(h, chain, counts(0, 0), &pending)
                        .map(|_| ())
                } else {
                    agreed
                        .evaluate_request(h, chain, counts(0, 0), None)
                        .map(|_| ())
                }
            };
            assert_eq!(evaluate(&good, PayloadType::Notify, &bytes), Ok(()));
            for change in 0..9 {
                let mut wrong = good.clone();
                match change {
                    0 => wrong.initiator_spi = 0,
                    1 => wrong.responder_spi += 1,
                    2 => {
                        wrong.flags =
                            HeaderFlags::from_bits(role == Role::Initiator, is_response, false)
                    }
                    3 => {
                        wrong.flags =
                            HeaderFlags::from_bits(role == Role::Responder, !is_response, false)
                    }
                    4 => wrong.exchange_type = EXCHANGE_TYPE_IKE_AUTH,
                    5 => wrong.message_id = 1,
                    6 => wrong.next_payload = PayloadType::Notify.as_u8(),
                    7 => wrong.major_version = 1,
                    _ => std::mem::swap(&mut wrong.initiator_spi, &mut wrong.responder_spi),
                }
                assert_eq!(
                    evaluate(&wrong, PayloadType::Notify, &bytes),
                    Err(RuleError::Drop)
                );
            }
            assert_eq!(
                evaluate(&good, PayloadType::VendorId, &bytes),
                Err(RuleError::Drop)
            );
            for length in 0..bytes.len() {
                assert_eq!(
                    evaluate(&good, PayloadType::Notify, &bytes[..length]),
                    Err(RuleError::Drop)
                );
            }
            // Even the RFC-permitted extra IPSEC_REPLAY_COUNTER_SYNC Notify
            // (16423) is outside this message-ID-only profile.
            for tail in [vec![0], bytes.to_vec(), vec![0, 0, 0, 8, 0, 0, 0x40, 0x27]] {
                let mut extra = bytes.to_vec();
                extra[0] = PayloadType::Notify.as_u8();
                extra.extend(tail);
                assert_eq!(
                    evaluate(&good, PayloadType::Notify, &extra),
                    Err(RuleError::Drop)
                );
            }
            let mut accepted = good.clone();
            accepted.next_payload = PayloadType::EncryptedFragment.as_u8();
            accepted.flags = HeaderFlags::new(good.flags.raw() | 0xd7); // Receiver-ignored bits.
            accepted.minor_version = 9;
            assert_eq!(evaluate(&accepted, PayloadType::Notify, &bytes), Ok(()));
        }
    }
}

#[test]
fn exhaustion_never_wraps_and_rekey_requires_an_unused_ordinary_id() {
    for role in [Role::Initiator, Role::Responder] {
        let agreed = agreement(role);
        let pending = agreed.propose(counts(2, 3), NONCE).unwrap();
        for counters in [counts(u32::MAX, 0), counts(0, u32::MAX)] {
            assert_eq!(
                agreed.propose(counters, NONCE),
                Err(RuleError::RekeyRequired)
            );
        }
        for value in [Sync::new(NONCE, u32::MAX, 3), Sync::new(NONCE, 3, u32::MAX)] {
            assert_eq!(
                request(role, counts(0, 0), None, value),
                Err(RuleError::RekeyRequired)
            );
            assert_eq!(
                response(role, counts(2, 3), &pending, value),
                Err(RuleError::RekeyRequired)
            );
        }
        let mut counters = counts(0, 0);
        counters.highest_peer_request = Some(u32::MAX);
        assert_eq!(
            agreed.propose(counters, NONCE),
            Err(RuleError::RekeyRequired)
        );
        assert_eq!(
            request(role, counters, None, Sync::new(NONCE, u32::MAX, 0)),
            Err(RuleError::Drop)
        );
        counters.highest_local_request = Some(u32::MAX);
        assert_eq!(agreed.propose(counters, NONCE), Err(RuleError::CloseIkeSa));
        assert_eq!(
            response(role, counters, &pending, Sync::new(NONCE, 3, 2)),
            Err(RuleError::CloseIkeSa)
        );
        let mut counters = counts(0, 0);
        counters.highest_local_proposal = Some(u32::MAX);
        assert_eq!(
            agreed.propose(counters, NONCE),
            Err(RuleError::RekeyRequired)
        );
        assert_eq!(
            agreed
                .propose(counts(u32::MAX - 1, u32::MAX - 1), NONCE)
                .unwrap()
                .notification(),
            Sync::new(NONCE, u32::MAX - 1, u32::MAX - 1)
        );
    }
}

#[test]
fn diagnostics_redact_proposals_spis_and_counters() {
    let agreed = agreement(Role::Initiator);
    let pending = agreed.propose(counts(123456789, 987654321), NONCE).unwrap();
    assert_eq!(format!("{pending:?}"), "Ikev2MessageIdSyncPending { .. }");
    assert_eq!(
        format!("{:?}", counts(123456789, 987654321)),
        "Ikev2MessageIdSyncCounters { .. }"
    );
    assert_eq!(
        format!("{:?}", sa(Role::Initiator)),
        "Ikev2MessageIdSyncSa { .. }"
    );
}
