//! RFC 7296 §§2.1–2.4 and RFC 6311 §5.1: no-write probes, independent
//! opposite-direction traffic, bounded unwritten IDs and exact retransmission.
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CbcRecoveryProfile as Cbc, Ikev2CommittedWindow as Window,
        Ikev2CommittedWindowDomain as Domain, Ikev2CommittedWindowRecord as Record,
        Ikev2LivenessProbePolicy as ProbePolicy, Ikev2LivenessRecord as LivenessRecord,
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as Disposition,
        Ikev2SyncInitiatorAction as SyncAction, Ikev2SyncRecoveryPolicy as SyncPolicy,
        Ikev2SyncResponderRecord as SyncRecord, Ikev2WindowError as Error,
    },
    Ikev2AesGcmIvPurpose as Purpose, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
    Ikev2ProtectedPayloadDirection as Direction,
};
#[path = "support/canonical.rs"]
mod canonical_fixtures;
#[path = "recovery_profile/cbc.rs"]
mod cbc;
#[allow(
    dead_code,
    reason = "shared independent peer used by recovery integration tests"
)]
#[path = "recovery_profile/peer.rs"]
mod peer;
mod support;
#[allow(dead_code, reason = "shared independent peer packet adapter")]
#[path = "recovery_profile/wire.rs"]
mod wire;
use canonical_fixtures::{delete, empty, opposite, Fixture, ALGORITHMS, DIRECTIONS};
use peer::{Event, PeerModel, Sync};
use wire::Wire;

fn probe_policy() -> ProbePolicy {
    ProbePolicy::new(1_000, 3, 10).unwrap()
}

fn enable(window: &mut Window, maximum: u32) {
    let prepared = window.prepare_liveness(maximum).unwrap();
    let stored = prepared.record().clone();
    let _commit = prepared.commit_after_durable(&stored).unwrap();
}

#[test]
fn answered_probe_is_exact_no_write_and_advances_only_the_live_send_floor() {
    support::ensure_ike_crypto();
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let mut f = Fixture::new(
                410_000 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            enable(&mut f.window, 4);
            let before = f.window.record().clone();
            let mut peer = PeerModel::new(
                Wire::new(f.profile, &f.keys, f.spis, opposite(direction)),
                0,
                0,
                false,
            );
            let request = f
                .window
                .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
                .unwrap()
                .bytes()
                .to_vec();
            assert_eq!(
                f.window.record(),
                &before,
                "sending a probe writes no window row"
            );
            assert_eq!(f.window.next_send(), Some(1));
            assert_eq!(f.window.next_receive(), Some(0));
            assert!(f.window.replay_request().unwrap().is_none());
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
            let opened = peer.wire.open(&request).unwrap();
            assert_eq!(opened.header.exchange_type, 37);
            assert_eq!(opened.first.as_u8(), 0);
            assert!(opened.body.is_empty());
            let response = peer.respond(0, empty()).unwrap();
            assert!(matches!(
                f.window.retry_empty_probe(109),
                Err(Error::LivenessBackoff)
            ));
            let retry = f.window.retry_empty_probe(110).unwrap().bytes().to_vec();
            assert_eq!(retry, request);
            assert_eq!(peer.receive(&retry), Ok(Event::Replay(response.clone())));
            let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
            assert_eq!(f.window.complete_empty_probe(&response, 111), Ok(empty()));
            assert_eq!(
                f.window.complete_empty_probe(&response, 112),
                Err(Error::Drop)
            );
            assert!(matches!(f.window.retry_empty_probe(112), Err(Error::Drop)));
            assert_eq!(
                f.window.record(),
                &before,
                "completion writes no window row"
            );
            let next = f
                .window
                .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 120)
                .unwrap()
                .bytes()
                .to_vec();
            assert_eq!(peer.receive(&next), Ok(Event::NewRequest(1)));
            assert_ne!(request[32..40], next[32..40]);
        }
    }
}

#[test]
fn a_pending_probe_allows_peer_requests_but_serializes_local_rekey_and_delete() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_100, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f.window, 4);
    let mut peer = PeerModel::new(
        Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction)),
        0,
        0,
        false,
    );
    let probe = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
        .unwrap()
        .bytes()
        .to_vec();
    assert_eq!(peer.receive(&probe), Ok(Event::NewRequest(0)));
    for exchange in [Exchange::CreateChildSa, Exchange::Informational] {
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        assert!(matches!(
            f.window
                .prepare_request(f.profile, &f.keys, allocation, exchange, delete(),),
            Err(Error::RequestOutstanding)
        ));
    }
    let incoming = peer.request(37, delete()).unwrap();
    let incoming = f.window.open_peer(f.profile, &f.keys, &incoming).unwrap();
    let prepared = f
        .window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &incoming,
            empty(),
            Bytes::from_static(b"deleted"),
        )
        .unwrap();
    let row = prepared.record().clone();
    assert_eq!(
        row.next_send(),
        Some(1),
        "fold the probe ID into any durable operation"
    );
    let commit = prepared.commit_after_durable(&row).unwrap();
    assert_eq!(
        f.window.apply_committed(commit).unwrap(),
        Some(Bytes::from_static(b"deleted"))
    );
    let reply = f
        .window
        .replay_response(&incoming)
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
    assert_eq!(peer.receive(&reply), Ok(Event::Completed(0)));
    assert_eq!(f.window.retry_empty_probe(110).unwrap().bytes(), probe);
    let response = peer.respond(0, empty()).unwrap();
    let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
    f.window.complete_empty_probe(&response, 111).unwrap();
    let prepared = f
        .window
        .prepare_request(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete(),
        )
        .unwrap();
    let row = prepared.record().clone();
    let _commit = prepared.commit_after_durable(&row).unwrap();
    let request = f
        .window
        .replay_request()
        .unwrap()
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
    assert_eq!(peer.receive(&request), Ok(Event::NewRequest(1)));
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 120,),
        Err(Error::RequestOutstanding)
    ));
    let restored = Window::restore(
        &Domain::from_iv_record(&f.iv),
        f.profile,
        &f.keys,
        &row,
        &f.iv,
    )
    .unwrap();
    assert_eq!(
        restored.replay_request().unwrap().unwrap().bytes().unwrap(),
        request
    );
}

#[test]
fn wrong_id_wrong_class_and_bad_mac_never_complete_a_probe() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_101, ALGORITHMS[0], DIRECTIONS[1]);
    enable(&mut f.window, 4);
    let wire = Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    let probe = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
        .unwrap()
        .bytes()
        .to_vec();
    let stored = f.window.record().clone();
    for (id, response, exchange, payload) in [
        (1, true, 37, empty()),
        (0, false, 37, empty()),
        (0, true, 36, empty()),
    ] {
        let incoming = wire.seal(id, response, exchange, payload);
        let incoming = f.window.open_peer(f.profile, &f.keys, &incoming).unwrap();
        assert_eq!(
            f.window.complete_empty_probe(&incoming, 101),
            Err(Error::Drop)
        );
        assert_eq!(f.window.record(), &stored);
    }
    let mut bad = wire.seal(0, true, 37, empty()).to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert!(matches!(
        f.window.open_peer(f.profile, &f.keys, &bad),
        Err(Error::Drop)
    ));
    assert_eq!(f.window.retry_empty_probe(110).unwrap().bytes(), probe);
    let response = f
        .window
        .open_peer(f.profile, &f.keys, &wire.seal(0, true, 37, empty()))
        .unwrap();
    assert_eq!(f.window.complete_empty_probe(&response, 111), Ok(empty()));
}

#[test]
fn fixed_timeout_and_exponential_retries_never_create_a_new_request() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_102, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f.window, 4);
    let stored = f.window.record().clone();
    let request = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
        .unwrap()
        .bytes()
        .to_vec();
    assert_eq!(f.window.retry_empty_probe(110).unwrap().bytes(), request);
    assert!(matches!(
        f.window.retry_empty_probe(129),
        Err(Error::LivenessBackoff)
    ));
    assert_eq!(f.window.retry_empty_probe(130).unwrap().bytes(), request);
    assert!(matches!(
        f.window.retry_empty_probe(170),
        Err(Error::LivenessRetryLimit)
    ));
    assert_eq!(f.window.check_empty_probe_deadline(1_099), Ok(()));
    assert_eq!(
        f.window.check_empty_probe_deadline(1_100),
        Err(Error::LivenessExpired)
    );
    assert!(matches!(
        f.window.retry_empty_probe(1_101),
        Err(Error::LivenessExpired)
    ));
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 1_102,),
        Err(Error::LivenessExpired)
    ));
    assert_eq!(f.window.record(), &stored);
    let mut backwards = Fixture::new(410_103, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut backwards.window, 4);
    let _probe = backwards
        .window
        .start_empty_probe(
            backwards.profile,
            &backwards.keys,
            &mut backwards.allocator,
            probe_policy(),
            100,
        )
        .unwrap();
    assert_eq!(
        backwards.window.check_empty_probe_deadline(99),
        Err(Error::LivenessClock)
    );
    assert!(matches!(
        backwards.window.retry_empty_probe(110),
        Err(Error::LivenessClock)
    ));
    assert_eq!(ProbePolicy::new(0, 3, 10).err(), Some(Error::InvalidRecord));
    assert_eq!(
        ProbePolicy::new(100, 0, 10).err(),
        Some(Error::InvalidRecord)
    );
    assert_eq!(
        ProbePolicy::new(100, 3, 0).err(),
        Some(Error::InvalidRecord)
    );
}

#[test]
fn bounded_unwritten_lead_is_folded_only_by_a_real_durable_acknowledgement() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_104, ALGORITHMS[0], DIRECTIONS[0]);
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100,),
        Err(Error::LivenessDisabled)
    ));
    enable(&mut f.window, 2);
    let initial = f.window.record().clone();
    let wire = Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    for id in 0..2 {
        let _probe = f
            .window
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                probe_policy(),
                100 + u64::from(id) * 10,
            )
            .unwrap();
        let response = f
            .window
            .open_peer(f.profile, &f.keys, &wire.seal(id, true, 37, empty()))
            .unwrap();
        f.window
            .complete_empty_probe(&response, 101 + u64::from(id) * 10)
            .unwrap();
    }
    assert_eq!(f.window.record(), &initial);
    assert_eq!(f.window.next_send(), Some(2));
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 120,),
        Err(Error::LivenessLeadExhausted)
    ));
    let prepared = f.window.prepare_liveness(2).unwrap();
    let folded = prepared.record().clone();
    assert_eq!(folded.next_send(), Some(2));
    drop(prepared);
    assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
    f.window
        .reconcile(f.profile, &f.keys, &initial, &f.iv)
        .unwrap();
    assert_eq!(f.window.next_send(), Some(2));
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 120,),
        Err(Error::LivenessLeadExhausted)
    ));
    let prepared = f.window.prepare_liveness(2).unwrap();
    let folded = prepared.record().clone();
    let _commit = prepared.commit_after_durable(&folded).unwrap();
    assert_eq!(f.window.record().next_send(), Some(2));
    let request = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 120)
        .unwrap()
        .bytes()
        .to_vec();
    assert_eq!(&request[20..24], &2u32.to_be_bytes());
    let restarted = Window::restore(
        &Domain::from_iv_record(&f.iv),
        f.profile,
        &f.keys,
        &folded,
        &f.iv,
    )
    .unwrap();
    assert_eq!(restarted.ready(), Err(Error::LivenessRecoveryRequired));
    assert_eq!(restarted.next_send(), Some(4));
}

fn with_sync(f: &mut Fixture) {
    let role = if f.direction == Direction::InitiatorToResponder {
        Role::Initiator
    } else {
        Role::Responder
    };
    let agreement =
        Agreement::from_persisted(Sa::new(f.spis.0, f.spis.1, role).unwrap(), Mode::Negotiated);
    let record = f
        .window
        .record()
        .clone()
        .with_sync_state(
            SyncRecord::from_persisted(agreement, None, None, None, None, Disposition::Continue, 0)
                .unwrap(),
        )
        .unwrap();
    f.window = Window::restore(
        &Domain::from_iv_record(&f.iv),
        f.profile,
        &f.keys,
        &record,
        &f.iv,
    )
    .unwrap();
}

#[test]
fn restart_of_answered_and_outstanding_probes_syncs_beyond_the_whole_unwritten_range() {
    support::ensure_ike_crypto();
    for answered in [false, true] {
        let mut f = Fixture::new(410_110 + u64::from(answered), ALGORITHMS[0], DIRECTIONS[0]);
        with_sync(&mut f);
        enable(&mut f.window, 4);
        let saved = f.window.record().clone();
        let mut peer = PeerModel::new(
            Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction)),
            0,
            0,
            true,
        );
        let request = f
            .window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
            .unwrap()
            .bytes()
            .to_vec();
        assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
        if answered {
            let response = peer.respond(0, empty()).unwrap();
            let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
            f.window.complete_empty_probe(&response, 101).unwrap();
        }
        f.window = Window::restore(
            &Domain::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &saved,
            &f.iv,
        )
        .unwrap();
        // Process restart discards the allocator's unused tail too.
        f.allocator =
            opc_proto_ikev2::Ikev2AesGcmIvAllocator::restore(f.iv.domain(), &f.iv).unwrap();
        let prepared = f.allocator.prepare(64, Purpose::Ordinary).unwrap();
        f.iv = prepared.record().clone();
        prepared.activate_after_commit(&f.iv).unwrap();
        assert_eq!(f.window.ready(), Err(Error::LivenessRecoveryRequired));
        assert_eq!(f.window.next_send(), Some(4));
        assert!(matches!(
            f.window.retry_empty_probe(110),
            Err(Error::LivenessRecoveryRequired)
        ));
        let clock = Clock::new(200, 1);
        let policy = SyncPolicy::new(1, clock, 2_000, 3, 10).unwrap();
        let prepared = f
            .window
            .begin_sync(policy, clock, None)
            .unwrap()
            .prepare(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row, clock).unwrap();
        let SyncAction::SendRequest(sync) = f.window.release_sync_action(commit, clock).unwrap()
        else {
            panic!("expected synchronization request")
        };
        let opened = peer.wire.open(&sync).unwrap();
        assert_eq!(
            u32::from_be_bytes(opened.body[12..16].try_into().unwrap()),
            4
        );
        let Event::SyncReply { wire, .. } = peer.receive(&sync).unwrap() else {
            panic!("expected peer synchronization reply")
        };
        let prepared = f
            .window
            .complete_sync(f.profile, &f.keys, &wire, Clock::new(201, 1))
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared
            .commit_after_durable(&row, Clock::new(201, 1))
            .unwrap();
        assert!(matches!(
            f.window.release_sync_action(commit, Clock::new(201, 1)),
            Ok(SyncAction::Recovered)
        ));
        assert_eq!(f.window.ready(), Ok(()));
        let next = f
            .window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 210)
            .unwrap()
            .bytes()
            .to_vec();
        assert_eq!(peer.receive(&next), Ok(Event::NewRequest(4)));
        assert_ne!(&next[32..40], &request[32..40]);
    }
}

#[test]
fn peer_sync_retires_a_live_probe_without_claiming_an_uncertain_mutation() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_112, ALGORITHMS[0], DIRECTIONS[1]);
    with_sync(&mut f);
    enable(&mut f.window, 4);
    let mut peer = PeerModel::new(
        Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction)),
        0,
        0,
        true,
    );
    let request = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
        .unwrap()
        .bytes()
        .to_vec();
    assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
    let request = peer
        .begin_sync(Sync {
            nonce: [7; 4],
            send: 1,
            receive: 1,
        })
        .unwrap();
    let prepared = f
        .window
        .begin_sync_response(f.profile, &f.keys, &request, None, None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let row = prepared.record().clone();
    let commit = prepared.commit_after_durable(&row).unwrap();
    let (reply, disposition) = f.window.release_sync_response(commit).unwrap().into_parts();
    assert_eq!(disposition, Disposition::Continue);
    assert_eq!(peer.receive(&reply), Ok(Event::Synchronized));
    assert!(matches!(f.window.retry_empty_probe(110), Err(Error::Drop)));
}

#[test]
fn cbc_probes_use_fresh_ivs_but_retries_keep_the_exact_bytes() {
    support::ensure_ike_crypto();
    for (index, profile) in cbc::profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = cbc::Fixture::new(profile, direction, 410_200 + (index * 2 + role) as u64);
            let mut window: Window<Cbc> = f.window();
            let prepared = window.prepare_liveness(4).unwrap();
            let row = prepared.record().clone();
            let _commit = prepared.commit_after_durable(&row).unwrap();
            let mut peer = PeerModel::new(
                Wire::new(profile, &f.keys, f.spis, opposite(direction)),
                0,
                0,
                false,
            );
            let request = window
                .start_empty_probe(profile, &f.keys, probe_policy(), 100)
                .unwrap()
                .bytes()
                .to_vec();
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
            let response = peer.respond(0, empty()).unwrap();
            assert_eq!(window.retry_empty_probe(110).unwrap().bytes(), request);
            let response = window.open_peer(profile, &f.keys, &response).unwrap();
            window.complete_empty_probe(&response, 111).unwrap();
            assert_eq!(window.record(), &row);
            let next = window
                .start_empty_probe(profile, &f.keys, probe_policy(), 120)
                .unwrap()
                .bytes()
                .to_vec();
            assert_eq!(peer.receive(&next), Ok(Event::NewRequest(1)));
            assert_ne!(&request[32..48], &next[32..48]);
        }
    }
}

#[test]
fn cancelled_activation_requires_exact_readback_before_any_probe() {
    support::ensure_ike_crypto();
    for landed in [false, true] {
        let mut f = Fixture::new(410_400 + u64::from(landed), ALGORITHMS[0], DIRECTIONS[0]);
        let old = f.window.record().clone();
        let prepared = f.window.prepare_liveness(2).unwrap();
        let candidate = prepared.record().clone();
        drop(prepared);
        assert!(matches!(
            f.window
                .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100),
            Err(Error::CommitUncertain)
        ));
        let readback = if landed { &candidate } else { &old };
        f.window
            .reconcile(f.profile, &f.keys, readback, &f.iv)
            .unwrap();
        if landed {
            let probe = f
                .window
                .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
                .unwrap();
            assert_eq!(probe.message_id(), 0);
            assert_eq!(probe.deadline_ms(), 1_100);
        } else {
            assert!(matches!(
                f.window.start_empty_probe(
                    f.profile,
                    &f.keys,
                    &mut f.allocator,
                    probe_policy(),
                    100
                ),
                Err(Error::LivenessDisabled)
            ));
        }
    }
}

#[test]
fn checkpoint_after_settled_work_retains_authenticated_probe_history() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_402, ALGORITHMS[0], DIRECTIONS[0]);
    with_sync(&mut f);
    enable(&mut f.window, 4);
    let wire = Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    let prepared = f
        .window
        .prepare_request(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete(),
        )
        .unwrap();
    let row = prepared.record().clone();
    let _commit = prepared.commit_after_durable(&row).unwrap();
    let response = f
        .window
        .open_peer(f.profile, &f.keys, &wire.seal(0, true, 37, empty()))
        .unwrap();
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
    let probe = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
        .unwrap()
        .bytes()
        .to_vec();
    let response = f
        .window
        .open_peer(f.profile, &f.keys, &wire.seal(1, true, 37, empty()))
        .unwrap();
    f.window.complete_empty_probe(&response, 101).unwrap();
    let prepared = f.window.prepare_liveness(4).unwrap();
    let folded = prepared.record().clone();
    let _commit = prepared.commit_after_durable(&folded).unwrap();
    assert_eq!(folded.next_send(), Some(2));
    assert_eq!(
        folded.liveness().unwrap().last_probe(),
        Some(probe.as_slice())
    );
    assert_eq!(
        folded.sync_state().unwrap().highest_local_request(),
        Some(1)
    );
    let restored = Window::restore(
        &Domain::from_iv_record(&f.iv),
        f.profile,
        &f.keys,
        &folded,
        &f.iv,
    )
    .unwrap();
    assert_eq!(restored.next_send(), Some(6));
    assert_eq!(restored.ready(), Err(Error::LivenessRecoveryRequired));
    assert_eq!(
        restored.record().outbound().unwrap().outcome(),
        Some(b"settled".as_slice())
    );
}

#[test]
fn persisted_probe_shape_authentication_and_iv_coverage_are_checked() {
    support::ensure_ike_crypto();
    for case in 0..6 {
        let mut f = Fixture::new(410_410 + case, ALGORITHMS[0], DIRECTIONS[0]);
        enable(&mut f.window, 4);
        let probe = f
            .window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
            .unwrap()
            .bytes()
            .to_vec();
        let local = Wire::new(f.profile, &f.keys, f.spis, f.direction);
        let mut evidence = match case {
            0 => local.seal(0, true, 37, empty()).to_vec(),
            1 => local.seal(0, false, 36, empty()).to_vec(),
            2 => local.seal(0, false, 37, delete()).to_vec(),
            3 => local.seal(1, false, 37, empty()).to_vec(),
            _ => probe,
        };
        if case == 4 {
            *evidence.last_mut().unwrap() ^= 1;
        }
        let record = Record::from_persisted(
            Domain::from_iv_record(&f.iv),
            2,
            Some(1),
            Some(0),
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .with_liveness(LivenessRecord::from_persisted(4, Some(Bytes::from(evidence))).unwrap())
        .unwrap();
        if case == 5 {
            let behind = opc_proto_ikev2::Ikev2AesGcmIvRecord::from_persisted(
                opc_proto_ikev2::Ikev2AesGcmEpochInputs {
                    initiator_spi: f.spis.0,
                    responder_spi: f.spis.1,
                    sending_direction: f.direction,
                    profile: f.profile,
                    keys: &f.keys,
                },
                f.iv.limits(),
                0,
                f.iv.canonical_format(),
            )
            .unwrap();
            assert!(matches!(
                Window::restore(record.domain(), f.profile, &f.keys, &record, &behind),
                Err(Error::InvalidRecord)
            ));
        } else {
            assert!(matches!(
                Window::restore(record.domain(), f.profile, &f.keys, &record, &f.iv),
                Err(Error::InvalidRecord)
            ));
        }
    }
    assert_eq!(
        LivenessRecord::from_persisted(0, None),
        Err(Error::InvalidRecord)
    );
}

#[test]
fn final_message_id_is_reserved_and_restored_lead_never_wraps() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_420, ALGORITHMS[0], DIRECTIONS[0]);
    let record = Record::initial(Domain::from_iv_record(&f.iv), u32::MAX - 1, 0);
    f.window = Window::restore(record.domain(), f.profile, &f.keys, &record, &f.iv).unwrap();
    enable(&mut f.window, 4);
    let saved = f.window.record().clone();
    let request = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100)
        .unwrap()
        .bytes()
        .to_vec();
    assert_eq!(&request[20..24], &(u32::MAX - 1).to_be_bytes());
    let wire = Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    let response = f
        .window
        .open_peer(
            f.profile,
            &f.keys,
            &wire.seal(u32::MAX - 1, true, 37, empty()),
        )
        .unwrap();
    f.window.complete_empty_probe(&response, 101).unwrap();
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 110),
        Err(Error::Exhausted)
    ));
    assert_eq!(f.window.next_send(), Some(u32::MAX));
    let prepared = f
        .window
        .prepare_request(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Control).unwrap(),
            Exchange::Informational,
            delete(),
        )
        .unwrap();
    assert_eq!(prepared.record().next_send(), None);
    drop(prepared);
    let restored = Window::restore(saved.domain(), f.profile, &f.keys, &saved, &f.iv).unwrap();
    assert_eq!(restored.next_send(), Some(u32::MAX));
    assert_eq!(restored.ready(), Err(Error::LivenessRecoveryRequired));
}

#[test]
fn unavailable_reserved_ivs_cannot_start_a_probe_or_advance_its_id() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_421, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f.window, 4);
    f.allocator = opc_proto_ikev2::Ikev2AesGcmIvAllocator::restore(f.iv.domain(), &f.iv).unwrap();
    let before = f.window.record().clone();
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, probe_policy(), 100),
        Err(Error::Iv(_))
    ));
    assert_eq!(f.window.next_send(), Some(0));
    assert_eq!(f.window.record(), &before);
    assert!(matches!(f.window.retry_empty_probe(110), Err(Error::Drop)));
}

#[test]
fn spent_transmissions_still_allow_an_in_time_response_but_clock_overflow_is_terminal() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(410_423, ALGORITHMS[0], DIRECTIONS[0]);
    enable(&mut f.window, 4);
    let policy = ProbePolicy::new(100, 1, 10).unwrap();
    let _probe = f
        .window
        .start_empty_probe(f.profile, &f.keys, &mut f.allocator, policy, 100)
        .unwrap();
    assert!(matches!(
        f.window.retry_empty_probe(110),
        Err(Error::LivenessRetryLimit)
    ));
    let wire = Wire::new(f.profile, &f.keys, f.spis, opposite(f.direction));
    let response = f
        .window
        .open_peer(f.profile, &f.keys, &wire.seal(0, true, 37, empty()))
        .unwrap();
    f.window.complete_empty_probe(&response, 199).unwrap();
    assert!(matches!(
        f.window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, policy, u64::MAX - 10),
        Err(Error::LivenessClock)
    ));
    assert_eq!(f.window.ready(), Err(Error::LivenessClock));
    assert_eq!(f.window.next_send(), Some(1));
    assert!(matches!(
        f.window.prepare_liveness(4),
        Err(Error::LivenessClock)
    ));
}
