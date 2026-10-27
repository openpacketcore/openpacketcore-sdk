//! Fresh RFC 7296 liveness without per-probe window writes.

#[path = "support/canonical.rs"]
mod canonical_fixtures;
mod support;

use canonical_fixtures::{empty, Fixture, ALGORITHMS, DIRECTIONS};
use opc_proto_ikev2::Ikev2AesGcmIvPurpose as Purpose;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CommittedWindow as Window, Ikev2CommittedWindowRecord as Record,
        Ikev2LivenessProbePolicy as ProbePolicy, Ikev2WindowError as Error,
    },
    Ikev2ExchangeKind as Exchange,
};

#[test]
fn local_empty_informational_can_start_a_fresh_liveness_exchange() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124100, ALGORITHMS[0], DIRECTIONS[0]);
    let prepared = f.window.prepare_liveness(4).unwrap();
    let record = prepared.record().clone();
    let commit = prepared.commit_after_durable(&record).unwrap();
    assert_eq!(f.window.apply_committed(commit).unwrap(), None);
    let probe = f
        .window
        .start_empty_probe(
            f.profile,
            &f.keys,
            &mut f.allocator,
            ProbePolicy::new(1000, 3, 10).unwrap(),
            100,
        )
        .unwrap();
    assert_eq!(probe.message_id(), 0);
    drop(probe);
    let response = f.peer(0, true, 37, empty(), 0, 91);
    let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
    assert_eq!(f.window.pending_empty_request_message_id(), Some(0));
    assert_eq!(f.window.complete_empty_probe(&response, 100), Ok(()));
    assert_eq!(f.window.record(), &record);
    assert_eq!(f.window.next_send(), Some(1));
}

#[test]
fn probes_leave_the_final_id_for_ordinary_work_and_never_wrap_after_commit_or_restore() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124101, ALGORITHMS[0], DIRECTIONS[0]);
    let domain = f.window.record().domain().clone();
    f.window = Window::restore(
        &domain,
        f.profile,
        &f.keys,
        &Record::initial(domain.clone(), u32::MAX - 1, 0),
        &f.iv,
    )
    .unwrap();
    let prepared = f.window.prepare_liveness(4).unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    assert_eq!(
        f.window
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100
            )
            .unwrap()
            .message_id(),
        u32::MAX - 1
    );
    let response = f.peer(u32::MAX - 1, true, 37, empty(), 0, 50);
    let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
    f.window.complete_empty_probe(&response, 100).unwrap();
    assert_eq!(
        f.window
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100
            )
            .err(),
        Some(Error::Exhausted)
    );
    let prepared = f
        .window
        .prepare_request(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            canonical_fixtures::delete(),
        )
        .unwrap();
    let record = prepared.record().clone();
    assert_eq!(record.next_send(), None);
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    assert_eq!(f.window.next_send(), None);
    let mut restored = Window::restore(&domain, f.profile, &f.keys, &record, &f.iv).unwrap();
    assert!(restored.replay_request().unwrap().is_some());
    assert_eq!(restored.next_send(), None);
    let response = f.peer(u32::MAX, true, 37, empty(), 0, 51);
    let response = restored.open_peer(f.profile, &f.keys, &response).unwrap();
    let prepared = restored
        .prepare_completion(&response, bytes::Bytes::new())
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    restored.apply_committed(token).unwrap();
    assert_eq!(restored.next_send(), None);
    assert_eq!(
        restored
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100
            )
            .err(),
        Some(Error::Exhausted)
    );
}

#[test]
fn unlanded_inbound_commit_retains_the_pending_probe_and_its_unwritten_floor() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124102, ALGORITHMS[0], DIRECTIONS[0]);
    let prepared = f.window.prepare_liveness(4).unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    let probe = f
        .window
        .start_empty_probe(
            f.profile,
            &f.keys,
            &mut f.allocator,
            ProbePolicy::new(1000, 3, 10).unwrap(),
            100,
        )
        .unwrap()
        .bytes()
        .to_vec();
    let wire = f.peer(0, false, 37, canonical_fixtures::delete(), 0, 60);
    let incoming = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
    let prepared = f
        .window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &incoming,
            empty(),
            bytes::Bytes::new(),
        )
        .unwrap();
    assert_eq!(prepared.record().next_send(), Some(1));
    drop(prepared);
    assert_eq!(f.window.ready(), Err(Error::CommitUncertain));
    f.window
        .reconcile(f.profile, &f.keys, &record, &f.iv)
        .unwrap();
    assert_eq!(f.window.record().next_send(), Some(0));
    assert_eq!(f.window.next_send(), Some(1));
    assert_eq!(f.window.retry_empty_probe(110).unwrap().bytes(), probe);
    let response = f.peer(0, true, 37, empty(), 0, 61);
    let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
    f.window.complete_empty_probe(&response, 110).unwrap();
    assert_eq!(f.window.next_send(), Some(1));
}

#[test]
fn failed_probe_sealing_consumes_no_message_id_and_empty_requests_stay_outside_durable_work() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124103, ALGORITHMS[0], DIRECTIONS[0]);
    assert_eq!(
        f.window
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100
            )
            .err(),
        Some(Error::LivenessDisabled)
    );
    let prepared = f.window.prepare_liveness(4).unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    let wrong_keys = canonical_fixtures::key_material(f.profile, 124104);
    assert_eq!(
        f.window
            .start_empty_probe(
                f.profile,
                &wrong_keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100
            )
            .err(),
        Some(Error::DomainMismatch)
    );
    assert_eq!(f.window.next_send(), Some(0));
    assert!(matches!(f.window.retry_empty_probe(100), Err(Error::Drop)));
    assert_eq!(
        f.window
            .prepare_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                empty()
            )
            .err(),
        Some(Error::NoDurableWork)
    );
    assert_eq!(
        f.window
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100
            )
            .unwrap()
            .message_id(),
        0
    );
}

#[test]
fn checkpoint_retains_authenticated_probe_iv_evidence_and_rejects_reused_reservations() {
    use opc_proto_ikev2::{
        recovery::{Ikev2SyncDisposition, Ikev2SyncResponderRecord},
        Ikev2MessageIdSyncAgreement, Ikev2MessageIdSyncMode, Ikev2MessageIdSyncRole,
        Ikev2MessageIdSyncSa,
    };
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124105, ALGORITHMS[0], DIRECTIONS[0]);
    let domain = f.window.record().domain().clone();
    let agreement = Ikev2MessageIdSyncAgreement::from_persisted(
        Ikev2MessageIdSyncSa::new(f.spis.0, f.spis.1, Ikev2MessageIdSyncRole::Initiator).unwrap(),
        Ikev2MessageIdSyncMode::Negotiated,
    );
    let record = f
        .window
        .record()
        .clone()
        .with_sync_state(
            Ikev2SyncResponderRecord::from_persisted(
                agreement,
                None,
                None,
                None,
                None,
                Ikev2SyncDisposition::Continue,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    f.window = Window::restore(&domain, f.profile, &f.keys, &record, &f.iv).unwrap();
    let bound = 4;
    let prepared = f.window.prepare_liveness(bound).unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    let mut last_probe = None;
    for id in 0..2 {
        let probe = f
            .window
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100,
            )
            .unwrap();
        assert_eq!(probe.message_id(), id);
        last_probe = Some(probe.bytes().to_vec());
        drop(probe);
        let response = f.peer(id, true, 37, empty(), 0, 100 + u64::from(id));
        let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
        f.window.complete_empty_probe(&response, 100).unwrap();
    }
    let prepared = f.window.prepare_liveness(bound).unwrap();
    let record = prepared.record().clone();
    assert!(record.outbound().is_none());
    assert_eq!(record.next_send(), Some(2));
    assert_eq!(
        record.sync_state().unwrap().highest_local_request(),
        Some(1)
    );
    // RFC 5282 section 3.1 requires IV uniqueness, independently of where
    // the durable record carries its evidence. This API retains the packet.
    let evidence = record.liveness().unwrap().last_probe().unwrap();
    assert_eq!(Some(evidence), last_probe.as_deref());
    assert_eq!(u64::from_be_bytes(evidence[32..40].try_into().unwrap()), 1);
    drop(prepared);
    let restored =
        Window::restore(&domain, f.profile, &f.keys, &record, &f.stored(Some(1), 2)).unwrap();
    assert_eq!(restored.record(), &record);
    assert_eq!(
        Window::restore(&domain, f.profile, &f.keys, &record, &f.stored(Some(1), 1)).err(),
        Some(Error::InvalidRecord)
    );
}

#[test]
fn readback_must_cover_live_probe_ivs_even_when_no_window_write_was_prepared() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124106, ALGORITHMS[0], DIRECTIONS[0]);
    let prepared = f.window.prepare_liveness(4).unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    for _ in 0..64 {
        drop(f.allocator.allocate(Purpose::Ordinary).unwrap());
    }
    let reserved = f.allocator.prepare(4, Purpose::Ordinary).unwrap();
    let iv = reserved.record().clone();
    reserved.activate_after_commit(&iv).unwrap();
    drop(
        f.window
            .start_empty_probe(
                f.profile,
                &f.keys,
                &mut f.allocator,
                ProbePolicy::new(1000, 3, 10).unwrap(),
                100,
            )
            .unwrap(),
    );
    assert_eq!(f.window.record(), &record);
    // The ordinary window has no cached request, but it still knows IV 64 escaped.
    assert_eq!(
        f.window.reconcile(f.profile, &f.keys, &record, &f.iv),
        Err(Error::InvalidRecord)
    );
}
