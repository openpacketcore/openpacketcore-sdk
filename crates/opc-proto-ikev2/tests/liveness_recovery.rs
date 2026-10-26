//! Fresh RFC 7296 liveness without per-probe window writes.

#[path = "support/canonical.rs"]
mod canonical_fixtures;
mod support;

use canonical_fixtures::{empty, Fixture, ALGORITHMS, DIRECTIONS};
use opc_proto_ikev2::Ikev2AesGcmIvPurpose as Purpose;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CommittedWindow as Window, Ikev2CommittedWindowRecord as Record,
        Ikev2WindowError as Error,
    },
    Ikev2ExchangeKind as Exchange,
};

#[test]
fn local_empty_informational_can_start_a_fresh_liveness_exchange() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124100, ALGORITHMS[0], DIRECTIONS[0]);
    let prepared = f
        .window
        .prepare_liveness(std::num::NonZeroU32::new(4).unwrap())
        .unwrap();
    let record = prepared.record().clone();
    let commit = prepared.commit_after_durable(&record).unwrap();
    assert_eq!(f.window.apply_committed(commit).unwrap(), None);
    let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
    let probe = f
        .window
        .send_empty_request(f.profile, &f.keys, allocation)
        .unwrap();
    assert_eq!(probe.message_id(), 0);
    drop(probe);
    let response = f.peer(0, true, 37, empty(), 0, 91);
    let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
    assert_eq!(
        f.window
            .complete_empty_request(&response)
            .unwrap()
            .message_id(),
        0
    );
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
    let prepared = f
        .window
        .prepare_liveness(std::num::NonZeroU32::new(4).unwrap())
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    assert_eq!(
        f.window
            .send_empty_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap()
            )
            .unwrap()
            .message_id(),
        u32::MAX - 1
    );
    let response = f.peer(u32::MAX - 1, true, 37, empty(), 0, 50);
    let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
    f.window.complete_empty_request(&response).unwrap();
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
fn unlanded_inbound_commit_retains_the_pending_probe_and_its_unwritten_floor() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124102, ALGORITHMS[0], DIRECTIONS[0]);
    let prepared = f
        .window
        .prepare_liveness(std::num::NonZeroU32::new(4).unwrap())
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    let probe = f
        .window
        .send_empty_request(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
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
    assert_eq!(
        f.window
            .retransmit_empty_request()
            .unwrap()
            .unwrap()
            .bytes(),
        probe
    );
    let response = f.peer(0, true, 37, empty(), 0, 61);
    let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
    f.window.complete_empty_request(&response).unwrap();
    assert_eq!(f.window.next_send(), Some(1));
}

#[test]
fn failed_probe_sealing_consumes_no_message_id_and_empty_requests_stay_outside_durable_work() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124103, ALGORITHMS[0], DIRECTIONS[0]);
    assert_eq!(
        f.window
            .send_empty_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap()
            )
            .err(),
        Some(Error::LivenessDisabled)
    );
    let prepared = f
        .window
        .prepare_liveness(std::num::NonZeroU32::new(4).unwrap())
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    let wrong_keys = canonical_fixtures::key_material(f.profile, 124104);
    assert_eq!(
        f.window
            .send_empty_request(
                f.profile,
                &wrong_keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap()
            )
            .err(),
        Some(Error::DomainMismatch)
    );
    assert_eq!(f.window.next_send(), Some(0));
    assert!(f.window.retransmit_empty_request().unwrap().is_none());
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
            .send_empty_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap()
            )
            .unwrap()
            .message_id(),
        0
    );
}

#[test]
fn checkpoint_retains_probe_iv_evidence_after_its_wire_cache_has_been_discarded() {
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
    let bound = std::num::NonZeroU32::new(4).unwrap();
    let prepared = f.window.prepare_liveness(bound).unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    f.window.apply_committed(token).unwrap();
    for id in 0..2 {
        let probe = f
            .window
            .send_empty_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        assert_eq!(probe.message_id(), id);
        drop(probe);
        let response = f.peer(id, true, 37, empty(), 0, 100 + u64::from(id));
        let response = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
        f.window.complete_empty_request(&response).unwrap();
    }
    let prepared = f.window.prepare_liveness(bound).unwrap();
    let record = prepared.record().clone();
    assert!(record.outbound().is_none());
    assert_eq!(record.next_send(), Some(2));
    assert_eq!(
        record.sync_state().unwrap().highest_local_request(),
        Some(1)
    );
    assert_eq!(record.sync_state().unwrap().minimum_send_iv_end(), 2);
    drop(prepared);
    assert_eq!(
        Window::restore(&domain, f.profile, &f.keys, &record, &f.stored(Some(1), 1)).err(),
        Some(Error::InvalidRecord)
    );
}

#[test]
fn readback_must_cover_live_probe_ivs_even_when_no_window_write_was_prepared() {
    support::ensure_ike_crypto();
    let mut f = Fixture::new(124106, ALGORITHMS[0], DIRECTIONS[0]);
    let prepared = f
        .window
        .prepare_liveness(std::num::NonZeroU32::new(4).unwrap())
        .unwrap();
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
            .send_empty_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
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
