use super::super::changes::tests::{apply, clock, time};
use super::*;
use crate::FencedTransitionRequestId;

pub(in crate::consensus::native) fn request(
    id: u128,
    template: &FencedTransitionV2Request,
) -> FencedTransitionRequest {
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes(id.to_be_bytes()),
        template.lease().clone(),
        template.mutation().clone(),
    )
    .unwrap()
}

pub(in crate::consensus::native) fn command(
    index: u64,
    request: &FencedTransitionRequest,
    now: Timestamp,
    activate: bool,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = clock(index, now);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes());
    command.intent = if activate {
        SessionMutationIntent::ActivateFencedTransition {
            request: Box::new(request.clone()),
            scope_identity: command.identity,
            voter_set_digest: fenced_transition_voter_set_digest(
                command.identity,
                &[7, 8, 9]
                    .map(|id| SessionConsensusNodeId::new(id).unwrap())
                    .into(),
            ),
        }
    } else {
        SessionMutationIntent::FencedTransition(Box::new(request.clone()))
    };
    entry
}

pub(in crate::consensus::native) fn fixture() -> (
    NativeStorage,
    FencedTransitionRequest,
    FencedTransitionOutcome,
) {
    let (old, template, _) = super::super::changes::tests::fixture();
    let mut storage =
        NativeStorage::empty(old.business.identity, old.business.members.clone()).unwrap();
    let formation = old.log.read(0, Some(1), None).unwrap().remove(0);
    let first = request(1, &template);
    let applied = apply(
        &mut storage,
        &[formation, command(1, &first, time(1), true)],
    );
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &applied.responses[1].result else {
        panic!("V1 activation");
    };
    (storage, first, outcome.clone())
}

#[test]
fn native_v1_capture_rejects_binding_family_body_and_certificate_mutations() {
    for case in 0..7 {
        let (mut storage, first, _) = fixture();
        storage.business.begin_changes().unwrap();
        let proof = std::sync::Arc::clone(storage.business.require_business_proof().unwrap());
        let before = serde_json::to_vec(&storage.business.frontiers).unwrap();
        let id = SessionConsensusRequestId::from_bytes(*first.request_id().as_bytes());
        let mut delta = storage.business.prepare(&[clock(2, time(2))]).unwrap();
        let mut row = (**storage.business.generic_receipts.get(&id).unwrap()).clone();
        let NativeGenericReceipt::FencedV1(value) = &mut row else {
            unreachable!()
        };
        match case {
            0 => value.payload_digest[0] ^= 1,
            1 => value.retained_until = value.retained_until.add_seconds(1).unwrap(),
            2 => value.response = None,
            3 => value.response.as_mut().unwrap().result = Err(StoreError::CasConflict),
            4 => {
                row = NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
                    payload_digest: value.payload_digest,
                    response: value.response.as_ref().unwrap().clone(),
                })
            }
            5 => delta.frontiers.v1_activation = None,
            _ => delta.frontiers.v1_activation.as_mut().unwrap().voters[0] ^= 1,
        }
        delta.generic_receipts.insert(id, row);
        assert!(
            changes::Publication::prepare(delta).is_err(),
            "immutable V1 field {case}"
        );
        assert_eq!(
            serde_json::to_vec(&storage.business.frontiers).unwrap(),
            before
        );
        assert!(std::sync::Arc::ptr_eq(
            &proof,
            storage.business.require_business_proof().unwrap()
        ));
        storage.business.capture_changes().unwrap();
        storage.validate_image().unwrap();
    }
    let (mut storage, first, _) = fixture();
    let id = SessionConsensusRequestId::from_bytes(*first.request_id().as_bytes());
    let until = time(1)
        .add_seconds(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs() as i64)
        .unwrap();
    storage.begin_changes().unwrap();
    let applied = apply(&mut storage, &[command(2, &first, until, false)]);
    assert_eq!(
        applied.responses[0].result,
        Err(StoreError::FencedTransitionRequestExpired)
    );
    let capture = storage.take_changes().unwrap();
    capture.validate(&|| Ok(())).unwrap();
    assert!(storage.business.generic_receipts[&id].response().is_none());
    assert_eq!(
        storage
            .business
            .require_business_proof()
            .unwrap()
            .expiry
            .v1_count(),
        1
    );
}

#[test]
fn native_v1_original_lifetime_capacity_and_signed_sequence_horizon_are_exact() {
    let (mut storage, first, outcome) = fixture();
    let template = super::super::changes::tests::request(1, None);
    let first_id = SessionConsensusRequestId::from_bytes(*first.request_id().as_bytes());
    let NativeGenericReceipt::FencedV1(original) =
        &**storage.business.generic_receipts.get(&first_id).unwrap()
    else {
        unreachable!()
    };
    let original = original.clone();
    let maximum = FENCED_TRANSITION_MAX_HISTORY_ENTRIES;
    assert_eq!(maximum, 4096);
    // An explicitly seeded, fully admitted ledger exercises the original
    // lifetime boundary. This is not a public workload/performance claim.
    for id in 2..maximum {
        let request = request(id as u128, &template);
        let row = NativeV1Receipt {
            payload_digest: sql::fenced_transition_payload_digest(
                storage.business.identity,
                &request,
            )
            .unwrap(),
            ..original.clone()
        };
        storage.business.generic_receipts.insert(
            SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes()),
            SharedRow::new(NativeGenericReceipt::FencedV1(row)).unwrap(),
        );
    }
    storage.business.admit_business().unwrap();
    storage.validate_image().unwrap();
    assert_eq!(
        storage
            .business
            .require_business_proof()
            .unwrap()
            .expiry
            .v1_count(),
        maximum - 1
    );
    let last = request(maximum as u128, &template);
    assert_eq!(
        apply(&mut storage, &[command(2, &last, time(2), false)]).responses[0].result,
        Err(StoreError::StaleFence)
    );
    assert_eq!(
        storage
            .business
            .require_business_proof()
            .unwrap()
            .expiry
            .v1_count(),
        maximum
    );
    let extra = request(maximum as u128 + 1, &template);
    assert_eq!(
        storage.business.status_v1(&extra).unwrap(),
        FencedTransitionStatus::HistoryFull
    );
    let sequence = storage.business.frontiers.sequence;
    let full = apply(&mut storage, &[command(3, &extra, time(3), false)]);
    assert_eq!(
        full.responses[0].result,
        Err(StoreError::FencedTransitionHistoryFull)
    );
    assert_eq!(storage.business.frontiers.sequence, sequence);
    assert_eq!(
        storage.business.status_v1(&first).unwrap(),
        FencedTransitionStatus::Recorded(Box::new(Ok(outcome)))
    );
    let until = original.retained_until;
    assert_eq!(
        apply(&mut storage, &[command(4, &first, until, false)]).responses[0].result,
        Err(StoreError::FencedTransitionRequestExpired)
    );
    assert_eq!(
        storage
            .business
            .require_business_proof()
            .unwrap()
            .expiry
            .v1_count(),
        maximum,
        "expiry cannot reclaim a V1 ID"
    );
    assert_eq!(
        storage.business.status_v1(&extra).unwrap(),
        FencedTransitionStatus::HistoryFull
    );

    let (mut storage, _, outcome) = fixture();
    storage.business.frontiers.sequence = COUNTER_MAX;
    storage.business.admit_business().unwrap();
    storage.validate_image().unwrap();
    let before = postcard::to_allocvec(&(
        &storage.business.keys,
        storage.business.frontiers.next_fence,
        storage.business.frontiers.next_credential,
        storage.business.frontiers.restore_revision,
        storage.business.frontiers.watch_sequence,
    ))
    .unwrap();
    let digest = storage.business.frontiers.digest;
    let stale = request(2, &template);
    assert_eq!(
        apply(&mut storage, &[command(2, &stale, time(2), false)]).responses[0].result,
        Err(StoreError::StaleFence)
    );
    let update = request(3, &super::super::changes::tests::request(2, Some(&outcome)));
    assert_eq!(
        apply(&mut storage, &[command(3, &update, time(3), false)]).responses[0].result,
        Err(StoreError::FencedTransitionStorageExhausted)
    );
    assert_eq!(storage.business.frontiers.sequence, COUNTER_MAX);
    assert_eq!(storage.business.frontiers.digest, digest);
    assert_eq!(
        postcard::to_allocvec(&(
            &storage.business.keys,
            storage.business.frontiers.next_fence,
            storage.business.frontiers.next_credential,
            storage.business.frontiers.restore_revision,
            storage.business.frontiers.watch_sequence
        ))
        .unwrap(),
        before
    );
    assert_eq!(storage.business.notifications.len(), 1);
}

#[test]
fn native_v1_full_image_four_preserves_tombstones_and_explicit_legacy_readers() {
    let (mut ordinary, _, _) = super::super::changes::tests::fixture();
    apply(&mut ordinary, &[clock(2, time(2))]);
    for version in 1..=4 {
        let mut bytes = Vec::new();
        match version {
            1 => ordinary.write_legacy_image_for_test(&mut bytes, [0xD1; 32], 9),
            2 => ordinary.write_legacy_v2_image_for_test(&mut bytes, [0xD1; 32], 9),
            3 => ordinary.write_legacy_v3_image_for_test(&mut bytes, [0xD1; 32], 9),
            _ => ordinary.write_image(&mut bytes, [0xD1; 32], 9),
        }
        .unwrap();
        let actual = NativeStorage::read_image(
            &mut bytes.as_slice(),
            [0xD1; 32],
            9,
            ordinary.business.identity,
        )
        .unwrap();
        assert_eq!(
            generation::Version::capture(&actual)
                .unwrap()
                .context_digest()
                .unwrap(),
            generation::Version::capture(&ordinary)
                .unwrap()
                .context_digest()
                .unwrap()
        );
    }
    let (mut storage, first, _) = fixture();
    for expired in [false, true] {
        if expired {
            let until = time(1)
                .add_seconds(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs() as i64)
                .unwrap();
            apply(&mut storage, &[command(2, &first, until, false)]);
        }
        let mut decoded: NativeState =
            postcard::from_bytes(&postcard::to_allocvec(&storage.business).unwrap()).unwrap();
        assert!(decoded.proof.is_none());
        decoded.admit_business().unwrap();
        assert_eq!(
            decoded.status_v1(&first).unwrap(),
            storage.business.status_v1(&first).unwrap()
        );
        let mut bytes = Vec::new();
        storage.write_image(&mut bytes, [0xD1; 32], 9).unwrap();
        assert_eq!(&bytes[..8], b"OPCNAT04");
        let actual = NativeStorage::read_image(
            &mut bytes.as_slice(),
            [0xD1; 32],
            9,
            storage.business.identity,
        )
        .unwrap();
        assert_eq!(
            actual.business.status_v1(&first).unwrap(),
            storage.business.status_v1(&first).unwrap()
        );
        assert_eq!(
            generation::Version::capture(&actual)
                .unwrap()
                .context_digest()
                .unwrap(),
            generation::Version::capture(&storage)
                .unwrap()
                .context_digest()
                .unwrap()
        );
        for old in [b"OPCNAT01", b"OPCNAT02", b"OPCNAT03"] {
            let mut mislabeled = bytes.clone();
            mislabeled[..8].copy_from_slice(old);
            assert_eq!(
                NativeStorage::read_image(
                    &mut mislabeled.as_slice(),
                    [0xD1; 32],
                    9,
                    storage.business.identity
                )
                .err()
                .unwrap()
                .to_string(),
                "native legacy image carries an unsupported V1 context"
            );
        }
        assert!(storage
            .write_legacy_v3_image_for_test(&mut Vec::new(), [0xD1; 32], 9)
            .is_err());
    }
}
