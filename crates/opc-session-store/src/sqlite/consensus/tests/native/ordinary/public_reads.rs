use super::*;
use crate::consumer::{
    SessionConsumerOperation, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerScope,
};
use crate::sqlite::consensus::consumer_receipts;

fn id(index: u64) -> SessionConsensusRequestId {
    let EntryPayload::Normal(command) =
        command(index, SessionMutationIntent::AdvanceLogicalTime, now(1)).payload
    else {
        unreachable!()
    };
    command.request_id
}

fn binding_bytes(
    result: Result<ConsumerRequestBindingLookup, StoreError>,
) -> Result<(u8, Vec<u8>), StoreError> {
    Ok(match result? {
        ConsumerRequestBindingLookup::Missing => (0, Vec::new()),
        ConsumerRequestBindingLookup::Matched(response) => (1, encode_json(&response).unwrap()),
        ConsumerRequestBindingLookup::Conflict => (2, Vec::new()),
    })
}

fn binding(
    wal: &Wal,
    oracle: &SqliteSessionBackend,
    id: SessionConsensusRequestId,
    commitment: [u8; 32],
    expected: u8,
) {
    let actual = binding_bytes(
        wal.native_public_read(&|| Ok(()), |state, _| {
            consumer_receipts::read_consumer_request_binding_sync(
                &state.consumer_receipts()?,
                identity(),
                identity(),
                id,
                commitment,
            )
        })
        .unwrap(),
    );
    let sql = binding_bytes(read_consumer_request_binding_sync(
        &oracle.conn.blocking_lock(),
        identity(),
        identity(),
        id,
        commitment,
    ));
    assert_eq!(actual, sql);
    assert_eq!(actual.unwrap().0, expected);
}

fn lease_status(
    wal: &Wal,
    oracle: &SqliteSessionBackend,
    binding_id: SessionConsensusRequestId,
    operation_id: SessionConsensusRequestId,
    request: &SessionConsumerRequest,
) -> crate::consumer::SessionConsumerLeaseMutationStatus {
    let actual = wal
        .native_public_read(&|| Ok(()), |state, _| {
            consumer_receipts::read_consumer_lease_mutation_status_sync(
                &state.consumer_receipts()?,
                identity(),
                identity(),
                binding_id,
                operation_id,
                request,
            )
        })
        .unwrap();
    let expected = read_consumer_lease_mutation_status_sync(
        &oracle.conn.blocking_lock(),
        identity(),
        identity(),
        binding_id,
        operation_id,
        request,
    );
    assert_eq!(actual, expected);
    actual.unwrap()
}

fn cas_status(
    wal: &Wal,
    oracle: &SqliteSessionBackend,
    lookup: ConsumerCompareAndSetReceiptLookup,
) -> crate::consumer::SessionConsumerCompareAndSetStatus {
    let actual = wal
        .native_public_read(&|| Ok(()), |state, _| {
            consumer_receipts::read_consumer_compare_and_set_status_sync(
                &state.consumer_receipts()?,
                identity(),
                lookup,
            )
        })
        .unwrap();
    let expected =
        read_consumer_compare_and_set_status_sync(&oracle.conn.blocking_lock(), identity(), lookup);
    assert_eq!(actual, expected);
    actual.unwrap()
}

#[test]
fn native_public_consumer_binding_lease_and_cas_receipts_preserve_exact_status_and_conflict_after_reopen(
) {
    use crate::consumer::{
        SessionConsumerCompareAndSetStatus as CasStatus,
        SessionConsumerLeaseMutationStatus as LeaseStatus,
    };
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let request = SessionConsumerRequest::new(
        SessionConsumerScope::new(identity()),
        SessionConsumerRequestId::from_bytes([0xB7; 16]),
        SessionConsumerOperation::AcquireLease {
            key: key(),
            owner: OwnerId::new("native-consumer-read").unwrap(),
            ttl: Duration::from_secs(60),
        },
    );
    let commitment = crate::consumer::consumer_request_commitment(&request).unwrap();
    binding(&fixture.wal, &fixture.oracle, id(1), commitment, 0);
    assert!(matches!(
        lease_status(&fixture.wal, &fixture.oracle, id(1), id(2), &request),
        LeaseStatus::NotFound
    ));
    fixture.parity(&[command(
        1,
        SessionMutationIntent::BindConsumerRequest {
            request_commitment: commitment,
        },
        now(1),
    )]);
    binding(&fixture.wal, &fixture.oracle, id(1), commitment, 1);
    binding(&fixture.wal, &fixture.oracle, id(1), [0xEE; 32], 2);
    assert!(matches!(
        lease_status(&fixture.wal, &fixture.oracle, id(1), id(2), &request),
        LeaseStatus::NotFound
    ));
    let SessionConsumerOperation::AcquireLease { key, owner, ttl } = request.operation() else {
        unreachable!()
    };
    let guard = lease(
        fixture
            .parity(&[command(
                2,
                SessionMutationIntent::AcquireLease {
                    key: key.clone(),
                    owner: owner.clone(),
                    ttl: *ttl,
                },
                now(2),
            )])
            .responses
            .remove(0),
    );
    assert!(matches!(
        lease_status(&fixture.wal, &fixture.oracle, id(1), id(2), &request),
        LeaseStatus::Recorded(_)
    ));
    assert!(matches!(
        lease_status(&fixture.wal, &fixture.oracle, id(1), id(1), &request),
        LeaseStatus::RequestConflict
    ));
    let operation = CompareAndSet {
        key: guard.key().clone(),
        lease: guard.clone(),
        expected_generation: None,
        new_record: record(&guard, 1, None),
    };
    let cas_commitment = [0xB8; 32];
    let lookup = consumer_compare_and_set_receipt_lookup(
        identity(),
        identity(),
        id(3),
        id(4),
        cas_commitment,
        &operation,
    )
    .unwrap();
    assert!(matches!(
        cas_status(&fixture.wal, &fixture.oracle, lookup),
        CasStatus::NotFound
    ));
    fixture.parity(&[command(
        3,
        SessionMutationIntent::BindConsumerRequest {
            request_commitment: cas_commitment,
        },
        now(3),
    )]);
    assert!(matches!(
        cas_status(&fixture.wal, &fixture.oracle, lookup),
        CasStatus::NotFound
    ));
    fixture.parity(&[command(
        4,
        SessionMutationIntent::CompareAndSet(Arc::new(operation.clone())),
        now(4),
    )]);
    let exact = cas_status(&fixture.wal, &fixture.oracle, lookup);
    assert!(matches!(exact, CasStatus::Recorded(_)));
    let changed = CompareAndSet {
        new_record: record(&guard, 2, None),
        ..operation
    };
    let conflict = consumer_compare_and_set_receipt_lookup(
        identity(),
        identity(),
        id(3),
        id(4),
        cas_commitment,
        &changed,
    )
    .unwrap();
    assert!(matches!(
        cas_status(&fixture.wal, &fixture.oracle, conflict),
        CasStatus::RequestConflict
    ));
    // A permanent V1 receipt occupies an ID even though it is absent from the
    // ordinary outcome table. All three original evaluators preserve that.
    let template = sdk741_component_request(Sdk741Payload::Create, 151, 0, None);
    let fenced = crate::FencedTransitionRequest::new(
        crate::FencedTransitionRequestId::from_bytes([0xB9; 16]),
        template.lease().clone(),
        template.mutation().clone(),
    )
    .unwrap();
    let mut entry = command(
        5,
        SessionMutationIntent::ActivateFencedTransition {
            request: Box::new(fenced),
            scope_identity: identity(),
            voter_set_digest: fenced_transition_voter_set_digest(identity(), &fixed_members()),
        },
        now(5),
    );
    let EntryPayload::Normal(value) = &mut entry.payload else {
        unreachable!()
    };
    value.request_id = SessionConsensusRequestId::from_bytes([0xB9; 16]);
    fixture.parity(&[entry]);
    let fenced_id = SessionConsensusRequestId::from_bytes([0xB9; 16]);
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    binding(&reopened, &fixture.oracle, id(1), commitment, 1);
    binding(&reopened, &fixture.oracle, fenced_id, commitment, 2);
    assert!(matches!(
        lease_status(&reopened, &fixture.oracle, fenced_id, id(2), &request),
        LeaseStatus::RequestConflict
    ));
    assert!(matches!(
        cas_status(
            &reopened,
            &fixture.oracle,
            ConsumerCompareAndSetReceiptLookup {
                binding_request_id: fenced_id,
                ..lookup
            }
        ),
        CasStatus::RequestConflict
    ));
    assert_eq!(cas_status(&reopened, &fixture.oracle, lookup), exact);
    assert_eq!(reopened.native_sql_fallback_count().unwrap(), 0);
    reopened.shutdown().unwrap();
}
