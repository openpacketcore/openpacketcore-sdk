use super::*;
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};

pub(crate) fn identity(name: &str) -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(format!("spiffe://scope.test/{name}")).unwrap()
}

pub(crate) fn scope() -> ScopeId {
    let cluster = ConsensusClusterId::new("scope-test").unwrap();
    let epoch = ConsensusConfigurationEpoch::new(1).unwrap();
    ScopeId::new(
        SessionConsensusIdentity::new(
            cluster,
            derive_configuration_id(cluster, epoch, &[[1; 32]]),
            epoch,
        ),
        TenantId::new("scope-test").unwrap(),
        NetworkFunctionKind::new("test").unwrap(),
        [1; 32],
    )
    .unwrap()
}

pub(crate) fn execution(n: u8) -> ScopeExecution {
    ScopeExecution::new(
        identity(&format!("worker-{n}")),
        u64::from(n),
        [n; 16],
        [n; 16],
        [n; 32],
    )
    .unwrap()
}

pub(crate) fn at(seconds: i64) -> opc_types::Timestamp {
    opc_types::Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).unwrap(),
    )
}

pub(crate) fn request(
    revision: u64,
    n: u8,
    operation: ScopeAuthorityOperation,
) -> ScopeAuthorityRequest {
    ScopeAuthorityRequest::new(scope(), [n; 16], revision, operation).unwrap()
}

pub(crate) fn admitted() -> ScopeState {
    ScopeState::empty(scope())
        .transition(&request(
            0,
            1,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(1),
            },
        ))
        .unwrap()
}

pub(crate) fn evidence(kind: ScopeClosureKind, n: u8) -> ScopeClosureEvidence {
    ScopeClosureEvidence::new(kind, [n; 32]).unwrap()
}

pub(crate) fn successor(before: &ScopeState, n: u8) -> ScopeAuthorityRequest {
    request(
        before.view.revision(),
        n,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: before.view.stamp().unwrap().clone(),
            execution: execution(n),
            evidence: evidence(ScopeClosureKind::FinalTermination, n),
        },
    )
}

pub(crate) fn close(before: &ScopeState, n: u8) -> ScopeAuthorityRequest {
    request(
        before.view.revision(),
        n,
        ScopeAuthorityOperation::Close {
            current: before.view.stamp().unwrap().clone(),
            evidence: evidence(ScopeClosureKind::LocalQuiescence, n),
        },
    )
}

/// Retirement has no production entry point in this profile. Model a valid durable
/// retirement to exercise the already-required apply and snapshot predicates.
pub(crate) fn retired_fixture(before: &ScopeState, n: u8) -> ScopeState {
    let mut after = before.transition(&successor(before, n)).unwrap();
    let old = before.view.current_incarnation().unwrap().get();
    after.view.retired_through = old;
    after.view.stamp.as_mut().unwrap().namespace.incarnation =
        ScopeIncarnation::new(old + 1).unwrap();
    after.validate().unwrap();
    after
}

#[test]
fn exact_admission_replay_does_not_advance_authority_or_generation() {
    let initial = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let first = ScopeState::empty(scope()).transition(&initial).unwrap();
    assert_eq!(first.transition(&initial).unwrap(), first);
    assert_eq!(first.view.revision(), 1);
    assert_eq!(first.view.current_incarnation().unwrap().get(), 1);
    assert_eq!(first.view.admission_generation_floor(), 1);
    assert_eq!(first.view.retired_through(), 0);
}

#[test]
fn no_effect_requests_preserve_every_authority_byte() {
    let before = admitted();
    let requests = [
        request(
            1,
            2,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(2),
            },
        ),
        request(
            0,
            3,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(2),
            },
        ),
        request(
            1,
            4,
            ScopeAuthorityOperation::SucceedClosed {
                predecessor: before.view.stamp().unwrap().clone(),
                execution: execution(1),
                evidence: evidence(ScopeClosureKind::FinalTermination, 4),
            },
        ),
    ];
    let bytes = before.encode().unwrap();
    for denied in requests {
        assert!(before.transition(&denied).is_err());
        assert_eq!(before.encode().unwrap(), bytes);
    }
}

#[test]
fn successor_requires_exact_predecessor_new_nonce_key_and_higher_generation() {
    let before = admitted();
    let valid = successor(&before, 2);
    let after = before.transition(&valid).unwrap();
    assert_eq!(after.view.revision(), 2);
    assert_eq!(
        after.view.current_incarnation(),
        before.view.current_incarnation()
    );
    assert_eq!(after.view.admission_generation_floor(), 2);
    assert_eq!(after.view.stamp().unwrap().execution(), &execution(2));
    for field in 0..4 {
        let mut invalid = valid.clone();
        let ScopeAuthorityOperation::SucceedClosed {
            predecessor,
            execution,
            ..
        } = &mut invalid.operation
        else {
            unreachable!()
        };
        match field {
            0 => predecessor.revision += 1,
            1 => execution.admission_generation = 1,
            2 => execution.process = before.view.stamp().unwrap().execution.process,
            _ => execution.boot_key = before.view.stamp().unwrap().execution.boot_key,
        }
        assert!(
            before.transition(&invalid).is_err(),
            "invalid field {field}"
        );
    }
    assert_eq!(after.transition(&valid).unwrap(), after);
    assert!(after.transition(&close(&before, 3)).is_err());
}

#[test]
fn committed_close_keeps_floors_and_cannot_reopen_the_predecessor() {
    let before = admitted();
    let closing = close(&before, 2);
    let closed = before.transition(&closing).unwrap();
    assert!(!closed.view.is_active());
    assert_eq!(closed.view.admission_generation_floor(), 1);
    assert_eq!(closed.view.stamp().unwrap().execution(), &execution(1));
    assert_eq!(closed.transition(&closing).unwrap(), closed);
    assert!(closed.transition(&close(&closed, 3)).is_err());
    let next = request(
        2,
        3,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: closed.view.stamp().unwrap().clone(),
            execution: execution(2),
            evidence: closed.view.closed_evidence().unwrap(),
        },
    );
    let admitted = closed.transition(&next).unwrap();
    assert!(admitted.view.is_active());
    assert_eq!(admitted.view.admission_generation_floor(), 2);
    let mut invented = next.clone();
    let ScopeAuthorityOperation::SucceedClosed { evidence, .. } = &mut invented.operation else {
        unreachable!()
    };
    evidence.digest = [9; 32];
    assert_eq!(
        closed.transition(&invented),
        Err(ScopeAuthorityError::ClosureRequired)
    );
}

#[test]
fn closure_kind_and_digest_are_bound_to_the_exact_request() {
    let before = admitted();
    let accepted = successor(&before, 2);
    let after = before.transition(&accepted).unwrap();
    for changed in [
        evidence(ScopeClosureKind::FinalTermination, 8),
        evidence(ScopeClosureKind::CommittedClose, 2),
    ] {
        let mut different = accepted.clone();
        let ScopeAuthorityOperation::SucceedClosed { evidence, .. } = &mut different.operation
        else {
            unreachable!()
        };
        *evidence = changed;
        assert_ne!(different.digest().unwrap(), accepted.digest().unwrap());
        assert_eq!(
            after.transition(&different),
            Err(ScopeAuthorityError::IdempotencyConflict)
        );
    }
    let mut local_is_not_final = accepted;
    let ScopeAuthorityOperation::SucceedClosed { evidence, .. } = &mut local_is_not_final.operation
    else {
        unreachable!()
    };
    evidence.kind = ScopeClosureKind::LocalQuiescence;
    assert_eq!(
        before.transition(&local_is_not_final),
        Err(ScopeAuthorityError::ClosureRequired)
    );
}

#[test]
fn retired_incarnation_never_becomes_current_again() {
    let before = admitted();
    let retired = retired_fixture(&before, 2);
    assert_eq!(retired.view.retired_through(), 1);
    assert_eq!(retired.view.current_incarnation().unwrap().get(), 2);
    assert_eq!(retired.view.admission_generation_floor(), 2);
    assert!(retired.transition(&successor(&before, 3)).is_err());
    assert!(retired.transition(&close(&before, 4)).is_err());
    let restored = ScopeState::decode(&retired.encode().unwrap(), &scope()).unwrap();
    assert_eq!(restored, retired);
}

#[test]
fn stored_authority_and_wire_claims_reject_invalid_floors_and_trailing_data() {
    let before = admitted();
    for which in 0..5 {
        let mut invalid = before.clone();
        match which {
            0 => invalid.view.retired_through = 1,
            1 => invalid.view.admission_generation_floor = 2,
            2 => invalid.view.stamp.as_mut().unwrap().revision = 2,
            3 => invalid.view.stamp.as_mut().unwrap().execution.boot_key = [0; 32],
            _ => invalid.last_request_id = [0; 16],
        }
        assert!(invalid.encode().is_err(), "invalid field {which}");
    }
    let mut bytes = before.encode().unwrap();
    bytes.push(0);
    assert!(ScopeState::decode(&bytes, &scope()).is_err());
    assert!(ScopeIncarnation::new(0).is_err());
    assert!(ScopeIncarnation::new(i64::MAX as u64 + 1).is_err());
    assert!(serde_json::from_str::<ScopeIncarnation>("0").is_err());
    assert!(ScopeClosureEvidence::new(ScopeClosureKind::FinalTermination, [0; 32]).is_err());
}

#[test]
fn checked_authority_revision_does_not_wrap_or_reset_floors() {
    let mut before = admitted();
    before.view.revision = i64::MAX as u64;
    before.view.stamp.as_mut().unwrap().revision = i64::MAX as u64;
    assert_eq!(
        before.transition(&successor(&before, 2)),
        Err(ScopeAuthorityError::InvalidRequest)
    );
}

#[test]
fn same_scope_does_not_include_voter_configuration_in_request_digest() {
    let old = scope();
    let epoch = ConsensusConfigurationEpoch::new(2).unwrap();
    let changed = ScopeId::new(
        SessionConsensusIdentity::new(
            old.store(),
            derive_configuration_id(old.store(), epoch, &[[2; 32]]),
            epoch,
        ),
        old.tenant().clone(),
        old.nf_kind().clone(),
        *old.slot(),
    )
    .unwrap();
    assert_eq!(old, changed);
    let request = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let mut retry = request.clone();
    retry.scope = changed;
    assert_eq!(request.digest().unwrap(), retry.digest().unwrap());
}

#[test]
fn rfc026_authority_request_bytes_and_digests_match_frozen_vectors() {
    // RFC 026 v2 authority vectors at c3a70e022f11651ee7510261f7466d2714fe3c10:
    // keep fields, order, enum indices
    // and digest labels identical across the core and authenticated transport.
    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }
    let cluster = ConsensusClusterId::from_bytes([0x11; 32]);
    let epoch = ConsensusConfigurationEpoch::new(1).unwrap();
    let scope = ScopeId::new(
        SessionConsensusIdentity::new(
            cluster,
            derive_configuration_id(cluster, epoch, &[[1; 32]]),
            epoch,
        ),
        TenantId::new("example").unwrap(),
        NetworkFunctionKind::new("worker").unwrap(),
        [0x22; 32],
    )
    .unwrap();
    let initial = ScopeExecution::new(
        SessionConsumerIdentity::new(
            "spiffe://example.org/tenant/example/ns/example/sa/worker/nf/smf/instance/worker-0",
        )
        .unwrap(),
        127,
        bytes("00112233445566778899aabbccddeeff"),
        [0x33; 16],
        bytes("5baff89de7de5c1d7b6193a1567ceeeb397cbda88f03f725c8de328591bfc194"),
    )
    .unwrap();
    let successor = ScopeExecution::new(
        initial.identity().clone(),
        128,
        *initial.workload(),
        [0x44; 16],
        bytes("97e9d1d2a642f9d771b3a301aaedc8c8b534dfcb7bff6813309b04d088525031"),
    )
    .unwrap();
    let namespace = ScopeNamespace::new(scope.clone(), ScopeIncarnation::new(1).unwrap()).unwrap();
    let requests = [
        ScopeAuthorityRequest::new(
            scope.clone(),
            bytes("0102030405060708090a0b0c0d0e0f10"),
            0,
            ScopeAuthorityOperation::AdmitInitial {
                execution: initial.clone(),
            },
        )
        .unwrap(),
        ScopeAuthorityRequest::new(
            scope.clone(),
            bytes("1112131415161718191a1b1c1d1e1f20"),
            1,
            ScopeAuthorityOperation::SucceedClosed {
                predecessor: ScopeAuthorityStamp {
                    namespace: namespace.clone(),
                    revision: 1,
                    execution: initial,
                },
                execution: successor.clone(),
                evidence: ScopeClosureEvidence::new(
                    ScopeClosureKind::FinalTermination,
                    bytes("ea4cec45a23e4de05b132833c920e232ecb846cf131ea5b06040b136ca3d5e15"),
                )
                .unwrap(),
            },
        )
        .unwrap(),
        ScopeAuthorityRequest::new(
            scope,
            bytes("2122232425262728292a2b2c2d2e2f30"),
            2,
            ScopeAuthorityOperation::Close {
                current: ScopeAuthorityStamp {
                    namespace,
                    revision: 2,
                    execution: successor,
                },
                evidence: ScopeClosureEvidence::new(
                    ScopeClosureKind::LocalQuiescence,
                    bytes("7fbf3b952542a3e60190de1a2c448ab7dc8482b9cf63034c5d08c77e728b4050"),
                )
                .unwrap(),
            },
        )
        .unwrap(),
    ];
    let vectors = [
        ("admit_initial", concat!(
                "1111111111111111111111111111111111111111111111111111111111111111076578616d706c6506776f726b657222",
                "222222222222222222222222222222222222222222222222222222222222220102030405060708090a0b0c0d0e0f1000",
                "00517370696666653a2f2f6578616d706c652e6f72672f74656e616e742f6578616d706c652f6e732f6578616d706c65",
                "2f73612f776f726b65722f6e662f736d662f696e7374616e63652f776f726b65722d307f00112233445566778899aabb",
                "ccddeeff333333333333333333333333333333335baff89de7de5c1d7b6193a1567ceeeb397cbda88f03f725c8de3285",
                "91bfc194",
            ), "f6c8c45461a553b43d280376359b861272e2111f29d7a64813934eb756ef3201"),
        ("succeed_closed", concat!(
                "1111111111111111111111111111111111111111111111111111111111111111076578616d706c6506776f726b657222",
                "222222222222222222222222222222222222222222222222222222222222221112131415161718191a1b1c1d1e1f2001",
                "011111111111111111111111111111111111111111111111111111111111111111076578616d706c6506776f726b6572",
                "22222222222222222222222222222222222222222222222222222222222222220101517370696666653a2f2f6578616d",
                "706c652e6f72672f74656e616e742f6578616d706c652f6e732f6578616d706c652f73612f776f726b65722f6e662f73",
                "6d662f696e7374616e63652f776f726b65722d307f00112233445566778899aabbccddeeff3333333333333333333333",
                "33333333335baff89de7de5c1d7b6193a1567ceeeb397cbda88f03f725c8de328591bfc194517370696666653a2f2f65",
                "78616d706c652e6f72672f74656e616e742f6578616d706c652f6e732f6578616d706c652f73612f776f726b65722f6e",
                "662f736d662f696e7374616e63652f776f726b65722d30800100112233445566778899aabbccddeeff44444444444444",
                "44444444444444444497e9d1d2a642f9d771b3a301aaedc8c8b534dfcb7bff6813309b04d08852503101ea4cec45a23e",
                "4de05b132833c920e232ecb846cf131ea5b06040b136ca3d5e15",
            ), "0f754af826037abea1abcf168a1dfa0f7ef2804cbb0912a07ba03d2d6bde3903"),
        ("close", concat!(
                "1111111111111111111111111111111111111111111111111111111111111111076578616d706c6506776f726b657222",
                "222222222222222222222222222222222222222222222222222222222222222122232425262728292a2b2c2d2e2f3002",
                "021111111111111111111111111111111111111111111111111111111111111111076578616d706c6506776f726b6572",
                "22222222222222222222222222222222222222222222222222222222222222220102517370696666653a2f2f6578616d",
                "706c652e6f72672f74656e616e742f6578616d706c652f6e732f6578616d706c652f73612f776f726b65722f6e662f73",
                "6d662f696e7374616e63652f776f726b65722d30800100112233445566778899aabbccddeeff44444444444444444444",
                "44444444444497e9d1d2a642f9d771b3a301aaedc8c8b534dfcb7bff6813309b04d088525031007fbf3b952542a3e601",
                "90de1a2c448ab7dc8482b9cf63034c5d08c77e728b4050",
            ), "d7921ea0b1412862e6643a39f1d79795735b9bcdf6b158abb193cffc670e5b3a"),
    ];
    for (request, (name, encoded, digest)) in requests.into_iter().zip(vectors) {
        assert_eq!(
            hex::encode(postcard::to_allocvec(&request).unwrap()),
            encoded,
            "{name}"
        );
        assert_eq!(hex::encode(request.digest().unwrap()), digest, "{name}");
        let decoded: ScopeAuthorityRequest =
            postcard::from_bytes(&hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, request, "{name}");
    }
    assert_eq!(
        postcard::to_allocvec(&ScopeClosureKind::CommittedClose).unwrap(),
        [2]
    );
}
