//! Maximum encoded shapes, including both frontier copies in a delta. These
//! deliberately widen counters and names beyond semantic admission to prove
//! a conservative byte bound, not authority for the synthetic context.

use super::*;
use crate::consensus::native::{async_recovery::Boundary, voter_slot_tests as slots_fixture};
use opc_consensus::voter_slots::*;
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch, CONSENSUS_NODE_ID_MAX};

#[test]
fn native_compact_frontier_bounds_are_independent() {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let context = full_context(false);
    let value = serde_json::to_value(&context).unwrap();
    let _ = serde_json::from_value::<Context>(value.clone()).unwrap();
    let binary_oversize = BASE64.encode(vec![0; frontier_encoding::MAX_RECOVERY_BYTES + 1]);
    assert_eq!(
        binary_oversize.len(),
        4 * frontier_encoding::MAX_RECOVERY_BYTES.div_ceil(3)
    );
    for encoded in [
        "!".repeat(4 * frontier_encoding::MAX_RECOVERY_BYTES.div_ceil(3) + 4),
        binary_oversize,
    ] {
        let mut refused = value.clone();
        refused["business"]["frontiers"]["async_recovery"] = serde_json::json!(encoded);
        assert_eq!(
            serde_json::from_value::<Context>(refused)
                .err()
                .unwrap()
                .to_string(),
            "native recovery frontier exceeds encoding bound"
        );
    }
}

#[test]
fn native_slot_text_bound_is_exercised() {
    let context = full_context(true);
    let mut value = serde_json::to_value(&context).unwrap();
    let _ = serde_json::from_value::<Context>(value.clone()).unwrap();
    value["business"]["frontiers"]["voter_slots"]["current"] = serde_json::json!(
        "!".repeat(4 * opc_consensus::voter_slots::MAX_VOTER_SLOT_TABLE_BYTES.div_ceil(3) + 4)
    );
    assert_eq!(
        serde_json::from_value::<Context>(value)
            .err()
            .unwrap()
            .to_string(),
        "native slot table exceeds encoding bound"
    );
}
fn largest_slots() -> voter_slots::Table {
    let mut genesis = slots_fixture::genesis(9);
    genesis.cluster_instance = ConsensusClusterId::from_bytes([255; 32]);
    genesis.manifest_digest = [255; 32];
    for slot in &mut genesis.slots {
        slot.member.key_digest = [255; 32];
        slot.member.descriptor_digest = [255; 32];
    }
    let mut current = genesis.clone();
    current.revision = COUNTER_MAX - 1;
    current.configuration_epoch = ConsensusConfigurationEpoch::new(COUNTER_MAX - 1).unwrap();
    let cut = |offset| VoterSlotLogId {
        term: COUNTER_MAX,
        index: COUNTER_MAX - offset,
    };
    for slot in &mut current.slots {
        let ordinal = slot.member.identity.slot();
        slot.member.identity = VoterSlotIdentity::new(ordinal, VoterIncarnation::new(2).unwrap());
        slot.member.admission_generation = COUNTER_MAX - 1;
        slot.retired_through = 1;
        let mut request_id = [255; 16];
        request_id[0] = ordinal.get() as u8;
        slot.last_result = Some(VoterReplacementResult {
            request_id: SessionConsensusRequestId::from_bytes(request_id),
            request_digest: [255; 32],
            incarnation: VoterIncarnation::new(2).unwrap(),
            revision: COUNTER_MAX - 2,
            configuration_epoch: ConsensusConfigurationEpoch::new(COUNTER_MAX - 2).unwrap(),
            kind: VoterReplacementResultKind::Completed,
            terminal: cut(30),
        });
    }
    let predecessor = current.current_configuration();
    let mut request = slots_fixture::request(&current, 9);
    request.candidate.key_digest = [255; 32];
    request.candidate.descriptor_digest = [255; 32];
    request.candidate.admission_generation = COUNTER_MAX;
    let claims = &mut request.attestation;
    claims.candidate_key_digest = request.candidate.key_digest;
    claims.admission_generation = request.candidate.admission_generation;
    claims.candidate_spiffe_id = format!("spiffe://{}", "z".repeat(MAX_VOTER_SPIFFE_ID_BYTES - 9));
    claims.controller_spiffe_id = claims.candidate_spiffe_id.clone();
    claims.signing_key_digest = [255; 32];
    claims.policy_digest = [255; 32];
    claims.signature = [255; 64];
    claims.observation_start_ms = u64::MAX - 3;
    claims.decision_ms = u64::MAX - 2;
    claims.issued_ms = u64::MAX - 2;
    claims.expires_ms = u64::MAX - 1;
    claims.request_digest = voter_replacement_request_digest(
        request.expected_revision,
        request.expected_configuration,
        &request.candidate,
        claims,
    )
    .unwrap();
    current.revision = COUNTER_MAX;
    current.configuration_epoch = ConsensusConfigurationEpoch::new(COUNTER_MAX).unwrap();
    current.slots[8].member = request.candidate;
    current.slots[8].retired_through = 2;
    let successor = current.current_configuration();
    current.replacement = Some(VoterReplacementRecord {
        expected_revision: request.expected_revision,
        attestation: request.attestation,
        predecessor,
        successor,
        phase: VoterReplacementPhase::Uniform,
        evidence: VoterReplacementEvidence {
            prepare: cut(20),
            snapshot: Some(VoterSnapshotEvidence {
                cut: cut(19),
                snapshot_id: "z".repeat(MAX_VOTER_SNAPSHOT_ID_BYTES),
                digest: [255; 32],
            }),
            learner: Some(cut(18)),
            caught_up: Some(cut(17)),
            continuation: Some(cut(16)),
            fence: Some(cut(15)),
            joint: Some(cut(14)),
            uniform: Some(cut(13)),
        },
    });
    current.validate_successor_of(&genesis).unwrap();
    let genesis_bytes = encode_voter_slot_table(&genesis).unwrap();
    let current_bytes = encode_voter_slot_table(&current).unwrap();
    assert_eq!(genesis_bytes.len(), 916);
    assert_eq!(current_bytes.len(), 8_072);
    let decimal_carrier = serde_json::to_vec(&serde_json::json!({
        "genesis": genesis_bytes, "current": current_bytes,
    }))
    .unwrap();
    assert!(
        2 * decimal_carrier.len() > MAX_HEADER,
        "decimal byte arrays already exhaust the delta before other metadata"
    );
    voter_slots::Table {
        genesis: Arc::new(genesis),
        current,
    }
}

fn full_context(slots: bool) -> Context {
    let (storage, _, _) = fixture();
    let mut context = Version::capture(&storage).unwrap().context();
    // The roundtrip needs valid typed ordinals; widen the JSON scalars only
    // after it succeeds when computing the conservative encoded-size bound.
    let nodes: BTreeSet<_> = (1..=if slots { 10 } else { 5 })
        .map(|n| SessionConsensusNodeId::new(CONSENSUS_NODE_ID_MAX - (n - 1)).unwrap())
        .collect();
    let membership = StoredMembership::new(
        Some(slots_fixture::cut(COUNTER_MAX)),
        opc_consensus::engine::Membership::new(
            vec![nodes.clone(); if slots { 2 } else { 1 }],
            nodes,
        ),
    );
    let identity = context.business.identity;
    context.business.members = (1..=if slots { 9 } else { 5 })
        .map(|n| SessionConsensusNodeId::new(CONSENSUS_NODE_ID_MAX - (n - 1)).unwrap())
        .collect();
    let frontiers = &mut context.business.frontiers;
    frontiers.membership = membership.clone();
    frontiers.applied = Some(slots_fixture::cut(COUNTER_MAX));
    frontiers.digest = SessionConsensusEntryDigest::from_bytes([255; 32]);
    assert!(frontiers.history.is_some());
    frontiers.activation = Some(NativeActivation {
        identity,
        voters: [255; 32],
        profile: [255; 32],
    });
    frontiers.v1_activation = Some(NativeV1Activation {
        identity,
        voters: [255; 32],
    });
    frontiers.roster_v1_namespace = true;
    frontiers.roster_v2_activation = Some(NativeActivation {
        identity,
        voters: [255; 32],
        profile: [255; 32],
    });
    frontiers.fenced_transition_profile = FencedTransitionV2Profile::V2WithVoid;
    frontiers.current_snapshot = Some((
        SnapshotMeta {
            last_log_id: frontiers.applied,
            last_membership: membership,
            snapshot_id: "\0".repeat(256),
        },
        format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
        [255; 32],
        u64::MAX,
    ));
    if slots {
        frontiers.voter_slots = Some(largest_slots());
    } else {
        let mut boundary = Boundary::from_entry(2, [255; 32], slots_fixture::cut(COUNTER_MAX));
        boundary.protected = Some(Box::new(
            crate::consensus::protected_recovery::maximum_proof_for_native_frontier_test(),
        ));
        frontiers.async_recovery = Some(boundary);
    }
    context.business.roster = Some(RosterContext {
        root: Some([255; 32]),
        counts: [usize::MAX; 2],
        content: [[255; 32]; 2],
        witness: Some(crate::fenced_mutation_roster_storage::GlobalChargeWitness::empty()),
    });
    context.log.vote = Some(Vote::new_committed(
        COUNTER_MAX,
        slots_fixture::member(1, 1).identity.node_id(),
    ));
    context.log.committed = frontiers.applied;
    context.log.purged = frontiers.applied;
    context.log.slot_intent = frontiers.applied;
    context.log.first = frontiers.applied;
    context.log.last = frontiers.applied;
    context
}

fn widen_scalars(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Number(_) => *value = serde_json::json!(u64::MAX),
        serde_json::Value::Array(items) => {
            if matches!(items.len(), 16 | 32)
                && items
                    .iter()
                    .all(|item| item.as_u64().is_some_and(|n| n <= 255))
            {
                for item in items {
                    *item = serde_json::json!(255);
                }
            } else {
                for item in items {
                    widen_scalars(item);
                }
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values_mut() {
                widen_scalars(field);
            }
        }
        _ => {}
    }
}

#[test]
fn native_delta_header_budgets_both_maximum_frontiers_and_future_fields() {
    // 20 KiB for current frontier vocabulary + 4 KiB for future optional
    // fields. Each full context has another 4 KiB; outer delta metadata has 8.
    const CURRENT_FRONTIER: usize = 20 * 1024;
    const FRONTIER: usize = 24 * 1024;
    const CONTEXT: usize = 28 * 1024;
    const OUTER: usize = 8 * 1024;
    assert_eq!(2 * CONTEXT + OUTER, MAX_HEADER);
    for slots in [false, true] {
        let context = full_context(slots);
        let encoded = serde_json::to_vec(&context).unwrap();
        let recovered: Context = serde_json::from_slice(&encoded).unwrap();
        assert!(
            context == recovered,
            "compact carriers preserve every field"
        );
        let mut value = serde_json::to_value(&context).unwrap();
        if !slots {
            // Include the full enforced binary ceiling, even though the
            // present complete 32-owner proof is smaller than that ceiling.
            value["business"]["frontiers"]["async_recovery"] = serde_json::json!(
                "A".repeat(4 * frontier_encoding::MAX_RECOVERY_BYTES.div_ceil(3))
            );
        }
        for field in value["business"]["frontiers"]["history"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            *field = serde_json::json!(u64::MAX);
        }
        widen_scalars(&mut value);
        value["business"]["frontiers"]["logical_time"] = serde_json::json!("0".repeat(30));
        let frontier = &mut value["business"]["frontiers"];
        let current = serde_json::to_vec(frontier).unwrap().len();
        assert!(
            current <= CURRENT_FRONTIER,
            "current frontier uses {current} bytes"
        );
        frontier["reserved_future_fields"] = serde_json::json!("x".repeat(4 * 1024 - 64));
        assert!(serde_json::to_vec(frontier).unwrap().len() <= FRONTIER);
        assert!(serde_json::to_vec(&value).unwrap().len() <= CONTEXT);
        let digest = [255_u8; 32];
        let changed = [usize::MAX; 5];
        let roster_changed = [usize::MAX; 2];
        let header = serde_json::json!({
            "previous": {
                "binding": digest, "file_epoch": u64::MAX, "checkpoint_epoch": u64::MAX,
                "operation_sequence": u64::MAX, "frontiers": digest, "length": u64::MAX,
                "block_bytes": usize::MAX, "digest": digest
            },
            "checkpoint_epoch": u64::MAX, "operation_sequence": u64::MAX,
            "cut_binding": digest, "before": value, "after": value,
            "changed": changed, "roster_changed": roster_changed
        });
        let context_bytes = serde_json::to_vec(&header["before"]).unwrap().len();
        let bytes = encode_header(&header).unwrap();
        assert!(bytes.len() - 2 * context_bytes <= OUTER);
        assert!(bytes.len() <= MAX_HEADER);
        eprintln!(
            "native header budget slots={slots} frontier={current} delta_with_reserved_fields={}",
            bytes.len()
        );
    }
}

#[test]
fn native_compact_frontier_preserves_image_json_and_rejects_trailing_or_oversize_bytes() {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let context = full_context(false);
    let original = context.business.frontiers.async_recovery.as_ref().unwrap();
    original.protected.as_ref().unwrap().verify().unwrap();
    let image_json = serde_json::to_value(original).unwrap();
    assert!(image_json["protected"]["challenge"]["inventory"]["owners"].is_array());
    let value = serde_json::to_value(&context).unwrap();
    let encoded = value["business"]["frontiers"]["async_recovery"]
        .as_str()
        .unwrap();
    let recovered: Context = serde_json::from_value(value.clone()).unwrap();
    recovered
        .business
        .frontiers
        .async_recovery
        .as_ref()
        .unwrap()
        .protected
        .as_ref()
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(
        serde_json::to_value(
            recovered
                .business
                .frontiers
                .async_recovery
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        image_json,
        "the SQL image and command proof keep their original named vocabulary"
    );
    let mut trailing = BASE64.decode(encoded).unwrap();
    trailing.push(0);
    for (encoded, expected) in [
        (
            BASE64.encode(trailing),
            "native binary row contains trailing bytes",
        ),
        (
            "A".repeat(4 * frontier_encoding::MAX_RECOVERY_BYTES.div_ceil(3) + 4),
            "native recovery frontier exceeds encoding bound",
        ),
    ] {
        let mut refused = value.clone();
        refused["business"]["frontiers"]["async_recovery"] = serde_json::json!(encoded);
        assert_eq!(
            serde_json::from_value::<Context>(refused)
                .err()
                .unwrap()
                .to_string(),
            expected
        );
    }
}

#[test]
fn native_compact_frontier_roundtrips_unprotected_recovery_without_changing_image_json() {
    let mut context = full_context(false);
    let boundary = context.business.frontiers.async_recovery.as_mut().unwrap();
    boundary.protected = None;
    let image_json = serde_json::to_value(&*boundary).unwrap();
    assert!(image_json.get("protected").is_none());

    let encoded = serde_json::to_vec(&context).unwrap();
    let recovered: Context = serde_json::from_slice(&encoded).unwrap();
    assert!(
        context == recovered,
        "an unprotected recovery boundary survives the generation carrier"
    );
    assert_eq!(
        serde_json::to_value(
            recovered
                .business
                .frontiers
                .async_recovery
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        image_json,
        "portable image JSON keeps its existing omitted optional proof"
    );
}
