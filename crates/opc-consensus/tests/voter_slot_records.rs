use opc_consensus::voter_slots::*;
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusRequestId};

fn identity(slot: u16, incarnation: u64) -> VoterSlotIdentity {
    VoterSlotIdentity::new(
        SlotId::new(slot).expect("slot"),
        VoterIncarnation::new(incarnation).expect("incarnation"),
    )
}

fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
    VoterSlotMember {
        identity: identity(slot, incarnation),
        key_digest: [incarnation as u8; 32],
        descriptor_digest: [slot as u8; 32],
        admission_generation: incarnation,
    }
}

fn log(index: u64) -> VoterSlotLogId {
    VoterSlotLogId { term: 2, index }
}

fn snapshot(index: u64) -> VoterSnapshotEvidence {
    VoterSnapshotEvidence {
        cut: log(index),
        snapshot_id: "snapshot-10".into(),
        digest: [0x55; 32],
    }
}

fn genesis() -> VoterSlotTable {
    VoterSlotTable {
        cluster_instance: ConsensusClusterId::from_bytes([3; 32]),
        manifest_digest: [4; 32],
        revision: 1,
        configuration_epoch: ConsensusConfigurationEpoch::new(1).expect("epoch"),
        slots: (1..=3)
            .map(|slot| VoterSlotRecord {
                member: member(slot, 1),
                retired_through: 0,
                phase: VoterSlotPhase::Voting,
                last_result: None,
            })
            .collect(),
        replacement: None,
    }
}

fn attestation() -> LostVoterAttestationV1 {
    LostVoterAttestationV1 {
        request_id: ConsensusRequestId::from_bytes([5; 16]),
        request_digest: [6; 32],
        cluster_instance: ConsensusClusterId::from_bytes([3; 32]),
        slot: SlotId::new(3).expect("slot"),
        expected_incarnation: VoterIncarnation::new(1).expect("incarnation"),
        old_descriptor_digest: [3; 32],
        candidate_key_digest: [2; 32],
        admission_generation: 2,
        candidate_spiffe_id: "spiffe://example.test/voter/3".into(),
        controller_spiffe_id: "spiffe://example.test/controller".into(),
        signing_key_digest: [7; 32],
        reason: VoterLossReason::TimeBoundLoss,
        policy_digest: [8; 32],
        observation_start_ms: 100,
        decision_ms: 200,
        issued_ms: 200,
        expires_ms: 300,
        signature: [9; 64],
    }
}

fn prepared() -> VoterSlotTable {
    let mut table = genesis();
    let predecessor = VoterConfiguration {
        epoch: table.configuration_epoch,
        members: table.slots.iter().map(|s| s.member.clone()).collect(),
    };
    table.slots[2].member = member(3, 2);
    table.slots[2].retired_through = 1;
    table.slots[2].phase = VoterSlotPhase::Pending;
    let successor = VoterConfiguration {
        epoch: ConsensusConfigurationEpoch::new(2).expect("epoch"),
        members: table.slots.iter().map(|s| s.member.clone()).collect(),
    };
    table.revision = 2;
    table.replacement = Some(VoterReplacementRecord {
        expected_revision: 1,
        attestation: attestation(),
        predecessor,
        successor,
        phase: VoterReplacementPhase::Prepared,
        evidence: VoterReplacementEvidence {
            prepare: log(10),
            snapshot: None,
            learner: None,
            caught_up: None,
            continuation: None,
            fence: None,
            joint: None,
            uniform: None,
        },
    });
    table
}

fn at_phase(phase: VoterReplacementPhase) -> VoterSlotTable {
    let mut table = prepared();
    let operation = table.replacement.as_mut().expect("replacement");
    operation.phase = phase;
    if phase >= VoterReplacementPhase::SnapshotInstalled {
        operation.evidence.snapshot = Some(snapshot(10));
    }
    if phase >= VoterReplacementPhase::LearnerAdded {
        operation.evidence.learner = Some(log(12));
        table.slots[2].phase = VoterSlotPhase::CatchingUp;
    }
    if phase >= VoterReplacementPhase::CaughtUp {
        operation.evidence.caught_up = Some(log(14));
    }
    if phase >= VoterReplacementPhase::Fenced {
        operation.evidence.fence = Some(log(16));
    }
    if phase >= VoterReplacementPhase::Joint {
        operation.evidence.joint = Some(log(18));
        table.slots[2].phase = VoterSlotPhase::Voting;
    }
    if phase >= VoterReplacementPhase::Uniform {
        operation.evidence.uniform = Some(log(20));
        table.configuration_epoch = operation.successor.epoch;
    }
    table.revision = 3 + phase as u64;
    table
}

#[test]
fn records_roundtrip_all_phases_and_terminal_receipts() {
    for phase in [
        VoterReplacementPhase::Prepared,
        VoterReplacementPhase::SnapshotInstalled,
        VoterReplacementPhase::LearnerAdded,
        VoterReplacementPhase::CaughtUp,
        VoterReplacementPhase::Fenced,
        VoterReplacementPhase::Joint,
        VoterReplacementPhase::Uniform,
    ] {
        let table = at_phase(phase);
        let bytes = encode_voter_slot_table(&table).expect("valid record");
        assert_eq!(decode_voter_slot_table(&bytes).expect("reopen"), table);
        assert_eq!(
            encode_voter_slot_table(&decode_voter_slot_table(&bytes).expect("decoded"))
                .expect("canonical"),
            bytes
        );
    }
    let mut table = at_phase(VoterReplacementPhase::Uniform);
    table.replacement = None;
    table.slots[2].last_result = Some(VoterReplacementResult {
        request_id: attestation().request_id,
        request_digest: attestation().request_digest,
        incarnation: VoterIncarnation::new(2).expect("incarnation"),
        revision: table.revision,
        configuration_epoch: table.configuration_epoch,
        kind: VoterReplacementResultKind::Completed,
        terminal: log(22),
    });
    assert_eq!(
        decode_voter_slot_table(&encode_voter_slot_table(&table).expect("terminal"))
            .expect("reopen"),
        table
    );
}

#[test]
fn singleton_genesis_has_fixed_golden_bytes() {
    let table = VoterSlotTable {
        cluster_instance: ConsensusClusterId::from_bytes([0x33; 32]),
        manifest_digest: [0x44; 32],
        revision: 1,
        configuration_epoch: ConsensusConfigurationEpoch::new(1).expect("epoch"),
        slots: vec![VoterSlotRecord {
            member: VoterSlotMember {
                identity: identity(9, 1),
                key_digest: [0x11; 32],
                descriptor_digest: [0x22; 32],
                admission_generation: 7,
            },
            retired_through: 0,
            phase: VoterSlotPhase::Voting,
            last_result: None,
        }],
        replacement: None,
    };
    let expected = concat!(
        "4f5056490001",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "0000000000000001000000000000000101",
        "000900000000000000010000000000000000",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0000000000000007020000"
    );
    let encoded = encode_voter_slot_table(&table).expect("encode");
    assert_eq!(
        encoded
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        expected
    );
    assert_eq!(decode_voter_slot_table(&encoded).expect("decode"), table);
}

#[test]
fn codecs_reject_truncation_trailing_unknown_versions_and_oversize_before_decode() {
    let encoded = encode_voter_slot_table(&prepared()).expect("encode");
    for length in 0..encoded.len() {
        assert!(
            decode_voter_slot_table(&encoded[..length]).is_err(),
            "prefix {length}"
        );
    }
    let mut bad = encoded.clone();
    bad.push(0);
    assert_eq!(
        decode_voter_slot_table(&bad),
        Err(VoterSlotError::InvalidRecord)
    );
    let mut bad = encoded.clone();
    bad[5] = 2;
    assert_eq!(
        decode_voter_slot_table(&bad),
        Err(VoterSlotError::FreshInstallationRequired)
    );
    let mut bad = encoded.clone();
    bad[0] = 0;
    assert_eq!(
        decode_voter_slot_table(&bad),
        Err(VoterSlotError::InvalidRecord)
    );
    let bad = vec![0; MAX_VOTER_SLOT_TABLE_BYTES + 1];
    assert_eq!(decode_voter_slot_table(&bad), Err(VoterSlotError::TooLarge));
    let mut bad = encoded.clone();
    bad[86] = 255;
    assert!(decode_voter_slot_table(&bad).is_err());
    let mut bad = encoded;
    bad[87] = 0;
    bad[88] = 0;
    assert!(decode_voter_slot_table(&bad).is_err());
}

#[test]
fn table_validates_topology_floor_binding_and_one_operation() {
    let good = prepared();
    let mut bad = good.clone();
    bad.slots.swap(0, 1);
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.slots[1] = bad.slots[0].clone();
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.slots.pop();
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.slots[2].retired_through = 0;
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.slots[0].phase = VoterSlotPhase::Pending;
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement = None;
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement.as_mut().expect("op").successor.members[0] = member(1, 2);
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement
        .as_mut()
        .expect("op")
        .attestation
        .candidate_key_digest = [0; 32];
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement.as_mut().expect("op").expected_revision = bad.revision;
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good;
    bad.replacement.as_mut().expect("op").successor.epoch =
        ConsensusConfigurationEpoch::new(3).expect("epoch");
    assert!(encode_voter_slot_table(&bad).is_err());
}

#[test]
fn phase_evidence_requires_real_ordered_full_log_ids() {
    let good = at_phase(VoterReplacementPhase::Fenced);
    let mut bad = good.clone();
    bad.replacement.as_mut().expect("op").evidence.caught_up = None;
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement.as_mut().expect("op").evidence.snapshot = Some(snapshot(9));
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement.as_mut().expect("op").evidence.fence = Some(log(13));
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement.as_mut().expect("op").evidence.joint = Some(log(18));
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good.clone();
    bad.replacement
        .as_mut()
        .expect("op")
        .evidence
        .snapshot
        .as_mut()
        .expect("snapshot")
        .cut
        .term = 3;
    assert!(encode_voter_slot_table(&bad).is_err());
    let mut bad = good;
    bad.replacement.as_mut().expect("op").evidence.prepare.term = 0;
    assert!(encode_voter_slot_table(&bad).is_err());
}

#[test]
fn configuration_digest_binds_installation_manifest_epoch_incarnation_and_key() {
    let table = prepared();
    let op = table.replacement.as_ref().expect("op");
    let digest = op
        .predecessor
        .identity(table.cluster_instance, table.manifest_digest)
        .expect("config");
    assert_ne!(
        digest,
        op.successor
            .identity(table.cluster_instance, table.manifest_digest)
            .expect("successor")
    );
    assert_ne!(
        digest,
        op.predecessor
            .identity(
                ConsensusClusterId::from_bytes([9; 32]),
                table.manifest_digest
            )
            .expect("cluster")
    );
    assert_ne!(
        digest,
        op.predecessor
            .identity(table.cluster_instance, [9; 32])
            .expect("manifest")
    );
    let mut changed = op.predecessor.clone();
    changed.members[0].key_digest[0] ^= 1;
    assert_ne!(
        digest,
        changed
            .identity(table.cluster_instance, table.manifest_digest)
            .expect("key")
    );
    let mut changed = op.predecessor.clone();
    changed.epoch = op.successor.epoch;
    assert_ne!(
        digest,
        changed
            .identity(table.cluster_instance, table.manifest_digest)
            .expect("epoch")
    );
    let mut changed = op.predecessor.clone();
    changed.members.reverse();
    assert!(changed
        .identity(table.cluster_instance, table.manifest_digest)
        .is_err());
}

#[test]
fn loss_attestation_codec_is_bounded_and_is_only_data() {
    use sha2::{Digest, Sha256};
    let record = attestation();
    let bytes = encode_lost_voter_attestation(&record).expect("encode");
    // Fixed RFC 023 field-order vector, computed independently of this codec.
    assert_eq!(bytes.len(), 390);
    assert_eq!(
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "a448615fdb561bbca8f59e0aa171bd376bfdaf33d4853ee0dbdd54d1fd203e76"
    );
    assert_eq!(&bytes[..2], &[0, 1]);
    assert_eq!(&bytes[2..18], &[5; 16]);
    assert_eq!(
        decode_lost_voter_attestation(&bytes).expect("decode"),
        record
    );
    for length in 0..bytes.len() {
        assert!(decode_lost_voter_attestation(&bytes[..length]).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(decode_lost_voter_attestation(&bad).is_err());
    let mut bad = bytes;
    bad[1] = 2;
    assert!(decode_lost_voter_attestation(&bad).is_err());
    assert_eq!(
        decode_lost_voter_attestation(&vec![0; MAX_LOST_VOTER_ATTESTATION_BYTES + 1]),
        Err(VoterSlotError::TooLarge)
    );
    let mut bad = record.clone();
    bad.issued_ms = bad.expires_ms;
    assert!(encode_lost_voter_attestation(&bad).is_err());
    let mut bad = record.clone();
    bad.observation_start_ms = bad.decision_ms + 1;
    assert!(encode_lost_voter_attestation(&bad).is_err());
    let mut bad = record.clone();
    bad.candidate_spiffe_id = "x".repeat(2049);
    assert!(encode_lost_voter_attestation(&bad).is_err());
    let mut bad = record;
    bad.admission_generation = 0;
    assert!(encode_lost_voter_attestation(&bad).is_err());
}

#[test]
fn snapshot_recovery_never_rolls_back_retirement_or_changes_an_existing_binding() {
    let old = genesis();
    let prepared = prepared();
    prepared.validate_successor_of(&old).expect("advance");
    assert_eq!(
        old.validate_successor_of(&prepared),
        Err(VoterSlotError::Regression)
    );
    prepared
        .validate_successor_of(&prepared)
        .expect("exact retry");
    let mut bad = prepared.clone();
    bad.revision += 1;
    bad.slots[0].member.key_digest[0] ^= 1;
    assert!(bad.validate_successor_of(&prepared).is_err());
    let mut bad = old.clone();
    bad.revision = prepared.revision + 1;
    assert_eq!(
        bad.validate_successor_of(&prepared),
        Err(VoterSlotError::Regression)
    );
    let mut bad = prepared.clone();
    bad.cluster_instance = ConsensusClusterId::from_bytes([9; 32]);
    assert!(bad.validate_successor_of(&prepared).is_err());
    let mut bad = prepared.clone();
    bad.manifest_digest[0] ^= 1;
    assert!(bad.validate_successor_of(&prepared).is_err());
    let mut bad = old.clone();
    bad.slots[2].member = member(4, 1);
    bad.revision += 1;
    assert!(bad.validate_successor_of(&old).is_err());
    let mut bad = old.clone();
    bad.slots[0].member.admission_generation += 1;
    assert!(bad.validate_successor_of(&old).is_err());
}

#[test]
fn snapshot_recovery_retains_active_evidence_until_uniform_or_supersession() {
    let caught = at_phase(VoterReplacementPhase::CaughtUp);
    let fenced = at_phase(VoterReplacementPhase::Fenced);
    fenced.validate_successor_of(&caught).expect("forward");
    let mut bad = caught.clone();
    bad.revision = fenced.revision + 1;
    assert_eq!(
        bad.validate_successor_of(&fenced),
        Err(VoterSlotError::Regression)
    );
    let mut bad = fenced.clone();
    bad.revision += 1;
    bad.replacement.as_mut().expect("op").evidence.prepare.term = 1;
    assert!(bad.validate_successor_of(&fenced).is_err());
    let mut bad = fenced.clone();
    bad.revision += 1;
    bad.replacement = None;
    bad.slots[2].phase = VoterSlotPhase::Voting;
    assert!(bad.validate_successor_of(&fenced).is_err());
    at_phase(VoterReplacementPhase::Uniform)
        .validate_successor_of(&fenced)
        .expect("uniform");
}

#[test]
fn a_new_leader_can_refresh_catch_up_before_fence_but_not_after_it() {
    let old = at_phase(VoterReplacementPhase::CaughtUp);
    let mut refreshed = old.clone();
    refreshed.revision += 1;
    refreshed
        .replacement
        .as_mut()
        .expect("op")
        .evidence
        .caught_up = Some(VoterSlotLogId { term: 3, index: 15 });
    refreshed
        .validate_successor_of(&old)
        .expect("fresh current-term marker");
    assert_eq!(
        decode_voter_slot_table(&encode_voter_slot_table(&refreshed).expect("encode"))
            .expect("reopen"),
        refreshed
    );

    let fenced = at_phase(VoterReplacementPhase::Fenced);
    let mut changed = fenced.clone();
    changed.revision += 1;
    changed.replacement.as_mut().expect("op").evidence.caught_up = Some(log(15));
    assert_eq!(
        changed.validate_successor_of(&fenced),
        Err(VoterSlotError::Regression)
    );
}

fn finalized() -> VoterSlotTable {
    let mut table = at_phase(VoterReplacementPhase::Uniform);
    table.revision += 1;
    table.replacement = None;
    table.slots[2].last_result = Some(VoterReplacementResult {
        request_id: attestation().request_id,
        request_digest: attestation().request_digest,
        incarnation: VoterIncarnation::new(2).expect("incarnation"),
        revision: table.revision,
        configuration_epoch: table.configuration_epoch,
        kind: VoterReplacementResultKind::Completed,
        terminal: log(22),
    });
    table
}

fn superseded() -> VoterSlotTable {
    let mut table = prepared();
    table.revision = 11;
    table.slots[2].member = member(3, 3);
    table.slots[2].retired_through = 2;
    table.slots[2].last_result = Some(VoterReplacementResult {
        request_id: attestation().request_id,
        request_digest: attestation().request_digest,
        incarnation: VoterIncarnation::new(2).expect("incarnation"),
        revision: 11,
        configuration_epoch: table.configuration_epoch,
        kind: VoterReplacementResultKind::Superseded,
        terminal: log(23),
    });
    let op = table.replacement.as_mut().expect("op");
    op.expected_revision = 10;
    op.attestation.request_id = ConsensusRequestId::from_bytes([10; 16]);
    op.attestation.request_digest = [11; 32];
    op.attestation.expected_incarnation = VoterIncarnation::new(2).expect("incarnation");
    op.attestation.admission_generation = 3;
    op.attestation.candidate_key_digest = [3; 32];
    op.successor.members[2] = member(3, 3);
    op.evidence.prepare = log(23);
    table
}

#[test]
fn supersession_is_durable_before_fence_but_never_rewinds_fence() {
    let table = superseded();
    table
        .validate_successor_of(&at_phase(VoterReplacementPhase::CaughtUp))
        .expect("pre-Fence supersession");
    assert_eq!(
        decode_voter_slot_table(&encode_voter_slot_table(&table).expect("encode")).expect("reopen"),
        table
    );
    assert!(table
        .validate_successor_of(&at_phase(VoterReplacementPhase::Fenced))
        .is_err());
    finalized()
        .validate_successor_of(&at_phase(VoterReplacementPhase::Uniform))
        .expect("finalize");
}

#[test]
fn terminal_receipt_for_an_incarnation_is_immutable_even_at_a_later_revision() {
    let old = finalized();
    let mut new = old.clone();
    new.revision += 1;
    let receipt = new.slots[2].last_result.as_mut().expect("receipt");
    receipt.revision += 1;
    receipt.request_digest[0] ^= 1;
    assert_eq!(
        new.validate_successor_of(&old),
        Err(VoterSlotError::Regression)
    );
}

#[test]
fn completed_incarnations_need_their_receipt_and_active_candidates_cannot_have_one() {
    let mut missing = finalized();
    missing.slots[2].last_result = None;
    assert!(encode_voter_slot_table(&missing).is_err());
    let mut premature = at_phase(VoterReplacementPhase::Uniform);
    let mut receipt = finalized().slots[2].last_result.clone().expect("receipt");
    receipt.request_id = ConsensusRequestId::from_bytes([42; 16]);
    receipt.revision = premature.revision;
    premature.slots[2].last_result = Some(receipt);
    assert!(encode_voter_slot_table(&premature).is_err());
}

#[test]
fn terminal_evidence_must_follow_all_locally_retained_phase_cuts() {
    let old = at_phase(VoterReplacementPhase::Fenced);
    let mut new = finalized();
    new.slots[2].last_result.as_mut().expect("receipt").terminal = log(11);
    assert_eq!(
        new.validate_successor_of(&old),
        Err(VoterSlotError::Regression)
    );
}

#[test]
fn continuation_cannot_claim_another_committed_entrys_index_or_a_conflicting_term() {
    let mut table = at_phase(VoterReplacementPhase::Fenced);
    table
        .replacement
        .as_mut()
        .expect("op")
        .evidence
        .continuation = Some(log(14));
    assert!(encode_voter_slot_table(&table).is_err());
    table
        .replacement
        .as_mut()
        .expect("op")
        .evidence
        .continuation = Some(VoterSlotLogId { term: 3, index: 13 });
    assert!(encode_voter_slot_table(&table).is_err());
    table
        .replacement
        .as_mut()
        .expect("op")
        .evidence
        .continuation = Some(log(15));
    assert!(encode_voter_slot_table(&table).is_ok());
}

#[test]
fn snapshot_artifact_binding_survives_reopen_and_cannot_be_replaced() {
    let table = at_phase(VoterReplacementPhase::SnapshotInstalled);
    let decoded =
        decode_voter_slot_table(&encode_voter_slot_table(&table).expect("encode")).expect("reopen");
    assert_eq!(
        decoded.replacement.as_ref().expect("op").evidence.snapshot,
        Some(snapshot(10))
    );
    let mut bad = table.clone();
    bad.revision += 1;
    bad.replacement
        .as_mut()
        .expect("op")
        .evidence
        .snapshot
        .as_mut()
        .expect("snapshot")
        .digest[0] ^= 1;
    assert_eq!(
        bad.validate_successor_of(&table),
        Err(VoterSlotError::Regression)
    );
    let mut bad = table.clone();
    bad.revision += 1;
    bad.replacement
        .as_mut()
        .expect("op")
        .evidence
        .snapshot
        .as_mut()
        .expect("snapshot")
        .snapshot_id
        .push('x');
    assert_eq!(
        bad.validate_successor_of(&table),
        Err(VoterSlotError::Regression)
    );
    for id in [
        String::new(),
        "x".repeat(MAX_VOTER_SNAPSHOT_ID_BYTES + 1),
        "snapshot\n".into(),
    ] {
        let mut bad = table.clone();
        bad.replacement
            .as_mut()
            .expect("op")
            .evidence
            .snapshot
            .as_mut()
            .expect("snapshot")
            .snapshot_id = id;
        assert!(encode_voter_slot_table(&bad).is_err());
    }
}

#[test]
fn largest_topology_and_fields_stay_bounded_and_reopen_canonically() {
    let mut table = at_phase(VoterReplacementPhase::Fenced);
    for slot in 4..=9 {
        table.slots.push(VoterSlotRecord {
            member: member(slot, 1),
            retired_through: 0,
            phase: VoterSlotPhase::Voting,
            last_result: None,
        });
        let op = table.replacement.as_mut().expect("op");
        op.predecessor.members.push(member(slot, 1));
        op.successor.members.push(member(slot, 1));
    }
    let op = table.replacement.as_mut().expect("op");
    let prefix = "spiffe://example.test/";
    op.attestation.candidate_spiffe_id = format!(
        "{prefix}{}",
        "c".repeat(MAX_VOTER_SPIFFE_ID_BYTES - prefix.len())
    );
    op.attestation.controller_spiffe_id = format!(
        "{prefix}{}",
        "a".repeat(MAX_VOTER_SPIFFE_ID_BYTES - prefix.len())
    );
    op.evidence.snapshot.as_mut().expect("snapshot").snapshot_id =
        "s".repeat(MAX_VOTER_SNAPSHOT_ID_BYTES);
    let bytes = encode_voter_slot_table(&table).expect("maximum fields");
    assert!(bytes.len() < MAX_VOTER_SLOT_TABLE_BYTES);
    assert_eq!(decode_voter_slot_table(&bytes).expect("decode"), table);
    table.slots.push(VoterSlotRecord {
        member: member(10, 1),
        retired_through: 0,
        phase: VoterSlotPhase::Voting,
        last_result: None,
    });
    assert!(encode_voter_slot_table(&table).is_err());
}

#[test]
fn altered_frames_either_refuse_or_have_exactly_one_canonical_encoding() {
    for table in [
        genesis(),
        at_phase(VoterReplacementPhase::Uniform),
        superseded(),
        finalized(),
    ] {
        let bytes = encode_voter_slot_table(&table).expect("frame");
        for index in 0..bytes.len() {
            for mask in [1, 0x80, 0xff] {
                let mut altered = bytes.clone();
                altered[index] ^= mask;
                if let Ok(decoded) = decode_voter_slot_table(&altered) {
                    assert_eq!(
                        encode_voter_slot_table(&decoded).expect("re-encode"),
                        altered,
                        "offset {index}"
                    );
                }
            }
        }
    }
}

#[test]
fn attestation_decode_checks_field_lengths_utf8_and_unknown_tags() {
    let bytes = encode_lost_voter_attestation(&attestation()).expect("encode");
    let mut bad = bytes.clone();
    bad[164..166].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        decode_lost_voter_attestation(&bad),
        Err(VoterSlotError::TooLarge)
    );
    let mut bad = bytes.clone();
    bad[166] = 0xff;
    assert_eq!(
        decode_lost_voter_attestation(&bad),
        Err(VoterSlotError::InvalidRecord)
    );
    let reason_offset = 164
        + 2
        + attestation().candidate_spiffe_id.len()
        + 2
        + attestation().controller_spiffe_id.len()
        + 32;
    let mut bad = bytes;
    bad[reason_offset] = 3;
    assert_eq!(
        decode_lost_voter_attestation(&bad),
        Err(VoterSlotError::InvalidRecord)
    );
}

#[test]
fn persisted_record_reopens_with_identical_retirement_and_operation_evidence() {
    use std::io::Write;
    let directory = std::env::temp_dir().join(format!("opc-voter-slots-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("private temporary directory");
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let path = directory.join("slot-record");
    let table = at_phase(VoterReplacementPhase::Fenced);
    let bytes = encode_voter_slot_table(&table).expect("encode");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .expect("record");
    file.write_all(&bytes).expect("write");
    file.sync_all().expect("sync");
    drop(file);
    let restored =
        decode_voter_slot_table(&std::fs::read(path).expect("read after close")).expect("reopen");
    assert_eq!(restored, table);
    assert_eq!(
        genesis().validate_successor_of(&restored),
        Err(VoterSlotError::Regression)
    );
    finalized()
        .validate_successor_of(&restored)
        .expect("complete after reopen");
}

#[test]
fn same_engine_entry_has_identical_evidence_on_every_replica() {
    use opc_consensus::engine::{CommittedLeaderId, LogId};
    let first = LogId::new(CommittedLeaderId::new(7, 1_u64), 42);
    let other = LogId::new(CommittedLeaderId::new(7, 2_u64), 42);
    assert_eq!(first, other);
    assert_eq!(
        VoterSlotLogId::from(first),
        VoterSlotLogId { term: 7, index: 42 }
    );
    assert_eq!(VoterSlotLogId::from(first), VoterSlotLogId::from(other));
}

#[test]
fn superseded_receipt_after_fence_is_refused_even_when_epoch_has_advanced() {
    let old = at_phase(VoterReplacementPhase::Fenced);
    let mut forged = superseded();
    forged.configuration_epoch = ConsensusConfigurationEpoch::new(2).expect("epoch");
    let operation = forged.replacement.as_mut().expect("op");
    operation.predecessor.epoch = forged.configuration_epoch;
    operation.successor.epoch = ConsensusConfigurationEpoch::new(3).expect("epoch");
    assert!(
        encode_voter_slot_table(&forged).is_ok(),
        "structurally valid adversarial history"
    );
    assert_eq!(
        forged.validate_successor_of(&old),
        Err(VoterSlotError::Regression)
    );
}

#[test]
fn prepared_evidence_has_a_fixed_term_index_only_vector() {
    let bytes = encode_voter_slot_table(&prepared()).expect("prepare");
    assert_eq!(
        &bytes[bytes.len() - 23..],
        &[
            0, 0, 0, 0, 0, 0, 0, 2, // term
            0, 0, 0, 0, 0, 0, 0, 10, // index
            0, 0, 0, 0, 0, 0, 0, // absent evidence
        ]
    );
}

#[test]
fn signing_input_and_request_digest_match_controller_vectors_without_self_digest() {
    use opc_consensus::{ConsensusConfigurationId, ConsensusIdentity};
    use sha2::{Digest, Sha256};
    let mut claims = attestation();
    let context = ConsensusIdentity::new(
        claims.cluster_instance,
        ConsensusConfigurationId::from_bytes([0xaa; 32]),
        ConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let candidate = member(3, 2);
    let input = lost_voter_attestation_signing_input(&claims).expect("signing input");
    assert!(input.starts_with(b"openpacketcore/consensus/lost-voter-attestation/v1\0"));
    assert_eq!(input.len(), 377);
    assert_eq!(
        Sha256::digest(&input)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "ed8b9a0bf06a4ca21a50ed4fa1374af8389db6145fe5ed023df5aac74f27f68b"
    );
    let digest = voter_replacement_request_digest(7, context, &candidate, &claims).expect("digest");
    assert_eq!(
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "68f1fd765070a078a0702d457f4eb10e566c9156ecd5459f9e906a8c2d3b6df2"
    );
    claims.signature = [0xff; 64];
    assert_eq!(
        lost_voter_attestation_signing_input(&claims).expect("signature excluded"),
        input
    );
    claims.request_digest = digest;
    assert_eq!(
        voter_replacement_request_digest(7, context, &candidate, &claims)
            .expect("no circular digest"),
        digest
    );
    assert_ne!(
        lost_voter_attestation_signing_input(&claims).expect("digest is signed"),
        input
    );
    assert_ne!(
        voter_replacement_request_digest(8, context, &candidate, &claims).expect("revision bound"),
        digest
    );
    let mut changed = candidate.clone();
    changed.descriptor_digest[0] ^= 1;
    assert_ne!(
        voter_replacement_request_digest(7, context, &changed, &claims).expect("descriptor bound"),
        digest
    );
    claims.policy_digest[0] ^= 1;
    assert_ne!(
        voter_replacement_request_digest(7, context, &candidate, &claims).expect("policy bound"),
        digest
    );
    assert!(voter_replacement_request_digest(0, context, &candidate, &claims).is_err());
    changed = candidate.clone();
    changed.key_digest[0] ^= 1;
    assert!(voter_replacement_request_digest(7, context, &changed, &claims).is_err());
    let other_cluster = ConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0xff; 32]),
        context.configuration_id(),
        context.configuration_epoch(),
    );
    assert!(voter_replacement_request_digest(7, other_cluster, &candidate, &claims).is_err());
}
