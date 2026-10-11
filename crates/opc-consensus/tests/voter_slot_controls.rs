use std::collections::BTreeSet;

use opc_consensus::voter_slots::*;
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusNodeId, ConsensusRequestId,
};

fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
    VoterSlotMember {
        identity: VoterSlotIdentity::new(
            SlotId::new(slot).unwrap(),
            VoterIncarnation::new(incarnation).unwrap(),
        ),
        key_digest: [incarnation as u8; 32],
        descriptor_digest: [slot as u8; 32],
        admission_generation: incarnation,
    }
}

fn genesis(size: u16) -> VoterSlotTable {
    VoterSlotTable {
        cluster_instance: ConsensusClusterId::from_bytes([3; 32]),
        manifest_digest: [4; 32],
        revision: 1,
        configuration_epoch: ConsensusConfigurationEpoch::new(1).unwrap(),
        slots: (1..=size)
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

fn cut(index: u64) -> VoterSlotLogId {
    VoterSlotLogId { term: 2, index }
}

#[test]
fn genesis_membership_can_publish_the_engines_term_zero_cut() {
    let initial = genesis(3);
    let mut state = VoterSlotDurableState::new(initial.clone()).unwrap();
    state
        .publish_applied(initial, VoterSlotLogId { term: 0, index: 0 })
        .unwrap();
    assert!(state.intent().is_none());
}

fn request(table: &VoterSlotTable, slot: u16, id: u8) -> VoterReplacementRequest {
    let old = &table.slots[usize::from(slot - 1)].member;
    let candidate = member(slot, old.identity.incarnation().get() + 1);
    let mut attestation = LostVoterAttestationV1 {
        request_id: ConsensusRequestId::from_bytes([id; 16]),
        request_digest: [0; 32],
        cluster_instance: table.cluster_instance,
        slot: old.identity.slot(),
        expected_incarnation: old.identity.incarnation(),
        old_descriptor_digest: old.descriptor_digest,
        candidate_key_digest: candidate.key_digest,
        admission_generation: candidate.admission_generation,
        candidate_spiffe_id: format!("spiffe://example.test/voter/{slot}"),
        controller_spiffe_id: "spiffe://example.test/controller".into(),
        signing_key_digest: [7; 32],
        reason: VoterLossReason::TimeBoundLoss,
        policy_digest: [8; 32],
        observation_start_ms: 100,
        decision_ms: 200,
        issued_ms: 200,
        expires_ms: 300,
        signature: [9; 64],
    };
    let expected_configuration = table
        .current_configuration()
        .identity(table.cluster_instance, table.manifest_digest)
        .unwrap();
    attestation.request_digest = voter_replacement_request_digest(
        table.revision,
        expected_configuration,
        &candidate,
        &attestation,
    )
    .unwrap();
    VoterReplacementRequest {
        expected_revision: table.revision,
        expected_configuration,
        candidate,
        attestation,
    }
}

fn ids(members: &[VoterSlotMember]) -> BTreeSet<ConsensusNodeId> {
    members
        .iter()
        .map(|member| member.identity.node_id())
        .collect()
}

fn prepare(table: &mut VoterSlotTable, request: &VoterReplacementRequest, index: u64) {
    table
        .apply_control(
            &VoterSlotControl::Begin(Box::new(request.clone())),
            cut(index),
        )
        .unwrap();
}

fn command(request: &VoterReplacementRequest, step: VoterReplacementStep) -> VoterSlotControl {
    VoterSlotControl::Advance {
        request_id: request.attestation.request_id,
        request_digest: request.attestation.request_digest,
        step,
    }
}

fn caught_up(
    table: &mut VoterSlotTable,
    request: &VoterReplacementRequest,
) -> (BTreeSet<ConsensusNodeId>, BTreeSet<ConsensusNodeId>) {
    table
        .apply_control(
            &command(
                request,
                VoterReplacementStep::RecordSnapshot(VoterSnapshotEvidence {
                    cut: cut(10),
                    snapshot_id: "installed-10".into(),
                    digest: [0x55; 32],
                }),
            ),
            cut(11),
        )
        .unwrap();
    let operation = table.replacement.as_ref().unwrap();
    let old = ids(&operation.predecessor.members);
    let new = ids(&operation.successor.members);
    let nodes = old.union(&new).copied().collect();
    table
        .observe_membership(std::slice::from_ref(&old), &nodes, cut(12))
        .unwrap();
    table
        .apply_control(
            &command(request, VoterReplacementStep::RecordCaughtUp(cut(13))),
            cut(14),
        )
        .unwrap();
    (old, new)
}

#[test]
fn prepare_is_atomic_idempotent_and_reserves_only_one_slot() {
    let mut table = genesis(3);
    let wanted = request(&table, 3, 1);
    let other = request(&table, 2, 2);
    prepare(&mut table, &wanted, 10);
    assert_eq!(table.slots[2].retired_through, 1);
    assert_eq!(table.slots[2].member.identity, member(3, 2).identity);
    assert_eq!(table.slots[2].phase, VoterSlotPhase::Pending);
    let prepared = table.clone();
    prepare(&mut table, &wanted, 11);
    assert_eq!(
        table, prepared,
        "exact retries retain their original Prepare cut"
    );
    assert_eq!(
        table.apply_control(&VoterSlotControl::Begin(Box::new(other)), cut(12)),
        Err(VoterReplacementError::ReplacementInProgress)
    );
    assert_eq!(table, prepared);
    let mut changed = wanted.clone();
    changed.attestation.request_digest[0] ^= 1;
    assert_eq!(
        table.apply_control(&VoterSlotControl::Begin(Box::new(changed)), cut(13)),
        Err(VoterReplacementError::IdempotencyConflict)
    );
    assert_eq!(table, prepared);
}

#[test]
fn fixed_shapes_keep_both_original_denominators_and_require_applied_fence() {
    for size in [3, 5, 7, 9] {
        let mut table = genesis(size);
        let wanted = request(&table, size, 1);
        prepare(&mut table, &wanted, 10);
        let (old, new) = caught_up(&mut table, &wanted);
        let union = old.union(&new).copied().collect();
        let before = table.clone();
        assert!(table
            .observe_membership(&[old.clone(), new.clone()], &union, cut(15))
            .is_err());
        assert_eq!(table, before);
        table
            .apply_control(&command(&wanted, VoterReplacementStep::Fence), cut(16))
            .unwrap();
        let fenced = table.clone();
        assert!(
            table
                .observe_membership(std::slice::from_ref(&new), &new, cut(17))
                .is_err(),
            "no smaller or direct uniform configuration"
        );
        assert_eq!(table, fenced);
        table
            .observe_membership(&[old.clone(), new.clone()], &union, cut(18))
            .unwrap();
        assert_eq!(
            table.replacement.as_ref().unwrap().phase,
            VoterReplacementPhase::Joint
        );
        assert_eq!(old.len(), usize::from(size));
        assert_eq!(new.len(), usize::from(size));
        assert!(old.intersection(&new).count() >= usize::from(size / 2 + 1));
        table
            .observe_membership(std::slice::from_ref(&new), &new, cut(20))
            .unwrap();
        table
            .apply_control(&command(&wanted, VoterReplacementStep::Finalize), cut(21))
            .unwrap();
        assert!(table.replacement.is_none());
        assert_eq!(
            table.current_configuration().members.len(),
            usize::from(size)
        );
        assert_eq!(table.slots[usize::from(size - 1)].retired_through, 1);
        assert_eq!(
            table.slots[usize::from(size - 1)]
                .last_result
                .as_ref()
                .unwrap()
                .kind,
            VoterReplacementResultKind::Completed
        );
    }
}

#[test]
fn successor_leader_must_refresh_the_candidate_marker_before_fence() {
    let mut table = genesis(3);
    let wanted = request(&table, 3, 1);
    prepare(&mut table, &wanted, 10);
    caught_up(&mut table, &wanted);
    assert_eq!(
        table.apply_control(
            &command(&wanted, VoterReplacementStep::Fence),
            VoterSlotLogId { term: 3, index: 15 }
        ),
        Err(VoterReplacementError::InvalidTransition)
    );
    let marker = VoterSlotControl::Marker {
        request_id: wanted.attestation.request_id,
        request_digest: wanted.attestation.request_digest,
    };
    let before = table.clone();
    table
        .apply_control(&marker, VoterSlotLogId { term: 3, index: 16 })
        .unwrap();
    assert_eq!(table, before);
    table
        .apply_control(
            &command(
                &wanted,
                VoterReplacementStep::RecordCaughtUp(VoterSlotLogId { term: 3, index: 16 }),
            ),
            VoterSlotLogId { term: 3, index: 17 },
        )
        .unwrap();
    table
        .apply_control(
            &command(&wanted, VoterReplacementStep::Fence),
            VoterSlotLogId { term: 3, index: 18 },
        )
        .unwrap();
    assert!(table
        .apply_control(&marker, VoterSlotLogId { term: 3, index: 19 })
        .is_err());
}

#[test]
fn snapshot_record_is_immutable_and_fence_forbids_supersession() {
    let mut table = genesis(3);
    let wanted = request(&table, 3, 1);
    prepare(&mut table, &wanted, 10);
    caught_up(&mut table, &wanted);
    let caught = table.clone();
    assert!(table
        .apply_control(
            &command(
                &wanted,
                VoterReplacementStep::RecordSnapshot(VoterSnapshotEvidence {
                    cut: cut(11),
                    snapshot_id: "different".into(),
                    digest: [0x66; 32],
                })
            ),
            cut(15)
        )
        .is_err());
    assert_eq!(table, caught);
    let supersede = request(&table, 3, 2);
    let mut before_fence = table.clone();
    prepare(&mut before_fence, &supersede, 15);
    assert_eq!(before_fence.slots[2].retired_through, 2);
    assert_eq!(
        before_fence.slots[2].last_result.as_ref().unwrap().kind,
        VoterReplacementResultKind::Superseded
    );
    assert_eq!(
        before_fence
            .replacement
            .as_ref()
            .unwrap()
            .predecessor
            .members[2]
            .identity,
        member(3, 1).identity
    );
    table
        .apply_control(&command(&wanted, VoterReplacementStep::Fence), cut(16))
        .unwrap();
    let fenced = table.clone();
    assert_eq!(
        table.apply_control(&VoterSlotControl::Begin(Box::new(supersede)), cut(17)),
        Err(VoterReplacementError::ReplacementPastFence)
    );
    assert_eq!(table, fenced);
}

#[test]
fn supersession_keeps_one_retired_learner_only_until_engine_cleanup() {
    let mut table = genesis(3);
    let wanted = request(&table, 3, 1);
    prepare(&mut table, &wanted, 10);
    let (old, new) = caught_up(&mut table, &wanted);
    let obsolete = old.union(&new).copied().collect::<BTreeSet<_>>();
    let replacement = request(&table, 3, 2);
    prepare(&mut table, &replacement, 15);
    let before = table.clone();
    table
        .observe_membership(std::slice::from_ref(&old), &obsolete, cut(12))
        .unwrap();
    assert_eq!(
        table, before,
        "the retained obsolete learner grants no progress to its successor"
    );
    table
        .observe_membership(std::slice::from_ref(&old), &old, cut(16))
        .unwrap();
    assert_eq!(
        table, before,
        "Openraft removes the obsolete learner without changing C0"
    );
    let mut unknown = obsolete.clone();
    unknown.insert(member(2, 2).identity.node_id());
    assert!(table
        .observe_membership(std::slice::from_ref(&old), &unknown, cut(17))
        .is_err());
    unknown = obsolete;
    unknown.insert(member(3, 3).identity.node_id());
    assert!(table
        .observe_membership(std::slice::from_ref(&old), &unknown, cut(17))
        .is_err());
    let third = request(&table, 3, 3);
    prepare(&mut table, &third, 18);
    unknown.remove(&member(3, 3).identity.node_id());
    table
        .observe_membership(std::slice::from_ref(&old), &unknown, cut(12))
        .unwrap();
}

#[test]
fn restart_reinstalls_only_retired_effective_members_and_provisional_intents() {
    let mut table = genesis(3);
    let wanted = request(&table, 3, 1);
    let mut state = VoterSlotDurableState::new(table.clone()).unwrap();
    let intent = VoterSlotIntent {
        log_id: cut(10),
        request: wanted.clone(),
    };
    state.append_intent(intent.clone()).unwrap();
    let duplicate = state.clone();
    state.append_intent(intent).unwrap();
    assert_eq!(state, duplicate);
    let other = VoterSlotIntent {
        log_id: cut(11),
        request: request(&table, 2, 2),
    };
    assert_eq!(
        state.append_intent(other),
        Err(VoterReplacementError::ReplacementInProgress)
    );
    let empty = BTreeSet::new();
    assert_eq!(
        state.engine_fences(&empty),
        BTreeSet::from([member(3, 1).identity.node_id()])
    );
    let encoded = state.encode().unwrap();
    let mut reopened = VoterSlotDurableState::decode(&encoded).unwrap();
    assert_eq!(reopened, state);
    reopened.truncate_from(10);
    assert!(reopened.engine_fences(&empty).is_empty());
    prepare(&mut table, &wanted, 10);
    state.publish_applied(table.clone(), cut(10)).unwrap();
    assert!(state.intent().is_none());
    assert!(
        state.engine_fences(&empty).is_empty(),
        "historical floors do not recreate unnecessary core fence state"
    );
    let membership = BTreeSet::from([
        member(1, 1).identity.node_id(),
        member(2, 1).identity.node_id(),
        member(3, 1).identity.node_id(),
    ]);
    assert_eq!(
        state.engine_fences(&membership),
        BTreeSet::from([member(3, 1).identity.node_id()])
    );
    state.truncate_from(10);
    assert_eq!(
        state.table(),
        &table,
        "truncation cannot undo an applied retirement"
    );
}

#[test]
fn snapshot_below_intent_keeps_it_and_snapshot_past_intent_resolves_it() {
    let original = genesis(3);
    let wanted = request(&original, 3, 1);
    let mut state = VoterSlotDurableState::new(original.clone()).unwrap();
    state
        .append_intent(VoterSlotIntent {
            log_id: cut(10),
            request: wanted.clone(),
        })
        .unwrap();
    state.publish_snapshot(original.clone(), cut(9)).unwrap();
    assert!(state.intent().is_some());
    let mut displaced = state.clone();
    displaced
        .publish_snapshot(original.clone(), cut(12))
        .unwrap();
    assert!(displaced.intent().is_none());
    assert_eq!(displaced.table(), &original);
    let mut committed = original;
    prepare(&mut committed, &wanted, 10);
    state.publish_snapshot(committed.clone(), cut(12)).unwrap();
    assert!(state.intent().is_none());
    assert_eq!(state.table(), &committed);
    assert!(state.publish_snapshot(genesis(3), cut(13)).is_err());
}

#[test]
fn earlier_apply_cannot_erase_a_durable_intent_that_will_lose_its_cas() {
    let mut table = genesis(3);
    let wanted = request(&table, 3, 1);
    prepare(&mut table, &wanted, 10);
    caught_up(&mut table, &wanted);
    let supersede = request(&table, 3, 2);
    let mut state = VoterSlotDurableState::new(table.clone()).unwrap();
    state
        .append_intent(VoterSlotIntent {
            log_id: cut(17),
            request: supersede.clone(),
        })
        .unwrap();
    table
        .apply_control(&command(&wanted, VoterReplacementStep::Fence), cut(16))
        .unwrap();
    state.publish_applied(table.clone(), cut(16)).unwrap();
    let mut reopened = VoterSlotDurableState::decode(&state.encode().unwrap()).unwrap();
    assert!(
        reopened.intent().is_some(),
        "an earlier apply does not resolve the pending intent"
    );
    assert_eq!(
        table.apply_control(&VoterSlotControl::Begin(Box::new(supersede)), cut(17)),
        Err(VoterReplacementError::ReplacementPastFence)
    );
    reopened.publish_applied(table.clone(), cut(17)).unwrap();
    assert!(reopened.intent().is_none());
    assert_eq!(reopened.table(), &table);
}
