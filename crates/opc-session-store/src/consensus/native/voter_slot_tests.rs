use super::*;
use crate::sqlite::consensus::wal::Operation;
use bytes::Bytes;
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_consensus::voter_slots::*;
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch};

pub(crate) fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
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

pub(crate) fn genesis(size: u16) -> VoterSlotTable {
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

pub(crate) fn cut(index: u64) -> LogId<SessionConsensusNodeId> {
    LogId::new(
        CommittedLeaderId::new(2, member(1, 1).identity.node_id()),
        index,
    )
}

pub(crate) fn request(table: &VoterSlotTable, slot: u16) -> VoterReplacementRequest {
    let old = &table.slots[usize::from(slot - 1)].member;
    let candidate = member(slot, old.identity.incarnation().get() + 1);
    let expected_configuration = table
        .current_configuration()
        .identity(table.cluster_instance, table.manifest_digest)
        .unwrap();
    let mut attestation = LostVoterAttestationV1 {
        request_id: SessionConsensusRequestId::from_bytes([slot as u8; 16]),
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

pub(crate) fn command(
    table: &VoterSlotTable,
    index: u64,
    control: VoterSlotControl,
) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: cut(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: voter_slots::COMMAND_VERSION,
            identity: table
                .current_configuration()
                .identity(table.cluster_instance, table.manifest_digest)
                .unwrap(),
            request_id: SessionConsensusRequestId::from_bytes([index as u8; 16]),
            logical_time: Timestamp::now_utc(),
            intent: SessionMutationIntent::VoterSlotControl(control.encode().unwrap()),
        }),
    }
}

fn append(storage: &mut NativeStorage, entry: &Entry<SessionRaftTypeConfig>) {
    let bytes = Bytes::from(serde_json::to_vec(entry).unwrap());
    storage
        .log
        .project(&Operation::Append(vec![bytes]), &storage.business, None)
        .unwrap();
}

fn commit(storage: &mut NativeStorage, entry: &Entry<SessionRaftTypeConfig>) {
    storage
        .log
        .project(
            &Operation::Committed(Some(entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
    storage.replay_committed().unwrap();
}

#[test]
fn native_prepare_intent_and_permanent_floor_survive_strict_image_reopen() {
    for size in [3, 5, 9] {
        let initial = genesis(size);
        let identity = initial
            .current_configuration()
            .identity(initial.cluster_instance, initial.manifest_digest)
            .unwrap();
        let mut storage = NativeStorage::empty_with_voter_slots(initial.clone()).unwrap();
        let members = initial
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect::<BTreeSet<_>>();
        let formation = Entry {
            log_id: cut(0),
            payload: EntryPayload::Membership(Membership::new(vec![members.clone()], None)),
        };
        append(&mut storage, &formation);
        commit(&mut storage, &formation);
        let wanted = request(&initial, size);
        let prepare = command(
            &initial,
            1,
            VoterSlotControl::Begin(Box::new(wanted.clone())),
        );
        append(&mut storage, &prepare);
        let durable = storage.voter_slot_state().unwrap();
        assert_eq!(durable.table(), &initial);
        assert_eq!(durable.intent().unwrap().request, wanted);
        assert_eq!(
            durable.engine_fences(&members),
            BTreeSet::from([member(size, 1).identity.node_id()])
        );
        let mut image = Vec::new();
        storage.write_image(&mut image, [6; 32], 1).unwrap();
        let mut reopened =
            NativeStorage::read_image(&mut image.as_slice(), [6; 32], 1, identity).unwrap();
        assert_eq!(reopened.voter_slot_state().unwrap(), durable);
        commit(&mut reopened, &prepare);
        let published = reopened.voter_slot_state().unwrap();
        assert!(published.intent().is_none());
        assert!(published
            .table()
            .is_retired(member(size, 1).identity.node_id()));
        assert_eq!(
            reopened.business.frontiers.sequence, 0,
            "slot controls do not consume application receipts"
        );
        let mut image = Vec::new();
        reopened.write_image(&mut image, [6; 32], 2).unwrap();
        let recovered =
            NativeStorage::read_image(&mut image.as_slice(), [6; 32], 2, identity).unwrap();
        assert_eq!(recovered.voter_slot_state().unwrap(), published);
    }
}

#[test]
fn native_legacy_profile_cannot_accept_a_slot_control() {
    let initial = genesis(3);
    let identity = initial
        .current_configuration()
        .identity(initial.cluster_instance, initial.manifest_digest)
        .unwrap();
    let members = initial
        .current_configuration()
        .members
        .iter()
        .map(|member| member.identity.node_id())
        .collect();
    let mut storage = NativeStorage::empty(identity, members).unwrap();
    let prepare = command(
        &initial,
        0,
        VoterSlotControl::Begin(Box::new(request(&initial, 3))),
    );
    let bytes = Bytes::from(serde_json::to_vec(&prepare).unwrap());
    assert!(storage
        .log
        .project(&Operation::Append(vec![bytes]), &storage.business, None)
        .is_err());
    assert!(storage.log.last().is_none());
}

#[test]
fn native_slot_selected_generation_reopens_the_same_provisional_and_applied_gates() {
    use generation::{BaseParameters, Catalog, CatalogScope, PreparedBase, PreparedDelta, Version};
    const MAXIMUM: u64 = 16 * 1024 * 1024;
    for size in [3, 5, 9] {
        let initial = genesis(size);
        let mut storage = NativeStorage::empty_with_voter_slots(initial.clone()).unwrap();
        let identity = storage.business.identity;
        let members = storage.business.members.clone();
        let formation = Entry {
            log_id: cut(0),
            payload: EntryPayload::Membership(Membership::new(vec![members.clone()], None)),
        };
        append(&mut storage, &formation);
        commit(&mut storage, &formation);
        let prepare = command(
            &initial,
            1,
            VoterSlotControl::Begin(Box::new(request(&initial, size))),
        );
        append(&mut storage, &prepare);
        let expected = storage.voter_slot_state().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("slots.native");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        let base = PreparedBase::prepare(
            &storage,
            BaseParameters {
                binding: [6; 32],
                file_epoch: 1,
                checkpoint_epoch: 1,
                operation_sequence: 1,
                cut_binding: [7; 32],
                block_bytes: 64 * 1024,
                maximum: MAXIMUM,
            },
            &|| Ok(()),
        )
        .unwrap();
        let prefix = base.write_to(&mut file, &|| Ok(())).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let scope = || CatalogScope {
            identity,
            members: &members,
            roster_root: None,
        };
        let (mut owner, catalog) =
            Catalog::open(&path, prefix, MAXIMUM, scope(), [7; 32], &|| Ok(())).unwrap();
        let mut reopened = catalog.into_storage(&|| Ok(())).unwrap();
        assert_eq!(reopened.voter_slot_state().unwrap(), expected);
        assert!(reopened.log.entries.values().all(|entry| entry.is_cold()));
        let version = Version::capture(&reopened).unwrap();
        reopened.begin_changes().unwrap();
        commit(&mut reopened, &prepare);
        let applied = reopened.voter_slot_state().unwrap();
        assert!(applied.intent().is_none());
        let delta = PreparedDelta::prepare(
            owner.current(),
            &version,
            2,
            2,
            [8; 32],
            reopened.take_changes().unwrap(),
            &|| Ok(()),
        )
        .unwrap();
        let (selected, _) = delta
            .append_with_relocations(&mut owner, &|| Ok(()))
            .unwrap();
        drop(owner);
        let (_, catalog) = Catalog::open(
            &path,
            selected.identity(),
            MAXIMUM,
            scope(),
            [8; 32],
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(
            catalog
                .into_storage(&|| Ok(()))
                .unwrap()
                .voter_slot_state()
                .unwrap(),
            applied
        );
    }
}

#[test]
fn native_slot_intent_cannot_be_missing_displaced_or_smuggled_into_an_old_format() {
    let initial = genesis(3);
    let mut storage = NativeStorage::empty_with_voter_slots(initial.clone()).unwrap();
    let formation = Entry {
        log_id: cut(0),
        payload: EntryPayload::Membership(Membership::new(
            vec![storage.business.members.clone()],
            None,
        )),
    };
    append(&mut storage, &formation);
    commit(&mut storage, &formation);
    let prepare = command(
        &initial,
        1,
        VoterSlotControl::Begin(Box::new(request(&initial, 3))),
    );
    append(&mut storage, &prepare);
    let mut missing = storage.clone();
    missing.log.slot_intent = None;
    assert!(missing.validate_image().is_err());
    let mut displaced = storage.clone();
    let blank = Entry {
        log_id: cut(1),
        payload: EntryPayload::Blank,
    };
    displaced.log.entries.insert(
        1,
        SharedRow::new(log::NativeLogEntry::new_with_profile(
            serde_json::to_vec(&blank).unwrap().into(),
            blank,
            true,
        ))
        .unwrap(),
    );
    assert!(displaced.validate_image().is_err());
    let mut image = Vec::new();
    storage.write_image(&mut image, [6; 32], 1).unwrap();
    assert_eq!(&image[..8], b"OPCNAT05");
    image[..8].copy_from_slice(b"OPCNAT04");
    assert!(NativeStorage::read_image(
        &mut image.as_slice(),
        [6; 32],
        1,
        storage.business.identity
    )
    .is_err());
    storage
        .log
        .project(&Operation::Truncate(cut(1)), &storage.business, None)
        .unwrap();
    assert!(storage.voter_slot_state().unwrap().intent().is_none());
    assert!(storage
        .voter_slot_state()
        .unwrap()
        .engine_fences(&storage.business.members)
        .is_empty());
}

#[path = "voter_slot_memory_tests.rs"]
mod memory_tests;

#[test]
fn native_voter_profile_refuses_scope_continuation_and_preserves_main_wire_tags() {
    use crate::scope_authority::{ScopeProfileActivation, ScopeProfileContinuation};
    use crate::scope_batch::{ScopeBatchCancelCommand, ScopeBatchError, ScopeBatchRequest};
    let initial = genesis(3);
    let mut storage = NativeStorage::empty_with_voter_slots(initial.clone()).unwrap();
    let identity = storage.business.identity;
    let members = storage.business.members.clone();
    let formation = Entry {
        log_id: cut(0),
        payload: EntryPayload::Membership(Membership::new(vec![members.clone()], None)),
    };
    append(&mut storage, &formation);
    commit(&mut storage, &formation);
    let mut successor = initial.clone();
    successor.configuration_epoch = ConsensusConfigurationEpoch::new(2).unwrap();
    successor.slots[2].member = member(3, 2);
    let next_identity = successor
        .current_configuration()
        .identity(successor.cluster_instance, successor.manifest_digest)
        .unwrap();
    let next_members = successor
        .slots
        .iter()
        .map(|slot| slot.member.identity.node_id())
        .collect();
    let certificate = ScopeProfileContinuation {
        transition_id: [0x11; 16],
        transition_digest: [0x12; 32],
        predecessor: ScopeProfileActivation::new(
            identity,
            crate::consensus::types::fenced_transition_voter_set_digest(identity, &members),
        ),
        successor: ScopeProfileActivation::new(
            next_identity,
            crate::consensus::types::fenced_transition_voter_set_digest(
                next_identity,
                &next_members,
            ),
        ),
    };
    certificate.validate().unwrap();
    let intent = SessionMutationIntent::CertifyScopeProfileContinuation(Box::new(certificate));
    let authority = crate::scope_authority::tests::admitted();
    let batch = ScopeBatchRequest::new(
        authority.view.stamp().unwrap(),
        [1; 16],
        0,
        vec![crate::scope_batch::tests::create(1, &[])],
        vec![],
    )
    .unwrap();
    let cancel = SessionMutationIntent::ScopeBatchCancel(Box::new(ScopeBatchCancelCommand {
        attempt: batch.attempt().unwrap(),
    }));
    for (tag, value) in [
        (39, intent.clone()),
        (40, cancel),
        (41, SessionMutationIntent::VoterSlotControl(vec![1])),
    ] {
        let bytes = postcard::to_allocvec(&value).unwrap();
        assert_eq!(
            bytes[0], tag,
            "published intent discriminants must stay stable"
        );
        assert_eq!(
            postcard::from_bytes::<SessionMutationIntent>(&bytes).unwrap(),
            value
        );
    }
    for (tag, value) in [
        (
            11,
            SessionMutationOutcome::ScopeBatch(Err(ScopeBatchError::InvalidRequest)),
        ),
        (
            12,
            SessionMutationOutcome::ScopeBatchCancel(Err(ScopeBatchError::InvalidRequest)),
        ),
        (13, SessionMutationOutcome::VoterSlotControl(Ok(()))),
    ] {
        let bytes = postcard::to_allocvec(&value).unwrap();
        assert_eq!(
            bytes[0], tag,
            "published outcome discriminants must stay stable"
        );
        assert_eq!(
            postcard::from_bytes::<SessionMutationOutcome>(&bytes).unwrap(),
            value
        );
    }
    let mut entry = command(
        &initial,
        1,
        VoterSlotControl::Marker {
            request_id: SessionConsensusRequestId::from_bytes([1; 16]),
            request_digest: [1; 32],
        },
    );
    if let EntryPayload::Normal(command) = &mut entry.payload {
        command.schema_version = crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION;
        command.intent = intent;
    }
    let before = storage.voter_slot_state().unwrap();
    let bytes = Bytes::from(serde_json::to_vec(&entry).unwrap());
    assert!(
        storage
            .log
            .project(&Operation::Append(vec![bytes]), &storage.business, None)
            .is_err(),
        "the voter profile cannot admit scope continuity before its activation slice"
    );
    assert_eq!(storage.voter_slot_state().unwrap(), before);
    assert_eq!(storage.log.last(), Some(cut(0)));
    storage.validate_image().unwrap();
}
