use super::super::tests::{
    initialize_protected_roster_v2_recovery_fixture, ProtectedRosterV2RecoveryFixtureState,
};
use super::*;
use crate::fenced_mutation_roster::{
    AdmissionProposal, EstablishedMutation, RosterAttestationCertificateRoleV1,
    RosterAttestationLeafCertificatePartsV1, RosterAttestationLeafCertificateV1,
    RosterCompactAdmissionProvenanceSigningInputV2, RosterIngressAttestationSigningInputV1,
    RosterIngressAttestationV1,
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

fn sign(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
    let signature: Signature = key.sign_prehash(&digest).unwrap();
    signature.normalize_s().to_bytes().into()
}

/// This fixture signs the actual V1 capsule and provenance under the same
/// configured root as the SQL-created predecessor. Wire-shape-only fixtures
/// with placeholder capsule/proof digests cannot exercise native admission.
pub(crate) fn signed_v1_command(
    signed: &crate::consensus::types::RosterV2PersistenceFixture,
) -> ConsensusRosterAdmissionCommand {
    signed_v1_command_with_mutation(signed, EstablishedMutation::no_op())
}

pub(crate) fn signed_v1_command_with_mutation(
    signed: &crate::consensus::types::RosterV2PersistenceFixture,
    mutation: EstablishedMutation,
) -> ConsensusRosterAdmissionCommand {
    let admission = Admission::authenticate(
        AdmissionProposal::new(
            crate::fenced_mutation_roster::Profile::v1(),
            RosterId::from_bytes([0xB1; 16]).unwrap(),
            signed.admission.members().to_vec(),
            mutation,
            vec![0xB2],
            vec![0xB3],
            vec![0xB4],
        )
        .unwrap(),
        signed.admission.key().clone(),
        signed.admission.scope(),
        signed.authority.owner().clone(),
        signed.authority.fence(),
        signed.authority.generation(),
    )
    .unwrap();
    let root_key = SigningKey::from_bytes((&[0x96; 32]).into()).unwrap();
    let ingress_key = SigningKey::from_bytes((&[0x97; 32]).into()).unwrap();
    let input = RosterIngressAttestationSigningInputV1 {
        peer_identity_commitment: [0xB5; 32],
        consumer_scope: admission.scope().digest(),
        request_id: [0xB6; 16],
        operation_tag: 1,
        canonical_capsule_digest: roster_poll_admit_ingress_capsule_commitment(
            &admission,
            &signed.authority,
        )
        .unwrap(),
        authenticated_at: signed.authority.acquired_at().add_seconds(1).unwrap(),
        peer_certificate_expires_at: signed.authority.expires_at(),
        material_generation: 1,
        handshake_epoch: 1,
    };
    let mut certificate = RosterAttestationLeafCertificatePartsV1 {
        root_id: signed.root.root_id(),
        role: RosterAttestationCertificateRoleV1::TransportIngress,
        configuration_identity: signed.identity,
        scope: admission.scope().digest(),
        subject_identity_commitment: input.peer_identity_commitment,
        leaf_epoch: 1,
        key_id: [0xB7; 32],
        not_before: signed.authority.acquired_at(),
        not_after: signed.authority.expires_at(),
        public_key: ingress_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
        root_signature: [0; 64],
    };
    certificate.root_signature = sign(
        &root_key,
        RosterAttestationLeafCertificateV1::signing_digest(&certificate).unwrap(),
    );
    let ingress = RosterIngressAttestationV1::issue_from_signed_parts(
        &signed.root,
        certificate.clone(),
        &input,
        sign(&ingress_key, input.digest().unwrap()),
    )
    .unwrap();
    let provenance_input = RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
        signed.identity,
        &admission,
        &signed.authority,
        ingress.signing_input(),
        input.peer_identity_commitment,
    )
    .unwrap();
    let provenance = RosterCompactAdmissionProvenanceV2::issue_from_signed_parts(
        &signed.root,
        certificate,
        &provenance_input,
        sign(&ingress_key, provenance_input.digest().unwrap()),
    )
    .unwrap();
    ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id(
        admission,
        signed.authority.clone(),
        input.request_id,
        ingress,
        provenance,
    )
    .unwrap()
}

fn fixture(
    state: ProtectedRosterV2RecoveryFixtureState,
) -> (
    tempfile::TempDir,
    SqliteSessionBackend,
    crate::consensus::types::RosterV2PersistenceFixture,
) {
    let signed = match &state {
        ProtectedRosterV2RecoveryFixtureState::Aborted => {
            crate::consensus::types::roster_v2_aborted_persistence_fixture()
        }
        _ => crate::consensus::types::roster_v2_persistence_fixture(),
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native-roster-row.sqlite");
    initialize_protected_roster_v2_recovery_fixture(&path, state)
        .unwrap_or_else(|_| panic!("sealed SQL fixture must apply"));
    let backend = SqliteSessionBackend::open(&path).unwrap();
    (directory, backend, signed)
}

fn projection(signed: &crate::consensus::types::RosterV2PersistenceFixture) -> Projection {
    let command = ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
        signed.admission.clone(),
        signed.authority.clone(),
        signed.admission_ingress.request_id(),
        signed.admission_ingress.clone(),
        signed.admission_provenance.clone(),
    )
    .unwrap();
    Projection::from_admission(signed.admission.binding_key(1).unwrap(), &command)
        .unwrap_or_else(|_| panic!("exact original admission projection"))
}

fn canonical(
    conn: &Connection,
    signed: &crate::consensus::types::RosterV2PersistenceFixture,
    projection: &Projection,
) -> Vec<u8> {
    let (bytes,stable,admission_id,terminal_id): (Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>) = conn.query_row(
        "SELECT canonical_record,stable_slot,admission_request_id,terminal_request_id FROM consensus_protected_roster_v2_admissions WHERE binding=?1",
        [signed.admission.binding_key(1).unwrap().to_bytes().as_slice()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).unwrap();
    assert_eq!(stable, projection.stable_slot);
    assert_eq!(admission_id, projection.request_ids()[0]);
    assert_eq!(terminal_id, projection.request_ids()[1]);
    bytes
}

fn checked(
    projection: Projection,
    binding: RequestBindingKey,
    canonical: Vec<u8>,
    root: &RosterAttestationTrustRootV1,
    scope: &MembershipValidationScope,
) -> Hydration {
    hydrate(projection, binding, canonical, root, scope)
        .unwrap_or_else(|_| panic!("original signed carrier must authenticate"))
}

#[test]
fn native_roster_v2_carriers_preserve_signed_lifecycle_and_immutable_projection() {
    for state in [
        ProtectedRosterV2RecoveryFixtureState::Live,
        ProtectedRosterV2RecoveryFixtureState::Established,
        ProtectedRosterV2RecoveryFixtureState::Aborted,
    ] {
        let (_directory, backend, signed) = fixture(state);
        let conn = backend.conn.blocking_lock();
        let projection = projection(&signed);
        let scope = read_membership_scope_sync(&conn, signed.identity).unwrap();
        let binding = signed.admission.binding_key(1).unwrap();
        let first = canonical(&conn, &signed, &projection);
        let initial = checked(
            projection.clone(),
            binding,
            first.clone(),
            &signed.root,
            &scope,
        );
        let was_live = initial.facts.state == State::Live;
        assert_eq!(initial.canonical(), first);
        assert!(initial.projection == projection);
        let (body, memory) = initial.into_parts();
        assert!(matches!(body, Body::V2(_)));
        drop(body);
        drop(memory);
        let steps = if was_live { 1 } else { 2 };
        for step in 0..steps {
            if step == 1 {
                let now = read_machine_sync(&conn, signed.identity)
                    .unwrap()
                    .2
                    .unwrap();
                reclaim_protected_rosters_sync(
                    &conn,
                    signed.identity,
                    now.add_seconds(24 * 60 * 60).unwrap(),
                )
                .unwrap();
                validate_protected_roster_state_sync(&conn, signed.identity)
                    .unwrap_or_else(|_| panic!("original SQL compact-row scanner"));
            }
            let bytes = canonical(&conn, &signed, &projection);
            let row = checked(
                projection.clone(),
                binding,
                bytes.clone(),
                &signed.root,
                &scope,
            );
            assert!(
                row.facts.state
                    == if was_live {
                        State::Live
                    } else if step == 0 {
                        State::Retained
                    } else {
                        State::Tombstone
                    }
            );
            assert_eq!(row.canonical(), bytes);
            assert_eq!(
                row.facts.terminal_raft_log_index,
                if was_live { None } else { Some(2) }
            );
            assert_eq!(
                row.facts.terminal_sequence,
                if was_live { None } else { Some(2) }
            );
            drop(row);
            for field in 0..9 {
                let mut changed = projection.clone();
                match field {
                    0 => changed.profile = Profile::V1,
                    1 => changed.stable_slot[0] ^= 1,
                    2 => changed.terminal_slot[0] ^= 1,
                    3 => changed.original.owner = OwnerId::new("native-other-owner").unwrap(),
                    4 => changed.original.fence += 1,
                    5 => changed.original.credential_id += 1,
                    6 => changed.original.generation += 1,
                    7 => {
                        changed.original.acquired_at =
                            changed.original.acquired_at.add_seconds(1).unwrap()
                    }
                    8 => {
                        changed.original.expires_at =
                            changed.original.expires_at.add_seconds(1).unwrap()
                    }
                    _ => unreachable!(),
                }
                assert!(
                    hydrate(changed, binding, bytes.clone(), &signed.root, &scope).is_err(),
                    "immutable projection field {field}"
                );
            }
            let mut damaged = bytes.clone();
            damaged[0] ^= 1;
            assert!(hydrate(projection.clone(), binding, damaged, &signed.root, &scope).is_err());
            let mut foreign = binding.to_bytes();
            foreign[0] ^= 1;
            assert!(hydrate(
                projection.clone(),
                RequestBindingKey::from_bytes(foreign).unwrap(),
                bytes.clone(),
                &signed.root,
                &scope
            )
            .is_err());
            let mut foreign_scope = scope.clone();
            foreign_scope.current_identity = SessionConsensusIdentity::new(
                signed.identity.cluster_id(),
                SessionConsensusConfigurationId::from_bytes([0xBA; 32]),
                signed.identity.configuration_epoch(),
            );
            assert!(hydrate(
                projection.clone(),
                binding,
                bytes.clone(),
                &signed.root,
                &foreign_scope
            )
            .is_err());
            assert!(hydrate(
                projection.clone(),
                binding,
                Vec::new(),
                &signed.root,
                &scope
            )
            .is_err());
            let mut trailing = bytes;
            trailing.push(0);
            assert!(hydrate(projection.clone(), binding, trailing, &signed.root, &scope).is_err());
        }
    }
}

#[test]
fn native_roster_v2_rows_require_business_partition_and_global_history_proofs() {
    let (_created_dir, created_backend, created_signed) =
        fixture(ProtectedRosterV2RecoveryFixtureState::Established);
    let created = ops::get_raw_sync(
        &created_backend.conn.blocking_lock(),
        created_signed.admission.key(),
    )
    .unwrap()
    .unwrap();
    for state in [
        ProtectedRosterV2RecoveryFixtureState::Live,
        ProtectedRosterV2RecoveryFixtureState::Established,
    ] {
        let (_directory, backend, signed) = fixture(state);
        let conn = backend.conn.blocking_lock();
        let projection = projection(&signed);
        let scope = read_membership_scope_sync(&conn, signed.identity).unwrap();
        let binding = signed.admission.binding_key(1).unwrap();
        let row = checked(
            projection.clone(),
            binding,
            canonical(&conn, &signed, &projection),
            &signed.root,
            &scope,
        );
        let live = row.facts.state == State::Live;
        assert!(row.validate_business(None).is_ok());
        assert_eq!(row.validate_business(Some(&created)).is_err(), live);
        assert_eq!(row.reserved_key().is_some(), live);
        if live {
            assert_eq!(row.reserved_key(), Some(signed.admission.key()));
        }
        let key = ProductionFloorKey::from_binding(binding).unwrap();
        let floor = protected_roster_read_floor_sync(&conn, signed.identity, key)
            .unwrap_or_else(|_| panic!("floor"))
            .unwrap();
        let witness = protected_roster_read_witness_sync(&conn, signed.identity)
            .unwrap_or_else(|_| panic!("witness"))
            .unwrap();
        row.validate_partition(floor, None)
            .unwrap_or_else(|_| panic!("exact shared floor"));
        let mut foreign = binding.to_bytes();
        foreign[8] ^= 1;
        let foreign_floor =
            IrreversibleHistoryFloor::initial(RequestBindingKey::from_bytes(foreign).unwrap())
                .unwrap();
        assert!(row.validate_partition(foreign_floor, None).is_err());
        let sequence = read_machine_sync(&conn, signed.identity).unwrap().0;
        let horizon = read_applied_sync(&conn, signed.identity)
            .unwrap()
            .map(|id| id.index);
        let mut validator = ProductionSnapshotStreamValidator::new(sequence, horizon);
        row.account(&mut validator, witness)
            .unwrap_or_else(|_| panic!("exact applied horizon"));
        validator.add_floor(floor).unwrap();
        validator
            .finish(Some(witness), GlobalChargeBudget::production())
            .unwrap();
        for invalid in [None, Some(0)] {
            assert!(row
                .account(
                    &mut ProductionSnapshotStreamValidator::new(sequence, invalid),
                    witness
                )
                .is_err());
        }
        if !live {
            assert!(row
                .account(
                    &mut ProductionSnapshotStreamValidator::new(1, horizon),
                    witness
                )
                .is_err());
            assert!(row
                .account(
                    &mut ProductionSnapshotStreamValidator::new(sequence, Some(1)),
                    witness
                )
                .is_err());
        }
        let mut duplicate = ProductionSnapshotStreamValidator::new(sequence, horizon);
        row.account(&mut duplicate, witness)
            .unwrap_or_else(|_| panic!("first binding"));
        assert!(row.account(&mut duplicate, witness).is_err());
        let mut missing_charge = ProductionSnapshotStreamValidator::new(sequence, horizon);
        row.account(&mut missing_charge, witness)
            .unwrap_or_else(|_| panic!("charged binding"));
        missing_charge.add_floor(floor).unwrap();
        assert!(missing_charge
            .finish(
                Some(GlobalChargeWitness::empty()),
                GlobalChargeBudget::production()
            )
            .is_err());
    }
}

#[test]
fn native_roster_v1_admission_authenticates_the_exact_reserved_business_row() {
    let (_directory, backend, signed) = fixture(ProtectedRosterV2RecoveryFixtureState::Established);
    let conn = backend.conn.blocking_lock();
    let current = ops::get_raw_sync(&conn, signed.admission.key())
        .unwrap()
        .unwrap();
    let scope = read_membership_scope_sync(&conn, signed.identity).unwrap();
    let command = signed_v1_command(&signed);
    let binding = command.admission().binding_key(3).unwrap();
    let projection =
        Projection::from_admission(binding, &command).unwrap_or_else(|_| panic!("V1 projection"));
    let reservation = ProductionAdmissionBusinessReservation::new(
        command.admission(),
        ProductionBusinessState::from_authoritative_record(&current).unwrap(),
    )
    .unwrap();
    let record = ProductionReservationRecord::live_with_provenance_and_ingress(
        command.admission(),
        &command.ingress_attestation().unwrap(),
        &command.admission_provenance().unwrap(),
        binding.history_epoch(),
        reservation,
        ChargeProfile::v1(),
    )
    .unwrap();
    let bytes = record.to_canonical_bytes().unwrap();
    let row = checked(
        projection.clone(),
        binding,
        bytes.clone(),
        &signed.root,
        &scope,
    );
    assert!(matches!(row.body(), Body::V1(_)));
    assert!(row.facts.state == State::Live);
    assert_eq!(row.facts.terminal_sequence, None);
    assert_eq!(row.facts.terminal_raft_log_index, None);
    assert_eq!(row.canonical(), bytes);
    assert_eq!(row.reserved_key(), Some(&current.key));
    assert!(row.validate_business(Some(&current)).is_ok());
    assert!(row.validate_business(None).is_err());
    let mut changed_business = current.clone();
    changed_business.owner = OwnerId::new("changed-business-owner").unwrap();
    assert!(row.validate_business(Some(&changed_business)).is_err());
    let floor = IrreversibleHistoryFloor::initial(binding).unwrap();
    row.validate_partition(floor, None)
        .unwrap_or_else(|_| panic!("V1 floor"));
    let vacancy = ProductionBindingVacancyGuard::from_lookups(binding, None, None).unwrap();
    let prepared = prepare_production_admission(ProductionAdmissionPreparation {
        vacancy: &vacancy,
        existing: None,
        record,
        existing_floor: None,
        existing_retirement_cursor: None,
        witness: GlobalChargeWitness::empty(),
        budget: GlobalChargeBudget::production(),
        profile: ChargeProfile::v1(),
    })
    .unwrap();
    let mut validator = ProductionSnapshotStreamValidator::new(3, Some(3));
    row.account(&mut validator, prepared.next_witness())
        .unwrap_or_else(|_| panic!("V1 charge"));
    validator.add_floor(floor).unwrap();
    validator
        .finish(
            Some(prepared.next_witness()),
            GlobalChargeBudget::production(),
        )
        .unwrap();
    assert!(row
        .account(
            &mut ProductionSnapshotStreamValidator::new(3, Some(2)),
            prepared.next_witness()
        )
        .is_err());
    drop(row);
    for field in 0..4 {
        let mut changed = projection.clone();
        match field {
            0 => changed.profile = Profile::V2,
            1 => changed.stable_slot[0] ^= 1,
            2 => changed.terminal_slot[0] ^= 1,
            3 => changed.original.credential_id += 1,
            _ => unreachable!(),
        }
        assert!(hydrate(changed, binding, bytes.clone(), &signed.root, &scope).is_err());
    }
    let mut foreign_scope = scope;
    foreign_scope.current_identity = SessionConsensusIdentity::new(
        signed.identity.cluster_id(),
        SessionConsensusConfigurationId::from_bytes([0xBA; 32]),
        signed.identity.configuration_epoch(),
    );
    assert!(hydrate(
        projection.clone(),
        binding,
        bytes.clone(),
        &signed.root,
        &foreign_scope
    )
    .is_err());
    let wrong_root_key = SigningKey::from_bytes((&[0xBC; 32]).into()).unwrap();
    let wrong_root = RosterAttestationTrustRootV1::new(
        signed.root.root_id(),
        wrong_root_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert!(hydrate(
        projection,
        binding,
        bytes,
        &wrong_root,
        &read_membership_scope_sync(&conn, signed.identity).unwrap()
    )
    .is_err());
}
