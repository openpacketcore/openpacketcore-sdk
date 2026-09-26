//! Prepared codec qualification, separate from engine admission or authentication.
use crate::consensus::types::{
    decode_config_wire, decode_config_wire_for_profile, encode_config_wire,
    encode_config_wire_for_profile,
};
use crate::consensus::{ConfigConsensusCommand, ConfigMutationIntent, ConfigRaftTypeConfig};
use crate::RetainedConfigProfile;
use opc_consensus::engine::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use opc_consensus::engine::{SnapshotMeta, StoredMembership, Vote};
use opc_consensus::{ConsensusCodecError, ConsensusNodeId};
use serde::{de::DeserializeOwned, Serialize};

fn profile_round_trip<T: Serialize + DeserializeOwned>(value: &T) {
    #[derive(Serialize)]
    struct ContractEnvelope<'a, T> {
        revision: u16,
        value: &'a T,
    }

    let legacy = encode_config_wire(value).unwrap();
    let explicit_legacy =
        encode_config_wire_for_profile(value, RetainedConfigProfile::Legacy).unwrap();
    assert!(legacy == explicit_legacy, "legacy wire bytes changed");
    assert!(decode_config_wire::<T>(&legacy).is_ok());
    let target =
        encode_config_wire_for_profile(value, RetainedConfigProfile::NetconfTargetsV1).unwrap();
    let contract = opc_consensus::encode_bounded(&ContractEnvelope { revision: 9, value }).unwrap();
    assert!(
        target == contract,
        "target wire revision differs from contract"
    );
    let restored: T =
        decode_config_wire_for_profile(&target, RetainedConfigProfile::NetconfTargetsV1).unwrap();
    assert!(
        encode_config_wire_for_profile(&restored, RetainedConfigProfile::NetconfTargetsV1).unwrap()
            == target,
        "target wire round trip changed the payload"
    );
    assert!(matches!(
        decode_config_wire::<T>(&target),
        Err(ConsensusCodecError::Decode)
    ));
    assert!(matches!(
        decode_config_wire_for_profile::<T>(&target, RetainedConfigProfile::Legacy),
        Err(ConsensusCodecError::Decode)
    ));
    assert!(matches!(
        decode_config_wire_for_profile::<T>(&legacy, RetainedConfigProfile::NetconfTargetsV1),
        Err(ConsensusCodecError::Decode)
    ));
    for revision in [0, 1, 2, 3, 4, 5, 6, 8, 10, u16::MAX] {
        let unallocated =
            opc_consensus::encode_bounded(&ContractEnvelope { revision, value }).unwrap();
        for profile in [
            RetainedConfigProfile::Legacy,
            RetainedConfigProfile::NetconfTargetsV1,
        ] {
            assert!(matches!(
                decode_config_wire_for_profile::<T>(&unallocated, profile),
                Err(ConsensusCodecError::Decode)
            ));
        }
    }
    for end in 0..target.len() {
        assert!(
            decode_config_wire_for_profile::<T>(
                &target[..end],
                RetainedConfigProfile::NetconfTargetsV1
            )
            .is_err(),
            "truncated target envelope admitted"
        );
    }
    let mut trailing = target;
    trailing.push(0);
    assert!(
        decode_config_wire_for_profile::<T>(&trailing, RetainedConfigProfile::NetconfTargetsV1)
            .is_err(),
        "trailing target wire bytes admitted"
    );
}

#[test]
fn target_profile_wire_codec_preserves_legacy_and_refuses_both_downgrade_directions() {
    assert_eq!(encode_config_wire(&42_u64).unwrap(), [7, 42]);
    profile_round_trip(&42_u64);
    let node = ConsensusNodeId::new(1).unwrap();
    profile_round_trip(&VoteRequest {
        vote: Vote::new(1, node),
        last_log_id: None,
    });
    profile_round_trip(&AppendEntriesRequest::<ConfigRaftTypeConfig> {
        vote: Vote::new_committed(1, node),
        prev_log_id: None,
        entries: Vec::new(),
        leader_commit: None,
    });
    profile_round_trip(&InstallSnapshotRequest::<ConfigRaftTypeConfig> {
        vote: Vote::new_committed(1, node),
        meta: SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "profile-fixture".into(),
        },
        offset: 0,
        data: vec![0x61, 0x62],
        done: true,
    });
}

#[test]
fn target_profile_command_requires_explicit_profile_and_allocated_revision() {
    let prepared = super::signed_discard();
    let identity = prepared.handle.body.identity;
    let mut command = ConfigConsensusCommand {
        schema_version: 9,
        identity,
        request_id: crate::ConfigConsensusRequestId::from_bytes([0x51; 16]),
        logical_time: "2026-01-01T00:00:00Z".parse().unwrap(),
        intent: ConfigMutationIntent::ManagementAudit(super::AuditCommand::NetconfTarget(
            Box::new(crate::consensus::audit_mutation::TargetAuditCommandV1::Apply(prepared)),
        )),
    };
    assert!(command
        .validate_for_profile(identity, RetainedConfigProfile::NetconfTargetsV1)
        .is_ok());
    assert!(command.validate(identity).is_err());
    assert!(command
        .validate_for_profile(identity, RetainedConfigProfile::Legacy)
        .is_err());
    for revision in [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, u16::MAX] {
        command.schema_version = revision;
        assert!(
            command
                .validate_for_profile(identity, RetainedConfigProfile::NetconfTargetsV1)
                .is_err(),
            "target command admitted under another revision"
        );
    }
    command.schema_version = 9;
    let foreign = crate::ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0x71; 32]),
        identity.configuration_id(),
        identity.configuration_epoch(),
    );
    assert!(command
        .validate_for_profile(foreign, RetainedConfigProfile::NetconfTargetsV1)
        .is_err());
    assert!(command
        .validate_for_profile(identity, RetainedConfigProfile::NetconfTargetsV1)
        .is_ok());
}

#[test]
fn target_profile_keeps_historical_command_validation_without_admitting_capacity_revision() {
    let identity = super::signed_discard().handle.body.identity;
    let mut command = ConfigConsensusCommand {
        schema_version: 1,
        identity,
        request_id: crate::ConfigConsensusRequestId::from_bytes([0x52; 16]),
        logical_time: "2026-01-01T00:00:00Z".parse().unwrap(),
        intent: ConfigMutationIntent::MarkConfirmed {
            tx_id: opc_types::TxId::new(),
        },
    };
    for revision in 1..=7 {
        command.schema_version = revision;
        assert!(command.validate(identity).is_ok());
        assert!(
            command
                .validate_for_profile(identity, RetainedConfigProfile::NetconfTargetsV1)
                .is_ok(),
            "inherited historical command lost its original validation"
        );
    }
    command.schema_version = 9;
    assert!(command.validate(identity).is_err());
    assert!(command
        .validate_for_profile(identity, RetainedConfigProfile::NetconfTargetsV1)
        .is_ok());
    for revision in [0, 8, 10, u16::MAX] {
        command.schema_version = revision;
        assert!(command.validate(identity).is_err());
        assert!(command
            .validate_for_profile(identity, RetainedConfigProfile::NetconfTargetsV1)
            .is_err());
    }
}
