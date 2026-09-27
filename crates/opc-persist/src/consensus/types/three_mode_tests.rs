//! Exact old wire bytes and profile-first rejection across all three modes.
use super::*;
const MODES: [RetainedConfigMode; 3] = [
    RetainedConfigMode::Legacy,
    RetainedConfigMode::BoundedV1,
    RetainedConfigMode::NetconfTargetsV1,
];
#[derive(Debug)]
struct PayloadMustNotDecode;
impl<'de> serde::Deserialize<'de> for PayloadMustNotDecode {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        panic!("THREE_MODE_PROFILE_BEFORE_PAYLOAD");
    }
}
#[test]
fn three_mode_wire_and_command_revisions_are_closed_and_preserve_old_bytes() {
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x31; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    for (mode, revision, storage) in [(MODES[0], 7_u16, 5_u16), (MODES[1], 8, 6), (MODES[2], 9, 7)]
    {
        assert_eq!(
            encode_config_wire_for_profile(mode, &42_u64).unwrap(),
            [revision as u8, 42],
            "THREE_MODE_WIRE_BYTES"
        );
        assert_eq!(config_command_revision(mode), revision);
        assert_eq!(config_storage_revision(mode), storage);
        assert_eq!(config_snapshot_revision(mode), storage);
        let payload = encode_config_wire_for_profile(mode, &vec![0x71_u8; 128]).unwrap();
        for other in MODES.into_iter().filter(|other| *other != mode) {
            assert!(
                decode_config_wire_for_profile::<PayloadMustNotDecode>(other, &payload).is_err()
            );
        }
        for future in [0_u16, 6, 10, u16::MAX] {
            let payload = opc_consensus::encode_bounded(&(future, vec![0x72_u8; 128])).unwrap();
            assert!(
                decode_config_wire_for_profile::<PayloadMustNotDecode>(mode, &payload).is_err()
            );
        }
        let mut command = ConfigConsensusCommand {
            schema_version: 1,
            identity,
            request_id: ConfigConsensusRequestId::from_bytes([0x41; 16]),
            logical_time: "2026-01-01T00:00:00Z".parse().unwrap(),
            intent: ConfigMutationIntent::MarkConfirmed { tx_id: TxId::new() },
        };
        for old in 1..=7 {
            command.schema_version = old;
            assert!(command.validate_structure_for_mode(identity, mode).is_ok());
        }
        for candidate in [0, 8, 9, 10, u16::MAX] {
            command.schema_version = candidate;
            assert_eq!(
                command.validate_structure_for_mode(identity, mode).is_ok(),
                candidate == revision && candidate != 7,
                "THREE_MODE_COMMAND_REVISION"
            );
        }
    }
}
