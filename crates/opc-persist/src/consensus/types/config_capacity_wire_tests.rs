//! Profile selection must precede payload decoding on every config RPC.

use super::{config_wire_revision, decode_config_wire_for_profile, encode_config_wire_for_profile};
use opc_consensus::{encode_bounded, ConsensusCodecError, CONSENSUS_MAX_RPC_PAYLOAD_BYTES};
use opc_crypto::ConfigCapacityProfile;

#[derive(Debug)]
struct PayloadMustNotDecode;

impl<'de> serde::Deserialize<'de> for PayloadMustNotDecode {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        panic!("mismatched profile must reject before payload deserialization")
    }
}

#[test]
fn capacity_profile_preserves_legacy_bytes_and_distinguishes_the_opt_in_wire() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let value = vec![0xC7_u8; 128];
        let encoded = encode_config_wire_for_profile(profile, &value).expect("profile encoding");
        let original_shape = encode_bounded(&(config_wire_revision(profile), &value))
            .expect("original ordered wire fields");
        assert!(
            encoded == original_shape,
            "profile does not alter field encoding"
        );
        assert!(
            decode_config_wire_for_profile::<Vec<u8>>(profile, &encoded).expect("round trip")
                == value
        );
    }
    assert_eq!(config_wire_revision(ConfigCapacityProfile::Legacy), 7);
    assert_eq!(config_wire_revision(ConfigCapacityProfile::BoundedV1), 8);
}

#[test]
fn capacity_profile_mismatch_precedes_payload_deserialization() {
    for (sender, receiver) in [
        (
            ConfigCapacityProfile::Legacy,
            ConfigCapacityProfile::BoundedV1,
        ),
        (
            ConfigCapacityProfile::BoundedV1,
            ConfigCapacityProfile::Legacy,
        ),
    ] {
        let encoded =
            encode_config_wire_for_profile(sender, &vec![0xC8_u8; 128]).expect("sender payload");
        assert!(matches!(
            decode_config_wire_for_profile::<PayloadMustNotDecode>(receiver, &encoded),
            Err(ConsensusCodecError::Decode)
        ));
    }
    let unsupported = encode_bounded(&(9_u16, vec![0xC9_u8; 128])).expect("future payload");
    assert!(matches!(
        decode_config_wire_for_profile::<PayloadMustNotDecode>(
            ConfigCapacityProfile::BoundedV1,
            &unsupported
        ),
        Err(ConsensusCodecError::Decode)
    ));
}

#[test]
fn capacity_wire_keeps_the_exact_shared_rpc_ceiling_and_rejects_trailing_bytes() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        // One-byte revision plus the actual three-byte vector-length prefix.
        let mut value = vec![0xCA_u8; CONSENSUS_MAX_RPC_PAYLOAD_BYTES - 4];
        let encoded = encode_config_wire_for_profile(profile, &value).expect("at-limit RPC");
        assert_eq!(encoded.len(), CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
        assert!(
            decode_config_wire_for_profile::<Vec<u8>>(profile, &encoded).expect("at-limit decode")
                == value
        );
        value.push(0xCA);
        assert!(matches!(
            encode_config_wire_for_profile(profile, &value),
            Err(ConsensusCodecError::TooLarge)
        ));
        let mut over = encoded;
        over.push(0);
        assert!(matches!(
            decode_config_wire_for_profile::<PayloadMustNotDecode>(profile, &over),
            Err(ConsensusCodecError::TooLarge)
        ));
        let mut trailing = encode_config_wire_for_profile(profile, &7_u8).expect("small payload");
        trailing.push(0);
        assert!(matches!(
            decode_config_wire_for_profile::<u8>(profile, &trailing),
            Err(ConsensusCodecError::Decode)
        ));
    }
}
