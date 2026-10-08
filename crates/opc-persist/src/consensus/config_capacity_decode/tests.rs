use super::*;
use crate::consensus::capacity_tests::support::*;

fn bytes_boundary<const MAX: usize>() {
    for count in [0, MAX, MAX + 1] {
        let value = vec![255u8; count];
        let binary = opc_consensus::encode_bounded(&value).unwrap();
        let json = serde_json::to_vec(&value).unwrap();
        let binary = opc_consensus::decode_bounded::<Bytes<MAX>>(&binary);
        let json = serde_json::from_slice::<Bytes<MAX>>(&json);
        assert_eq!(binary.is_ok(), count <= MAX);
        assert_eq!(json.is_ok(), count <= MAX);
        if count <= MAX {
            assert_eq!(binary.unwrap().0, value);
            assert_eq!(json.unwrap().0, value);
        }
    }
    let declared = opc_consensus::encode_bounded(&u64::MAX).unwrap();
    assert!(opc_consensus::decode_bounded::<Bytes<MAX>>(&declared).is_err());
}

fn text_boundary<const MAX: usize>() {
    for count in [0, MAX, MAX + 1] {
        let value = "x".repeat(count);
        let binary = opc_consensus::encode_bounded(&value).unwrap();
        let json = serde_json::to_vec(&value).unwrap();
        let binary = opc_consensus::decode_bounded::<Text<MAX>>(&binary);
        let json = serde_json::from_slice::<Text<MAX>>(&json);
        assert_eq!(binary.is_ok(), count <= MAX);
        assert_eq!(json.is_ok(), count <= MAX);
        if count <= MAX {
            assert_eq!(binary.unwrap().0, value);
            assert_eq!(json.unwrap().0, value);
        }
    }
    let declared = opc_consensus::encode_bounded(&u64::MAX).unwrap();
    assert!(opc_consensus::decode_bounded::<Text<MAX>>(&declared).is_err());
}

#[test]
fn byte_fields_admit_exact_bounds_before_copying() {
    bytes_boundary::<32>();
    bytes_boundary::<CONFIG_CAPACITY_V1_ENVELOPE_BYTES>();
    bytes_boundary::<{ 1024 * 1024 }>();
}

#[test]
fn text_fields_admit_exact_bounds_before_owning() {
    text_boundary::<CONFIG_PRINCIPAL_MAX_BYTES>();
    text_boundary::<CONFIG_AUDIT_PATH_MAX_BYTES>();
    text_boundary::<{ crate::CONFIG_ROLLBACK_LABEL_MAX_BYTES }>();
    text_boundary::<12>();
    text_boundary::<128>();
}

#[test]
fn json_preflight_bounds_raw_strings_and_complete_input() {
    let at = format!("\"{}\"", "\\u0078".repeat(CONFIG_PRINCIPAL_MAX_BYTES));
    assert!(json_preflight(at.as_bytes()).is_ok());
    let text: Text<CONFIG_PRINCIPAL_MAX_BYTES> = serde_json::from_str(&at).unwrap();
    assert_eq!(text.0.len(), CONFIG_PRINCIPAL_MAX_BYTES);
    let over = format!("\"{}x\"", "\\u0078".repeat(CONFIG_PRINCIPAL_MAX_BYTES));
    assert!(json_preflight(over.as_bytes()).is_err());
    let mut frame = vec![b' '; super::super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES];
    frame[0] = b'0';
    assert!(json_preflight(&frame).is_ok());
    frame.push(b' ');
    assert!(json_preflight(&frame).is_err());
    assert!(json_preflight(b"\"truncated\\").is_err());
}

#[test]
fn list_checks_count_before_constructing_an_extra_element() {
    use std::cell::Cell;
    thread_local! { static VISITS: Cell<usize> = const { Cell::new(0) }; }
    struct Element;
    impl<'de> Deserialize<'de> for Element {
        fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
            VISITS.with(|v| v.set(v.get() + 1));
            u8::deserialize(input)?;
            Ok(Self)
        }
    }
    for (input, accepted, visits) in [("[0,0]", true, 2), ("[0,0,0]", false, 2)] {
        VISITS.with(|v| v.set(0));
        assert_eq!(
            serde_json::from_str::<List<Element, 2>>(input).is_ok(),
            accepted
        );
        assert_eq!(VISITS.with(Cell::get), visits);
    }
    let declared = opc_consensus::encode_bounded(&u64::MAX).unwrap();
    VISITS.with(|v| v.set(0));
    assert!(opc_consensus::decode_bounded::<List<Element, 2>>(&declared).is_err());
    assert_eq!(VISITS.with(Cell::get), 0);
    let over = opc_consensus::encode_bounded(&vec![0u8; 3]).unwrap();
    VISITS.with(|v| v.set(0));
    assert!(opc_consensus::decode_bounded::<List<Element, 2>>(&over).is_err());
    assert_eq!(VISITS.with(Cell::get), 0);
}

#[test]
fn bounded_representations_decode_privately_but_legacy_gates_stay_closed() {
    for audited in [false, true] {
        for resolution in [
            None,
            Some(ConfirmedCommitResolution::Confirm {
                pending_tx_id: parent(),
            }),
        ] {
            let command = bounded_command(audited, resolution);
            let binary = opc_consensus::encode_bounded(&command).unwrap();
            let json = serde_json::to_vec(&command).unwrap();
            let binary: ConfigConsensusCommand = opc_consensus::decode_bounded::<Command>(&binary)
                .unwrap()
                .into();
            json_preflight(&json).unwrap();
            let decoded: ConfigConsensusCommand =
                serde_json::from_slice::<Command>(&json).unwrap().into();
            assert_eq!(binary, command);
            assert_eq!(decoded, command);
            let error = serde_json::from_slice::<ConfigConsensusCommand>(&json).unwrap_err();
            assert!(error
                .to_string()
                .contains("unknown variant `BoundedAppend`"));
            assert!(matches!(
                opc_consensus::decode_bounded::<ConfigConsensusCommand>(
                    &opc_consensus::encode_bounded(&command).unwrap()
                ),
                Err(opc_consensus::ConsensusCodecError::Decode)
            ));
            let wire = super::super::types::encode_config_wire(&command).unwrap();
            assert!(matches!(
                super::super::types::decode_config_wire::<ConfigConsensusCommand>(&wire),
                Err(opc_consensus::ConsensusCodecError::Decode)
            ));
            assert!(decoded.validate(identity()).is_err());
            if let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent {
                assert!(PreparedAuditedMutation::decode(&prepared.encode().unwrap()).is_err());
            }
        }
    }
}

#[test]
fn every_legacy_command_fixture_decodes_to_the_same_value() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../capacity_tests/legacy.json")).unwrap();
    let mut commands = 0;
    for row in rows {
        if row.get("payload_digest").is_none() {
            continue;
        }
        let bytes = row["json"].as_str().unwrap().as_bytes();
        let original: ConfigConsensusCommand = serde_json::from_slice(bytes).unwrap();
        let wire = super::super::types::encode_config_wire(&original).unwrap();
        assert_eq!(
            super::super::types::decode_config_wire::<ConfigConsensusCommand>(&wire).unwrap(),
            original
        );
        let decoded: ConfigConsensusCommand =
            serde_json::from_slice::<Command>(bytes).unwrap().into();
        assert_eq!(decoded, original, "{}", row["name"]);
        let compact = opc_consensus::encode_bounded(&original).unwrap();
        let decoded: ConfigConsensusCommand = opc_consensus::decode_bounded::<Command>(&compact)
            .unwrap()
            .into();
        assert_eq!(decoded, original);
        let native = row["native_json"].as_str().unwrap().as_bytes();
        let entry: opc_consensus::engine::Entry<crate::consensus::ConfigRaftTypeConfig> =
            serde_json::from_slice(native).unwrap();
        assert_eq!(engine::native_json::entry(native).unwrap(), entry);
        commands += 1;
    }
    assert!(commands >= 20);
}

#[test]
fn audit_aggregate_limit_is_independent_of_each_field() {
    let mut entry = audit().remove(0);
    entry.yang_path = "x".repeat(1024);
    let mut size = opc_consensus::AppendEntriesBatchAccumulator::new();
    size.consider(&entry).unwrap();
    let per_entry = size.serialized_entry_bytes();
    let count = CONFIG_CAPACITY_V1_METADATA_BYTES / per_entry - 1;
    let mut at = vec![entry.clone(); count];
    let needed = CONFIG_CAPACITY_V1_METADATA_BYTES - count * per_entry;
    entry.yang_path = (1..=CONFIG_AUDIT_PATH_MAX_BYTES)
        .find_map(|length| {
            let mut candidate = entry.clone();
            candidate.yang_path = "/".repeat(length);
            let mut size = opc_consensus::AppendEntriesBatchAccumulator::new();
            size.consider(&candidate).unwrap();
            (size.serialized_entry_bytes() == needed).then_some(candidate.yang_path)
        })
        .unwrap();
    at.push(entry);
    let total: usize = at
        .iter()
        .map(|record| opc_consensus::encode_bounded(record).unwrap().len())
        .sum();
    assert_eq!(total, CONFIG_CAPACITY_V1_METADATA_BYTES);
    assert!(serde_json::from_slice::<Audit>(&serde_json::to_vec(&at).unwrap()).is_ok());
    at.last_mut().unwrap().yang_path.push('/');
    let total: usize = at
        .iter()
        .map(|record| opc_consensus::encode_bounded(record).unwrap().len())
        .sum();
    assert_eq!(total, CONFIG_CAPACITY_V1_METADATA_BYTES + 1);
    assert!(serde_json::from_slice::<Audit>(&serde_json::to_vec(&at).unwrap()).is_err());
}
