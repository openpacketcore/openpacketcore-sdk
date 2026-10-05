use super::*;
use crate::consensus::capacity_tests::support::{aad, record};
use serde_json::{json, Value};

fn canonical() -> Vec<u8> {
    opc_key::serialize_bound_aad(
        &aad(&record(), "running"),
        &opc_key::KeyId::new("synthetic-key").unwrap(),
    )
    .unwrap()
}

fn reject(value: &Value) {
    assert!(
        preflight(&serde_json::to_vec(value).unwrap()).is_err(),
        "{value}"
    );
}

#[test]
fn scalar_shapes_include_null_parent_and_escaped_unicode() {
    preflight(&canonical()).unwrap();
    let mut record = record();
    record.parent_tx_id = None;
    record.principal = "writer-\"\\é-🙂".into();
    let aad = aad(&record, "store-\"\\é");
    let bytes =
        opc_key::serialize_bound_aad(&aad, &opc_key::KeyId::new("key-AZaz09-_.:/").unwrap())
            .unwrap();
    preflight(&bytes).unwrap();
    assert_eq!(opc_key::decode_bound_aad(&bytes).unwrap().0, aad);
}

#[test]
fn each_scalar_rejects_every_other_json_shape() {
    let original: Value = serde_json::from_slice(&canonical()).unwrap();
    for field in ["tenant", "purpose", "key_id"] {
        for invalid in [
            Value::Null,
            json!(true),
            json!(0),
            json!([]),
            json!({}),
            json!({"nested": [0]}),
        ] {
            let mut value = original.clone();
            value[field] = invalid;
            reject(&value);
        }
    }
    for field in [
        "kind",
        "tx_id",
        "parent_tx_id",
        "committed_at",
        "principal",
        "schema_digest",
        "store_kind",
    ] {
        for invalid in [
            Value::Null,
            json!(true),
            json!(0),
            json!([]),
            json!({}),
            json!({"nested": [0]}),
        ] {
            if field == "parent_tx_id" && invalid.is_null() {
                continue;
            }
            let mut value = original.clone();
            value["metadata"][field] = invalid;
            reject(&value);
        }
    }
    for invalid in [
        Value::Null,
        json!(true),
        json!("1"),
        json!(-1),
        json!(1.5),
        json!([]),
        json!({}),
    ] {
        let mut value = original.clone();
        value["version"] = invalid;
        reject(&value);
    }
    let mut overflow = String::from_utf8(canonical()).unwrap();
    overflow = overflow.replace("\"version\":2", "\"version\":18446744073709551616");
    assert!(preflight(overflow.as_bytes()).is_err());
    for field in ["purpose", "metadata"] {
        let mut value = original.clone();
        if field == "purpose" {
            value[field] = json!("session");
        } else {
            value[field]["kind"] = json!("session");
        }
        reject(&value);
    }
}

#[test]
fn containers_fields_duplicates_and_trailing_input_are_closed() {
    let original: Value = serde_json::from_slice(&canonical()).unwrap();
    for invalid in [
        Value::Null,
        json!(true),
        json!(0),
        json!("scalar"),
        json!([]),
    ] {
        reject(&invalid);
        let mut value = original.clone();
        value["metadata"] = invalid;
        reject(&value);
    }
    // Nonempty positional forms would otherwise be accepted by derived structs.
    let mut value = original.clone();
    let m = &original["metadata"];
    value["metadata"] = json!([
        m["kind"],
        m["tx_id"],
        m["parent_tx_id"],
        m["committed_at"],
        m["principal"],
        m["schema_digest"],
        m["store_kind"]
    ]);
    reject(&value);
    reject(&json!([
        original["tenant"],
        original["purpose"],
        original["version"],
        original["key_id"],
        original["metadata"]
    ]));
    for nested in [false, true] {
        let object = if nested {
            &original["metadata"]
        } else {
            &original
        };
        for field in object.as_object().unwrap().keys() {
            let mut value = original.clone();
            let target = if nested {
                &mut value["metadata"]
            } else {
                &mut value
            };
            target.as_object_mut().unwrap().remove(field);
            reject(&value);
            // Work with raw bytes so a JSON Value cannot collapse duplicates.
            let encoded = String::from_utf8(canonical()).unwrap();
            let duplicate = format!("\"{field}\":{},\"{field}\":", object[field]);
            let duplicated = encoded.replacen(&format!("\"{field}\":"), &duplicate, 1);
            assert!(
                preflight(duplicated.as_bytes()).is_err(),
                "duplicate {field}"
            );
        }
        let mut value = original.clone();
        let target = if nested {
            &mut value["metadata"]
        } else {
            &mut value
        };
        target["unknown"] = json!({"nested": [0, 1, 2]});
        reject(&value);
    }
    let mut trailing = canonical();
    trailing.extend_from_slice(b"{}");
    assert!(preflight(&trailing).is_err());
    assert!(preflight(b"{\"metadata\":").is_err());
    assert!(preflight(&[0xff]).is_err());
}

#[test]
fn key_and_complete_aad_have_inclusive_limits() {
    let key = opc_key::KeyId::new("k".repeat(512)).unwrap();
    let record = record();
    let base = opc_key::serialize_bound_aad(&aad(&record, "s"), &key)
        .unwrap()
        .len();
    let store = "s".repeat(CONFIG_CAPACITY_V1_AAD_BYTES - base + 1);
    let at = opc_key::serialize_bound_aad(&aad(&record, &store), &key).unwrap();
    assert_eq!(at.len(), CONFIG_CAPACITY_V1_AAD_BYTES);
    preflight(&at).unwrap();
    opc_key::decode_bound_aad(&at).unwrap();
    let over = opc_key::serialize_bound_aad(&aad(&record, &(store + "s")), &key).unwrap();
    assert_eq!(over.len(), CONFIG_CAPACITY_V1_AAD_BYTES + 1);
    assert!(preflight(&over).is_err());
    let mut value: Value = serde_json::from_slice(&canonical()).unwrap();
    value["key_id"] = json!("k".repeat(512));
    preflight(&serde_json::to_vec(&value).unwrap()).unwrap();
    value["key_id"] = json!("k".repeat(513));
    reject(&value);
}

#[test]
fn structural_success_does_not_replace_canonical_encoding() {
    let mut padded = canonical();
    opc_key::decode_bound_aad(&padded).unwrap();
    padded.push(b' ');
    preflight(&padded).unwrap();
    assert!(opc_key::decode_bound_aad(&padded).is_err());
}

#[test]
fn canonical_aad_for_other_record_metadata_cannot_verify() {
    use super::super::CapacityRecordBinding;
    use crate::consensus::capacity_tests::support::*;
    use hmac::Mac;
    let profile = opc_crypto::ConfigCapacityProfile::BoundedV1;
    let attested = bounded_attested(32, 64);
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key()).unwrap();
    binding
        .verify(attested.record(), identity(), &key(), profile)
        .unwrap();
    for field in 0..3 {
        let mut metadata = attested.record().clone();
        match field {
            0 => metadata.tx_id = parent(),
            1 => metadata.committed_at = "2026-01-02T00:00:00.123456789Z".parse().unwrap(),
            2 => metadata.schema_digest = opc_types::SchemaDigest::from_bytes([99; 32]),
            _ => unreachable!(),
        }
        let mut record = attested.record().clone();
        let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(&record.encrypted_blob).unwrap();
        envelope.aad =
            opc_key::serialize_bound_aad(&aad(&metadata, "running"), &envelope.key_id).unwrap();
        // Typed canonical serialization preserves field order in every feature
        // graph; shape and domain decoding must both succeed before rejection.
        preflight(&envelope.aad).unwrap();
        opc_key::decode_bound_aad(&envelope.aad).unwrap();
        record.encrypted_blob = envelope.encode().unwrap();
        let mut binding = binding;
        binding.tag = binding
            .mac(&record, identity(), &key())
            .unwrap()
            .finalize()
            .into_bytes()
            .into();
        // The matching MAC removes ciphertext substitution as a competing cause.
        assert!(
            binding
                .verify(&record, identity(), &key(), profile)
                .is_err(),
            "field {field}"
        );
    }
}
