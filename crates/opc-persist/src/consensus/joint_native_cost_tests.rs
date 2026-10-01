//! Retained originals are independently signed/encoded by the old JSON/HMAC
//! recipe. These component tests do not qualify native RPC completion latency.

use super::*;
use crate::audit_authority::ledger::native_cost_tests::{observe, original_mac, Bytes, Stage};
use crate::audit_authority::AuditCaller;
use crate::consensus::audit_mutation::RecoverySizeCounter;

#[tokio::test]
async fn native_cost_retained_encoding_and_comparison_bound_actual_sink_work() {
    let pool = ConfigPreparationPool::bounded_v1();
    let plaintext = format!("\"{}\"", "x".repeat(65_534));
    let prepared = signed(payload(&pool, plaintext.as_bytes()).await);
    let original = serde_json::to_vec(prepared.command()).unwrap();
    let (encoded, encoding) = observe(|| prepared.command().encode_retained(&key(), identity()));
    assert_eq!(
        encoded.unwrap(),
        original,
        "NATIVE_COST_RETAINED_ORIGINAL_BYTES"
    );
    // Closed command metadata is fixed for this fixture; only its real encrypted
    // byte array grows. The baseline makes over 130,000 payload sink calls.
    let bound = 8_192 + original.len().div_ceil(1_020);
    let count = encoding.stage(Stage::RetainedCount);
    assert_eq!(count.bytes, original.len());
    assert!(
        count.calls <= bound,
        "NATIVE_COST_RETAINED_COUNT_WORK_RED: {} > {}",
        count.calls,
        bound
    );
    let output = encoding.stage(Stage::RetainedOutput);
    assert_eq!(output.bytes, original.len());
    assert!(
        output.calls <= bound,
        "NATIVE_COST_RETAINED_OUTPUT_WORK_RED: {} > {}",
        output.calls,
        bound
    );
    let (decoded, comparison) = observe(|| {
        PreparedTargetMutation::decode_retained(
            &original,
            &key(),
            identity(),
            prepared.handle(),
            event().caller,
        )
    });
    let decoded = decoded.unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), original);
    let canonical = comparison.stage(Stage::CanonicalComparison);
    assert_eq!(canonical.bytes, original.len());
    assert!(
        canonical.calls <= bound,
        "NATIVE_COST_CANONICAL_WORK_RED: {} > {}",
        canonical.calls,
        bound
    );
    assert!(decoded.preparation.is_none());
    eprintln!(
        "NATIVE_COST_RETAINED_SINK_WORK count={} output={} canonical={} bytes={}",
        count.calls,
        output.calls,
        canonical.calls,
        original.len()
    );
}

#[tokio::test]
async fn native_cost_retained_accepts_independent_original_and_refuses_substitutions() {
    let pool = ConfigPreparationPool::bounded_v1();
    let mut prepared = signed(payload(&pool, br#"{"enabled":true}"#).await);
    let effect_mac = original_mac(
        &key(),
        b"openpacketcore/management-audit/netconf-target/v1\0",
        &prepared.command().effect,
    );
    assert_eq!(prepared.handle().body.mutation, Some(effect_mac));
    let mut body = prepared.handle().body.clone();
    body.mutation = Some(effect_mac);
    body.binding = AuditOperationBinding::project(&privacy(), &body.event, 0, &effect_mac).unwrap();
    // Issue the actual retained original with independent default Serde and
    // HMAC. Neither the new formatter nor AuditOperationHandle::issue is used.
    let handle = AuditOperationHandle {
        mac: original_mac(
            &key(),
            b"openpacketcore/management-audit/operation-handle/v1\0",
            &body,
        ),
        body,
    };
    assert_eq!(prepared.handle(), &handle);
    prepared.command_mut().handle = handle.clone();
    let original = serde_json::to_vec(prepared.command()).unwrap();
    let decoded = PreparedTargetMutation::decode_retained(
        &original,
        &key(),
        identity(),
        &handle,
        event().caller,
    )
    .unwrap();
    assert_eq!(
        decoded.handle(),
        &handle,
        "NATIVE_COST_INDEPENDENT_ORIGINAL_ACCEPTED"
    );
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), original);
    assert!(decoded.preparation.is_none());
    assert!(decoded.encode().is_err());
    assert!(decoded
        .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
        .is_err());
    let foreign_pool = ConfigPreparationPool::bounded_v1();
    assert!(decoded
        .begin_submission(&foreign_pool, ConfigCapacityProfile::BoundedV1)
        .is_err());
    all_slots_available(&foreign_pool);

    let text = std::str::from_utf8(&original).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let mut unknown = value.clone();
    unknown["unexpected"] = json!(true);
    let mut tampered = value.clone();
    let ciphertext = tampered["effect"]["encrypted_payload"]["bounded-running"]["commit"]["record"]
        ["encrypted_blob"]
        .as_array_mut()
        .unwrap();
    let last = ciphertext.last_mut().unwrap();
    *last = json!(last.as_u64().unwrap() ^ 1);
    let cases = [
        format!(" {text}").into_bytes(),
        format!("{text} ").into_bytes(),
        serde_json::to_vec_pretty(&value).unwrap(),
        text.replacen("fixture.invalid", "fixt\\u0075re.invalid", 1)
            .into_bytes(),
        text.replacen("\"effect\":{", "\"effect\":{\"format\":1,", 1)
            .into_bytes(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&tampered).unwrap(),
        original[..original.len() - 1].to_vec(),
    ];
    for (index, bytes) in cases.iter().enumerate() {
        assert_ne!(bytes, &original, "adversarial mutation must be effective");
        assert!(
            PreparedTargetMutation::decode_retained(
                bytes,
                &key(),
                identity(),
                &handle,
                event().caller
            )
            .is_err(),
            "NATIVE_COST_RETAINED_ADVERSARIAL_{index}"
        );
    }
    let wrong_key = AuditKey::new([0x42; 32]).unwrap();
    assert!(PreparedTargetMutation::decode_retained(
        &original,
        &wrong_key,
        identity(),
        &handle,
        event().caller
    )
    .is_err());
    let wrong_identity = ConfigConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0x43; 32]),
        identity().configuration_id(),
        identity().configuration_epoch(),
    );
    assert!(PreparedTargetMutation::decode_retained(
        &original,
        &key(),
        wrong_identity,
        &handle,
        event().caller
    )
    .is_err());
    let wrong_caller = AuditCaller::project(&privacy(), "synthetic", "other-principal").unwrap();
    assert!(PreparedTargetMutation::decode_retained(
        &original,
        &key(),
        identity(),
        &handle,
        wrong_caller
    )
    .is_err());
    let mut other_body = handle.body.clone();
    other_body.nonce[0] ^= 1;
    let other_original = AuditOperationHandle {
        mac: original_mac(
            &key(),
            b"openpacketcore/management-audit/operation-handle/v1\0",
            &other_body,
        ),
        body: other_body,
    };
    other_original
        .verify(&key(), identity(), event().caller)
        .unwrap();
    assert!(
        PreparedTargetMutation::decode_retained(
            &original,
            &key(),
            identity(),
            &other_original,
            event().caller
        )
        .is_err(),
        "NATIVE_COST_EXACT_ORIGINAL_BINDING"
    );
    drop(decoded);
    drop(prepared);
    all_slots_available(&pool);
}

#[tokio::test]
async fn native_cost_retained_counting_and_decode_preserve_size_fences() {
    let limit = crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES;
    for length in [0, 1, 255, 256, 257, 1_024, 16_384] {
        let bytes: Vec<u8> = (0..=255).cycle().take(length).collect();
        let value = Bytes(&bytes);
        let encoded = serde_json::to_vec(&value).unwrap();
        for remaining in [0, 1, encoded.len() - 1, encoded.len(), encoded.len() + 1] {
            let mut old = RecoverySizeCounter(limit - remaining);
            let mut new = RecoverySizeCounter(limit - remaining);
            let old_result = serde_json::to_writer(&mut old, &value);
            let new_result =
                crate::consensus::config_capacity_json::count_to_writer(&mut new, &value);
            assert_eq!(
                new_result.is_ok(),
                old_result.is_ok(),
                "NATIVE_COST_COUNT_EXACT_FENCE"
            );
            assert!(old.0 <= limit && new.0 <= limit);
            if old_result.is_ok() {
                assert_eq!(old.0, new.0);
            }
        }
    }
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let oversized = vec![b' '; limit + 1];
    assert!(matches!(
        PreparedTargetMutation::decode_retained(
            &oversized,
            &key(),
            identity(),
            prepared.handle(),
            event().caller
        ),
        Err(AuditAuthorityError::InvalidInput)
    ));
    // This exercises the unchanged early decoder fence. It does not admit a
    // structurally valid command at every aggregate command/ledger size limit.
}
