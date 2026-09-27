//! Routing is only a decoder hint. The independent full-route/default-Serde
//! oracle below retains the original acceptance contract. No timing assertion.

use super::*;
use crate::audit_authority::ledger::native_cost_tests::original_mac;
use crate::audit_authority::AuditCaller;
use crate::consensus::audit_mutation::target_recovery::uses_bounded;
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::cell::Cell;

thread_local! {
    static ROUTE_BYTES: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(in crate::consensus) fn record_consumed(bytes: usize) {
    ROUTE_BYTES.with(|slot| {
        if let Some(previous) = slot.get() {
            slot.set(Some(previous + bytes));
        }
    });
}

struct RouteScope;
impl Drop for RouteScope {
    fn drop(&mut self) {
        ROUTE_BYTES.with(|slot| slot.set(None));
    }
}

fn observe<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    ROUTE_BYTES.with(|slot| assert!(slot.replace(Some(0)).is_none()));
    let scope = RouteScope;
    let result = operation();
    let bytes = ROUTE_BYTES.with(|slot| slot.take().unwrap());
    drop(scope);
    (result, bytes)
}

// Deliberately independent copy of the original routing schema. It consumes
// the entire input with default Serde and is not the production probe.
#[derive(Deserialize)]
struct OriginalRoute {
    effect: OriginalEffect,
}

#[derive(Deserialize)]
struct OriginalEffect {
    encrypted_payload: Option<OriginalPayload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum OriginalPayload {
    Target(IgnoredAny),
    Running(IgnoredAny),
    ProviderCopy(IgnoredAny),
    BoundedRunning(IgnoredAny),
}

impl OriginalPayload {
    fn selects_bounded(self) -> bool {
        match self {
            Self::BoundedRunning(value) => {
                let IgnoredAny = value;
                true
            }
            Self::Target(value) | Self::Running(value) | Self::ProviderCopy(value) => {
                let IgnoredAny = value;
                false
            }
        }
    }
}

fn original_route(bytes: &[u8]) -> Result<bool, serde_json::Error> {
    let route: OriginalRoute = serde_json::from_slice(bytes)?;
    Ok(route
        .effect
        .encrypted_payload
        .is_some_and(OriginalPayload::selects_bounded))
}

fn original_decode(
    bytes: &[u8],
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    handle: &AuditOperationHandle,
    caller: AuditCaller,
) -> Result<PreparedTargetMutation, AuditAuthorityError> {
    handle.verify(key, identity, caller)?;
    if bytes.len() > crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
        return Err(AuditAuthorityError::InvalidInput);
    }
    let decoded = if original_route(bytes).map_err(|_| AuditAuthorityError::InvalidInput)? {
        decode_unowned(bytes)?
    } else {
        PreparedTargetMutation::decode(bytes)?
    };
    if decoded.handle() != handle {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    decoded.command().verify_retained(key, identity, caller)?;
    if serde_json::to_vec(&decoded).map_err(|_| AuditAuthorityError::BindingMismatch)? != bytes {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    Ok(decoded)
}

fn sign_independently(prepared: &mut PreparedTargetMutation) {
    let mutation = original_mac(
        &key(),
        b"openpacketcore/management-audit/netconf-target/v1\0",
        &prepared.command().effect,
    );
    let mut body = prepared.handle().body.clone();
    body.mutation = Some(mutation);
    body.binding = AuditOperationBinding::project(&privacy(), &body.event, 0, &mutation).unwrap();
    prepared.command_mut().handle = AuditOperationHandle {
        mac: original_mac(
            &key(),
            b"openpacketcore/management-audit/operation-handle/v1\0",
            &body,
        ),
        body,
    };
}

#[tokio::test]
async fn native_route_bounded_hint_stops_before_ciphertext() {
    // Removing the production shortcut must make this fail after successful
    // decoding: real slice-parser traversal grows with the ciphertext again.
    for length in [1_024, 65_534] {
        let pool = ConfigPreparationPool::bounded_v1();
        let plaintext = format!("\"{}\"", "x".repeat(length));
        let mut prepared = signed(payload(&pool, plaintext.as_bytes()).await);
        sign_independently(&mut prepared);
        let bytes = serde_json::to_vec(prepared.command()).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let ciphertext_start = text.find("\"encrypted_blob\":[").unwrap();
        let mut old_input = serde_json::Deserializer::from_slice(&bytes);
        let _: OriginalRoute = OriginalRoute::deserialize(&mut old_input).unwrap();
        old_input.end().unwrap();
        assert_eq!(
            old_input.into_iter::<IgnoredAny>().byte_offset(),
            bytes.len()
        );
        let (result, consumed) = observe(|| {
            PreparedTargetMutation::decode_retained(
                &bytes,
                &key(),
                identity(),
                prepared.handle(),
                event().caller,
            )
        });
        let decoded = result.unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        assert_eq!(
            decoded,
            original_decode(
                &bytes,
                &key(),
                identity(),
                prepared.handle(),
                event().caller
            )
            .unwrap()
        );
        assert!(consumed > 0, "NATIVE_ROUTE_OBSERVER_MUST_RUN");
        assert!(
            consumed < ciphertext_start,
            "NATIVE_ROUTE_PAYLOAD_RESCAN_RED consumed={consumed} ciphertext_start={ciphertext_start} total={}",
            bytes.len()
        );
        assert!(decoded.preparation.is_none());
        eprintln!(
            "NATIVE_ROUTE_WORK consumed={consumed} total={}",
            bytes.len()
        );
        drop(decoded);
        drop(prepared);
        all_slots_available(&pool);
    }
}

#[test]
fn native_route_legacy_unsupported_and_decoy_outcomes_match_original() {
    // A substring search, permissive fallback, or stopping at a legacy tag
    // without the old parser would fail these independent literal outcomes.
    let cases: &[(&[u8], Option<bool>)] = &[
        (br#"{"effect":{"encrypted_payload":null}}"#, Some(false)),
        (br#"{"effect":{}}"#, Some(false)),
        (br#"{"effect":{"encrypted_payload":{"target":[1,2]}}}"#, Some(false)),
        (br#"{"effect":{"encrypted_payload":{"running":null}}}"#, Some(false)),
        (br#"{"effect":{"encrypted_payload":{"provider-copy":{}}}}"#, Some(false)),
        (br#"{"effect":{"encrypted_payload":{"bounded-running":{}}}}"#, Some(true)),
        (br#"{"decoy":{"effect":{"encrypted_payload":{"bounded-running":{}}}},"effect":{"encrypted_payload":null}}"#, Some(false)),
        (br#"{"effect":{"unrelated":{"encrypted_payload":{"bounded-running":{}}},"encrypted_payload":{"running":null}}}"#, Some(false)),
        (br#"{"effect":{"encrypted_payload":{"running":{"bounded-running":{}}}}}"#, Some(false)),
        (br#"{"effect":{"encrypted_payload":{"future-running":{}}}}"#, None),
        (br#"{"effect":{"encrypted_payload":{"running":null,"bounded-running":{}}}}"#, None),
        (br#"{"effect":{"encrypted_payload":{"running":null},"encrypted_payload":{"bounded-running":{}}}}"#, None),
        (br#"{"effect":{"encrypted_payload":null},"effect":{"encrypted_payload":{"bounded-running":{}}}}"#, None),
        (br#"{"effect":{"encrypted_payload":{"running":null}}} trailing"#, None),
        (br#"{"effect":{"encrypted_payload":{"running":[1,2"#, None),
        (br#"{"effect":{"encrypted_payload":"bounded-running"}}"#, None),
    ];
    for (index, (bytes, expected)) in cases.iter().enumerate() {
        assert_eq!(
            original_route(bytes).ok(),
            *expected,
            "original case {index}"
        );
        assert_eq!(
            uses_bounded(bytes).ok(),
            *expected,
            "NATIVE_ROUTE_LEGACY_{index}"
        );
    }
}

#[tokio::test]
async fn native_route_hint_never_accepts_structural_or_noncanonical_tail() {
    let pool = ConfigPreparationPool::bounded_v1();
    let mut prepared = signed(payload(&pool, br#"{"enabled":true}"#).await);
    sign_independently(&mut prepared);
    let original = serde_json::to_vec(prepared.command()).unwrap();
    let text = std::str::from_utf8(&original).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let effect = serde_json::to_string(&value["effect"]).unwrap();
    let handle = serde_json::to_string(&value["handle"]).unwrap();
    let payload = serde_json::to_string(&value["effect"]["encrypted_payload"]).unwrap();
    let mut unknown = value.clone();
    unknown["unknown"] = json!({"effect":{"encrypted_payload":{"bounded-running":{}}}});
    let mut scalar = value.clone();
    scalar["effect"]["encrypted_payload"]["bounded-running"]["commit"]["record"]
        ["encrypted_blob"] = json!([256]);
    let mut oversized = value.clone();
    oversized["effect"]["encrypted_payload"]["bounded-running"]["commit"]["record"]["principal"] =
        json!("x".repeat(crate::consensus::types::CONFIG_PRINCIPAL_MAX_BYTES + 1));
    let mut tampered = value.clone();
    let ciphertext = tampered["effect"]["encrypted_payload"]["bounded-running"]["commit"]["record"]
        ["encrypted_blob"]
        .as_array_mut()
        .unwrap();
    let last = ciphertext.last_mut().unwrap();
    *last = json!(last.as_u64().unwrap() ^ 1);
    let mut cases = vec![
        format!("{text} ").into_bytes(),
        format!(" {text}").into_bytes(),
        format!("{{\"effect\":{effect},\"handle\":{handle}}}").into_bytes(),
        format!("{{\"handle\":{handle},\"effect\":{effect},\"effect\":{effect}}}").into_bytes(),
        format!("{{\"handle\":{handle},\"effect\":{effect},\"handle\":{handle}}}").into_bytes(),
        text.replacen("\"effect\":{", "\"effect\":{\"format\":1,", 1)
            .into_bytes(),
        text.replacen(
            "\"resolution\":null",
            &format!("\"encrypted_payload\":{payload},\"resolution\":null"),
            1,
        )
        .into_bytes(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&scalar).unwrap(),
        serde_json::to_vec(&tampered).unwrap(),
        serde_json::to_vec(&oversized).unwrap(),
        text.replacen("bounded-running", "bounded\\u002drunning", 1)
            .into_bytes(),
        original[..original.len() - 1].to_vec(),
        text.as_bytes()[..text.find("\"encrypted_blob\":[").unwrap() + 18].to_vec(),
    ];
    let mut extra_tag = value.clone();
    extra_tag["effect"]["encrypted_payload"]["running"] = json!(null);
    cases.push(serde_json::to_vec(&extra_tag).unwrap());
    for (index, bytes) in cases.iter().enumerate() {
        assert_ne!(bytes, &original, "effective adversarial case {index}");
        // Each case actually reaches the hint. A rejection before routing
        // cannot accidentally qualify the retained validation boundary.
        assert!(uses_bounded(bytes).unwrap(), "hint case {index}");
        assert!(
            original_decode(bytes, &key(), identity(), prepared.handle(), event().caller).is_err()
        );
        assert!(
            PreparedTargetMutation::decode_retained(
                bytes,
                &key(),
                identity(),
                prepared.handle(),
                event().caller
            )
            .is_err(),
            "NATIVE_ROUTE_FULL_REJECTION_{index}"
        );
    }
    drop(prepared);
    all_slots_available(&pool);
}

#[tokio::test]
async fn native_route_original_scope_and_size_precede_hint_without_ownership() {
    let pool = ConfigPreparationPool::bounded_v1();
    let mut prepared = signed(payload(&pool, b"null").await);
    sign_independently(&mut prepared);
    let bytes = serde_json::to_vec(prepared.command()).unwrap();
    let correct_key = key();
    let wrong_key = AuditKey::new([0x42; 32]).unwrap();
    let wrong_identity = ConfigConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0x43; 32]),
        identity().configuration_id(),
        identity().configuration_epoch(),
    );
    let wrong_caller = AuditCaller::project(&privacy(), "synthetic", "other-principal").unwrap();
    for (supplied_key, supplied_identity, supplied_caller) in [
        (&wrong_key, identity(), event().caller),
        (&correct_key, wrong_identity, event().caller),
        (&correct_key, identity(), wrong_caller),
    ] {
        let (result, consumed) = observe(|| {
            PreparedTargetMutation::decode_retained(
                &bytes,
                supplied_key,
                supplied_identity,
                prepared.handle(),
                supplied_caller,
            )
        });
        assert!(result.is_err(), "NATIVE_ROUTE_INDEPENDENT_SCOPE");
        assert_eq!(consumed, 0, "NATIVE_ROUTE_AUTH_BEFORE_PARSE");
    }
    let too_large = vec![b' '; crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES + 1];
    let (result, consumed) = observe(|| {
        PreparedTargetMutation::decode_retained(
            &too_large,
            &key(),
            identity(),
            prepared.handle(),
            event().caller,
        )
    });
    assert!(result.is_err());
    assert_eq!(consumed, 0, "NATIVE_ROUTE_WHOLE_SIZE_BEFORE_PARSE");

    let mut body = prepared.handle().body.clone();
    body.nonce[0] ^= 1;
    let other = AuditOperationHandle {
        mac: original_mac(
            &key(),
            b"openpacketcore/management-audit/operation-handle/v1\0",
            &body,
        ),
        body,
    };
    other.verify(&key(), identity(), event().caller).unwrap();
    assert!(PreparedTargetMutation::decode_retained(
        &bytes,
        &key(),
        identity(),
        &other,
        event().caller
    )
    .is_err());
    let decoded = PreparedTargetMutation::decode_retained(
        &bytes,
        &key(),
        identity(),
        prepared.handle(),
        event().caller,
    )
    .unwrap();
    assert_eq!(
        decoded,
        original_decode(
            &bytes,
            &key(),
            identity(),
            prepared.handle(),
            event().caller
        )
        .unwrap()
    );
    assert!(decoded.preparation.is_none());
    assert!(decoded.encode().is_err());
    assert!(decoded
        .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
        .is_err());
    let foreign = ConfigPreparationPool::bounded_v1();
    assert!(decoded
        .begin_submission(&foreign, ConfigCapacityProfile::BoundedV1)
        .is_err());
    all_slots_available(&foreign);
    drop(decoded);
    drop(prepared);
    all_slots_available(&pool);
}

#[tokio::test]
async fn native_route_legacy_original_keeps_bytes_and_acceptance() {
    let pool = ConfigPreparationPool::bounded_v1();
    let bounded = signed(payload(&pool, b"null").await);
    let mut effect = bounded.command().effect.clone();
    effect.encrypted_payload = Some(TargetPayloadV1::Running {
        commit: Box::new(bounded.bounded_running().unwrap().commit().clone()),
        confirmation_ownership: None,
    });
    let mut legacy = PreparedTargetMutation::new(bounded.handle().clone(), effect, None);
    sign_independently(&mut legacy);
    let bytes = serde_json::to_vec(legacy.command()).unwrap();
    assert!(!uses_bounded(&bytes).unwrap());
    let decoded = PreparedTargetMutation::decode_retained(
        &bytes,
        &key(),
        identity(),
        legacy.handle(),
        event().caller,
    )
    .unwrap();
    assert_eq!(
        decoded,
        original_decode(&bytes, &key(), identity(), legacy.handle(), event().caller).unwrap()
    );
    assert_eq!(decoded.encode().unwrap(), bytes);
    let mut decoy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    decoy["unrelated"] = json!({"effect":{"encrypted_payload":{"bounded-running":{}}}});
    let decoy = serde_json::to_vec(&decoy).unwrap();
    assert!(!uses_bounded(&decoy).unwrap());
    assert!(PreparedTargetMutation::decode_retained(
        &decoy,
        &key(),
        identity(),
        legacy.handle(),
        event().caller
    )
    .is_err());
    drop(bounded);
    all_slots_available(&pool);
}
