//! Local stages of an exact synthetic encrypted Get response. No transport,
//! consensus or selector authority is replaced by these diagnostic samples.

use super::*;
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_session_store::{
    EncryptedSessionPayload, FenceToken, Generation, SessionKey, SessionKeyType, StateClass,
    StateType, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};
use std::io::Write;
use std::time::Instant;

#[tokio::test]
async fn encrypted_get_response_local_stage_profile() {
    let cycles = std::env::var("OPC_CONSUMER_PAYLOAD_PROFILE_CYCLES")
        .map(|value| value.parse::<u8>().expect("numeric profile cycles"))
        .unwrap_or(1);
    assert!((1..=100).contains(&cycles));
    let provider = MemoryKeyProvider::new();
    let tenant = TenantId::from_static("payload-profile");
    provider
        .insert_active_key(
            KeyId::new("payload-profile-key").unwrap(),
            KeyPurpose::Session,
            tenant.clone(),
            Zeroizing::new([0x65; 32]),
        )
        .unwrap();
    for plaintext_bytes in [1_280, 30_092, 58_842] {
        let plaintext = vec![0x57; plaintext_bytes];
        let mut record = StoredSessionRecord {
            key: SessionKey {
                tenant: tenant.clone(),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: bytes::Bytes::from_static(b"payload-profile")
                    .try_into()
                    .unwrap(),
            },
            generation: Generation::new(1),
            owner: OwnerId::new("payload-profile-owner").unwrap(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("payload-profile"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(&plaintext),
        };
        record.payload = EncryptedSessionPayload::encrypt(&provider, &record, "payload-profile")
            .await
            .unwrap();
        let response = consumer_wire_response_from_public(
            ConsumerLeaseWireContext::Other,
            SessionConsumerResponse::Get(Ok(Some(record.clone()))),
        )
        .unwrap();
        let wire = ConsumerWireResponse::Response(ConsumerCallResponse {
            correlation: ConsumerCorrelation {
                sequence: NonZeroU32::new(1).unwrap(),
                nonce: uuid::Uuid::from_u128(1),
            },
            response: Box::new(response),
        });
        let expected = serde_json::to_vec(&wire).unwrap();
        let mut phases: std::collections::BTreeMap<&str, Vec<u64>> =
            std::collections::BTreeMap::new();
        for _ in 0..cycles {
            let started = Instant::now();
            let encoded = serde_json::to_vec(&wire).unwrap();
            sample(&mut phases, "serde_encode", started);
            assert_eq!(encoded, expected);

            let started = Instant::now();
            let decoded: ConsumerWireResponse = serde_json::from_slice(&expected).unwrap();
            sample(&mut phases, "serde_decode", started);
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);

            let started = Instant::now();
            let decoded: ConsumerWireResponse = decode_consumer_frame_payload(&expected).unwrap();
            sample(&mut phases, "strict_decode", started);
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);

            let started = Instant::now();
            write_frame_bounded_until(
                &mut tokio::io::sink(),
                &wire,
                MAX_NEGOTIATED_FRAME_SIZE,
                tokio::time::Instant::now() + DEFAULT_CONSUMER_OPERATION_TIMEOUT,
            )
            .await
            .unwrap();
            sample(&mut phases, "bounded_encode_to_sink", started);

            let started = Instant::now();
            record.payload.validate_envelope().unwrap();
            sample(&mut phases, "validate_envelope", started);

            let started = Instant::now();
            let decoded = record
                .payload
                .decrypt(
                    &provider,
                    &record.key,
                    &record.state_type,
                    record.generation,
                    record.fence,
                    "payload-profile",
                )
                .await
                .unwrap();
            sample(&mut phases, "decrypt", started);
            assert_eq!(*decoded, plaintext);
        }
        let evidence = serde_json::json!({
            "schema": "opc-consumer-payload-local-profile-v1",
            "plaintext_bytes": plaintext_bytes,
            "envelope_bytes": record.payload.len(),
            "wire_bytes": expected.len(),
            "cycles": cycles,
            "phases_us": phases,
            "limits": ["local_stages_only", "no_tls_or_quorum", "synthetic_encrypted_payload"],
        });
        writeln!(
            std::io::stderr(),
            "consumer_payload_local_profile={evidence}"
        )
        .unwrap();
    }
}

fn sample(
    phases: &mut std::collections::BTreeMap<&str, Vec<u64>>,
    name: &'static str,
    started: Instant,
) {
    phases
        .entry(name)
        .or_default()
        .push(u64::try_from(started.elapsed().as_micros()).unwrap());
}
