use super::{evidence::*, wire::*};
use opc_session_store::scope_authority::*;
use serde_json::Value;
use std::sync::Mutex;
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../docs/rfc/026-scope-authenticated-transport-vectors.json"
    ))
    .unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    v.as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn field(v: &Value, name: &str) -> String {
    v[name].as_str().unwrap().to_owned()
}
fn boot() -> BootAuthorityRecord {
    let v = vectors();
    BootAuthorityRecord::new(
        ScopeBinding::decode(&bytes(&v["scope"]["transport_bytes_hex"])).unwrap(),
        postcard::from_bytes(&bytes(&v["executions"][0]["canonical_postcard_hex"])).unwrap(),
        bytes(&v["executions"][0]["public_key_hex"])
            .try_into()
            .unwrap(),
        b"uid".to_vec(),
        b"not-a-counter".to_vec(),
    )
    .unwrap()
}
struct Boots(Mutex<BootAuthorityRecord>);
#[async_trait::async_trait]
impl ScopeBootAuthority for Boots {
    async fn read_current(
        &self,
        _scope: &ScopeBinding,
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn read_known(
        &self,
        _scope: &ScopeBinding,
        _key: [u8; 32],
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        Ok(self.0.lock().unwrap().clone())
    }
}
#[tokio::test]
async fn independently_current_ticket_must_match_every_boot_field_and_opaque_reference() {
    let expected = boot();
    let source = Boots(Mutex::new(expected.clone()));
    assert_eq!(
        verify_current_ticket(
            &source,
            &expected.scope,
            &expected.execution,
            &expected.public_key,
            &expected.reference
        )
        .await
        .unwrap(),
        expected
    );
    for change in 0..5 {
        let mut value = expected.clone();
        match change {
            0 => value.reference.revision = b"different".to_vec(),
            1 => value.reference.record_uid = b"replacement".to_vec(),
            2 => {
                value.scope = ScopeBinding::new(
                    [9; 32],
                    opc_types::TenantId::new("example").unwrap(),
                    opc_types::NetworkFunctionKind::new("worker").unwrap(),
                    [0x22; 32],
                )
                .unwrap()
            }
            3 => {
                value.execution = ScopeExecution::new(
                    value.execution.identity().clone(),
                    999,
                    *value.execution.workload(),
                    *value.execution.process(),
                    *value.execution.boot_key(),
                )
                .unwrap()
            }
            _ => {
                value.public_key = bytes(&vectors()["executions"][1]["public_key_hex"])
                    .try_into()
                    .unwrap()
            }
        }
        *source.0.lock().unwrap() = value;
        assert_eq!(
            verify_current_ticket(
                &source,
                &expected.scope,
                &expected.execution,
                &expected.public_key,
                &expected.reference
            )
            .await
            .unwrap_err(),
            ScopeEvidenceError::Mismatch
        );
    }
}
fn final_record() -> FinalTerminationRecord {
    let v = vectors();
    let c = &v["closure_evidence"]["final_termination"];
    let f = &c["fields"];
    FinalTerminationRecord::new(
        postcard::from_bytes(&bytes(&c["predecessor_stamp_hex"])).unwrap(),
        field(f, "namespace"),
        field(f, "pod_name"),
        bytes(&f["pod_uid_hex"]).try_into().unwrap(),
        field(f, "container_name"),
        field(f, "container_id"),
        0,
        0,
        field(f, "reason"),
        field(f, "message"),
        field(f, "started_at"),
        field(f, "finished_at"),
        field(f, "record_uid").into_bytes(),
        field(f, "record_revision").into_bytes(),
    )
    .unwrap()
}

#[tokio::test]
async fn shared_worker_identity_does_not_substitute_another_slots_ticket_or_boot_key() {
    let first = boot();
    let mut scope_bytes = first.scope.encode();
    *scope_bytes.last_mut().unwrap() ^= 1;
    let second_scope = ScopeBinding::decode(&scope_bytes).unwrap();
    let second_key: [u8; 33] = bytes(&vectors()["executions"][1]["public_key_hex"])
        .try_into()
        .unwrap();
    let second = BootAuthorityRecord::new(
        second_scope,
        ScopeExecution::new(
            first.execution.identity().clone(),
            128,
            [0x55; 16],
            [0x66; 16],
            hash(&second_key),
        )
        .unwrap(),
        second_key,
        b"second-slot-issuance".to_vec(),
        b"second-revision".to_vec(),
    )
    .unwrap();
    assert_eq!(first.execution.identity(), second.execution.identity());
    let principal = opc_types::SpiffeId::new(first.execution.identity().as_str()).unwrap();
    let policy = super::ScopePolicy::new(vec![super::PrincipalGrant::new(
        principal.clone(),
        super::ScopeRole::Worker,
        vec![first.scope.clone(), second.scope.clone()],
    )
    .expect("the shared worker identity is explicitly granted both slots")])
    .unwrap();
    for own in [&first, &second] {
        assert!(policy
            .authorize(
                &principal,
                &own.scope,
                Method::AdmitInitial,
                Class::SafetyControl
            )
            .unwrap()
            .requires_worker_proof());
        let source = Boots(Mutex::new(own.clone()));
        verify_current_ticket(
            &source,
            &own.scope,
            &own.execution,
            &own.public_key,
            &own.reference,
        )
        .await
        .unwrap();
        let other = if own == &first { &second } else { &first };
        for (scope, execution, public_key, reference) in [
            (
                &other.scope,
                &own.execution,
                &own.public_key,
                &own.reference,
            ),
            (
                &own.scope,
                &other.execution,
                &own.public_key,
                &own.reference,
            ),
            (
                &own.scope,
                &own.execution,
                &other.public_key,
                &own.reference,
            ),
            (
                &own.scope,
                &own.execution,
                &own.public_key,
                &other.reference,
            ),
        ] {
            assert_eq!(
                verify_current_ticket(&source, scope, execution, public_key, reference)
                    .await
                    .err(),
                Some(ScopeEvidenceError::Mismatch)
            );
        }
    }
}

#[test]
fn final_termination_commits_full_kubernetes_message_bytes() {
    let vectors = vectors();
    let fixtures = vectors["closure_evidence"]["termination_message_boundaries"]
        .as_array()
        .unwrap();
    assert_eq!(
        fixtures.len(),
        7,
        "file, fallback and expanded API captures are covered"
    );
    for fixture in fixtures {
        let length = fixture["message_bytes"].as_u64().unwrap() as usize;
        let mut record = final_record();
        record.observation.message = format!(
            "{}{}",
            field(fixture, "message_prefix"),
            field(fixture, "message_repeat")
                .repeat(fixture["message_repeat_count"].as_u64().unwrap() as usize)
        );
        assert_eq!(record.observation.message.len(), length);
        let digest = record
            .digest()
            .expect("a complete API capture must remain verifiable");
        assert_eq!(digest.as_slice(), bytes(&fixture["digest_hex"]));
        assert_eq!(
            record
                .observation
                .input(&record.predecessor.encode_canonical().unwrap())
                .unwrap(),
            bytes(&fixture["input_hex"])
        );
        record.observation.message.pop();
        record.observation.message.push('y');
        assert_ne!(
            record.digest().unwrap(),
            digest,
            "the last character is committed"
        );
    }
}

#[test]
fn final_termination_message_commitment_preserves_utf8_without_truncating() {
    let mut record = final_record();
    record.observation.message = format!("{}é", "x".repeat(4094));
    let original = record.digest().unwrap();
    record.observation.message.push('x');
    assert_ne!(record.digest().unwrap(), original);
}

#[test]
fn expanded_api_termination_messages_still_commit_every_byte() {
    let messages = [
        // A 4096-byte tail cut inside a four-byte UTF-8 character leaves three
        // invalid bytes, each replaced by a three-byte U+FFFD in the API string.
        format!("{}{}", "\u{fffd}".repeat(3), "x".repeat(4093)),
        "\u{fffd}".repeat(4096),
        "\u{fffd}".repeat(12288),
        format!("runtime reported failure: {}", "x".repeat(4096)),
        "x".repeat(65536),
    ];
    let mut record = final_record();
    let stamp = record.predecessor.encode_canonical().unwrap();
    let input_length = record.observation.input(&stamp).unwrap().len();
    for message in messages {
        record.observation.message = message;
        let digest = record
            .digest()
            .expect("an expanded API message must not prevent predecessor closure");
        assert_eq!(
            record.observation.input(&stamp).unwrap().len(),
            input_length,
            "the commitment size is independent of the message length"
        );
        record.observation.message.push('y');
        assert_ne!(
            record.digest().unwrap(),
            digest,
            "the entire message is committed"
        );
    }
}

fn local_record() -> LocalClosureRecord {
    let v = vectors();
    let c = &v["closure_evidence"]["local_quiescence"];
    LocalClosureRecord::new(
        postcard::from_bytes(&bytes(&c["current_stamp_hex"])).unwrap(),
        bytes(&c["fence_nonce_hex"]).try_into().unwrap(),
    )
    .unwrap()
}
struct Closures {
    altered: Mutex<bool>,
}
#[async_trait::async_trait]
impl ScopeClosureSource for Closures {
    async fn read_final(
        &self,
        _predecessor: &ScopeAuthorityStamp,
        _digest: [u8; 32],
    ) -> Result<FinalTerminationRecord, ScopeEvidenceError> {
        let mut result = final_record();
        if *self.altered.lock().unwrap() {
            result.observation.container_id.push_str("-replacement");
        }
        Ok(result)
    }
    async fn read_local(
        &self,
        _predecessor: &ScopeAuthorityStamp,
        _digest: [u8; 32],
    ) -> Result<LocalClosureRecord, ScopeEvidenceError> {
        let mut result = local_record();
        if *self.altered.lock().unwrap() {
            result.fence_nonce[0] ^= 1;
        }
        Ok(result)
    }
}
#[tokio::test]
async fn independent_closure_digest_is_exact_native_stamp_and_retained_observation() {
    let v = vectors();
    let final_record = final_record();
    let local_record = local_record();
    let retained = LocalClosureRecord::new(
        local_record.predecessor().clone(),
        *local_record.fence_nonce(),
    )
    .unwrap();
    assert_eq!(retained.digest().unwrap(), local_record.digest().unwrap());
    assert_eq!(
        final_record.digest().unwrap().as_slice(),
        bytes(&v["closure_evidence"]["final_termination"]["digest_hex"])
    );
    assert_eq!(
        local_record.digest().unwrap().as_slice(),
        bytes(&v["closure_evidence"]["local_quiescence"]["digest_hex"])
    );
    let source = Closures {
        altered: Mutex::new(false),
    };
    for (predecessor, kind, digest) in [
        (
            &final_record.predecessor,
            ScopeClosureKind::FinalTermination,
            final_record.digest().unwrap(),
        ),
        (
            &local_record.predecessor,
            ScopeClosureKind::LocalQuiescence,
            local_record.digest().unwrap(),
        ),
    ] {
        let evidence = ScopeClosureEvidence::new(kind, digest).unwrap();
        *source.altered.lock().unwrap() = false;
        verify_closure(&source, predecessor, &evidence)
            .await
            .unwrap();
        *source.altered.lock().unwrap() = true;
        assert_eq!(
            verify_closure(&source, predecessor, &evidence).await,
            Err(ScopeEvidenceError::Mismatch)
        );
    }
    let mut wrong_pod = final_record;
    wrong_pod.observation.pod_uid = [9; 16];
    assert!(wrong_pod.digest().is_err());
    // A positive committed Close is checked against the native checkpoint,
    // never by this external-source verifier accepting a client digest.
    assert!(verify_closure(
        &source,
        &local_record.predecessor,
        &ScopeClosureEvidence::new(ScopeClosureKind::CommittedClose, [7; 32]).unwrap()
    )
    .await
    .is_err());
}
