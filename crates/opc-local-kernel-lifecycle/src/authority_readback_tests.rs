//! Adversarial observations at the private production store boundary. These
//! serialized values cannot construct an authority or local effect capability.
use super::*;
use opc_session_store::scope_authority::{ScopeId, ScopeIncarnation, ScopeNamespace};
use opc_session_store::scope_batch::{ScopeClaimKey, ScopeSealedValue};
use opc_session_store::{SessionConsensusClusterId, SessionConsumerIdentity};
use opc_types::{NetworkFunctionKind, TenantId};
use serde_json::{json, Value};
use std::sync::Mutex;

struct Store {
    stamp: ScopeAuthorityStamp,
    outcome: ScopeBatchOutcome,
    row: Option<ScopeChildRecord>,
    stale_at: Option<usize>,
    events: Mutex<Vec<&'static str>>,
}
#[async_trait::async_trait]
impl ActivationStore for Store {
    fn stamp(&self) -> &ScopeAuthorityStamp {
        &self.stamp
    }
    async fn current(&self) -> Result<(), LocalEffectError> {
        let mut events = self.events.lock().unwrap();
        let number = events.iter().filter(|event| **event == "current").count();
        events.push("current");
        if self.stale_at == Some(number) {
            Err(LocalEffectError::Stale)
        } else {
            Ok(())
        }
    }
    async fn execute(
        &self,
        _request: &ScopeBatchRequest,
    ) -> Result<ScopeBatchOutcome, LocalEffectError> {
        self.events.lock().unwrap().push("execute");
        Ok(self.outcome.clone())
    }
    async fn read(
        &self,
        child: ScopeChildKey,
    ) -> Result<Option<ScopeChildRecord>, LocalEffectError> {
        assert_eq!(child, ScopeChildKey::new([7; 32]).unwrap());
        self.events.lock().unwrap().push("read");
        Ok(self.row.clone())
    }
}
fn value(n: u8) -> ScopeSealedValue {
    ScopeSealedValue::new(
        opc_crypto::CryptoEnvelopeV1 {
            algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
            key_id: opc_key::KeyId::new("readback-fixture").unwrap(),
            nonce: vec![n; 12],
            aad: vec![n; 32],
            ciphertext_and_tag: vec![n; 32],
        }
        .encode()
        .unwrap(),
    )
    .unwrap()
}
fn fixture() -> (Store, ScopeBatchRequest, ScopeChildKey) {
    let cluster = SessionConsensusClusterId::new("readback").unwrap();
    let epoch = opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap();
    let identity = opc_session_store::SessionConsensusIdentity::new(
        cluster,
        opc_consensus::derive_configuration_id(cluster, epoch, &[[1; 32]]),
        epoch,
    );
    let scope = ScopeId::new(
        identity,
        TenantId::from_static("readback"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let execution = ScopeExecution::new(
        SessionConsumerIdentity::new("spiffe://test/readback").unwrap(),
        1,
        [1; 16],
        [2; 16],
        [3; 32],
    )
    .unwrap();
    let stamp: ScopeAuthorityStamp = serde_json::from_value(json!({
        "namespace": ScopeNamespace::new(scope, ScopeIncarnation::new(1).unwrap()).unwrap(),
        "revision": 1, "execution": execution,
    }))
    .unwrap();
    let child = ScopeChildKey::new([7; 32]).unwrap();
    let claims = vec![ScopeClaimKey::new([8; 32]).unwrap()];
    let request = ScopeBatchRequest::new(
        &stamp,
        [9; 16],
        0,
        vec![ScopeChildMutation::Create {
            key: child,
            value: value(7),
            claims: claims.clone(),
        }],
        vec![],
    )
    .unwrap();
    let revision = ScopeChildRevision::new(1, 1).unwrap();
    let outcome = serde_json::from_value(json!({
        "request_digest": request.digest().unwrap(), "lane": 0, "sequence": 1,
        "revision": 1, "rows": [revision], "counters": vec![0; 16],
    }))
    .unwrap();
    let row = serde_json::from_value(json!({
        "namespace": stamp.namespace(), "key": child, "revision": revision,
        "batch_revision": 1, "value": value(7), "claims": claims,
    }))
    .unwrap();
    (
        Store {
            stamp,
            outcome,
            row: Some(row),
            stale_at: None,
            events: Mutex::new(vec![]),
        },
        request,
        child,
    )
}

#[tokio::test]
async fn matching_store_readback_follows_current_execute_current_read_current_order() {
    let (store, request, child) = fixture();
    let (key, _, _) = commit_readback(&store, request.clone(), child)
        .await
        .unwrap();
    assert_eq!(key.request(), &request);
    assert_eq!(
        *store.events.lock().unwrap(),
        ["current", "execute", "current", "read", "current"]
    );
    store.events.lock().unwrap().clear();
    recheck_record(&store, &key).await.unwrap();
    assert_eq!(
        *store.events.lock().unwrap(),
        ["current", "read", "current"]
    );
}

#[tokio::test]
async fn nonmatching_store_outcome_is_unknown_even_with_an_exact_child_row() {
    for field in ["request_digest", "lane", "sequence", "rows"] {
        let (mut store, request, child) = fixture();
        let mut outcome = serde_json::to_value(&store.outcome).unwrap();
        outcome[field] = match field {
            "request_digest" => json!(vec![99; 32]),
            "rows" => json!([]),
            _ => json!(2),
        };
        store.outcome = serde_json::from_value(outcome).unwrap();
        assert!(
            matches!(
                commit_readback(&store, request, child).await,
                Err(LocalEffectError::OutcomeUnknown)
            ),
            "wrong {field}"
        );
        assert_eq!(*store.events.lock().unwrap(), ["current", "execute"]);
    }
}

#[tokio::test]
async fn changed_or_missing_child_readback_never_authorizes_an_effect() {
    for field in [
        "missing",
        "namespace",
        "key",
        "birth",
        "generation",
        "value",
        "claims",
    ] {
        let (mut store, request, child) = fixture();
        let mut row = serde_json::to_value(store.row.as_ref().unwrap()).unwrap();
        match field {
            "namespace" => {
                row["namespace"] = serde_json::to_value(
                    ScopeNamespace::new(request.scope().clone(), ScopeIncarnation::new(2).unwrap())
                        .unwrap(),
                )
                .unwrap()
            }
            "key" => {
                row["key"] = serde_json::to_value(ScopeChildKey::new([99; 32]).unwrap()).unwrap()
            }
            "birth" | "generation" => row["revision"][field] = json!(2),
            "value" => row["value"] = serde_json::to_value(value(99)).unwrap(),
            "claims" => row["claims"] = json!([]),
            "missing" => row = Value::Null,
            _ => unreachable!(),
        }
        store.row = serde_json::from_value(row).unwrap();
        assert!(
            matches!(
                commit_readback(&store, request, child).await,
                Err(LocalEffectError::Stale)
            ),
            "changed {field}"
        );
    }
}

#[tokio::test]
async fn stale_currentness_prevents_submission_and_each_later_read_boundary() {
    for boundary in 0..3 {
        let (mut store, request, child) = fixture();
        store.stale_at = Some(boundary);
        assert!(matches!(
            commit_readback(&store, request, child).await,
            Err(LocalEffectError::Stale)
        ));
        let expected: &[&str] = match boundary {
            0 => &["current"],
            1 => &["current", "execute", "current"],
            _ => &["current", "execute", "current", "read", "current"],
        };
        assert_eq!(store.events.lock().unwrap().as_slice(), expected);
    }
}
