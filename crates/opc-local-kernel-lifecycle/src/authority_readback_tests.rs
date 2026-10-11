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
        let number = events
            .iter()
            .filter(|event| matches!(**event, "current" | "read"))
            .count();
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
    async fn read_current(
        &self,
        child: ScopeChildKey,
    ) -> Result<Option<ScopeChildRecord>, LocalEffectError> {
        assert_eq!(child, ScopeChildKey::new([7; 32]).unwrap());
        let mut events = self.events.lock().unwrap();
        let number = events
            .iter()
            .filter(|event| matches!(**event, "current" | "read"))
            .count();
        events.push("read");
        if self.stale_at == Some(number) {
            return Err(LocalEffectError::Stale);
        }
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
async fn matching_store_readback_preserves_pre_submission_current_and_one_child_cut() {
    let (store, request, child) = fixture();
    let (key, _, _) = commit_readback(&store, request.clone(), child)
        .await
        .unwrap();
    assert_eq!(key.request(), &request);
    assert_eq!(
        *store.events.lock().unwrap(),
        ["current", "execute", "read"]
    );
    store.events.lock().unwrap().clear();
    recheck_record(&store, &key).await.unwrap();
    assert_eq!(*store.events.lock().unwrap(), ["read"]);
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
async fn activation_readback_rejects_a_different_batch_revision() {
    let (mut store, request, child) = fixture();
    let mut row = serde_json::to_value(store.row.as_ref().unwrap()).unwrap();
    row["batch_revision"] = json!(2);
    store.row = Some(serde_json::from_value(row).unwrap());
    assert!(matches!(
        commit_readback(&store, request, child).await,
        Err(LocalEffectError::Stale)
    ), "the exact birth, generation, value and claims cannot substitute for the activation outcome's batch revision");
}

#[tokio::test]
async fn activation_readback_uses_one_current_child_cut_after_submission() {
    let (store, request, child) = fixture();
    let (key, _, _) = commit_readback(&store, request, child).await.unwrap();
    assert_eq!(*store.events.lock().unwrap(), ["current", "execute", "read"],
        "the local pre-submission current check stays; child readback supplies one current-authority cut");
    store.events.lock().unwrap().clear();
    recheck_record(&store, &key).await.unwrap();
    assert_eq!(
        *store.events.lock().unwrap(),
        ["read"],
        "effect rechecks use the child cut without surrounding Current reads"
    );
}

#[tokio::test]
async fn stale_currentness_prevents_submission_and_each_later_child_cut() {
    for boundary in 0..3 {
        let (mut store, request, child) = fixture();
        store.stale_at = Some(boundary);
        if boundary < 2 {
            assert!(matches!(
                commit_readback(&store, request, child).await,
                Err(LocalEffectError::Stale)
            ));
        } else {
            // A change after a completed atomic read cannot retroactively
            // invalidate its cut. A later recheck must observe the stale cut.
            let (key, _, _) = commit_readback(&store, request, child).await.unwrap();
            assert!(matches!(
                recheck_record(&store, &key).await,
                Err(LocalEffectError::Stale)
            ));
        }
        let expected: &[&str] = match boundary {
            0 => &["current"],
            1 => &["current", "execute", "read"],
            _ => &["current", "execute", "read", "read"],
        };
        assert_eq!(store.events.lock().unwrap().as_slice(), expected);
    }
}

#[tokio::test]
async fn committed_readback_checks_every_child_field_without_submitting_again() {
    for field in [
        "valid",
        "missing",
        "namespace",
        "key",
        "birth",
        "generation",
        "batch_revision",
        "value",
        "claims",
    ] {
        let (mut store, request, child) = fixture();
        let mut row = serde_json::to_value(store.row.as_ref().unwrap()).unwrap();
        match field {
            "valid" => {}
            "missing" => row = Value::Null,
            "namespace" => row["namespace"]["incarnation"] = json!(2),
            "key" => row["key"] = json!(vec![99; 32]),
            "birth" | "generation" => row["revision"][field] = json!(2),
            "batch_revision" => row[field] = json!(2),
            "value" => row[field] = serde_json::to_value(value(99)).unwrap(),
            "claims" => row[field] = json!([]),
            _ => unreachable!(),
        }
        store.row = serde_json::from_value(row).unwrap();
        let result = readback_applied(
            &store,
            &store.stamp,
            request.clone(),
            child,
            store.outcome.clone(),
        )
        .await;
        if field == "valid" {
            let (key, outcome, index) = result.unwrap();
            assert_eq!(key.request(), &request);
            assert_eq!(key.batch_revision(), outcome.revision());
            assert_eq!(index, 0);
        } else {
            assert!(matches!(result, Err(LocalEffectError::Stale)), "{field}");
        }
        assert_eq!(*store.events.lock().unwrap(), ["read"], "{field}");
    }
}

#[tokio::test]
async fn committed_readback_rejects_wrong_outcome_before_current_child_observation() {
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
                readback_applied(&store, &store.stamp, request, child, store.outcome.clone()).await,
                Err(LocalEffectError::OutcomeUnknown)
            ),
            "{field}"
        );
        assert!(store.events.lock().unwrap().is_empty(), "{field}");
    }
}

#[cfg(feature = "native-scope")]
#[test]
fn native_authority_readback_keeps_the_backend_effect_type_concrete() {
    async fn construct(
        lifecycle: LocalKernelLifecycle,
        execution: ScopeExecution,
        committed: CommittedScopeAuthority,
        client: opc_session_net::scope::ScopeClient,
    ) -> Result<ScopeKernelAuthority<NativeScopeAuthority>, LocalEffectError> {
        ScopeKernelAuthority::from_scope_client(
            lifecycle,
            execution,
            committed,
            client,
            opc_session_store::scope_scheduler::ScopeWorkClass::Normal,
            std::time::Duration::from_secs(2),
        )
        .await
    }
    async fn readback(
        authority: ScopeKernelAuthority<NativeScopeAuthority>,
        request: ScopeBatchRequest,
        child: ScopeChildKey,
        completion: opc_session_store::scope_batch::ScopeBatchCompletion,
    ) -> Result<CommittedScopeEffect, LocalEffectError> {
        authority
            .readback_activation(request, child, &completion)
            .await
    }
    let _ = (construct, readback);
}
