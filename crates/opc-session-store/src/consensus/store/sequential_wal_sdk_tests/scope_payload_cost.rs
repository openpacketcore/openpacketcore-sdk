use super::scope_authority::{Admission, Clock};
use super::*;
use crate::scope_authority::tests::{execution, identity};
use crate::scope_authority::*;
use crate::scope_batch::tests::{key, value};
use crate::scope_batch::*;
use crate::sqlite::consensus::scope_payload_decode_observer;
use std::sync::atomic::AtomicU64;

async fn wait_for_all_applied(fleet: &Fleet, index: u64) {
    tokio::time::timeout(
        super::super::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
        async {
            while !fleet.stores.iter().all(|store| {
                store
                    .status()
                    .applied_index
                    .is_some_and(|applied| applied >= index)
            }) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        },
    )
    .await
    .expect("every voter completes the measured write within the original operation bound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_large_child_write_decodes_one_payload_per_voter_independent_of_history() {
    let mut observations = Vec::new();
    for history in [0_u8, 32] {
        let mut fleet = Fleet::new("scope_large_child_constant_decodes");
        fleet.clock = Some(Arc::new(Clock(AtomicU64::new(0))));
        fleet.open().await;
        let result = AssertUnwindSafe(async {
            let leader = fleet.stores.iter().position(|store| store.status().leader_id == Some(store.status().node_id)).unwrap();
            let store = &fleet.stores[leader];
            let scope = ScopeId::new(
                fleet.topologies[0].consensus_identity().unwrap(),
                TenantId::from_static("scope-payload-decode-bound"),
                NetworkFunctionKind::smf(),
                [history + 1; 32],
            ).unwrap();
            let authority = ScopeAuthorityStore::new(Arc::new(store.clone()), scope.clone(), Arc::new(Admission)).unwrap();
            let granted = authority.admit(
                &identity("worker-1"),
                &ScopeAuthorityRequest::new(scope.clone(), [1; 16], 0, ScopeAuthorityOperation::AdmitInitial { execution: execution(1) }).unwrap(),
            ).await.unwrap();
            let reader = ScopeBatchStore::new(Arc::new(store.clone()), granted.stamp().namespace().clone(), Arc::new(Admission)).unwrap();
            for sequence in 1..=history {
                reader.execute(
                    &identity("worker-1"),
                    &ScopeBatchRequest::in_lane(granted.stamp(), [sequence + 1; 16], 0, u64::from(sequence), vec![ScopeChildMutation::Create { key: key(sequence), value: value(sequence), claims: vec![] }], vec![]).unwrap(),
                ).await.unwrap();
            }
            wait_for_all_applied(&fleet, store.status().applied_index.unwrap()).await;
            let encoded = value(1).envelope().to_vec();
            let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(&encoded).unwrap();
            let overhead = encoded.len() - envelope.ciphertext_and_tag.len();
            envelope.ciphertext_and_tag.resize(MAX_SCOPE_CHILD_VALUE_BYTES - 4096 - overhead, 1);
            let large = ScopeSealedValue::new(envelope.encode().unwrap()).unwrap();
            let observer = scope_payload_decode_observer::PayloadDecodeObservation::new(scope, 0);
            for ordinal in 1..=5_u8 {
                let sequence = history + ordinal;
                let before = observer.counts();
                let started = Instant::now();
                reader.execute(
                    &identity("worker-1"),
                    &ScopeBatchRequest::in_lane(granted.stamp(), [sequence + 1; 16], 0, u64::from(sequence), vec![ScopeChildMutation::Create { key: key(sequence), value: large.clone(), claims: vec![] }], vec![]).unwrap(),
                ).await.unwrap();
                let elapsed = started.elapsed();
                let index = store.status().applied_index.unwrap();
                wait_for_all_applied(&fleet, index).await;
                let rows = reader.read_current(&identity("worker-1"), granted.stamp(), &[key(sequence)]).await.unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].as_ref().unwrap().value(), Some(&large));
                if ordinal > 1 {
                    let earlier = reader.read_current(&identity("worker-1"), granted.stamp(), &[key(history + 1)]).await.unwrap();
                    assert_eq!(earlier[0].as_ref().unwrap().value(), Some(&large), "earlier children remain intact");
                }
                let counts = observer.counts().since(&before);
                scope_payload_decode_observer::report(serde_json::json!({"case": "constant-decodes-regression", "history": history, "ordinal": ordinal, "index": index, "elapsed_us": elapsed.as_micros(), "counts": counts}));
                observations.push((history, ordinal, index, fleet.stores.len(), counts));
            }
        }).catch_unwind().await;
        fleet.close().await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
    assert_eq!(observations.len(), 10);
    for (history, ordinal, index, voters, counts) in observations {
        assert_eq!(
            counts.final_audits,
            BTreeMap::from([(index, voters)]),
            "each voter must audit the final stored bytes; history={history}, write={ordinal}"
        );
        assert_eq!(counts.decodes, BTreeMap::from([(index, voters)]), "decode the new payload once per voter, never a previous child's payload; history={history}, write={ordinal}");
    }
}
