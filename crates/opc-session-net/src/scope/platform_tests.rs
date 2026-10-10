use super::{platform::*, wire::ScopeBinding};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
fn enrollment() -> PodEnrollment {
    PodEnrollment::new(
        ScopeBinding::new(
            [1; 32],
            TenantId::new("test").unwrap(),
            NetworkFunctionKind::new("smf").unwrap(),
            [2; 32],
        )
        .unwrap(),
        "test".into(),
        "worker-0".into(),
        "worker".into(),
        [3; 16],
        "worker".into(),
        [4; 16],
        SpiffeId::new(
            "spiffe://example.test/tenant/test/ns/test/sa/worker/nf/smf/instance/worker-0",
        )
        .unwrap(),
        8443,
    )
    .unwrap()
}
fn pod() -> Value {
    json!({
        "metadata":{"name":"worker-0","namespace":"test","uid":uuid::Uuid::from_bytes([5;16]).to_string(),"resourceVersion":"rv-42",
            "ownerReferences":[{"uid":uuid::Uuid::from_bytes([4;16]).to_string(),"controller":true}]},
        "spec":{"serviceAccountName":"worker"},
        "status":{"podIP":"127.0.0.1","containerStatuses":[{"name":"worker","containerID":"cri-o://container-1","restartCount":99,"state":{"running":{"startedAt":"2026-10-01T00:00:00Z"}}}]}
    })
}

#[tokio::test]
async fn pending_pods_retry_until_the_enrolled_container_is_running() {
    let api = Arc::new(Api {
        pod: Mutex::new(pod()),
        calls: Mutex::new(vec![]),
    });
    let reader = KubernetesBootReader::new(api.clone());
    for status in [
        json!({"phase":"Pending"}),
        json!({"phase":"Pending", "podIP":"", "containerStatuses":[]}),
        json!({"podIP":"127.0.0.1", "containerStatuses":[{"name":"worker", "state":{"waiting":{"reason":"ContainerCreating"}}}]}),
        json!({"podIP":"127.0.0.1", "containerStatuses":[{"name":"worker", "state":{"terminated":{"exitCode":0}}}]}),
        json!({"podIP":"", "containerStatuses":[{"name":"worker", "containerID":"cri-o://container-1", "state":{"running":{"startedAt":"2026-10-01T00:00:00Z"}}}]}),
    ] {
        let mut value = pod();
        value["status"] = status;
        *api.pod.lock().unwrap() = value;
        assert_eq!(
            reader.observe(&enrollment()).await.err(),
            Some(PlatformError::Unavailable)
        );
    }
    // A pending status must never hide a definitive owner mismatch.
    api.pod.lock().unwrap()["metadata"]["ownerReferences"][0]["uid"] =
        json!(uuid::Uuid::from_bytes([8; 16]).to_string());
    assert_eq!(
        reader.observe(&enrollment()).await.err(),
        Some(PlatformError::Invalid)
    );
    *api.pod.lock().unwrap() = pod();
    assert!(reader.observe(&enrollment()).await.is_ok());
}
struct Api {
    pod: Mutex<Value>,
    calls: Mutex<Vec<(String, String)>>,
}
#[tokio::test]
async fn a_still_shown_terminated_container_remains_unavailable_until_running() {
    let mut terminated = pod();
    terminated["status"]["containerStatuses"][0]["state"] =
        json!({"terminated":{"exitCode":137,"reason":"OOMKilled"}});
    let api = Arc::new(Api {
        pod: Mutex::new(terminated),
        calls: Mutex::new(vec![]),
    });
    let reader = KubernetesBootReader::new(api.clone());
    for _ in 0..3 {
        assert_eq!(
            reader.observe(&enrollment()).await.err(),
            Some(PlatformError::Unavailable)
        );
    }
    *api.pod.lock().unwrap() = pod();
    reader.observe(&enrollment()).await.unwrap();
}
#[async_trait::async_trait]
impl KubernetesPodSource for Api {
    async fn get_pod_consistent(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<u8>, PlatformError> {
        self.calls
            .lock()
            .unwrap()
            .push((namespace.into(), name.into()));
        Ok(serde_json::to_vec(&*self.pod.lock().unwrap()).unwrap())
    }
}
#[tokio::test]
async fn exact_namespaced_observation_and_opaque_revision_revalidation() {
    let api = Arc::new(Api {
        pod: Mutex::new(pod()),
        calls: Mutex::new(vec![]),
    });
    let reader = KubernetesBootReader::new(api.clone());
    let observed = reader.observe(&enrollment()).await.unwrap();
    assert_eq!(observed.workload(), &[5; 16]);
    assert_eq!(observed.address().to_string(), "127.0.0.1:8443");
    reader.revalidate(&enrollment(), &observed).await.unwrap();
    api.pod.lock().unwrap()["metadata"]["resourceVersion"] = json!("rv-1");
    assert_eq!(
        reader
            .revalidate(&enrollment(), &observed)
            .await
            .unwrap_err(),
        PlatformError::Changed
    );
    assert!(api
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| call == &("test".into(), "worker-0".into())));
}
#[tokio::test]
async fn deleted_replaced_unowned_or_nonrunning_pods_cannot_bootstrap() {
    let api = Arc::new(Api {
        pod: Mutex::new(pod()),
        calls: Mutex::new(vec![]),
    });
    let reader = KubernetesBootReader::new(api.clone());
    for (pointer, bad) in [
        ("/metadata/name", json!("other")),
        ("/metadata/namespace", json!("other")),
        ("/spec/serviceAccountName", json!("other")),
        (
            "/metadata/ownerReferences/0/uid",
            json!(uuid::Uuid::from_bytes([8; 16]).to_string()),
        ),
        ("/metadata/ownerReferences/0/controller", json!(false)),
        ("/status/containerStatuses/0/name", json!("other")),
        ("/status/containerStatuses/0/containerID", json!("")),
        (
            "/status/containerStatuses/0/state",
            json!({"terminated":{"exitCode":0}}),
        ),
        ("/status/podIP", json!("bad address")),
        ("/metadata/resourceVersion", json!("")),
    ] {
        let mut value = pod();
        *value.pointer_mut(pointer).unwrap() = bad;
        *api.pod.lock().unwrap() = value;
        assert!(reader.observe(&enrollment()).await.is_err(), "{pointer}");
    }
    let mut value = pod();
    value["metadata"]["deletionTimestamp"] = json!("2026-10-01T00:00:01Z");
    *api.pod.lock().unwrap() = value;
    assert!(reader.observe(&enrollment()).await.is_err());
    *api.pod.lock().unwrap() = pod();
    let observed = reader.observe(&enrollment()).await.unwrap();
    api.pod.lock().unwrap()["status"]["containerStatuses"][0]["containerID"] =
        json!("cri-o://next-container");
    assert_eq!(
        reader
            .revalidate(&enrollment(), &observed)
            .await
            .unwrap_err(),
        PlatformError::Changed
    );
}
