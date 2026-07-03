use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use operator_controller::status_patch::{
    execute_owned_status_patch, execute_status_patch, owned_status_merge_patch, status_merge_patch,
    StatusPatchClient, StatusPatchClientError, StatusPatchError, StatusPatchOutcomeKind,
    StatusPatchResourceSnapshot,
};
use operator_lifecycle::{
    ConflictRetryIntent, OwnedStatusProjection, ReconcileIntentError, StatusPatchIntent,
    TrafficStatusIntent,
};
use serde_json::{json, Value};

#[derive(Debug)]
struct FakeStatusClient {
    snapshots: Mutex<VecDeque<StatusPatchResourceSnapshot>>,
    patch_results: Mutex<VecDeque<Result<(), StatusPatchClientError>>>,
    patches: Mutex<Vec<(String, Value)>>,
}

impl FakeStatusClient {
    fn new(
        snapshots: Vec<StatusPatchResourceSnapshot>,
        patch_results: Vec<Result<(), StatusPatchClientError>>,
    ) -> Self {
        Self {
            snapshots: Mutex::new(VecDeque::from(snapshots)),
            patch_results: Mutex::new(VecDeque::from(patch_results)),
            patches: Mutex::new(Vec::new()),
        }
    }

    fn patches(&self) -> Vec<(String, Value)> {
        self.patches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[async_trait]
impl StatusPatchClient for FakeStatusClient {
    async fn get_status_snapshot(
        &self,
    ) -> Result<StatusPatchResourceSnapshot, StatusPatchClientError> {
        self.snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .ok_or(StatusPatchClientError::Unavailable)
    }

    async fn patch_status(
        &self,
        resource_version: &str,
        patch: &Value,
    ) -> Result<(), StatusPatchClientError> {
        self.patches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((resource_version.to_string(), patch.clone()));
        self.patch_results
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .unwrap_or(Ok(()))
    }
}

fn intent() -> StatusPatchIntent {
    let mut intent = StatusPatchIntent::new(
        7,
        TrafficStatusIntent::blocked("RestoreBlocked", "restore evidence missing"),
    );
    intent.conflict_retry = ConflictRetryIntent {
        retry_on_conflict: true,
        max_attempts: 3,
        initial_backoff_millis: 0,
    };
    intent
}

fn snapshot(resource_version: &str, generation: i64, status: Value) -> StatusPatchResourceSnapshot {
    StatusPatchResourceSnapshot::new(resource_version, generation, status)
}

#[derive(Debug, Clone)]
struct CamelCaseProjection {
    observed_generation: i64,
    conflict_retry: ConflictRetryIntent,
    owned_status: Value,
}

impl CamelCaseProjection {
    fn new(observed_generation: i64) -> Self {
        Self {
            observed_generation,
            conflict_retry: ConflictRetryIntent {
                retry_on_conflict: true,
                max_attempts: 3,
                initial_backoff_millis: 0,
            },
            owned_status: json!({
                "observedGeneration": observed_generation,
                "phase": "Reconciling",
                "conditions": [{"type": "Ready", "status": "False"}],
                "alarmConditions": [],
                "recentEvents": [],
                "appConfigStatus": {
                    "accepted": true,
                    "candidateRevision": "rev-1"
                },
                "trafficStatus": {
                    "trafficReady": false,
                    "reason": "WaitingForEvidence"
                }
            }),
        }
    }
}

impl OwnedStatusProjection for CamelCaseProjection {
    fn owned_status(&self) -> Value {
        self.owned_status.clone()
    }

    fn observed_generation(&self) -> i64 {
        self.observed_generation
    }

    fn conflict_retry(&self) -> &ConflictRetryIntent {
        &self.conflict_retry
    }

    fn validate(&self) -> Result<(), ReconcileIntentError> {
        if self.observed_generation < 0 {
            return Err(ReconcileIntentError::InvalidIntent(
                "observed generation must be non-negative".to_string(),
            ));
        }
        Ok(())
    }
}

#[test]
fn status_patch_intent_projection_preserves_legacy_shape() {
    let intent = intent();
    assert_eq!(
        status_merge_patch(&intent)["status"],
        <StatusPatchIntent as OwnedStatusProjection>::owned_status(&intent)
    );
}

#[tokio::test]
async fn status_patch_executor_applies_owned_status_merge_patch() {
    let intent = intent();
    let client = FakeStatusClient::new(
        vec![snapshot("rv1", 7, json!({"unknown": "preserved"}))],
        vec![Ok(())],
    );

    let outcome = match execute_status_patch(&client, &intent).await {
        Ok(value) => value,
        Err(error) => panic!("status patch failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::Patched);
    assert_eq!(outcome.attempts, 1);
    let patches = client.patches();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].0, "rv1");
    assert!(patches[0].1.get("status").is_some());
    assert!(patches[0].1.get("spec").is_none());
    assert!(patches[0].1.get("metadata").is_none());
}

#[tokio::test]
async fn owned_status_executor_patches_camel_case_projection_only_under_status() {
    let projection = CamelCaseProjection::new(7);
    let client = FakeStatusClient::new(
        vec![snapshot("rv1", 7, json!({"unowned": "preserved"}))],
        vec![Ok(())],
    );

    let outcome = match execute_owned_status_patch(&client, &projection).await {
        Ok(value) => value,
        Err(error) => panic!("owned status patch failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::Patched);
    let patches = client.patches();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].0, "rv1");
    let patch = &patches[0].1;
    assert_eq!(patch.as_object().map(serde_json::Map::len), Some(1));
    assert!(patch.get("status").is_some());
    assert!(patch.get("spec").is_none());
    assert!(patch.get("metadata").is_none());
    let status = match patch["status"].as_object() {
        Some(status) => status,
        None => panic!("status patch body should be an object"),
    };
    assert_eq!(status.len(), 7);
    assert!(status.contains_key("observedGeneration"));
    assert!(status.contains_key("phase"));
    assert!(status.contains_key("conditions"));
    assert!(status.contains_key("alarmConditions"));
    assert!(status.contains_key("recentEvents"));
    assert!(status.contains_key("appConfigStatus"));
    assert!(status.contains_key("trafficStatus"));
    assert!(!status.contains_key("unowned"));
    assert_eq!(owned_status_merge_patch(&projection), *patch);
}

#[tokio::test]
async fn owned_status_executor_noops_on_recursive_subset_match() {
    let projection = CamelCaseProjection::new(7);
    let mut current = projection.owned_status();
    current["appConfigStatus"]["extra"] = json!("other-writer");
    let client = FakeStatusClient::new(vec![snapshot("rv1", 7, current)], vec![]);

    let outcome = match execute_owned_status_patch(&client, &projection).await {
        Ok(value) => value,
        Err(error) => panic!("owned status no-op failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::NoOp);
    assert_eq!(outcome.attempts, 0);
    assert!(client.patches().is_empty());
}

#[tokio::test]
async fn owned_status_executor_rejects_non_object_before_client_call() {
    let mut projection = CamelCaseProjection::new(7);
    projection.owned_status = json!(["not", "an", "object"]);
    let client = FakeStatusClient::new(Vec::new(), Vec::new());

    let error = match execute_owned_status_patch(&client, &projection).await {
        Ok(value) => panic!("non-object projection unexpectedly patched: {value:?}"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        StatusPatchError::Schema("owned status must be an object")
    );
    assert!(client.patches().is_empty());
}

#[tokio::test]
async fn owned_status_executor_retries_conflict_with_camel_case_projection() {
    let mut projection = CamelCaseProjection::new(7);
    projection.conflict_retry.max_attempts = 2;
    let client = FakeStatusClient::new(
        vec![snapshot("rv1", 7, json!({})), snapshot("rv2", 7, json!({}))],
        vec![
            Err(StatusPatchClientError::Conflict),
            Err(StatusPatchClientError::Conflict),
        ],
    );

    let outcome = match execute_owned_status_patch(&client, &projection).await {
        Ok(value) => value,
        Err(error) => panic!("owned status conflict retry failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::ConflictExhausted);
    assert_eq!(outcome.attempts, 2);
    assert_eq!(outcome.conflicts, 2);
    let patches = client.patches();
    assert_eq!(patches[0].0, "rv1");
    assert_eq!(patches[1].0, "rv2");
}

#[tokio::test]
async fn owned_status_executor_reports_stale_generation_without_patch() {
    let projection = CamelCaseProjection::new(6);
    let client = FakeStatusClient::new(vec![snapshot("rv1", 7, json!({}))], vec![Ok(())]);

    let outcome = match execute_owned_status_patch(&client, &projection).await {
        Ok(value) => value,
        Err(error) => panic!("owned status stale generation failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::StaleGeneration);
    assert_eq!(outcome.attempts, 0);
    assert!(client.patches().is_empty());
}

#[tokio::test]
async fn status_patch_executor_returns_noop_when_owned_fields_match() {
    let intent = intent();
    let desired_status = status_merge_patch(&intent)["status"].clone();
    let client = FakeStatusClient::new(vec![snapshot("rv1", 7, desired_status)], vec![]);

    let outcome = match execute_status_patch(&client, &intent).await {
        Ok(value) => value,
        Err(error) => panic!("status no-op failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::NoOp);
    assert_eq!(outcome.attempts, 0);
    assert!(client.patches().is_empty());
}

#[tokio::test]
async fn status_patch_executor_retries_conflict_with_fresh_resource_version() {
    let intent = intent();
    let client = FakeStatusClient::new(
        vec![snapshot("rv1", 7, json!({})), snapshot("rv2", 7, json!({}))],
        vec![Err(StatusPatchClientError::Conflict), Ok(())],
    );

    let outcome = match execute_status_patch(&client, &intent).await {
        Ok(value) => value,
        Err(error) => panic!("status retry failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::Patched);
    assert_eq!(outcome.attempts, 2);
    assert_eq!(outcome.conflicts, 1);
    let patches = client.patches();
    assert_eq!(patches[0].0, "rv1");
    assert_eq!(patches[1].0, "rv2");
}

#[tokio::test]
async fn status_patch_executor_reports_conflict_exhausted() {
    let mut intent = intent();
    intent.conflict_retry.max_attempts = 2;
    let client = FakeStatusClient::new(
        vec![snapshot("rv1", 7, json!({})), snapshot("rv2", 7, json!({}))],
        vec![
            Err(StatusPatchClientError::Conflict),
            Err(StatusPatchClientError::Conflict),
        ],
    );

    let outcome = match execute_status_patch(&client, &intent).await {
        Ok(value) => value,
        Err(error) => panic!("status conflict exhaustion failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::ConflictExhausted);
    assert_eq!(outcome.attempts, 2);
    assert_eq!(outcome.conflicts, 2);
}

#[tokio::test]
async fn status_patch_executor_reports_stale_generation_without_patch() {
    let mut intent = intent();
    intent.observed_generation = 6;
    let client = FakeStatusClient::new(vec![snapshot("rv1", 7, json!({}))], vec![Ok(())]);

    let outcome = match execute_status_patch(&client, &intent).await {
        Ok(value) => value,
        Err(error) => panic!("status stale generation failed: {error:?}"),
    };

    assert_eq!(outcome.kind, StatusPatchOutcomeKind::StaleGeneration);
    assert_eq!(outcome.attempts, 0);
    assert!(client.patches().is_empty());
}
