use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use operator_controller::status_patch::{
    execute_status_patch, status_merge_patch, StatusPatchClient, StatusPatchClientError,
    StatusPatchOutcomeKind, StatusPatchResourceSnapshot,
};
use operator_lifecycle::{ConflictRetryIntent, StatusPatchIntent, TrafficStatusIntent};
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
