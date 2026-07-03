//! Kubernetes status patch executor contract.

use std::{error::Error, fmt, time::Duration};

use async_trait::async_trait;
use operator_lifecycle::{
    ConflictRetryIntent, OwnedStatusProjection, ReconcileIntentError, StatusPatchIntent,
};
use serde_json::{json, Value};

/// Snapshot of the Kubernetes resource status boundary before patching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPatchResourceSnapshot {
    /// Kubernetes `metadata.resourceVersion`.
    pub resource_version: String,
    /// Kubernetes `metadata.generation`.
    pub generation: i64,
    /// Current resource `status` object.
    pub status: Value,
}

impl StatusPatchResourceSnapshot {
    /// Construct a resource snapshot.
    pub fn new(resource_version: impl Into<String>, generation: i64, status: Value) -> Self {
        Self {
            resource_version: resource_version.into(),
            generation,
            status,
        }
    }
}

/// Minimal Kubernetes API boundary needed by the status patch executor.
#[async_trait]
pub trait StatusPatchClient: Send + Sync {
    /// Read the latest resource version, generation, and status.
    async fn get_status_snapshot(
        &self,
    ) -> Result<StatusPatchResourceSnapshot, StatusPatchClientError>;

    /// Apply a status merge patch against the supplied resource version.
    async fn patch_status(
        &self,
        resource_version: &str,
        patch: &Value,
    ) -> Result<(), StatusPatchClientError>;
}

/// Error returned by an injected Kubernetes status client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusPatchClientError {
    /// Kubernetes resource-version conflict.
    Conflict,
    /// Resource was not found.
    NotFound,
    /// Client or API server was unavailable.
    Unavailable,
    /// Patch schema or serialization failed.
    Schema,
}

impl StatusPatchClientError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Conflict => "status_patch_client_conflict",
            Self::NotFound => "status_patch_client_not_found",
            Self::Unavailable => "status_patch_client_unavailable",
            Self::Schema => "status_patch_client_schema",
        }
    }
}

impl fmt::Display for StatusPatchClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for StatusPatchClientError {}

/// Final status patch executor outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPatchOutcome {
    /// Machine-readable outcome kind.
    pub kind: StatusPatchOutcomeKind,
    /// Number of patch attempts made.
    pub attempts: u8,
    /// Number of resource-version conflicts observed.
    pub conflicts: u8,
    /// Resource version used for the final decision, when known.
    pub resource_version: Option<String>,
}

impl StatusPatchOutcome {
    fn new(
        kind: StatusPatchOutcomeKind,
        attempts: u8,
        conflicts: u8,
        resource_version: Option<String>,
    ) -> Self {
        Self {
            kind,
            attempts,
            conflicts,
            resource_version,
        }
    }
}

/// Machine-readable status patch outcome kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusPatchOutcomeKind {
    /// Patch was applied.
    Patched,
    /// Current status already matched the SDK-owned status projection.
    NoOp,
    /// Resource generation is newer than the intent's observed generation.
    StaleGeneration,
    /// Resource-version conflicts exhausted the configured retry budget.
    ConflictExhausted,
}

impl StatusPatchOutcomeKind {
    /// Stable machine-readable outcome code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Patched => "patched",
            Self::NoOp => "no-op",
            Self::StaleGeneration => "stale-generation",
            Self::ConflictExhausted => "conflict-exhausted",
        }
    }
}

/// Error returned by the status patch executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusPatchError {
    /// Input intent failed SDK validation.
    InvalidIntent(ReconcileIntentError),
    /// Kubernetes client returned an unrecoverable error.
    Client(StatusPatchClientError),
    /// Snapshot or patch shape was invalid.
    Schema(&'static str),
}

impl StatusPatchError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidIntent(_) => "status_patch_invalid_intent",
            Self::Client(error) => error.as_str(),
            Self::Schema(_) => "status_patch_schema",
        }
    }
}

impl fmt::Display for StatusPatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for StatusPatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidIntent(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::Schema(_) => None,
        }
    }
}

/// Execute a Kubernetes status merge-patch loop for a [`StatusPatchIntent`].
///
/// The generated patch contains only the top-level `status` object and only the
/// SDK-owned status fields. Unknown fields already present under status are
/// preserved by Kubernetes merge-patch semantics because they are omitted from
/// the patch body.
///
/// # Errors
///
/// Returns [`StatusPatchError`] for invalid intents, invalid snapshots, and
/// unrecoverable client errors. Resource-version conflicts are retried according
/// to the intent and return [`StatusPatchOutcomeKind::ConflictExhausted`] when
/// the retry budget is exhausted.
pub async fn execute_status_patch<C>(
    client: &C,
    intent: &StatusPatchIntent,
) -> Result<StatusPatchOutcome, StatusPatchError>
where
    C: StatusPatchClient + ?Sized,
{
    execute_owned_status_patch(client, intent).await
}

/// Execute a Kubernetes status merge-patch loop for any owned status projection.
///
/// The generated patch contains exactly one top-level key, `status`, whose
/// value is `projection.owned_status()`. Kubernetes merge-patch semantics
/// preserve status fields not listed by the projection.
///
/// # Errors
///
/// Returns [`StatusPatchError`] for invalid projections, invalid snapshots, and
/// unrecoverable client errors. Resource-version conflicts are retried according
/// to the projection and return [`StatusPatchOutcomeKind::ConflictExhausted`]
/// when the retry budget is exhausted.
pub async fn execute_owned_status_patch<C, P>(
    client: &C,
    projection: &P,
) -> Result<StatusPatchOutcome, StatusPatchError>
where
    C: StatusPatchClient + ?Sized,
    P: OwnedStatusProjection + ?Sized,
{
    projection
        .validate()
        .map_err(StatusPatchError::InvalidIntent)?;
    let owned_status = projection.owned_status();
    if !owned_status.is_object() {
        return Err(StatusPatchError::Schema("owned status must be an object"));
    }

    let max_attempts = max_attempts(projection.conflict_retry());
    let mut attempts = 0_u8;
    let mut conflicts = 0_u8;

    loop {
        let snapshot = client
            .get_status_snapshot()
            .await
            .map_err(StatusPatchError::Client)?;
        validate_snapshot(&snapshot)?;

        if projection.observed_generation() < snapshot.generation {
            return Ok(StatusPatchOutcome::new(
                StatusPatchOutcomeKind::StaleGeneration,
                attempts,
                conflicts,
                Some(snapshot.resource_version),
            ));
        }

        if owned_status_subset_matches(&snapshot.status, &owned_status) {
            return Ok(StatusPatchOutcome::new(
                StatusPatchOutcomeKind::NoOp,
                attempts,
                conflicts,
                Some(snapshot.resource_version),
            ));
        }

        attempts = attempts.saturating_add(1);
        let patch = json!({ "status": owned_status.clone() });
        match client
            .patch_status(snapshot.resource_version.as_str(), &patch)
            .await
        {
            Ok(()) => {
                return Ok(StatusPatchOutcome::new(
                    StatusPatchOutcomeKind::Patched,
                    attempts,
                    conflicts,
                    Some(snapshot.resource_version),
                ));
            }
            Err(StatusPatchClientError::Conflict) => {
                conflicts = conflicts.saturating_add(1);
                if attempts >= max_attempts {
                    return Ok(StatusPatchOutcome::new(
                        StatusPatchOutcomeKind::ConflictExhausted,
                        attempts,
                        conflicts,
                        Some(snapshot.resource_version),
                    ));
                }
                sleep_before_retry(projection.conflict_retry(), attempts).await;
            }
            Err(error) => return Err(StatusPatchError::Client(error)),
        }
    }
}

/// Build the Kubernetes merge-patch body for a status intent.
///
/// The returned value is suitable for a status subresource merge patch and does
/// not include `spec` or metadata fields.
pub fn status_merge_patch(intent: &StatusPatchIntent) -> Value {
    owned_status_merge_patch(intent)
}

/// Build the Kubernetes merge-patch body for any owned status projection.
///
/// The returned value is suitable for a status subresource merge patch and does
/// not include `spec` or metadata fields.
pub fn owned_status_merge_patch<P>(projection: &P) -> Value
where
    P: OwnedStatusProjection + ?Sized,
{
    json!({ "status": projection.owned_status() })
}

fn owned_status_subset_matches(current: &Value, desired: &Value) -> bool {
    match (current, desired) {
        (Value::Object(current), Value::Object(desired)) => desired.iter().all(|(key, value)| {
            current
                .get(key)
                .is_some_and(|current| owned_status_subset_matches(current, value))
        }),
        _ => current == desired,
    }
}

fn validate_snapshot(snapshot: &StatusPatchResourceSnapshot) -> Result<(), StatusPatchError> {
    if snapshot.resource_version.trim().is_empty() {
        return Err(StatusPatchError::Schema("resource version is required"));
    }
    if snapshot.generation < 0 {
        return Err(StatusPatchError::Schema("generation must be non-negative"));
    }
    if !snapshot.status.is_object() {
        return Err(StatusPatchError::Schema("status must be an object"));
    }
    Ok(())
}

fn max_attempts(conflict_retry: &ConflictRetryIntent) -> u8 {
    if conflict_retry.retry_on_conflict {
        conflict_retry.max_attempts.max(1)
    } else {
        1
    }
}

async fn sleep_before_retry(conflict_retry: &ConflictRetryIntent, attempts: u8) {
    let base = conflict_retry.initial_backoff_millis;
    if base == 0 {
        return;
    }
    let shift = u32::from(attempts.saturating_sub(1)).min(20);
    let factor = 1_u64.checked_shl(shift).unwrap_or(1);
    let millis = base.saturating_mul(factor);
    tokio::time::sleep(Duration::from_millis(millis)).await;
}
