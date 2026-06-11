//! Candidate resolution for rollback commits: loads the requested rollback
//! target from the durable store and refuses targets that are unpublishable
//! (schema drift, pending commit-confirmed, or unreconciled recovery marker).

use crate::datastore::ManagedDatastore;
use crate::types::{StoreError, StoreErrorCode, StoredConfig};
use opc_config_model::{CommitError, CommitMode, OpcConfig, RequestId};
use std::sync::Arc;

const ROLLBACK_NOT_FOUND_MESSAGE: &str = "rollback target was not found";
const ROLLBACK_UNAVAILABLE_MESSAGE: &str = "rollback target could not be loaded";

pub(crate) async fn resolve_candidate<C: OpcConfig>(
    request_id: RequestId,
    mode: CommitMode,
    candidate: Option<C>,
    store: &dyn ManagedDatastore<C>,
    current_running: Arc<C>,
    has_pending: bool,
) -> Result<C, CommitError> {
    match mode {
        CommitMode::Rollback { target } => {
            let stored = store.load_rollback(target).await.map_err(|err| {
                log_store_error("load_rollback failed", request_id, &err);
                crate::metrics::record_rollback_failure();
                if err.code == StoreErrorCode::NotFound {
                    CommitError::rollback_not_found(ROLLBACK_NOT_FOUND_MESSAGE)
                } else {
                    CommitError::rollback_unavailable(ROLLBACK_UNAVAILABLE_MESSAGE)
                }
            })?;
            validate_publishable_stored_config(&stored).map_err(|err| {
                log_store_error("rollback target validation failed", request_id, &err);
                crate::metrics::record_rollback_failure();
                CommitError::rollback_unavailable(ROLLBACK_UNAVAILABLE_MESSAGE)
            })?;
            Ok(stored.config)
        }
        CommitMode::Commit | CommitMode::CommitConfirmed { .. } => {
            if let Some(cand) = candidate {
                Ok(cand)
            } else if has_pending {
                Ok((*current_running).clone())
            } else {
                Err(CommitError::missing_candidate())
            }
        }
        CommitMode::ValidateOnly => candidate.ok_or_else(CommitError::missing_candidate),
    }
}

fn log_store_error(operation: &str, request_id: RequestId, error: &StoreError) {
    tracing::error!(
        request_id = %request_id,
        store_error_code = %error.code,
        store_error = %opc_types::redact(&error.message),
        "{operation}"
    );
}

fn validate_publishable_stored_config<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<(), StoreError> {
    validate_stored_schema_digest(stored)?;
    validate_restored_recovery_marker(stored)?;
    validate_restored_confirmed_deadline(stored)
}

fn validate_stored_schema_digest<C: OpcConfig>(stored: &StoredConfig<C>) -> Result<(), StoreError> {
    let actual = stored.config.schema_digest();
    if stored.schema_digest != actual {
        tracing::error!(
            tx_id = %stored.tx_id,
            version = %stored.version,
            stored_schema_digest = %stored.schema_digest,
            computed_schema_digest = %actual,
            "stored running config schema digest mismatch"
        );
        Err(StoreError::restore_schema_mismatch(
            crate::restore::RESTORE_SCHEMA_MISMATCH_MESSAGE,
        ))
    } else {
        Ok(())
    }
}

fn validate_restored_recovery_marker<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<(), StoreError> {
    if stored.recovery_required {
        tracing::error!(
            tx_id = %stored.tx_id,
            version = %stored.version,
            "stored running config requires recovery reconciliation before publication"
        );
        Err(StoreError::restore_recovery_required(
            crate::restore::RESTORE_RECOVERY_REQUIRED_MESSAGE,
        ))
    } else {
        Ok(())
    }
}

fn validate_restored_confirmed_deadline<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<(), StoreError> {
    if let Some(confirmed_deadline) = stored.confirmed_deadline {
        tracing::error!(
            tx_id = %stored.tx_id,
            version = %stored.version,
            confirmed_deadline = %confirmed_deadline,
            "stored running config requires commit-confirmed recovery before publication"
        );
        Err(StoreError::restore_confirmed_deadline(
            crate::restore::RESTORE_CONFIRMED_DEADLINE_MESSAGE,
        ))
    } else {
        Ok(())
    }
}
