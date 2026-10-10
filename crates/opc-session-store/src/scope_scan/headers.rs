//! Required header decoding from one retained backend cut.

use super::{ScopeScanError, ScopeScanHeaderFault};
use crate::scope_authority::{
    ScopeAuthorityCheckpoint, ScopeAuthorityError, ScopeAuthorityStamp, ScopeAuthorityView,
    ScopeNamespace, MAX_SCOPE_AUTHORITY_RECORD_BYTES,
};
use crate::scope_batch::{ScopeBatchCheckpoint, MAX_SCOPE_BATCH_LEDGER_BYTES};
use crate::scope_storage::{self, ScopeRow};
use crate::{SessionConsensusNodeId, SessionKey, StoredSessionRecord};
use opc_consensus::engine::LogId;

// A read owns at most one bounded row. Keep its metadata inline to avoid an
// additional heap allocation for every header and inventory item inspected.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RawScopeRecord {
    Missing,
    Present(StoredSessionRecord),
    Corrupt,
}

impl RawScopeRecord {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_native(record: Option<&StoredSessionRecord>, maximum: usize) -> Self {
        match record {
            Some(record) if record.payload.len() <= maximum => Self::Present(record.clone()),
            Some(_) => Self::Corrupt,
            None => Self::Missing,
        }
    }
}

pub(crate) struct CapturedHeaders {
    pub(crate) authority: ScopeAuthorityView,
    pub(crate) checkpoint: ScopeBatchCheckpoint,
}

pub(crate) fn authority_error(error: ScopeAuthorityError) -> ScopeScanError {
    match error {
        ScopeAuthorityError::Unauthorized => ScopeScanError::Unauthorized,
        ScopeAuthorityError::Retired => ScopeScanError::Retired,
        ScopeAuthorityError::StaleAuthority | ScopeAuthorityError::Superseded => {
            ScopeScanError::StaleAuthority
        }
        ScopeAuthorityError::FreshInstallationRequired => ScopeScanError::FreshInstallationRequired,
        ScopeAuthorityError::FormatMismatch => {
            ScopeScanError::ScopeFault(ScopeScanHeaderFault::Authority)
        }
        _ => ScopeScanError::Unavailable,
    }
}

pub(crate) fn decode_headers(
    namespace: &ScopeNamespace,
    stamp: &ScopeAuthorityStamp,
    read: impl FnMut(&SessionKey, usize) -> Result<RawScopeRecord, ScopeScanError>,
) -> Result<CapturedHeaders, ScopeScanError> {
    decode_headers_with_handover(namespace, stamp, None, read)
}

pub(crate) fn decode_headers_with_handover(
    namespace: &ScopeNamespace,
    stamp: &ScopeAuthorityStamp,
    succession: Option<&crate::scope_authority::ScopeAuthorityRequest>,
    mut read: impl FnMut(&SessionKey, usize) -> Result<RawScopeRecord, ScopeScanError>,
) -> Result<CapturedHeaders, ScopeScanError> {
    let authority_fault = ScopeScanError::ScopeFault(ScopeScanHeaderFault::Authority);
    let checkpoint_fault = ScopeScanError::ScopeFault(ScopeScanHeaderFault::Checkpoint);
    if stamp.namespace() != namespace {
        return Err(ScopeScanError::ScopeFault(ScopeScanHeaderFault::Namespace));
    }
    let mut required = |key: &SessionKey, maximum: usize, fault: ScopeScanError| {
        let record = match read(key, maximum)? {
            RawScopeRecord::Present(record)
                if record.key == *key && record.payload.len() <= maximum =>
            {
                record
            }
            _ => return Err(fault),
        };
        scope_storage::require_current_record_format(&record)
            .map_err(|_| ScopeScanError::FreshInstallationRequired)?;
        Ok(record)
    };
    let key = namespace.scope().key().map_err(|_| authority_fault)?;
    let record = required(&key, MAX_SCOPE_AUTHORITY_RECORD_BYTES, authority_fault)?;
    let state = ScopeAuthorityCheckpoint::from_record(&record)
        .and_then(|checkpoint| checkpoint.state())
        .map_err(|_| authority_fault)?;
    state.check_stamp(stamp).map_err(authority_error)?;
    if let Some(request) = succession {
        use crate::scope_authority::ScopeAuthorityOperation;
        let exact_successor = matches!(request.operation(),
            ScopeAuthorityOperation::SucceedClosed { predecessor, execution, .. }
                if predecessor.namespace() == namespace
                    && execution == stamp.execution()
                    && request.expected_revision().checked_add(1) == Some(stamp.revision()));
        // Matching claims are insufficient. Only the exact immutable request
        // retained by committed authority proves that this handover happened.
        if !exact_successor || state.replay(request) != Ok(true) {
            return Err(ScopeScanError::HandoverRequired);
        }
    }
    let key = scope_storage::batch_key(namespace.scope()).map_err(|_| checkpoint_fault)?;
    let record = required(&key, MAX_SCOPE_BATCH_LEDGER_BYTES, checkpoint_fault)?;
    let checkpoint = match ScopeRow::from_record(&record).map_err(|_| checkpoint_fault)? {
        ScopeRow::Batch(checkpoint) if checkpoint.scope == *namespace.scope() => *checkpoint,
        _ => return Err(checkpoint_fault),
    };
    checkpoint
        .validate_authority(&state)
        .map_err(|_| checkpoint_fault)?;
    Ok(CapturedHeaders {
        authority: state.view,
        checkpoint,
    })
}

pub(crate) fn validate_applied(
    barrier: Option<LogId<SessionConsensusNodeId>>,
    applied: Option<LogId<SessionConsensusNodeId>>,
) -> Result<LogId<SessionConsensusNodeId>, ScopeScanError> {
    let applied = applied.ok_or(ScopeScanError::Unavailable)?;
    if barrier.is_some_and(|barrier| {
        applied.index < barrier.index
            || applied < barrier
            || (applied.index == barrier.index && applied != barrier)
    }) {
        return Err(ScopeScanError::Unavailable);
    }
    Ok(applied)
}

#[cfg(test)]
#[path = "headers_tests.rs"]
mod tests;
