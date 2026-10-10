//! Fixed typed operation failures; no diagnostic strings cross the transport.
use super::*;
use crate::scope_scan::codec::{Reader, Writer};

pub(super) fn write(
    w: &mut Writer,
    failure: ScopeScanRequestFailure,
) -> Result<(), ScopeScanWireError> {
    let (kind, tag) = match failure {
        ScopeScanRequestFailure::Retryable(cause) => (
            1,
            match cause {
                ScopeScanRetryCause::Unavailable => 0,
                ScopeScanRetryCause::IdleExpired => 1,
                ScopeScanRetryCause::BackendRestarted => 2,
                ScopeScanRetryCause::SnapshotInstalled => 3,
                ScopeScanRetryCause::ConfigurationChanged => 4,
                ScopeScanRetryCause::WorkBudgetExceeded => 5,
                ScopeScanRetryCause::AdmissionPressure => 6,
                ScopeScanRetryCause::ViewEnded => 7,
            },
        ),
        ScopeScanRequestFailure::Final(error) => (
            0,
            match error {
                ScopeScanError::Unauthorized => 1,
                ScopeScanError::HandoverRequired => 2,
                ScopeScanError::StaleAuthority => 3,
                ScopeScanError::Retired => 4,
                ScopeScanError::Unavailable => 5,
                ScopeScanError::RestartRequired => 6,
                ScopeScanError::InvalidPageLimits => 7,
                ScopeScanError::InvalidCursor => 8,
                ScopeScanError::ScopeFault(ScopeScanHeaderFault::Authority) => 9,
                ScopeScanError::ScopeFault(ScopeScanHeaderFault::Checkpoint) => 10,
                ScopeScanError::ScopeFault(ScopeScanHeaderFault::Namespace) => 11,
                ScopeScanError::FreshInstallationRequired => 12,
                ScopeScanError::DurableConsensusRequired => 13,
                ScopeScanError::CapacityRefused => 14,
            },
        ),
    };
    w.u8(kind)?;
    w.u8(tag)
}
pub(super) fn read(r: &mut Reader<'_>) -> Result<ScopeScanRequestFailure, ScopeScanWireError> {
    Ok(match (r.u8()?, r.u8()?) {
        (0, tag) => ScopeScanRequestFailure::Final(match tag {
            1 => ScopeScanError::Unauthorized,
            2 => ScopeScanError::HandoverRequired,
            3 => ScopeScanError::StaleAuthority,
            4 => ScopeScanError::Retired,
            5 => ScopeScanError::Unavailable,
            6 => ScopeScanError::RestartRequired,
            7 => ScopeScanError::InvalidPageLimits,
            8 => ScopeScanError::InvalidCursor,
            9 => ScopeScanError::ScopeFault(ScopeScanHeaderFault::Authority),
            10 => ScopeScanError::ScopeFault(ScopeScanHeaderFault::Checkpoint),
            11 => ScopeScanError::ScopeFault(ScopeScanHeaderFault::Namespace),
            12 => ScopeScanError::FreshInstallationRequired,
            13 => ScopeScanError::DurableConsensusRequired,
            14 => ScopeScanError::CapacityRefused,
            _ => return Err(ScopeScanWireError),
        }),
        (1, tag) => ScopeScanRequestFailure::Retryable(match tag {
            0 => ScopeScanRetryCause::Unavailable,
            1 => ScopeScanRetryCause::IdleExpired,
            2 => ScopeScanRetryCause::BackendRestarted,
            3 => ScopeScanRetryCause::SnapshotInstalled,
            4 => ScopeScanRetryCause::ConfigurationChanged,
            5 => ScopeScanRetryCause::WorkBudgetExceeded,
            6 => ScopeScanRetryCause::AdmissionPressure,
            7 => ScopeScanRetryCause::ViewEnded,
            _ => return Err(ScopeScanWireError),
        }),
        _ => return Err(ScopeScanWireError),
    })
}
