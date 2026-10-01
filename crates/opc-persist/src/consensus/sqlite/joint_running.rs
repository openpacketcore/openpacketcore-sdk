//! Native application of an authenticated bounded Running record.
//!
//! Context comes from the independently selected Running authority. The target
//! reducer retains Intent, session, lock and result ownership in its existing
//! savepoint. Legacy dispatch supplies no context and still refuses the payload.

use super::*;
use crate::audit_authority::AuditCaller;
use crate::consensus::audit_mutation::TargetMutationCommand;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::PreparedConfigCommit;

/// Private, nonserialized call context, not a proof decoded from a command.
pub(super) struct CapacityRunningAuthority {
    pub(super) identity: ConsensusIdentity,
    pub(super) caller: AuditCaller,
    pub(super) mode: RetainedConfigMode,
}

struct AuthenticatedRunning<'a> {
    commit: &'a PreparedConfigCommit,
    binding: &'a CapacityRecordBinding,
}

impl<'a> AuthenticatedRunning<'a> {
    fn check(
        prepared: &'a TargetMutationCommand,
        key: &AuditKey,
        authority: &CapacityRunningAuthority,
    ) -> Result<Self, ConfigMutationFailure> {
        prepared
            .verify_bounded_running(key, authority.identity, authority.caller)
            .map_err(|_| ConfigMutationFailure::InvalidInput)?;
        let payload = prepared
            .bounded_running()
            .ok_or(ConfigMutationFailure::InvalidInput)?;
        Ok(Self {
            commit: payload.commit(),
            binding: payload.binding(),
        })
    }
}

/// Apply within the caller's existing transaction and audited-target savepoint.
/// A mutation refusal requires its rollback; I/O/cancellation requires outer
/// rollback. This function never commits, reenvelopes, or mints a capacity proof.
pub(super) fn apply_sync(
    conn: &Connection,
    key: &AuditKey,
    prepared: &TargetMutationCommand,
    pending_tx_id: Option<opc_types::TxId>,
    context: &super::super::audit::ApplyContext<'_>,
    authority: &CapacityRunningAuthority,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    context.cancellation.check_io()?;
    if conn.is_autocommit() {
        return Err(invalid_data(
            "bounded Running requires an authority transaction",
        ));
    }
    // Keep the existing isolated capacity component and admit only the explicit
    // Running subset through native target dispatch. Pending resolution remains
    // unsupported; neither command bytes nor stored rows select this context.
    if !matches!(
        authority.mode,
        RetainedConfigMode::BoundedV1 | RetainedConfigMode::NetconfRunningV1
    ) || pending_tx_id.is_some()
    {
        return Ok(Err(ConfigMutationFailure::InvalidInput));
    }
    let checked = match AuthenticatedRunning::check(prepared, key, authority) {
        Ok(checked) => checked,
        Err(failure) => return Ok(Err(failure)),
    };
    super::super::history::validate_access_for_profile_sync(
        conn,
        key,
        true,
        Some(authority.identity),
        authority.mode,
        context.cancellation,
    )?;
    let result = append_prepared_commit_sync(
        conn,
        checked.commit,
        None,
        super::super::types::config_command_revision(authority.mode),
        context.logical_time,
        context.request_id,
        context.cancellation,
    )?;
    if result.is_err() {
        return Ok(result);
    }
    context.cancellation.check_io()?;
    conn.execute(
        "INSERT INTO config_raft_capacity_records (tx_id, binding) VALUES (?1, ?2)",
        params![
            checked.commit.record.tx_id.as_uuid().as_bytes().as_slice(),
            checked.binding.encode().as_slice()
        ],
    )
    .map_err(db_error)?;
    context.cancellation.check_io()?;
    let result = super::super::history::refresh_sync(conn, key, false, context.cancellation)?;
    context.cancellation.check_io()?;
    Ok(result)
}
