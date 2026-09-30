//! Publication acknowledges one authenticated Running result after its audit
//! terminal/checkpoint. The result remains retained while its marker is owed.

use super::*;
use crate::consensus::ConfigMutationFailure;
use rusqlite::OptionalExtension;

struct Head {
    tx_id: Vec<u8>,
    version: u64,
    plaintext_digest: Vec<u8>,
    recovery_required: bool,
}

impl Head {
    fn matches(&self, outcome: NetconfAppliedOutcome) -> bool {
        matches!(outcome, NetconfAppliedOutcome::RunningReplaced {
            tx_id, running_version, plaintext_digest
        } if self.tx_id == tx_id.as_uuid().as_bytes()
            && self.version == running_version
            && self.plaintext_digest == plaintext_digest)
    }
}

fn read_head(
    conn: &Connection,
    key: &AuditKey,
    ledger: &LedgerState,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Option<Head>> {
    if conn.is_autocommit() {
        return Err(invalid());
    }
    let state = read_state_sync(conn, key, ledger.identity, cancellation)?;
    state.validate_anchor(Some(ledger))?;
    validate_running_state(&state)?;
    super::super::history::validate_record_chain_sync(conn, key, cancellation)?;
    let row: Option<(Vec<u8>, u64, Vec<u8>, String)> = conn
        .query_row(
            "SELECT tx_id,version,plaintext_digest,principal FROM config_history ORDER BY version DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    row.map(|(tx_id, version, plaintext_digest, principal)| {
        Ok(Head {
            tx_id,
            version,
            plaintext_digest,
            recovery_required: crate::types::config_recovery_required(&principal)
                .map_err(|_| invalid())?,
        })
    })
    .transpose()
}

pub(in crate::consensus) fn authorize_clear_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    keys: Option<&AuditKeyRing>,
    tx_id: opc_types::TxId,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let Some(ledger) = super::super::audit::read_with_keys_sync(conn, key, keys, identity)? else {
        return Ok(Err(ConfigMutationFailure::InvalidInput));
    };
    let Some(head) = read_head(conn, key, &ledger, cancellation)? else {
        return Ok(Err(ConfigMutationFailure::NotFound));
    };
    if head.tx_id != tx_id.as_uuid().as_bytes() {
        return Ok(Err(ConfigMutationFailure::NotFound));
    }
    // Exact replay remains harmless after export/pruning of an already
    // published operation. A pending marker always requires its real original.
    if !head.recovery_required {
        return Ok(Ok(()));
    }
    let settled = ledger.operations.iter().any(|operation| {
        matches!(operation.state, AuditOperationState::TargetV1(result)
            if head.matches(result.outcome()))
            && operation.terminal_recorded
            && ledger.continuity.as_ref().is_some_and(|chain| {
                chain
                    .checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| checkpoint.sequence() >= operation.last_sequence)
            })
    });
    cancellation.check_io()?;
    Ok(if settled {
        Ok(())
    } else {
        Err(ConfigMutationFailure::Conflict)
    })
}

pub(in crate::consensus) fn protects_prune_sync(
    conn: &Connection,
    key: &AuditKey,
    ledger: &LedgerState,
    through: u64,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<bool> {
    let Some(head) = read_head(conn, key, ledger, cancellation)? else {
        return Ok(false);
    };
    Ok(head.recovery_required
        && ledger.operations.iter().any(|operation| {
            operation.first_sequence <= through
                && matches!(operation.state, AuditOperationState::TargetV1(result)
                    if head.matches(result.outcome()))
        }))
}
