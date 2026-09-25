//! Management audit changes applied by the existing configuration state machine.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::io;

use super::ConfigMutationFailure;
use crate::audit_authority::continuity::{
    chain::ContinuityState, AuditCheckpoint, AuditKeyRing, AuditKeyTransition,
};
use crate::audit_authority::ledger::{
    authenticate, verify, LedgerState, MAX_STATE_BYTES, STATE_DOMAIN,
};
use crate::audit_authority::{
    AuditAuthorityError, AuditLedgerLimits, AuditOperationHandle, AuditOperationState, AuditToken,
};
use crate::{AuditKey, ConfigConsensusIdentity};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AuditCommand {
    Initialize {
        projection: AuditToken,
        limits: AuditLedgerLimits,
    },
    Intent(AuditOperationHandle),
    Reject(AuditOperationHandle),
    Terminal(AuditOperationHandle),
    InitializeWithContinuity {
        projection: AuditToken,
        limits: AuditLedgerLimits,
        initial_epoch: u64,
    },
    Transition(AuditKeyTransition),
    Checkpoint(AuditCheckpoint),
    Prune {
        through: u64,
        checkpoint: AuditCheckpoint,
    },
    AcknowledgeExport(AuditCheckpoint),
    // Append-only nested allocation; outer management-audit remains tag 6.
    NetconfTarget(Box<super::audit_mutation::TargetAuditCommandV1>),
}

impl std::fmt::Debug for AuditCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditCommand(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLedger {
    identity: ConfigConsensusIdentity,
    ledger: Option<LedgerState>,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid replicated management audit state",
    )
}

/// A signed inactive row distinguishes initial provisioning from lost authority.
pub(crate) fn initialize_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
) -> io::Result<()> {
    write_sync(conn, key, identity, None, true)
}

pub(crate) fn read_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
) -> io::Result<Option<LedgerState>> {
    let stored = read_verified_sync(conn, key)?;
    if stored.identity != identity {
        return Err(invalid());
    }
    Ok(stored.ledger)
}

pub(crate) fn read_with_keys_sync(
    conn: &Connection,
    key: &AuditKey,
    keys: Option<&AuditKeyRing>,
    identity: ConfigConsensusIdentity,
) -> io::Result<Option<LedgerState>> {
    let ledger = read_sync(conn, key, identity)?;
    if let Some(ledger) = &ledger {
        ledger.validate_continuity(keys).map_err(|_| invalid())?;
    }
    Ok(ledger)
}

fn read_verified_sync(conn: &Connection, key: &AuditKey) -> io::Result<StoredLedger> {
    let (encoded, mac): (Vec<u8>,Vec<u8>) = conn.query_row(
        "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton = 1 AND length(state_json) BETWEEN 1 AND 16777216 AND length(state_hmac) = 32",
        [], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(|_| invalid())?.ok_or_else(invalid)?;
    let mac: [u8; 32] = mac.try_into().map_err(|_| invalid())?;
    let stored: StoredLedger = serde_json::from_slice(&encoded).map_err(|_| invalid())?;
    verify(key, STATE_DOMAIN, &stored, &mac).map_err(|_| invalid())?;
    if let Some(ledger) = &stored.ledger {
        ledger
            .validate(key, stored.identity)
            .map_err(|_| invalid())?;
    }
    let identity = stored.identity;
    let matches: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM config_raft_identity WHERE singleton=1 AND cluster_id=?1 AND configuration_id=?2 AND configuration_epoch=?3)",
        params![identity.cluster_id().as_bytes().as_slice(),identity.configuration_id().as_bytes().as_slice(),identity.configuration_epoch().get() as i64],
        |row| row.get(0),
    ).map_err(|_| invalid())?;
    if !matches {
        return Err(invalid());
    }
    Ok(stored)
}

pub(crate) fn validate_sync(conn: &Connection, key: &AuditKey) -> io::Result<()> {
    read_verified_sync(conn, key).map(|_| ())
}

pub(crate) fn write_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    ledger: Option<LedgerState>,
    initialize: bool,
) -> io::Result<()> {
    let stored = StoredLedger { identity, ledger };
    let encoded = serde_json::to_vec(&stored).map_err(|_| invalid())?;
    if encoded.len() > MAX_STATE_BYTES {
        return Err(invalid());
    }
    let mac = authenticate(key, STATE_DOMAIN, &stored).map_err(|_| invalid())?;
    let statement = if initialize {
        "INSERT INTO config_raft_management_audit(singleton,state_json,state_hmac) VALUES(1,?1,?2)"
    } else {
        "UPDATE config_raft_management_audit SET state_json=?1,state_hmac=?2 WHERE singleton=1"
    };
    if conn
        .execute(statement, params![encoded, mac.as_slice()])
        .map_err(|_| invalid())?
        != 1
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn apply_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    command: &AuditCommand,
    now: i64,
    keys: Option<&AuditKeyRing>,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let mut ledger = read_with_keys_sync(conn, key, keys, identity)?;
    let result = match command {
        AuditCommand::Initialize { .. } if keys.is_some() => {
            Err(AuditAuthorityError::BindingMismatch)
        }
        AuditCommand::Initialize { projection, limits } => match &ledger {
            Some(current) if current.projection == *projection && current.limits == *limits => {
                Ok(())
            }
            Some(_) => Err(AuditAuthorityError::BindingMismatch),
            None => {
                let candidate = LedgerState::new(identity, *projection, *limits);
                candidate
                    .validate(key, identity)
                    .map(|()| ledger = Some(candidate))
            }
        },
        AuditCommand::InitializeWithContinuity {
            projection,
            limits,
            initial_epoch,
        } => match (keys, &ledger) {
            (Some(keys), None) => keys
                .key(*initial_epoch)
                .and_then(|_| keys.separate_from(key))
                .and_then(|()| {
                    let mut candidate = LedgerState::new(identity, *projection, *limits);
                    candidate.continuity = Some(ContinuityState::new(*initial_epoch));
                    candidate.validate(key, identity)?;
                    candidate.validate_continuity(Some(keys))?;
                    ledger = Some(candidate);
                    Ok(())
                }),
            (Some(_), Some(current))
                if current.projection == *projection
                    && current.limits == *limits
                    && current
                        .continuity
                        .as_ref()
                        .is_some_and(|chain| chain.initial_epoch == *initial_epoch) =>
            {
                Ok(())
            }
            _ => Err(AuditAuthorityError::BindingMismatch),
        },
        command => match ledger.as_mut() {
            None => Err(AuditAuthorityError::Unavailable),
            Some(ledger) => match command {
                AuditCommand::Intent(handle) => ledger.admit(key, handle, now),
                AuditCommand::Reject(handle) => {
                    ledger.resolve(key, handle, AuditOperationState::Rejected)
                }
                AuditCommand::Terminal(handle) => ledger.acknowledge_terminal(key, handle),
                AuditCommand::Transition(transition) => keys
                    .ok_or(AuditAuthorityError::KeyUnavailable)
                    .and_then(|keys| ledger.transition_key(key, keys, transition)),
                AuditCommand::Checkpoint(checkpoint) => keys
                    .ok_or(AuditAuthorityError::KeyUnavailable)
                    .and_then(|keys| {
                        checkpoint.verify(keys, identity)?;
                        ledger.matches_checkpoint(checkpoint)?;
                        let chain = ledger
                            .continuity
                            .as_mut()
                            .ok_or(AuditAuthorityError::Unavailable)?;
                        if chain.checkpoint.as_ref().is_some_and(|old| {
                            old.sequence() > checkpoint.sequence()
                                || (old.sequence() == checkpoint.sequence() && old != checkpoint)
                        }) {
                            return Err(AuditAuthorityError::RollbackDetected);
                        }
                        chain.checkpoint = Some(checkpoint.clone());
                        Ok(())
                    }),
                AuditCommand::AcknowledgeExport(checkpoint) => {
                    keys.ok_or(AuditAuthorityError::KeyUnavailable)
                        .and_then(|keys| {
                            checkpoint.verify(keys, identity)?;
                            ledger.matches_checkpoint(checkpoint)?;
                            let chain = ledger
                                .continuity
                                .as_mut()
                                .ok_or(AuditAuthorityError::Unavailable)?;
                            if checkpoint.body.acknowledged_export == [0; 32]
                                || chain.checkpoint.as_ref().is_none_or(|current| {
                                    current.sequence() < checkpoint.sequence()
                                })
                            {
                                return Err(AuditAuthorityError::BindingMismatch);
                            }
                            if chain
                                .export_checkpoint
                                .as_ref()
                                .is_none_or(|current| current.sequence() < checkpoint.sequence())
                            {
                                chain.export_checkpoint = Some(checkpoint.clone());
                            }
                            Ok(())
                        })
                }
                AuditCommand::Prune {
                    through,
                    checkpoint,
                } => keys
                    .ok_or(AuditAuthorityError::KeyUnavailable)
                    .and_then(|keys| ledger.prune(keys, *through, checkpoint, now)),
                AuditCommand::NetconfTarget(command) => {
                    use super::audit_mutation::TargetAuditCommandV1;
                    match &**command {
                        TargetAuditCommandV1::Admit(prepared) => {
                            ledger.admit_target(key, prepared, now)
                        }
                        TargetAuditCommandV1::Apply(prepared) => (|| {
                            prepared.verify_effect(key)?;
                            let original = ledger.recover_target(
                                key,
                                prepared.handle(),
                                prepared.handle.body.binding.caller,
                            )?;
                            if original.encode()? != prepared.encode()? {
                                Err(AuditAuthorityError::BindingMismatch)
                            } else {
                                // Target effects stay unavailable until the complete
                                // retained ownership/lifecycle path is connected.
                                Err(AuditAuthorityError::RecoveryRequired)
                            }
                        })(),
                    }
                }
                AuditCommand::Initialize { .. } | AuditCommand::InitializeWithContinuity { .. } => {
                    Err(AuditAuthorityError::InvalidInput)
                }
            },
        },
    };
    if let Err(error) = result {
        return Ok(Err(match error {
            AuditAuthorityError::Full => ConfigMutationFailure::HistoryFull,
            AuditAuthorityError::BindingMismatch | AuditAuthorityError::Expired => {
                ConfigMutationFailure::Conflict
            }
            _ => ConfigMutationFailure::InvalidInput,
        }));
    }
    if let Some(ledger) = &mut ledger {
        ledger.seal_continuity(keys).map_err(|_| invalid())?;
        ledger.validate(key, identity).map_err(|_| invalid())?;
        ledger.validate_continuity(keys).map_err(|_| invalid())?;
    }
    write_sync(conn, key, identity, ledger, false)?;
    Ok(Ok(()))
}

/// Closed public mapping, with no backend or operation identity.
pub(crate) fn map_failure(failure: ConfigMutationFailure) -> AuditAuthorityError {
    match failure {
        ConfigMutationFailure::HistoryFull => AuditAuthorityError::Full,
        ConfigMutationFailure::Conflict
        | ConfigMutationFailure::RequestIdCollision
        | ConfigMutationFailure::HistoryProtected => AuditAuthorityError::BindingMismatch,
        ConfigMutationFailure::NotFound | ConfigMutationFailure::InvalidInput => {
            AuditAuthorityError::InvalidInput
        }
    }
}

/// Read and authenticate the exact resulting operation inside the existing
/// apply transaction, including a durable rejection or a racing prior commit.
pub(crate) fn applied_receipt_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    intent: &super::ConfigMutationIntent,
) -> io::Result<Option<crate::audit_authority::receipt::AuthenticatedAuditReceipt>> {
    use crate::audit_authority::receipt::AuthenticatedAuditReceipt;
    let handle = match intent {
        super::ConfigMutationIntent::AuditedMutation(prepared) => &prepared.handle,
        super::ConfigMutationIntent::ManagementAudit(
            AuditCommand::Intent(handle)
            | AuditCommand::Reject(handle)
            | AuditCommand::Terminal(handle),
        ) => handle,
        super::ConfigMutationIntent::ManagementAudit(AuditCommand::NetconfTarget(command)) => {
            command.prepared().handle()
        }
        _ => return Ok(None),
    };
    // A rejected malformed/substituted handle has no receipt, not an I/O fault.
    if handle
        .verify(key, identity, handle.body.binding.caller)
        .is_err()
    {
        return Ok(None);
    }
    let Some(ledger) = read_sync(conn, key, identity)? else {
        return Ok(None);
    };
    ledger
        .lookup(key, handle, handle.body.binding.caller)
        .map_err(|_| invalid())?
        .map(|receipt| AuthenticatedAuditReceipt::seal(key, &receipt).map_err(|_| invalid()))
        .transpose()
}

/// Configuration retention cannot erase a still-unresolved audit reference.
pub(crate) fn protects_config_prefix(
    conn: &Connection,
    key: &AuditKey,
    retain_from: u64,
) -> io::Result<bool> {
    let stored = read_verified_sync(conn, key)?;
    Ok(stored.ledger.is_some_and(|ledger| {
        ledger.operations.iter().any(|op| {
            if op.terminal_recorded {
                return false;
            }
            let base = op.handle.body.binding.base_version;
            let running = match op.state {
                AuditOperationState::Committed { version } => Some(version),
                AuditOperationState::TargetV1(result) => result.outcome().running_version(),
                _ => None,
            };
            (base > 0 && base < retain_from) || running.is_some_and(|version| version < retain_from)
        })
    }))
}

#[cfg(test)]
#[path = "../../tests/management_audit_authority/target_command.rs"]
mod target_command_tests;

#[cfg(test)]
#[path = "../../tests/management_audit_authority/target_state.rs"]
mod target_state_tests;
