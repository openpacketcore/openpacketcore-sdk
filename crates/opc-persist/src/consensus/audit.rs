//! Management audit changes applied by the existing configuration state machine.

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;

use super::ConfigMutationFailure;
use crate::audit_authority::continuity::{
    chain::ContinuityState, AuditCheckpoint, AuditKeyRing, AuditKeyTransition,
};
use crate::audit_authority::ledger::{LedgerState, MAX_STATE_BYTES, STATE_DOMAIN};
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

// StoredLedger is a closed, immutable serde representation. Count its exact
// canonical JSON before authenticating the length-prefixed bytes. Verification
// needs no second complete JSON allocation alongside the SQL row and decoded
// ledger; writes allocate their one output buffer once. The transcript remains
// exactly the existing audit-authority STATE_DOMAIN, u64 length and JSON.
struct StateByteCounter(usize);

impl io::Write for StateByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_STATE_BYTES)
            .ok_or_else(invalid)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_state_len(stored: &StoredLedger) -> io::Result<usize> {
    let mut counter = StateByteCounter(0);
    serde_json::to_writer(&mut counter, stored).map_err(|_| invalid())?;
    Ok(counter.0)
}

struct StateWriter<'a> {
    mac: Hmac<Sha256>,
    remaining: usize,
    encoded: Option<&'a mut Vec<u8>>,
}

impl io::Write for StateWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(invalid)?;
        if let Some(encoded) = self.encoded.as_mut() {
            if encoded.capacity().saturating_sub(encoded.len()) < bytes.len() {
                return Err(invalid());
            }
            encoded.extend_from_slice(bytes);
        }
        self.mac.update(bytes);
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn stream_state(
    stored: &StoredLedger,
    key: &AuditKey,
    length: usize,
    encoded: Option<&mut Vec<u8>>,
) -> io::Result<Hmac<Sha256>> {
    if length > MAX_STATE_BYTES {
        return Err(invalid());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| invalid())?;
    mac.update(STATE_DOMAIN);
    mac.update(&(length as u64).to_be_bytes());
    let mut writer = StateWriter {
        mac,
        remaining: length,
        encoded,
    };
    serde_json::to_writer(&mut writer, stored).map_err(|_| invalid())?;
    if writer.remaining != 0 {
        return Err(invalid());
    }
    Ok(writer.mac)
}

fn encode_state(stored: &StoredLedger, key: &AuditKey) -> io::Result<(Vec<u8>, [u8; 32])> {
    let length = canonical_state_len(stored)?;
    let mut encoded = Vec::new();
    encoded.try_reserve_exact(length).map_err(|_| invalid())?;
    #[cfg(test)]
    let _observed_encoding =
        super::config_capacity_simultaneous_working_tests::ledger::encoding(&encoded);
    let mac = stream_state(stored, key, length, Some(&mut encoded))?;
    Ok((encoded, mac.finalize().into_bytes().into()))
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
    #[cfg(test)]
    let encoded =
        super::config_capacity_simultaneous_working_tests::ledger::EncodedRead::observe(encoded);
    let stored: StoredLedger = serde_json::from_slice(&encoded).map_err(|_| invalid())?;
    #[cfg(test)]
    let observed_read =
        super::config_capacity_simultaneous_working_tests::ledger::decoded(stored.ledger.as_ref());
    let length = canonical_state_len(&stored)?;
    stream_state(&stored, key, length, None)?
        .verify_slice(&mac)
        .map_err(|_| invalid())?;
    // Canonical authentication is complete. The decoded state owns every field
    // needed below; release the SQL JSON before validation derives operations.
    drop(encoded);
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
    #[cfg(test)]
    drop(observed_read);
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
    #[cfg(test)]
    let _observed_ledger =
        super::config_capacity_simultaneous_working_tests::ledger::decoded(stored.ledger.as_ref());
    let (encoded, mac) = encode_state(&stored, key)?;
    #[cfg(test)]
    let _observed_write =
        super::config_capacity_simultaneous_working_tests::ledger::write(&encoded);
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

/// Original committed command context; followers never synthesize time or identity.
pub(crate) struct ApplyContext<'a> {
    pub(crate) logical_time: opc_types::Timestamp,
    pub(crate) request_id: opc_consensus::ConsensusRequestId,
    pub(crate) cancellation: &'a super::sqlite::SqliteWorkCancellation,
}

#[cfg(test)]
pub(crate) fn apply_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    command: &AuditCommand,
    now: i64,
    keys: Option<&AuditKeyRing>,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    apply_cancellable_sync(
        conn,
        key,
        identity,
        command,
        keys,
        &ApplyContext {
            logical_time: opc_types::Timestamp::from_offset_datetime(
                time::OffsetDateTime::from_unix_timestamp(now).map_err(|_| invalid())?,
            ),
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0x61; 16]),
            cancellation: &super::sqlite::SqliteWorkCancellation::audit_test(),
        },
    )
}

pub(crate) fn apply_cancellable_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    command: &AuditCommand,
    keys: Option<&AuditKeyRing>,
    context: &ApplyContext<'_>,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let now = context.logical_time.as_offset_datetime().unix_timestamp();
    let cancellation = context.cancellation;
    cancellation.check_io()?;
    if let AuditCommand::NetconfTarget(command) = command {
        if let super::audit_mutation::TargetAuditCommandV1::Apply(prepared) = &**command {
            return super::audit_targets::apply_target_sync(
                conn, key, identity, prepared, keys, context,
            );
        }
    }
    let mut ledger = read_with_keys_sync(conn, key, keys, identity)?;
    #[cfg(test)]
    let observed_mutation = ledger
        .as_ref()
        .map(super::config_capacity_simultaneous_working_tests::ledger::mutating);
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
                        TargetAuditCommandV1::Admit(prepared) => ledger
                            .lookup(key, prepared.handle(), prepared.effect.caller)
                            .and_then(|existing| {
                                // A read-only preflight cannot reserve this ledger.
                                // Serialize new target intents against the current
                                // authenticated transaction, or two original intents
                                // can each block the other's effect forever. Exact
                                // replay still reaches admit_target's payload check.
                                if existing.is_none()
                                    && ledger.operations.iter().any(|operation| {
                                        !operation.terminal_recorded
                                            || ledger.mutation_outcome_needs_checkpoint(operation)
                                    })
                                {
                                    return Err(AuditAuthorityError::RecoveryRequired);
                                }
                                ledger.admit_target(key, prepared, now)
                            }),
                        TargetAuditCommandV1::RetireCleanup(prepared) => {
                            super::audit_targets::retire_cleanup_sync(
                                conn,
                                key,
                                ledger,
                                prepared,
                                now,
                                cancellation,
                            )?
                        }
                        TargetAuditCommandV1::EmptyCommit(prepared) => {
                            super::audit_targets::admit_empty_commit_sync(
                                conn, key, ledger, prepared, context,
                            )?
                        }
                        // Apply is dispatched above with the original cancellation
                        // token and enclosing authority transaction.
                        TargetAuditCommandV1::Apply(_) => Err(AuditAuthorityError::InvalidInput),
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
    cancellation.check_io()?;
    #[cfg(test)]
    drop(observed_mutation);
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
        super::ConfigMutationIntent::ManagementAudit(command) => match command.as_ref() {
            AuditCommand::Intent(handle)
            | AuditCommand::Reject(handle)
            | AuditCommand::Terminal(handle) => handle,
            AuditCommand::NetconfTarget(command) => command.handle(),
            _ => return Ok(None),
        },
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
    if let super::ConfigMutationIntent::ManagementAudit(audit) = intent {
        if let AuditCommand::NetconfTarget(command) = audit.as_ref() {
            let receipt = match command.lookup_receipt(&ledger, key, handle.body.binding.caller) {
                Ok(Some(receipt)) => receipt,
                Ok(None) | Err(_) => return Ok(None),
            };
            let proof = match &**command {
                super::audit_mutation::TargetAuditCommandV1::EmptyCommit(prepared) => {
                    AuthenticatedAuditReceipt::seal_empty_commit(key, prepared, &receipt)
                }
                _ => AuthenticatedAuditReceipt::seal(key, &receipt),
            };
            return proof.map(Some).map_err(|_| invalid());
        }
    }
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
#[path = "tests/config_capacity_957_ledger_allocations.rs"]
mod config_capacity_957_ledger_allocations;

#[cfg(test)]
#[path = "tests/config_capacity_957_ledger_streaming.rs"]
mod config_capacity_957_ledger_streaming;

#[cfg(test)]
#[path = "../../tests/management_audit_authority/target_command.rs"]
mod target_command_tests;

#[cfg(test)]
#[path = "../../tests/management_audit_authority/target_state.rs"]
mod target_state_tests;
