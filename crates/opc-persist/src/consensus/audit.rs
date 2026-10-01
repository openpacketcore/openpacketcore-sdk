//! Management audit changes applied by the existing configuration state machine.

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;

use super::ConfigMutationFailure;
use crate::audit_authority::continuity::{
    chain::ContinuityState, AuditCheckpoint, AuditKeyRing, AuditKeyTransition,
};
use crate::audit_authority::ledger::{
    LedgerMutationError, LedgerState, MAX_STATE_BYTES, STATE_DOMAIN,
};
use crate::audit_authority::{
    AuditAuthorityError, AuditLedgerLimits, AuditOperationHandle, AuditOperationState, AuditToken,
};
use crate::{AuditKey, ConfigConsensusIdentity};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

mod ledger_decode;

#[cfg(feature = "dangerous-test-hooks")]
use super::capacity_observation::{NativePhase, NativePhaseGuard};

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

const STATE_STREAM_BUFFER_BYTES: usize = 4 * 1024;

// Canonical serde JSON emits many very small fragments. Batch them before the
// authenticated sink so hashing and output extension operate on whole chunks.
// This adds a fixed 4 KiB stack payload plus a reference and length; it does not
// replace or enlarge the retained output allocation or change its size checks.
struct StateBuffer<'a, W: io::Write> {
    inner: &'a mut W,
    bytes: [u8; STATE_STREAM_BUFFER_BYTES],
    buffered: usize,
}

impl<'a, W: io::Write> StateBuffer<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            bytes: [0; STATE_STREAM_BUFFER_BYTES],
            buffered: 0,
        }
    }

    fn drain(&mut self) -> io::Result<()> {
        while self.buffered != 0 {
            let written = match self.inner.write(&self.bytes[..self.buffered]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.bytes.copy_within(written..self.buffered, 0);
            self.buffered -= written;
        }
        Ok(())
    }
}

impl<W: io::Write> io::Write for StateBuffer<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.buffered == self.bytes.len() {
            self.drain()?;
        }
        let accepted = bytes.len().min(self.bytes.len() - self.buffered);
        self.bytes[self.buffered..self.buffered + accepted].copy_from_slice(&bytes[..accepted]);
        self.buffered += accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()?;
        self.inner.flush()
    }
}

fn write_canonical_state(stored: &StoredLedger, writer: &mut impl io::Write) -> io::Result<()> {
    let mut buffered = StateBuffer::new(writer);
    serde_json::to_writer(&mut buffered, stored).map_err(|_| invalid())?;
    // Explicitly propagate the final partial chunk's errors before returning
    // the MAC. Dropping a buffer must never silently discard an error or tail.
    io::Write::flush(&mut buffered)
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
        #[cfg(test)]
        config_capacity_957_ledger_streaming::observe_authenticated_sink_write(
            bytes.len(),
            self.encoded.is_some(),
        );
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
    write_canonical_state(stored, &mut writer)?;
    if writer.remaining != 0 {
        return Err(invalid());
    }
    Ok(writer.mac)
}

fn encode_state(stored: &StoredLedger, key: &AuditKey) -> io::Result<(Vec<u8>, [u8; 32])> {
    #[cfg(feature = "dangerous-test-hooks")]
    let mut count_phase = NativePhaseGuard::start(NativePhase::WriteCanonicalCount);
    let length = canonical_state_len(stored)?;
    #[cfg(feature = "dangerous-test-hooks")]
    {
        count_phase.rows(1, length);
        count_phase.finish();
    }
    #[cfg(feature = "dangerous-test-hooks")]
    let mut reserve_phase = NativePhaseGuard::start(NativePhase::WriteReserve);
    let mut encoded = Vec::new();
    encoded.try_reserve_exact(length).map_err(|_| invalid())?;
    #[cfg(feature = "dangerous-test-hooks")]
    {
        reserve_phase.rows(1, length);
        reserve_phase.finish();
    }
    #[cfg(test)]
    let _observed_encoding =
        super::config_capacity_simultaneous_working_tests::ledger::encoding(&encoded);
    #[cfg(feature = "dangerous-test-hooks")]
    let mut mac_phase = NativePhaseGuard::start(NativePhase::WriteCanonicalMac);
    let mac = stream_state(stored, key, length, Some(&mut encoded))?;
    #[cfg(feature = "dangerous-test-hooks")]
    {
        mac_phase.rows(1, length);
        mac_phase.finish();
    }
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
        #[cfg(feature = "dangerous-test-hooks")]
        let mut phase = NativePhaseGuard::start(NativePhase::ContinuityValidation);
        #[cfg(feature = "dangerous-test-hooks")]
        phase.rows(
            ledger
                .continuity
                .as_ref()
                .map_or(0, |chain| chain.rows.len()),
            0,
        );
        ledger.validate_continuity(keys).map_err(|_| invalid())?;
        #[cfg(feature = "dangerous-test-hooks")]
        phase.finish();
    }
    Ok(ledger)
}

fn read_verified_sync(conn: &Connection, key: &AuditKey) -> io::Result<StoredLedger> {
    #[cfg(feature = "dangerous-test-hooks")]
    let mut row_phase = NativePhaseGuard::start(NativePhase::LedgerRowRead);
    let mut statement = conn.prepare(
        "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton = 1 AND length(state_json) BETWEEN 1 AND 16777216 AND length(state_hmac) = 32",
    ).map_err(|_| invalid())?;
    let mut rows = statement.query([]).map_err(|_| invalid())?;
    let row = rows.next().map_err(|_| invalid())?.ok_or_else(invalid)?;
    let encoded = row.get_ref(0).map_err(|_| invalid())?;
    let encoded = encoded.as_blob().map_err(|_| invalid())?;
    let mac = row.get_ref(1).map_err(|_| invalid())?;
    let mac = mac.as_blob().map_err(|_| invalid())?;
    #[cfg(feature = "dangerous-test-hooks")]
    {
        row_phase.rows(1, encoded.len());
        row_phase.finish();
    }
    #[cfg(test)]
    let observed_row =
        super::config_capacity_simultaneous_working_tests::ledger::borrowed_read(encoded);
    let stored = ledger_decode::decode(encoded)?;
    #[cfg(feature = "dangerous-test-hooks")]
    if let Some(ledger) = &stored.ledger {
        super::capacity_observation::sample(
            super::capacity_observation::NativeStage::DecodedLedger,
            ledger,
            None,
        );
    }
    #[cfg(test)]
    let observed_read =
        super::config_capacity_simultaneous_working_tests::ledger::decoded(stored.ledger.as_ref());
    #[cfg(feature = "dangerous-test-hooks")]
    let mut count_phase = NativePhaseGuard::start(NativePhase::ReadCanonicalCount);
    let length = canonical_state_len(&stored)?;
    #[cfg(feature = "dangerous-test-hooks")]
    {
        count_phase.rows(1, length);
        count_phase.finish();
    }
    #[cfg(feature = "dangerous-test-hooks")]
    let mut mac_phase = NativePhaseGuard::start(NativePhase::ReadCanonicalMac);
    stream_state(&stored, key, length, None)?
        .verify_slice(mac)
        .map_err(|_| invalid())?;
    #[cfg(feature = "dangerous-test-hooks")]
    {
        mac_phase.rows(1, length);
        mac_phase.finish();
    }
    // Canonical authentication is complete. End the immutable row borrow and
    // finalize its statement before validation derives operations. The caller's
    // connection/transaction still owns the complete read and identity check.
    #[cfg(test)]
    drop(observed_row);
    drop(rows);
    drop(statement);
    if let Some(ledger) = &stored.ledger {
        #[cfg(feature = "dangerous-test-hooks")]
        let mut phase = NativePhaseGuard::start(NativePhase::LedgerValidation);
        #[cfg(feature = "dangerous-test-hooks")]
        phase.rows(ledger.entries.len(), 0);
        ledger
            .validate(key, stored.identity)
            .map_err(|_| invalid())?;
        #[cfg(feature = "dangerous-test-hooks")]
        phase.finish();
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
    #[cfg(feature = "dangerous-test-hooks")]
    if let Some(ledger) = &stored.ledger {
        super::capacity_observation::sample(
            super::capacity_observation::NativeStage::LedgerWrite,
            ledger,
            Some(&encoded),
        );
    }
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

fn mutation_result(
    result: Result<(), LedgerMutationError>,
) -> io::Result<Result<(), AuditAuthorityError>> {
    match result {
        Ok(()) => Ok(Ok(())),
        Err(LedgerMutationError::Authority(error)) => Ok(Err(error)),
        Err(LedgerMutationError::Allocation) => Err(io::ErrorKind::OutOfMemory.into()),
    }
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
                AuditCommand::Intent(handle) => mutation_result(ledger.admit(key, handle, now))?,
                AuditCommand::Reject(handle) => {
                    mutation_result(ledger.resolve(key, handle, AuditOperationState::Rejected))?
                }
                AuditCommand::Terminal(handle) => {
                    mutation_result(ledger.acknowledge_terminal(key, handle))?
                }
                AuditCommand::Transition(transition) => match keys {
                    Some(keys) => mutation_result(ledger.transition_key(key, keys, transition))?,
                    None => Err(AuditAuthorityError::KeyUnavailable),
                },
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
    Ok(stored.ledger.is_some_and(|ledger| ledger.operations.iter().any(|op| {
        if op.terminal_recorded { return false; }
        let base = op.handle.body.binding.base_version;
        (base > 0 && base < retain_from) || matches!(op.state, AuditOperationState::Committed { version } if version < retain_from)
    })))
}

#[cfg(test)]
#[path = "tests/config_capacity_957_ledger_allocations.rs"]
mod config_capacity_957_ledger_allocations;

#[cfg(test)]
#[path = "tests/config_capacity_957_ledger_streaming.rs"]
mod config_capacity_957_ledger_streaming;

#[cfg(test)]
#[path = "tests/config_capacity_957_ledger_decode.rs"]
mod config_capacity_957_ledger_decode;
