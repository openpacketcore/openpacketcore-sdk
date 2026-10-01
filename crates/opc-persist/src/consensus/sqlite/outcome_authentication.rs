//! Authenticate retained results separately from caller/intent recovery handles.

use serde::{Deserialize, Serialize};

use super::*;
use crate::audit_authority::ledger::{authenticate, verify};

const DOMAIN: &[u8] = b"openpacketcore/config-consensus/retained-outcome/v1\0";
// Results contain only fixed-size fields and an optional fixed-size receipt.
// Check the SQLite view before allocating or deserializing corrupted storage.
const MAX_ENCODED_BYTES: usize = 16 * 1024;

#[derive(Serialize)]
struct ProofBody<'a> {
    identity: ConsensusIdentity,
    capacity_revision: u16,
    key_epoch: u64,
    request_id: opc_consensus::ConsensusRequestId,
    payload_digest: &'a [u8; 32],
    applied_sequence: u64,
    response: &'a ConfigConsensusResponse,
}

#[derive(Serialize)]
struct StoredResponseRef<'a> {
    #[serde(flatten)]
    response: &'a ConfigConsensusResponse,
    recovery_proof: [u8; 32],
}

#[derive(Deserialize)]
struct StoredResponse {
    #[serde(flatten)]
    response: ConfigConsensusResponse,
    #[serde(default)]
    recovery_proof: Option<[u8; 32]>,
}

pub(super) fn encode(
    key: &AuditKey,
    identity: ConsensusIdentity,
    profile: ConfigCapacityProfile,
    request_id: opc_consensus::ConsensusRequestId,
    payload_digest: &[u8; 32],
    response: &ConfigConsensusResponse,
) -> io::Result<Vec<u8>> {
    let proof = authenticate(
        key,
        DOMAIN,
        &ProofBody {
            identity,
            capacity_revision: profile.revision(),
            key_epoch: key.epoch(),
            request_id,
            payload_digest,
            applied_sequence: response.sequence,
            response,
        },
    )
    .map_err(|_| invalid())?;
    let encoded = encode_json(&StoredResponseRef {
        response,
        recovery_proof: proof,
    })?;
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err(invalid());
    }
    Ok(encoded)
}

fn decode(
    encoded: &[u8],
    key: &AuditKey,
    identity: ConsensusIdentity,
    profile: ConfigCapacityProfile,
    request_id: opc_consensus::ConsensusRequestId,
    payload_digest: &[u8; 32],
    applied_sequence: u64,
) -> io::Result<(ConfigConsensusResponse, bool)> {
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err(invalid());
    }
    let stored: StoredResponse = decode_json(encoded)?;
    if applied_sequence == 0 || stored.response.sequence != applied_sequence {
        return Err(invalid());
    }
    let Some(proof) = stored.recovery_proof else {
        // Existing Legacy authorities contain raw results. Keep their original
        // deduplication behavior, but never promote one to authenticated recovery.
        return if profile == ConfigCapacityProfile::Legacy {
            Ok((stored.response, false))
        } else {
            Err(invalid())
        };
    };
    verify(
        key,
        DOMAIN,
        &ProofBody {
            identity,
            capacity_revision: profile.revision(),
            key_epoch: key.epoch(),
            request_id,
            payload_digest,
            applied_sequence,
            response: &stored.response,
        },
        &proof,
    )
    .map_err(|_| invalid())?;
    Ok((stored.response, true))
}

pub(super) fn read(
    conn: &Connection,
    identity: ConsensusIdentity,
    key: &AuditKey,
    profile: ConfigCapacityProfile,
    request_id: opc_consensus::ConsensusRequestId,
    require_authenticated: bool,
) -> io::Result<Option<([u8; 32], ConfigConsensusResponse)>> {
    let mut statement = conn
        .prepare("SELECT configuration_epoch, applied_sequence, payload_digest, response_json FROM config_raft_request_outcomes WHERE request_id = ?1")
        .map_err(db_error)?;
    let mut rows = statement
        .query([request_id.as_bytes().as_slice()])
        .map_err(db_error)?;
    let Some(row) = rows.next().map_err(db_error)? else {
        return Ok(None);
    };
    validate_epoch(row.get(0).map_err(db_error)?, identity)?;
    let sequence = checked_positive_u64(row.get(1).map_err(db_error)?)?;
    let digest: [u8; 32] = row_blob(row, 2)?.try_into().map_err(|_| invalid())?;
    let (response, authenticated) = decode(
        row_blob(row, 3)?,
        key,
        identity,
        profile,
        request_id,
        &digest,
        sequence,
    )?;
    if require_authenticated {
        let current_sequence = current_sequence(conn, identity)?;
        if !authenticated || !in_window(sequence, current_sequence) {
            return Ok(None);
        }
    }
    Ok(Some((digest, response)))
}

pub(super) fn validate(
    conn: &Connection,
    identity: ConsensusIdentity,
    key: &AuditKey,
    profile: ConfigCapacityProfile,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    let current_sequence = current_sequence(conn, identity)?;
    let mut statement = conn
        .prepare("SELECT request_id, configuration_epoch, applied_sequence, payload_digest, response_json FROM config_raft_request_outcomes")
        .map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let mut count = 0_u64;
    while let Some(row) = rows.next().map_err(db_error)? {
        cancellation.check_io()?;
        count += 1;
        if count > CONFIG_CONSENSUS_RETAINED_REQUEST_OUTCOMES {
            return Err(invalid());
        }
        let request_id = opc_consensus::ConsensusRequestId::from_bytes(
            row_blob(row, 0)?.try_into().map_err(|_| invalid())?,
        );
        validate_epoch(row.get(1).map_err(db_error)?, identity)?;
        let sequence = checked_positive_u64(row.get(2).map_err(db_error)?)?;
        if !in_window(sequence, current_sequence) {
            return Err(invalid());
        }
        let digest: [u8; 32] = row_blob(row, 3)?.try_into().map_err(|_| invalid())?;
        decode(
            row_blob(row, 4)?,
            key,
            identity,
            profile,
            request_id,
            &digest,
            sequence,
        )?;
    }
    Ok(())
}

fn in_window(sequence: u64, current: u64) -> bool {
    sequence <= current
        && sequence > current.saturating_sub(CONFIG_CONSENSUS_RETAINED_REQUEST_OUTCOMES)
}

fn current_sequence(conn: &Connection, identity: ConsensusIdentity) -> io::Result<u64> {
    // Recovery needs no machine digest or logical-time allocation. Read only
    // the two scalar columns used by the retention decision.
    let (epoch, sequence): (i64, i64) = conn
        .query_row(
            "SELECT configuration_epoch, application_sequence FROM config_raft_machine WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    checked_u64(sequence)
}

fn invalid() -> io::Error {
    invalid_data("config consensus retained outcome is invalid")
}
