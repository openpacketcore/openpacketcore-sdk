//! Read-only access to an original, disposable snapshot installation image.
//! These helpers preserve the SQL validators and projections. They neither
//! select native files nor grant application or publication authority.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use rusqlite::types::ValueRef;

#[path = "native_snapshot_checked.rs"]
mod checked;
pub(crate) use checked::{Scope, ValidatedSource};

pub(crate) struct Metadata {
    pub(crate) machine: (u64, SessionConsensusEntryDigest, Option<Timestamp>, u64),
    pub(crate) v1: Option<(SessionConsensusIdentity, [u8; 32])>,
    pub(crate) v2: Option<(SessionConsensusIdentity, [u8; 32], [u8; 32])>,
    pub(crate) roster_v1: bool,
    pub(crate) roster_v2: Option<(SessionConsensusIdentity, [u8; 32], [u8; 32])>,
    pub(crate) history: Option<FencedTransitionV2HistoryState>,
    pub(crate) witness: Option<GlobalChargeWitness>,
}

/// Preflight borrowed SQLite values before any of the original decoders may
/// allocate them. The maximum live row and the two roster uniqueness indexes
/// are reserved together; the total payload volume is never materialized.
/// Native Catalog admission subsequently validates every emitted business,
/// notification and physical log row, including their complete lineage.
pub(crate) fn validate(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    placement: PlacementResiliencePolicy,
    root: Option<&RosterAttestationTrustRootV1>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(Metadata, VerificationMemory)> {
    let memory = reserve_input(conn, check)?;
    validate_reserved(conn, identity, members, bindings, placement, root, check)
        .map(|metadata| (metadata, memory))
}

/// Keep this guard through the original install transaction as well as its
/// allocating validators. Inputs remain pinned or transactionally borrowed.
pub(crate) fn reserve_input(
    conn: &Connection,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<VerificationMemory> {
    check()?;
    let mut maximum = 0usize;
    let mut roster_rows = 0usize;
    // Static names avoid allocating attacker-chosen identifiers. Optional V2
    // namespaces are classified by the original exact-layout validator below.
    for table in [
        "consensus_identity",
        "consensus_membership_scope",
        "consensus_membership_history",
        "consensus_membership_terminal_history",
        "consensus_candidate_bootstrap",
        "consensus_vote",
        "consensus_committed",
        "consensus_purged",
        "consensus_applied",
        "consensus_membership",
        "consensus_machine",
        "consensus_snapshot",
        "consensus_operator_recovery",
        "restore_scan_state",
        "lease_globals",
        "leases",
        "key_fences",
        "session_records",
        "consensus_request_outcomes",
        "consensus_log",
        "session_replication_log",
        "consensus_fenced_transition_receipts",
        "consensus_fenced_transition_activation",
        "consensus_fenced_transition_v2_receipts",
        "consensus_fenced_transition_v2_activation",
        "consensus_fenced_transition_v2_history",
        "consensus_protected_roster_rows",
        "consensus_protected_roster_floors",
        "consensus_protected_roster_retirement_cursors",
        "consensus_protected_roster_witness",
        "consensus_protected_roster_business",
        "consensus_protected_roster_admissions",
        "consensus_protected_roster_v2_admissions",
        "consensus_protected_roster_v2_absence_reservations",
        "consensus_protected_roster_v2_activation",
    ] {
        check()?;
        if !table_exists(conn, table).map_err(db_error)? {
            continue;
        }
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table}"))
            .map_err(db_error)?;
        let columns = statement.column_count();
        let mut rows = statement.query([]).map_err(db_error)?;
        while let Some(row) = rows.next().map_err(db_error)? {
            check()?;
            let mut bytes = 0usize;
            for column in 0..columns {
                let value = row.get_ref(column).map_err(db_error)?;
                let length = match value {
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => bytes.len(),
                    _ => 0,
                };
                // The native generation's existing item ceiling bounds even
                // generic response payloads; narrower original codecs still
                // enforce their own descriptor-derived bounds.
                if length > 2 * SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES {
                    return Err(invalid_data(
                        "native snapshot SQL value exceeds generation bound",
                    ));
                }
                bytes = bytes
                    .checked_add(length)
                    .ok_or_else(|| invalid_data("native snapshot row size overflow"))?;
            }
            maximum = maximum.max(bytes);
            if matches!(
                table,
                "consensus_protected_roster_rows" | "consensus_protected_roster_v2_admissions"
            ) {
                roster_rows = roster_rows
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("native snapshot roster count overflow"))?;
            }
            // A fixed native generation has no dynamic membership history.
            if matches!(
                table,
                "consensus_membership_history"
                    | "consensus_membership_terminal_history"
                    | "consensus_candidate_bootstrap"
            ) {
                return Err(invalid_data(
                    "native snapshot contains unsupported membership history",
                ));
            }
        }
    }
    // Each roster row can occupy one 120-byte binding in each B-tree. Four
    // times their combined pair sizes covers node occupancy and tree links.
    let index_bytes = roster_rows
        .checked_mul(
            4 * (std::mem::size_of::<(RequestBindingKey, ())>()
                + std::mem::size_of::<(u64, RequestBindingKey)>()),
        )
        .ok_or_else(|| invalid_data("native snapshot roster index reservation overflow"))?;
    let bytes = maximum
        .checked_mul(12)
        .and_then(|bytes| bytes.checked_add(index_bytes))
        .and_then(|bytes| bytes.checked_add(512 * 1024))
        .ok_or_else(|| invalid_data("native snapshot validation reservation overflow"))?;
    VerificationMemory::reserve(bytes)
}

fn validate_reserved(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    placement: PlacementResiliencePolicy,
    root: Option<&RosterAttestationTrustRootV1>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Metadata> {
    if read_roster_attestation_trust_root_sync(conn)
        .map_err(|_| invalid_data("native snapshot roster root corrupt"))?
        .as_ref()
        != root
        || !fixed_quorum_authority_is_exact_sync(
            conn, identity, members, bindings, placement, true,
        )?
    {
        return Err(invalid_data(
            "native snapshot independent authority differs",
        ));
    }
    check()?;
    validate_existing_schema(conn, identity)
        .map_err(|_| invalid_data("native snapshot original SQL validation failed"))?;
    validate_lease_state_sync(conn)?;
    let recovery = validate_current_operator_recovery_image_sync(conn, identity)?;
    if recovery.recovery_epoch != 0
        || recovery.last_plan_digest != [0; 32]
        || recovery.pending_epoch.is_some()
        || recovery.pending_plan_digest.is_some()
        || recovery.watch_cursor_invalidation_floor != 0
        || recovery.finalize_log_id.is_some()
        || recovery.finalize_entry_json.is_some()
        || recovery.v2_activated
    {
        return Err(invalid_data(
            "native snapshot contains unsupported operator recovery state",
        ));
    }
    check()?;
    let v2 = if table_exists(conn, "consensus_fenced_transition_v2_activation").map_err(db_error)? {
        read_fenced_transition_v2_activation_certificate_in_sync(conn, identity, false)?
    } else {
        None
    };
    let roster_v2 =
        if table_exists(conn, "consensus_protected_roster_v2_activation").map_err(db_error)? {
            read_protected_roster_v2_activation_certificate_in_sync(conn, identity, false)?
        } else {
            None
        };
    if (v2.is_none()
        && table_exists(conn, "consensus_fenced_transition_v2_activation").map_err(db_error)?)
        || (roster_v2.is_none()
            && table_exists(conn, "consensus_protected_roster_v2_activation").map_err(db_error)?)
    {
        return Err(invalid_data(
            "native snapshot contains unsupported inactive V2 namespace",
        ));
    }
    let v1 = read_fenced_transition_activation_certificate_sync(conn, identity, false)?;
    // Floors and witness rows are shared with V2. Their activated SQL layout
    // alone cannot grant the independent V1 roster capability.
    let roster_v1 = v1.is_some_and(|(scope, voters)| {
        scope == identity && voters == protected_roster_profile_voter_set_digest(identity, members)
    }) && protected_roster_recovery_layout_sync(conn)
        .map_err(|_| invalid_data("native snapshot roster layout invalid"))?
        == ProtectedRosterRecoveryLayout::Activated;
    Ok(Metadata {
        machine: read_machine_sync(conn, identity)?,
        v1,
        history: if v2.is_some() {
            Some(read_fenced_transition_v2_history_state_sync(
                conn, identity,
            )?)
        } else {
            None
        },
        v2,
        roster_v1,
        roster_v2,
        witness: protected_roster_read_witness_sync(conn, identity)
            .map_err(|_| invalid_data("native snapshot roster witness invalid"))?,
    })
}

pub(crate) fn ordinary(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    id: SessionConsensusRequestId,
) -> io::Result<([u8; 32], SessionConsensusResponse)> {
    read_outcome_sync(conn, identity, id)?
        .ok_or_else(|| invalid_data("native snapshot ordinary receipt disappeared"))
}

pub(crate) fn reserved(conn: &Connection, key: &crate::SessionKey) -> io::Result<bool> {
    match ensure_session_record_unreserved_sync(conn, key) {
        Ok(()) => Ok(false),
        Err(StoreError::SessionRecordReserved) => Ok(true),
        Err(_) => Err(invalid_data("native snapshot business reservation invalid")),
    }
}

pub(crate) fn v1(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    id: SessionConsensusRequestId,
) -> io::Result<([u8; 32], Timestamp, Option<SessionConsensusResponse>)> {
    let row = read_fenced_transition_receipt_sync(conn, identity, id)?
        .ok_or_else(|| invalid_data("native snapshot V1 receipt disappeared"))?;
    Ok((row.payload_digest, row.retained_until, row.response))
}

pub(crate) fn partition(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    key: ProductionFloorKey,
) -> io::Result<(IrreversibleHistoryFloor, Option<ProductionRetirementCursor>)> {
    let floor = protected_roster_read_floor_sync(conn, identity, key)
        .map_err(|_| invalid_data("native snapshot floor invalid"))?
        .ok_or_else(|| invalid_data("native snapshot floor disappeared"))?;
    let cursor = protected_roster_read_retirement_cursor_sync(conn, identity, key)
        .map_err(|_| invalid_data("native snapshot retirement cursor invalid"))?;
    Ok((floor, cursor))
}

pub(crate) fn roster(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    profile: roster_rows::Profile,
    binding: RequestBindingKey,
    canonical: &[u8],
    root: &RosterAttestationTrustRootV1,
    scope: &MembershipValidationScope,
) -> io::Result<roster_rows::Hydration> {
    use roster_rows::{OriginalAuthority, Profile};
    if canonical.is_empty() || canonical.len() > roster_rows::MAX_CANONICAL_BYTES {
        return Err(invalid_data(
            "native snapshot roster carrier exceeds original bound",
        ));
    }
    let _input = VerificationMemory::reserve(canonical.len() + 8192)?;
    let corrupt = |_| invalid_data("native snapshot original roster authority invalid");
    let (original, table) = match profile {
        Profile::V1 => {
            let row = protected_roster_original_authority_projection_sync(conn, identity, binding)
                .map_err(corrupt)?;
            (
                OriginalAuthority {
                    owner: row.owner,
                    fence: row.fence,
                    credential_id: row.credential_id,
                    generation: row.generation,
                    acquired_at: row.acquired_at,
                    expires_at: row.expires_at,
                },
                "consensus_protected_roster_admissions",
            )
        }
        Profile::V2 => {
            let row =
                protected_roster_v2_original_authority_projection_sync(conn, identity, binding)
                    .map_err(corrupt)?;
            (
                OriginalAuthority {
                    owner: row.owner,
                    fence: row.fence,
                    credential_id: row.credential_id,
                    generation: 1,
                    acquired_at: row.acquired_at,
                    expires_at: row.expires_at,
                },
                "consensus_protected_roster_v2_admissions",
            )
        }
    };
    let hydrated =
        roster_rows::hydrate_original(profile, original, binding, canonical.to_vec(), root, scope)
            .map_err(corrupt)?;
    let (slot,admission,terminal): (Vec<u8>,Vec<u8>,Vec<u8>) = conn.query_row(
        &format!("SELECT stable_slot,admission_request_id,terminal_request_id FROM {table} WHERE binding=?1"),
        [binding.to_bytes().as_slice()],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).map_err(db_error)?;
    let ids = hydrated.projection.request_ids();
    if slot != hydrated.projection.stable_slot || admission != ids[0] || terminal != ids[1] {
        return Err(invalid_data(
            "native snapshot roster request projection differs",
        ));
    }
    Ok(hydrated)
}
