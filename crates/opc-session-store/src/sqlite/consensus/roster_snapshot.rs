//! Cold compatibility output for fully hydrated native roster rows. These
//! functions execute no replicated command. The caller owns a disposable
//! transaction and runs the original complete recovery validator before its
//! commit. Scalar projections alone never authenticate a canonical carrier.

use super::roster_rows::{Body, Hydration};
use super::*;

pub(crate) fn read_root(
    conn: &Connection,
) -> Result<Option<RosterAttestationTrustRootV1>, SessionConsensusStorageError> {
    read_roster_attestation_trust_root_sync(conn)
}

pub(crate) fn activate_v1(conn: &Connection) -> io::Result<()> {
    activate_protected_roster_schema_sync(conn)
}

pub(crate) fn activate_v2(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    scope: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    profile: [u8; 32],
) -> io::Result<()> {
    activate_protected_roster_profile_v2_scope_sync(conn, identity, scope, members, profile)
}

pub(crate) fn write_row(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    hydrated: &Hydration,
) -> io::Result<()> {
    let projection = &hydrated.projection;
    let authority = &projection.original;
    let [admission_request, terminal_request] = projection.request_ids();
    let binding = hydrated.binding();
    let epoch = epoch_i64(identity)?;
    match hydrated.body() {
        Body::V1(hydrated) => {
            let record = hydrated.record();
            protected_roster_write_record_canonical_sync(
                conn,
                identity,
                record,
                hydrated.canonical(),
            )
            .map_err(|_| invalid_data("native snapshot V1 roster write failed"))?;
            // This immutable child must survive retained and compacted rows,
            // whose full Q1 body is intentionally no longer present.
            conn.execute(
                "INSERT INTO consensus_protected_roster_admissions \
                 (binding, stable_slot, admission_request_id, terminal_request_id, configuration_epoch, \
                  original_owner, original_fence, original_credential_id, original_generation, original_acquired_at, original_expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![binding.to_bytes().as_slice(), projection.stable_slot.as_slice(), admission_request.as_slice(),
                    terminal_request.as_slice(), epoch, authority.owner.as_str(), checked_positive_i64(authority.fence)?,
                    checked_positive_i64(authority.credential_id)?, checked_positive_i64(authority.generation)?,
                    ops::format_rfc3339_normalized(authority.acquired_at), ops::format_rfc3339_normalized(authority.expires_at)],
            ).map_err(db_error)?;
            if let Some(reservation) = record.business_reservation() {
                conn.execute(
                    "INSERT INTO consensus_protected_roster_business \
                     (business_key, binding, configuration_epoch, generation, canonical_business) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![binding.session_key_commitment().as_slice(), binding.to_bytes().as_slice(), epoch,
                        checked_positive_i64(reservation.expected().generation().get())?, reservation.expected().canonical_bytes()],
                ).map_err(db_error)?;
            }
        }
        Body::V2(hydrated) => {
            let record = hydrated.record();
            let state = match record.state() {
                ProductionReservationStateV2::Live => 1_i64,
                ProductionReservationStateV2::Retained => 2_i64,
                ProductionReservationStateV2::Tombstone => 3_i64,
            };
            let terminalized = record
                .terminalized_at()
                .map(|time| time.as_nanos().to_be_bytes());
            let sequence = record
                .terminal_sequence()
                .map(checked_positive_i64)
                .transpose()?;
            conn.execute(
                "INSERT INTO consensus_protected_roster_v2_admissions \
                 (binding, stable_slot, admission_request_id, terminal_request_id, configuration_epoch, \
                  partition, history_epoch, state, terminalized_at, terminal_sequence, original_owner, \
                  original_fence, original_credential_id, original_acquired_at, original_expires_at, canonical_record) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![binding.to_bytes().as_slice(), projection.stable_slot.as_slice(), admission_request.as_slice(),
                    terminal_request.as_slice(), epoch, binding.partition_bytes().as_slice(), checked_positive_i64(binding.history_epoch())?,
                    state, terminalized.as_ref().map(<[u8; 16]>::as_slice), sequence, authority.owner.as_str(),
                    checked_positive_i64(authority.fence)?, checked_positive_i64(authority.credential_id)?,
                    ops::format_rfc3339_normalized(authority.acquired_at), ops::format_rfc3339_normalized(authority.expires_at),
                    hydrated.canonical()],
            ).map_err(db_error)?;
            if let Some(reservation) = record.absence_reservation() {
                conn.execute(
                    "INSERT INTO consensus_protected_roster_v2_absence_reservations \
                     (business_key, binding, configuration_epoch) VALUES (?1, ?2, ?3)",
                    params![
                        session_key_commitment(reservation.predicate().key()).as_slice(),
                        binding.to_bytes().as_slice(),
                        epoch
                    ],
                )
                .map_err(db_error)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn write_partition(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    key: ProductionFloorKey,
    floor: IrreversibleHistoryFloor,
    cursor: Option<&ProductionRetirementCursor>,
) -> io::Result<()> {
    let epoch = epoch_i64(identity)?;
    conn.execute(
        "INSERT INTO consensus_protected_roster_floors (partition, configuration_epoch, canonical_floor) VALUES (?1, ?2, ?3)",
        params![key.as_bytes().as_slice(), epoch, floor.to_canonical_bytes()
            .map_err(|_| invalid_data("native snapshot roster floor encoding failed"))?],
    ).map_err(db_error)?;
    if let Some(cursor) = cursor {
        conn.execute(
            "INSERT INTO consensus_protected_roster_retirement_cursors (partition, configuration_epoch, canonical_cursor) VALUES (?1, ?2, ?3)",
            params![key.as_bytes().as_slice(), epoch, cursor.to_canonical_bytes()
                .map_err(|_| invalid_data("native snapshot roster cursor encoding failed"))?],
        ).map_err(db_error)?;
    }
    Ok(())
}

pub(crate) fn write_witness(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    witness: GlobalChargeWitness,
) -> io::Result<()> {
    protected_roster_write_witness_sync(conn, identity, witness)
        .map_err(|_| invalid_data("native snapshot roster witness write failed"))
}
