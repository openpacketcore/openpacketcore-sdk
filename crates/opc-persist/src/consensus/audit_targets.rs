//! Closed retained NETCONF target profiles. Selecting a profile is not admission.

use serde::{Deserialize, Serialize};

/// Independently selected configuration target and capacity contract.
///
/// The profile is admitted by the caller's storage authority, never inferred
/// from stored data. Selection alone does not enable an unsupported profile.
/// All variants use the existing configuration authority and native WAL.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetainedConfigProfile {
    /// Original running authority with its existing capacity and byte formats.
    Legacy,
    /// RFC 019 retained NETCONF targets with the landed legacy capacity bounds.
    /// Command/wire revision 9 and storage/snapshot revision 7 are required;
    /// this does not opt in to the separately reserved capacity profile.
    NetconfTargetsV1,
}

impl std::fmt::Debug for RetainedConfigProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedConfigProfile(<redacted>)")
    }
}

use std::io;

use rusqlite::{params, Connection};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use super::audit_mutation::{
    PreparedTargetMutation, TargetEncryptedBlobV1, TargetExpectationV1, TargetPayloadV1,
    TargetResolutionV1, TargetSourceV1,
};
use super::sqlite::SqliteWorkCancellation;
use crate::audit_authority::continuity::{AuditCheckpoint, AuditKeyRing};
use crate::audit_authority::ledger::LedgerState;
use crate::audit_authority::ledger::{authenticate, verify, MAX_STATE_BYTES};
use crate::audit_authority::{
    AuditAuthorityError, AuditCaller, AuditOperationState, NetconfAppliedOutcome,
    NetconfIncarnation, NetconfTargetResult,
};
use crate::{AuditKey, ConfigConsensusIdentity};

pub(super) const TARGET_STORAGE_VERSION: u16 = 7;
const PROFILE_DOMAIN: &[u8] = b"openpacketcore/config-netconf/profile/v1\0";
const TARGET_DOMAIN: &[u8] = b"openpacketcore/config-netconf/target/v1\0";
const LIFECYCLE_DOMAIN: &[u8] = b"openpacketcore/config-netconf/lifecycle/v1\0";
const STATE_DOMAIN: &[u8] = b"openpacketcore/config-netconf/state-digest/v1\0";

const SCHEMA: &str = r#"
CREATE TABLE config_netconf_profile (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 16777216),
    state_hmac BLOB NOT NULL CHECK (length(state_hmac) = 32)
);
CREATE TABLE config_netconf_targets (
    target INTEGER PRIMARY KEY CHECK (target IN (0, 1)),
    state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 16777216),
    state_hmac BLOB NOT NULL CHECK (length(state_hmac) = 32)
);
CREATE TABLE config_netconf_lifecycle (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 16777216),
    state_hmac BLOB NOT NULL CHECK (length(state_hmac) = 32)
);
"#;

const OBJECTS: &str = "SELECT type, name, tbl_name, sql FROM main.sqlite_schema \
    WHERE (name GLOB 'config_netconf_*' OR tbl_name GLOB 'config_netconf_*')";

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid retained NETCONF target state",
    )
}

/// Confirmation and cleanup records remain closed until the atomic running
/// transition is connected. Non-null unsupported ownership cannot be treated
/// as absent state or silently initialized.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Unactivated {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileBody {
    format: u16,
    authority: ConfigConsensusIdentity,
    target_profile: u8,
    capacity_profile: u8,
    activation_operation: Option<Activation>,
    bootstrap_checkpoint: Option<AuditCheckpoint>,
    device_incarnation: Option<[u8; 16]>,
    last_target_transition_sequence: u64,
    state_digest: [u8; 32],
}

#[derive(Serialize)]
struct ProfileDigestBody<'a> {
    format: u16,
    authority: ConfigConsensusIdentity,
    target_profile: u8,
    capacity_profile: u8,
    activation_operation: &'a Option<Activation>,
    bootstrap_checkpoint: &'a Option<AuditCheckpoint>,
    device_incarnation: &'a Option<[u8; 16]>,
    last_target_transition_sequence: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetBody {
    format: u16,
    target: u8,
    generation: u64,
    present: bool,
    schema: Option<opc_types::SchemaDigest>,
    encrypted_envelope: Option<TargetEncryptedBlobV1>,
    source_binding: Option<TargetBinding>,
    last_applying_operation: Option<[u8; 32]>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleBody {
    format: u16,
    device_ownership: Option<DeviceOwnership>,
    locks: [Option<LockState>; 3],
    pending_confirmation: Option<Unactivated>,
    rollback_parent: Option<Unactivated>,
    original_deadline: Option<Unactivated>,
    encrypted_confirmation_ownership: Option<Unactivated>,
    cleanup: [Option<Unactivated>; 3],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    operation: [u8; 32],
    profile_incarnation: [u8; 16],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceOwnership {
    incarnation: [u8; 16],
    caller: AuditCaller,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockState {
    incarnation: u64,
    session: Option<[u8; 16]>,
    caller: Option<AuditCaller>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetBinding {
    base_version: u64,
    source: Option<TargetSourceV1>,
    session: [u8; 16],
    caller: AuditCaller,
}

fn initial_state(
    authority: ConfigConsensusIdentity,
) -> io::Result<(ProfileBody, [TargetBody; 2], LifecycleBody)> {
    let mut profile = ProfileBody {
        format: 1,
        authority,
        target_profile: 1,
        capacity_profile: 0,
        activation_operation: None,
        bootstrap_checkpoint: None,
        device_incarnation: None,
        last_target_transition_sequence: 0,
        state_digest: [0; 32],
    };
    let targets = [0, 1].map(|target| TargetBody {
        format: 1,
        target,
        generation: 0,
        present: false,
        schema: None,
        encrypted_envelope: None,
        source_binding: None,
        last_applying_operation: None,
    });
    let lifecycle = LifecycleBody {
        format: 1,
        device_ownership: None,
        locks: [None, None, None],
        pending_confirmation: None,
        rollback_parent: None,
        original_deadline: None,
        encrypted_confirmation_ownership: None,
        cleanup: [None, None, None],
    };
    profile.state_digest = state_digest(&profile, &targets, &lifecycle)?;
    Ok((profile, targets, lifecycle))
}

fn state_digest(
    profile: &ProfileBody,
    targets: &[TargetBody; 2],
    lifecycle: &LifecycleBody,
) -> io::Result<[u8; 32]> {
    let digest_body = ProfileDigestBody {
        format: profile.format,
        authority: profile.authority,
        target_profile: profile.target_profile,
        capacity_profile: profile.capacity_profile,
        activation_operation: &profile.activation_operation,
        bootstrap_checkpoint: &profile.bootstrap_checkpoint,
        device_incarnation: &profile.device_incarnation,
        last_target_transition_sequence: profile.last_target_transition_sequence,
    };
    let mut digest = Sha256::new();
    digest.update(STATE_DOMAIN);
    for encoded in [
        serde_json::to_vec(&digest_body),
        serde_json::to_vec(&targets[0]),
        serde_json::to_vec(&targets[1]),
        serde_json::to_vec(&lifecycle),
    ] {
        let encoded = encoded.map_err(|_| invalid())?;
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    Ok(digest.finalize().into())
}

/// Independent DDL comparison, before loading any supplied body into Rust.
pub(super) fn schema_digest_sync(
    conn: &Connection,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<[u8; 32]> {
    cancellation.check_io()?;
    let expected = Connection::open_in_memory().map_err(|_| invalid())?;
    expected.execute_batch(SCHEMA).map_err(|_| invalid())?;
    let count: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM ({OBJECTS})"), [], |row| {
            row.get(0)
        })
        .map_err(|_| invalid())?;
    if count != 3 {
        return Err(invalid());
    }
    let mut statement = expected
        .prepare(&format!("{OBJECTS} ORDER BY name"))
        .map_err(|_| invalid())?;
    let mut rows = statement.query([]).map_err(|_| invalid())?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/config-netconf/catalog/v1\0");
    while let Some(row) = rows.next().map_err(|_| invalid())? {
        cancellation.check_io()?;
        let values = [
            row.get::<_, String>(0).map_err(|_| invalid())?,
            row.get::<_, String>(1).map_err(|_| invalid())?,
            row.get::<_, String>(2).map_err(|_| invalid())?,
            row.get::<_, String>(3).map_err(|_| invalid())?,
        ];
        let matches: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type=?1 AND name=?2 AND tbl_name=?3 AND sql=?4)",
            params![values[0], values[1], values[2], values[3]], |row| row.get(0),
        ).map_err(|_| invalid())?;
        if !matches {
            return Err(invalid());
        }
        for value in values {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    Ok(digest.finalize().into())
}

pub(super) fn initialize_inactive_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
) -> io::Result<()> {
    let (profile, targets, lifecycle) = initial_state(identity)?;
    let mut total = 0;
    conn.execute_batch(SCHEMA).map_err(|_| invalid())?;
    for (table, slot, body, domain) in [
        (
            "config_netconf_profile",
            1,
            serde_json::to_vec(&profile),
            PROFILE_DOMAIN,
        ),
        (
            "config_netconf_targets",
            0,
            serde_json::to_vec(&targets[0]),
            TARGET_DOMAIN,
        ),
        (
            "config_netconf_targets",
            1,
            serde_json::to_vec(&targets[1]),
            TARGET_DOMAIN,
        ),
        (
            "config_netconf_lifecycle",
            1,
            serde_json::to_vec(&lifecycle),
            LIFECYCLE_DOMAIN,
        ),
    ] {
        let body = body.map_err(|_| invalid())?;
        total += body.len();
        if total > MAX_STATE_BYTES {
            return Err(invalid());
        }
        // Authenticate the serialized struct, not its byte-array JSON wrapper.
        let mac = match table {
            "config_netconf_profile" => authenticate(key, domain, &profile),
            "config_netconf_lifecycle" => authenticate(key, domain, &lifecycle),
            _ => authenticate(key, domain, &targets[slot as usize]),
        }
        .map_err(|_| invalid())?;
        conn.execute(
            &format!("INSERT INTO {table} VALUES (?1, ?2, ?3)"),
            params![slot, body, mac.as_slice()],
        )
        .map_err(|_| invalid())?;
    }
    Ok(())
}

fn read_row<T: DeserializeOwned + Serialize>(
    conn: &Connection,
    table: &str,
    column: &str,
    slot: u8,
    key: &AuditKey,
    domain: &[u8],
) -> io::Result<T> {
    let (encoded, mac): (Vec<u8>, Vec<u8>) = conn.query_row(
        &format!("SELECT state_json, state_hmac FROM {table} WHERE {column}=?1 AND length(state_json) BETWEEN 1 AND 16777216 AND length(state_hmac)=32"),
        [slot], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| invalid())?;
    let body: T = serde_json::from_slice(&encoded).map_err(|_| invalid())?;
    if serde_json::to_vec(&body).map_err(|_| invalid())? != encoded {
        return Err(invalid());
    }
    let mac = mac.try_into().map_err(|_| invalid())?;
    verify(key, domain, &body, &mac).map_err(|_| invalid())?;
    Ok(body)
}

fn read_state_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<TargetState> {
    // The four bodies share one aggregate bound, not four separate allowances.
    let mut total = 0u64;
    for (table, expected) in [
        ("config_netconf_profile", 1),
        ("config_netconf_targets", 2),
        ("config_netconf_lifecycle", 1),
    ] {
        cancellation.check_io()?;
        let (count, bytes): (i64, u64) = conn
            .query_row(
                &format!("SELECT COUNT(*), COALESCE(SUM(length(state_json)),0) FROM {table}"),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| invalid())?;
        total = total.checked_add(bytes).ok_or_else(invalid)?;
        if count != expected || total > MAX_STATE_BYTES as u64 {
            return Err(invalid());
        }
    }
    let profile: ProfileBody = read_row(
        conn,
        "config_netconf_profile",
        "singleton",
        1,
        key,
        PROFILE_DOMAIN,
    )?;
    let candidate: TargetBody = read_row(
        conn,
        "config_netconf_targets",
        "target",
        0,
        key,
        TARGET_DOMAIN,
    )?;
    let startup: TargetBody = read_row(
        conn,
        "config_netconf_targets",
        "target",
        1,
        key,
        TARGET_DOMAIN,
    )?;
    let lifecycle: LifecycleBody = read_row(
        conn,
        "config_netconf_lifecycle",
        "singleton",
        1,
        key,
        LIFECYCLE_DOMAIN,
    )?;
    let state = TargetState {
        profile,
        targets: [candidate, startup],
        lifecycle,
    };
    state.validate(identity)?;
    cancellation.check_io()?;
    Ok(state)
}

#[derive(Clone)]
struct TargetState {
    profile: ProfileBody,
    targets: [TargetBody; 2],
    lifecycle: LifecycleBody,
}

impl TargetState {
    fn validate(&self, identity: ConfigConsensusIdentity) -> io::Result<()> {
        let p = &self.profile;
        if p.authority != identity
            || p.format != 1
            || p.target_profile != 1
            || p.capacity_profile != 0
            || p.state_digest != state_digest(p, &self.targets, &self.lifecycle)?
        {
            return Err(invalid());
        }
        let Some(activation) = &p.activation_operation else {
            if (p.clone(), self.targets.clone(), self.lifecycle.clone()) != initial_state(identity)?
            {
                return Err(invalid());
            }
            return Ok(());
        };
        if activation.profile_incarnation == [0; 16]
            || activation.operation == [0; 32]
            || p.last_target_transition_sequence == 0
            || p.bootstrap_checkpoint.as_ref().is_none_or(|c| {
                c.body.identity != identity || c.sequence() >= p.last_target_transition_sequence
            })
            || p.device_incarnation.is_none_or(|v| v == [0; 16])
            || self.lifecycle.format != 1
            || self
                .lifecycle
                .device_ownership
                .as_ref()
                .map(|d| d.incarnation)
                != p.device_incarnation
        {
            return Err(invalid());
        }
        for (slot, target) in self.targets.iter().enumerate() {
            if target.format != 1
                || target.target != slot as u8
                || (target.generation == 0
                    && (target.present || target.last_applying_operation.is_some()))
                || (target.generation > 0 && target.last_applying_operation.is_none())
            {
                return Err(invalid());
            }
            match (
                &target.encrypted_envelope,
                &target.source_binding,
                target.present,
            ) {
                (Some(blob), Some(binding), true)
                    if target.schema.as_ref() == Some(&blob.schema)
                        && binding.session != [0; 16]
                        && target.generation > 0 =>
                {
                    blob.validate().map_err(|_| invalid())?;
                }
                (None, None, false) if target.schema.is_none() => {}
                _ => return Err(invalid()),
            }
        }
        for lock in &self.lifecycle.locks {
            let Some(lock) = lock else {
                return Err(invalid());
            };
            if lock.session.is_some() != lock.caller.is_some()
                || lock.session == Some([0; 16])
                || (lock.session.is_some() && lock.incarnation == 0)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn validate_anchor(&self, ledger: Option<&LedgerState>) -> io::Result<()> {
        match (
            &self.profile.activation_operation,
            ledger.and_then(|l| l.target_anchor),
        ) {
            (None, None) => Ok(()),
            (Some(activation), Some(anchor))
                if anchor.sequence == self.profile.last_target_transition_sequence
                    && anchor.result.authority() == self.profile.authority
                    && anchor.result.profile_incarnation() == activation.profile_incarnation
                    && anchor.result.state_digest() == self.profile.state_digest =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }

    fn write(&self, conn: &Connection, key: &AuditKey) -> io::Result<()> {
        // Serialize and bound all rows before the first write. The enclosing
        // authority transaction owns both these rows and the ledger outcome.
        let rows = [
            (
                "config_netconf_profile",
                "singleton",
                1,
                serde_json::to_vec(&self.profile),
                authenticate(key, PROFILE_DOMAIN, &self.profile),
            ),
            (
                "config_netconf_targets",
                "target",
                0,
                serde_json::to_vec(&self.targets[0]),
                authenticate(key, TARGET_DOMAIN, &self.targets[0]),
            ),
            (
                "config_netconf_targets",
                "target",
                1,
                serde_json::to_vec(&self.targets[1]),
                authenticate(key, TARGET_DOMAIN, &self.targets[1]),
            ),
            (
                "config_netconf_lifecycle",
                "singleton",
                1,
                serde_json::to_vec(&self.lifecycle),
                authenticate(key, LIFECYCLE_DOMAIN, &self.lifecycle),
            ),
        ];
        let mut total = 0usize;
        for (_, _, _, bytes, mac) in &rows {
            total = total
                .checked_add(bytes.as_ref().map_err(|_| invalid())?.len())
                .ok_or_else(invalid)?;
            if total > MAX_STATE_BYTES || mac.is_err() {
                return Err(invalid());
            }
        }
        for (table, column, slot, bytes, mac) in rows {
            let bytes = bytes.map_err(|_| invalid())?;
            let mac = mac.map_err(|_| invalid())?;
            if conn
                .execute(
                    &format!("UPDATE {table} SET state_json=?1,state_hmac=?2 WHERE {column}=?3"),
                    params![bytes, mac.as_slice(), slot],
                )
                .map_err(|_| invalid())?
                != 1
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

// The legacy name is retained for the already-qualified call sites. This now
// validates either the exact inactive state or authenticated active rows and
// their latest retained audit anchor; it never infers the admitted profile.
pub(super) fn validate_inactive_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    let state = read_state_sync(conn, key, identity, cancellation)?;
    let ledger = super::audit::read_sync(conn, key, identity)?;
    state.validate_anchor(ledger.as_ref())
}

impl TargetState {
    fn advance_target(
        &mut self,
        slot: usize,
        prepared: &PreparedTargetMutation,
        blob: Option<TargetEncryptedBlobV1>,
    ) -> Result<(), AuditAuthorityError> {
        let target = &mut self.targets[slot];
        target.generation = target
            .generation
            .checked_add(1)
            .ok_or(AuditAuthorityError::Full)?;
        target.present = blob.is_some();
        target.schema = blob.as_ref().map(|b| b.schema);
        target.source_binding = if blob.is_some() {
            let lock = prepared
                .effect
                .lock
                .as_ref()
                .ok_or(AuditAuthorityError::BindingMismatch)?;
            Some(TargetBinding {
                base_version: prepared.handle.body.binding.base_version,
                source: prepared.effect.source.clone(),
                session: lock.requester,
                caller: prepared.effect.caller,
            })
        } else {
            None
        };
        target.encrypted_envelope = blob;
        target.last_applying_operation = Some(prepared.handle.mac);
        Ok(())
    }

    fn check_lock(
        &self,
        prepared: &PreparedTargetMutation,
        slot: usize,
    ) -> Result<(), AuditAuthorityError> {
        let expected = prepared
            .effect
            .lock
            .as_ref()
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        let current = self.lifecycle.locks[slot]
            .as_ref()
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        if usize::from(expected.datastore) != slot
            || expected.incarnation != current.incarnation
            || expected.session != current.session
            || current.session.is_some_and(|s| s != expected.requester)
            || current.caller.is_some_and(|c| c != prepared.effect.caller)
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    fn check_source(
        &self,
        source: &TargetSourceV1,
        conn: &Connection,
    ) -> Result<(), AuditAuthorityError> {
        let bad = AuditAuthorityError::BindingMismatch;
        match source {
            TargetSourceV1::Candidate {
                generation,
                schema,
                ciphertext_digest,
            } => {
                let target = &self.targets[0];
                if generation.get() != target.generation
                    || target.schema.as_ref() != Some(schema)
                    || target.encrypted_envelope.as_ref().is_none_or(|b| {
                        <[u8; 32]>::from(Sha256::digest(&b.encrypted_blob)) != *ciphertext_digest
                    })
                {
                    return Err(bad);
                }
            }
            TargetSourceV1::Startup {
                revision,
                schema,
                ciphertext_digest,
            } => {
                let target = &self.targets[1];
                if revision.get() != target.generation
                    || target.schema.as_ref() != Some(schema)
                    || target.encrypted_envelope.as_ref().is_none_or(|b| {
                        <[u8; 32]>::from(Sha256::digest(&b.encrypted_blob)) != *ciphertext_digest
                    })
                {
                    return Err(bad);
                }
            }
            TargetSourceV1::Running {
                version,
                schema,
                ciphertext_digest,
            }
            | TargetSourceV1::CandidateFallback {
                running_version: version,
                schema,
                ciphertext_digest,
                ..
            } => {
                if let TargetSourceV1::CandidateFallback { generation, .. } = source {
                    if self.targets[0].present || self.targets[0].generation != generation.get() {
                        return Err(bad);
                    }
                }
                let (current, current_schema, encrypted): (u64, Vec<u8>, Vec<u8>) = conn.query_row(
                    "SELECT version,schema_digest,encrypted_blob FROM config_history ORDER BY version DESC LIMIT 1", [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(|_| bad)?;
                if current != *version
                    || current_schema != schema.as_bytes()
                    || <[u8; 32]>::from(Sha256::digest(encrypted)) != *ciphertext_digest
                {
                    return Err(bad);
                }
            }
        }
        Ok(())
    }

    fn reduce(
        &mut self,
        conn: &Connection,
        prepared: &PreparedTargetMutation,
        ledger: &LedgerState,
        keys: &AuditKeyRing,
    ) -> Result<NetconfAppliedOutcome, AuditAuthorityError> {
        let effect = &prepared.effect;
        let bad = AuditAuthorityError::BindingMismatch;
        let action = u8::from(effect.action);
        let current_version: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version),0) FROM config_history",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        if current_version != prepared.handle.body.binding.base_version {
            return Err(bad);
        }
        match effect.destination {
            TargetExpectationV1::Candidate { generation }
                if generation.get() == self.targets[0].generation => {}
            TargetExpectationV1::Startup { revision }
                if revision.get() == self.targets[1].generation => {}
            TargetExpectationV1::Lifecycle { state_digest }
                if state_digest == self.profile.state_digest => {}
            TargetExpectationV1::Running { version } if version == current_version => {}
            _ => return Err(bad),
        }
        if let Some(source) = &effect.source {
            self.check_source(source, conn)?;
        }
        let lifecycle_result = |value| NetconfAppliedOutcome::Lifecycle {
            incarnation: NetconfIncarnation {
                authority: effect.authority,
                value,
            },
        };
        if action == 0 {
            let Some(TargetResolutionV1::Activate { checkpoint }) = &effect.resolution else {
                return Err(bad);
            };
            let operation = ledger
                .operations
                .iter()
                .find(|op| op.handle == prepared.handle)
                .ok_or(bad)?;
            checkpoint.verify(keys, effect.authority)?;
            ledger.matches_checkpoint(checkpoint)?;
            if self.profile.activation_operation.is_some()
                || current_version != 0
                || checkpoint.sequence().checked_add(1) != Some(operation.first_sequence)
                || effect.source.is_some()
                || effect.lock.is_some()
            {
                return Err(bad);
            }
            self.profile.activation_operation = Some(Activation {
                operation: prepared.handle.mac,
                profile_incarnation: effect.profile_incarnation,
            });
            self.profile.bootstrap_checkpoint = Some(checkpoint.clone());
            self.profile.device_incarnation = Some(effect.device_incarnation);
            self.lifecycle.device_ownership = Some(DeviceOwnership {
                incarnation: effect.device_incarnation,
                caller: effect.caller,
            });
            self.lifecycle.locks = std::array::from_fn(|_| {
                Some(LockState {
                    incarnation: 0,
                    session: None,
                    caller: None,
                })
            });
            return Ok(lifecycle_result(effect.device_incarnation));
        }
        let activation = self.profile.activation_operation.as_ref().ok_or(bad)?;
        if activation.profile_incarnation != effect.profile_incarnation
            || (action != 1 && self.profile.device_incarnation != Some(effect.device_incarnation))
        {
            return Err(bad);
        }
        // Pending ownership has no enabled constructor until the atomic running
        // promotion/rollback component is connected. Non-null unknown state is
        // rejected by the closed decoder instead of being treated as absent.
        match action {
            1 => {
                let Some(TargetResolutionV1::BeginDevice { previous }) = effect.resolution else {
                    return Err(bad);
                };
                if previous != self.profile.device_incarnation
                    || previous == Some(effect.device_incarnation)
                    || effect.lock.is_some()
                    || effect.source.is_some()
                {
                    return Err(bad);
                }
                if self.targets[0].present {
                    self.advance_target(0, prepared, None)?;
                }
                for lock in &mut self.lifecycle.locks {
                    let lock = lock.as_mut().ok_or(bad)?;
                    lock.incarnation = lock
                        .incarnation
                        .checked_add(1)
                        .ok_or(AuditAuthorityError::Full)?;
                    lock.session = None;
                    lock.caller = None;
                }
                self.profile.device_incarnation = Some(effect.device_incarnation);
                self.lifecycle.device_ownership = Some(DeviceOwnership {
                    incarnation: effect.device_incarnation,
                    caller: effect.caller,
                });
                Ok(lifecycle_result(effect.device_incarnation))
            }
            2 | 3 => {
                let expected = effect.lock.as_ref().ok_or(bad)?;
                let slot = usize::from(expected.datastore);
                self.check_lock(prepared, slot)?;
                let session = match effect.resolution {
                    Some(TargetResolutionV1::AcquireLock { session }) if action == 2 => session,
                    Some(TargetResolutionV1::ReleaseLock { session }) if action == 3 => session,
                    _ => return Err(bad),
                };
                if session != expected.requester {
                    return Err(bad);
                }
                let current = self.lifecycle.locks[slot].as_ref().ok_or(bad)?;
                if action == 2 {
                    if current.session.is_some()
                        || (slot == 1
                            && self.targets[0]
                                .source_binding
                                .as_ref()
                                .is_some_and(|b| b.session != session || b.caller != effect.caller))
                    {
                        return Err(bad);
                    }
                } else {
                    if current.session != Some(session) {
                        return Err(bad);
                    }
                    if slot == 1 {
                        self.advance_target(0, prepared, None)?;
                    }
                }
                let current = self.lifecycle.locks[slot].as_mut().ok_or(bad)?;
                current.incarnation = current
                    .incarnation
                    .checked_add(1)
                    .ok_or(AuditAuthorityError::Full)?;
                current.session = (action == 2).then_some(session);
                current.caller = (action == 2).then_some(effect.caller);
                Ok(lifecycle_result(prepared.handle.body.nonce))
            }
            4 | 5 | 7 | 8 => {
                let slot = if matches!(action, 4 | 5) { 0 } else { 1 };
                self.check_lock(prepared, slot + 1)?;
                let blob = match (&effect.encrypted_payload, action) {
                    (Some(TargetPayloadV1::Target(blob)), 4 | 7) => {
                        let next = self.targets[slot]
                            .generation
                            .checked_add(1)
                            .ok_or(AuditAuthorityError::Full)?;
                        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&blob.encrypted_blob)
                            .map_err(|_| bad)?;
                        let (aad, _) = opc_key::decode_bound_aad(envelope.aad).map_err(|_| bad)?;
                        let opc_key::EnvelopeMetadata::Config(metadata) = aad.metadata() else {
                            return Err(bad);
                        };
                        if aad.version() != next
                            || metadata.store_kind()
                                != effect.encryption_store_kind(blob.schema, slot as u8)?
                        {
                            return Err(bad);
                        }
                        Some(blob.clone())
                    }
                    (None, 5 | 8) => None,
                    _ => return Err(bad),
                };
                self.advance_target(slot, prepared, blob)?;
                if slot == 0 {
                    Ok(NetconfAppliedOutcome::Candidate {
                        generation: crate::CandidateGeneration {
                            authority: effect.authority,
                            value: self.targets[slot].generation,
                        },
                    })
                } else {
                    Ok(NetconfAppliedOutcome::Startup {
                        revision: crate::StartupRevision {
                            authority: effect.authority,
                            value: self.targets[slot].generation,
                        },
                    })
                }
            }
            13 => {
                let Some(TargetResolutionV1::EndSession { session }) = effect.resolution else {
                    return Err(bad);
                };
                if session == [0; 16] || effect.lock.is_some() || effect.source.is_some() {
                    return Err(bad);
                }
                let discard = self.targets[0]
                    .source_binding
                    .as_ref()
                    .is_some_and(|b| b.session == session)
                    || self.lifecycle.locks[1]
                        .as_ref()
                        .is_some_and(|l| l.session == Some(session));
                if self.targets[0]
                    .source_binding
                    .as_ref()
                    .is_some_and(|b| b.session == session && b.caller != effect.caller)
                    || self
                        .lifecycle
                        .locks
                        .iter()
                        .flatten()
                        .any(|l| l.session == Some(session) && l.caller != Some(effect.caller))
                {
                    return Err(bad);
                }
                if discard {
                    self.advance_target(0, prepared, None)?;
                }
                for lock in self.lifecycle.locks.iter_mut().flatten() {
                    // Closing a session invalidates its precomputed unlocked
                    // effects too. Foreign held leases retain their incarnation.
                    if lock.session.is_none() || lock.session == Some(session) {
                        lock.incarnation = lock
                            .incarnation
                            .checked_add(1)
                            .ok_or(AuditAuthorityError::Full)?;
                        lock.session = None;
                        lock.caller = None;
                    }
                }
                Ok(lifecycle_result(session))
            }
            _ => Err(AuditAuthorityError::RecoveryRequired),
        }
    }
}

/// Atomic non-running target transition inside the caller's authority transaction.
/// Runtime activation is still gated by the independently selected store profile.
pub(crate) fn apply_target_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    prepared: &PreparedTargetMutation,
    now: i64,
    keys: Option<&AuditKeyRing>,
) -> io::Result<Result<(), super::ConfigMutationFailure>> {
    use super::ConfigMutationFailure as Failure;
    if conn.is_autocommit() {
        return Err(invalid());
    }
    if prepared.verify_effect(key).is_err() {
        return Ok(Err(Failure::Conflict));
    }
    let Some(keys) = keys else {
        return Ok(Err(Failure::InvalidInput));
    };
    let Some(mut ledger) = super::audit::read_with_keys_sync(conn, key, Some(keys), identity)?
    else {
        return Ok(Err(Failure::InvalidInput));
    };
    let original = match ledger.recover_target(key, prepared.handle(), prepared.effect.caller) {
        Ok(original) => original,
        Err(_) => return Ok(Err(Failure::Conflict)),
    };
    if original != *prepared {
        return Ok(Err(Failure::Conflict));
    }
    let Some(operation) = ledger
        .operations
        .iter()
        .find(|op| op.handle == prepared.handle)
    else {
        return Ok(Err(Failure::Conflict));
    };
    match operation.state {
        AuditOperationState::TargetV1(_) => return Ok(Ok(())),
        AuditOperationState::Intent => {}
        _ => return Ok(Err(Failure::Conflict)),
    }
    if ledger
        .continuity
        .as_ref()
        .and_then(|c| c.checkpoint.as_ref())
        .is_none_or(|c| c.sequence() < operation.first_sequence)
        || ledger.operations.iter().any(|op| {
            (op.handle != prepared.handle && !op.terminal_recorded)
                || ledger.mutation_outcome_needs_checkpoint(op)
        })
    {
        return Ok(Err(Failure::InvalidInput));
    }
    let cancellation = SqliteWorkCancellation::new();
    let mut state = read_state_sync(conn, key, identity, &cancellation)?;
    state.validate_anchor(Some(&ledger))?;
    super::history::validate_record_chain_sync(conn, key, &cancellation)?;
    let reduced = prepared
        .handle
        .require_live(now)
        .and_then(|()| state.reduce(conn, prepared, &ledger, keys));
    let (result, applied) = match reduced {
        Ok(outcome) => {
            state.profile.last_target_transition_sequence =
                ledger.sequence.checked_add(1).ok_or_else(invalid)?;
            state.profile.state_digest =
                state_digest(&state.profile, &state.targets, &state.lifecycle)?;
            state.validate(identity)?;
            let result = NetconfTargetResult::new(
                identity,
                prepared.effect.profile_incarnation,
                state.profile.state_digest,
                outcome,
            )
            .map_err(|_| invalid())?;
            (Ok(()), AuditOperationState::TargetV1(result))
        }
        Err(AuditAuthorityError::RecoveryRequired) => return Ok(Err(Failure::InvalidInput)),
        Err(error) => (
            Err(if error == AuditAuthorityError::Full {
                Failure::HistoryFull
            } else {
                Failure::Conflict
            }),
            AuditOperationState::Rejected,
        ),
    };
    ledger
        .resolve(key, prepared.handle(), applied)
        .map_err(|_| invalid())?;
    ledger.seal_continuity(Some(keys)).map_err(|_| invalid())?;
    ledger.validate(key, identity).map_err(|_| invalid())?;
    ledger
        .validate_continuity(Some(keys))
        .map_err(|_| invalid())?;
    if result.is_ok() {
        state.validate_anchor(Some(&ledger))?;
        state.write(conn, key)?;
    }
    super::audit::write_sync(conn, key, identity, Some(ledger), false)?;
    Ok(result)
}
