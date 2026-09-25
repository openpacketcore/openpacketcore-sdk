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

use super::sqlite::SqliteWorkCancellation;
use crate::audit_authority::ledger::{authenticate, verify, MAX_STATE_BYTES};
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
    WHERE (name GLOB 'config_netconf_*' OR tbl_name GLOB 'config_netconf_*') \
    AND name NOT GLOB 'sqlite_autoindex_*'";

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid retained NETCONF target state",
    )
}

/// No activation path is connected yet. Only authenticated inactive bodies are
/// admitted here. Non-null ownership/content must never be treated as fresh
/// storage; its codec and authorization arrive with the corresponding effect.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
enum Unactivated {}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileBody {
    format: u16,
    authority: ConfigConsensusIdentity,
    target_profile: u8,
    capacity_profile: u8,
    activation_operation: Option<Unactivated>,
    bootstrap_checkpoint: Option<Unactivated>,
    device_incarnation: Option<Unactivated>,
    last_target_transition_sequence: u64,
    state_digest: [u8; 32],
}

#[derive(Serialize)]
struct ProfileDigestBody<'a> {
    format: u16,
    authority: ConfigConsensusIdentity,
    target_profile: u8,
    capacity_profile: u8,
    activation_operation: &'a Option<Unactivated>,
    bootstrap_checkpoint: &'a Option<Unactivated>,
    device_incarnation: &'a Option<Unactivated>,
    last_target_transition_sequence: u64,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetBody {
    format: u16,
    target: u8,
    generation: u64,
    present: bool,
    schema: Option<Unactivated>,
    encrypted_envelope: Option<Unactivated>,
    source_binding: Option<Unactivated>,
    last_applying_operation: Option<Unactivated>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleBody {
    format: u16,
    device_ownership: Option<Unactivated>,
    locks: [Option<Unactivated>; 3],
    pending_confirmation: Option<Unactivated>,
    rollback_parent: Option<Unactivated>,
    original_deadline: Option<Unactivated>,
    encrypted_confirmation_ownership: Option<Unactivated>,
    cleanup: [Option<Unactivated>; 3],
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
    profile.state_digest = digest.finalize().into();
    Ok((profile, targets, lifecycle))
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

pub(super) fn validate_inactive_sync(
    conn: &Connection,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
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
    if (profile, [candidate, startup], lifecycle) != initial_state(identity)? {
        return Err(invalid());
    }
    cancellation.check_io()
}
