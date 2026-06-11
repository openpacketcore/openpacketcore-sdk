use std::fmt;
use std::str::FromStr;

use bytes::Bytes;
use hmac::{Hmac, Mac};
use opc_types::{NetworkFunctionKind, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Classification of session state by consistency requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateClass {
    /// Single writer with fencing (e.g. PDU session owner, AMF/SMF ownership).
    AuthoritativeSession,
    /// Local atomic snapshot, rebuildable (e.g. TEID to session mapping).
    DataplaneLookup,
    /// Async, ordered by generation (e.g. warm standby copy).
    ReplicatedDr,
    /// Mergeable or lossy (e.g. counters, rates, timestamps).
    TelemetryDerived,
    /// TTL, fenced owner (e.g. temporary handover transaction state).
    EphemeralProcedure,
}

impl fmt::Display for StateClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateClass::AuthoritativeSession => write!(f, "authoritative-session"),
            StateClass::DataplaneLookup => write!(f, "dataplane-lookup"),
            StateClass::ReplicatedDr => write!(f, "replicated-dr"),
            StateClass::TelemetryDerived => write!(f, "telemetry-derived"),
            StateClass::EphemeralProcedure => write!(f, "ephemeral-procedure"),
        }
    }
}

impl StateClass {
    /// State classes that rely on ordered, monotonic generations instead of
    /// wall-clock last-writer-wins.
    pub const fn requires_monotonic_generation(self) -> bool {
        !matches!(self, StateClass::TelemetryDerived)
    }

    /// Map the consistency class to its required capability profile.
    pub const fn required_profile(self) -> crate::capability::SessionStateProfile {
        match self {
            StateClass::AuthoritativeSession => {
                crate::capability::SessionStateProfile::AuthoritativeSession
            }
            StateClass::EphemeralProcedure => {
                crate::capability::SessionStateProfile::EphemeralProcedure
            }
            StateClass::ReplicatedDr => {
                crate::capability::SessionStateProfile::ReplicatedDisasterRecovery
            }
            StateClass::DataplaneLookup | StateClass::TelemetryDerived => {
                crate::capability::SessionStateProfile::ReadThroughCache
            }
        }
    }
}

/// Discriminator for the schema / shape of a session record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateType(String);

impl StateType {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("state type cannot be empty".into());
        }
        if value.len() > 128 {
            return Err("state type must be at most 128 characters".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StateType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for StateType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StateType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Well-known categories of session key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionKeyType {
    SubscriberContext,
    PduSession,
    TeidMapping,
    PfcpSeid,
    HandoverTransaction,
    Other(String),
}

impl fmt::Display for SessionKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionKeyType::SubscriberContext => write!(f, "subscriber-context"),
            SessionKeyType::PduSession => write!(f, "pdu-session"),
            SessionKeyType::TeidMapping => write!(f, "teid-mapping"),
            SessionKeyType::PfcpSeid => write!(f, "pfcp-seid"),
            SessionKeyType::HandoverTransaction => write!(f, "handover-transaction"),
            SessionKeyType::Other(s) => f.write_str(s),
        }
    }
}

impl FromStr for SessionKeyType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "subscriber-context" => Ok(Self::SubscriberContext),
            "pdu-session" => Ok(Self::PduSession),
            "teid-mapping" => Ok(Self::TeidMapping),
            "pfcp-seid" => Ok(Self::PfcpSeid),
            "handover-transaction" => Ok(Self::HandoverTransaction),
            _ => {
                if value.is_empty() {
                    return Err("session key type cannot be empty".into());
                }
                Ok(Self::Other(value.to_owned()))
            }
        }
    }
}

impl Serialize for SessionKeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SessionKeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// Tenant-scoped, type-scoped identifier for a session record.
///
/// Raw subscriber identifiers MUST NOT be used directly as `stable_id` in
/// production; derive tenant-scoped keyed digests with
/// [`SessionKey::digest_with_key`] for backend keys and correlation IDs.
/// [`SessionKey::digest`] is provided only for non-privacy-sensitive,
/// deterministic hashing.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey {
    pub tenant: TenantId,
    pub nf_kind: NetworkFunctionKind,
    pub key_type: SessionKeyType,
    #[serde(with = "bytes_serde")]
    pub stable_id: Bytes,
}

mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes.as_ref())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Vec::<u8>::deserialize(deserializer)?;
        Ok(Bytes::from(v))
    }
}

impl SessionKey {
    pub(crate) fn canonical_digest_input(&self) -> Vec<u8> {
        let key_type = self.key_type.to_string();
        let mut out = Vec::with_capacity(
            (4 * std::mem::size_of::<u64>())
                + self.tenant.as_str().len()
                + self.nf_kind.as_str().len()
                + key_type.len()
                + self.stable_id.len(),
        );

        append_len_prefixed(&mut out, self.tenant.as_str().as_bytes());
        append_len_prefixed(&mut out, self.nf_kind.as_str().as_bytes());
        append_len_prefixed(&mut out, key_type.as_bytes());
        append_len_prefixed(&mut out, &self.stable_id);

        out
    }

    /// Produce a deterministic SHA-256 digest of the composite key.
    ///
    /// Different tenants produce different digests for the same `stable_id`,
    /// preventing cross-tenant key collision.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_digest_input());
        hasher.finalize().into()
    }

    /// Produce a tenant-scoped HMAC-SHA256 digest using a privacy key.
    ///
    /// This is the preferred form for correlation IDs and backend keys that
    /// must not expose raw subscriber identifiers (RFC 010 §5).
    pub fn digest_with_key(&self, tenant_privacy_key: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(tenant_privacy_key)
            .expect("HMAC-SHA256 accepts arbitrary key lengths");
        mac.update(&self.canonical_digest_input());
        mac.finalize().into_bytes().into()
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("tenant", &self.tenant)
            .field("nf_kind", &self.nf_kind)
            .field("key_type", &self.key_type)
            .field(
                "stable_id",
                &format_args!("[{} bytes]", self.stable_id.len()),
            )
            .finish()
    }
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Monotonic per-session version. Every authoritative update MUST increment it
/// atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Generation(u64);

impl Generation {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifies the NF replica that owns a session record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OwnerId(String);

impl OwnerId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("owner id cannot be empty".into());
        }
        if value.len() > 128 {
            return Err("owner id must be at most 128 characters".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OwnerId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Monotonic fencing token for a session key. Backends reject writes with a
/// token lower than the current recorded token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FenceToken(u64);

impl FenceToken {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for FenceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generic handover phase for session state machine support (RFC 004 §10.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandoverPhase {
    Stable,
    Preparing { tx: HandoverTxId, target: OwnerId },
    Prepared { tx: HandoverTxId, target: OwnerId },
    Activating { tx: HandoverTxId, target: OwnerId },
    Active { owner: OwnerId },
    Aborting { tx: HandoverTxId },
}

/// Unique identifier for a handover transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HandoverTxId(uuid::Uuid);

impl HandoverTxId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub const fn from_uuid(value: uuid::Uuid) -> Self {
        Self(value)
    }
}

impl Default for HandoverTxId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for HandoverTxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lease::LeaseGuard,
        record::{EncryptedSessionPayload, StoredSessionRecord},
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

    fn test_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("tenant-a").unwrap(),
            nf_kind: NetworkFunctionKind::new("smf").unwrap(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"same-id"),
        }
    }

    fn to_hex(bytes: [u8; 32]) -> String {
        bytes
            .into_iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn digest_with_key_matches_known_hmac_vector() {
        let digest = test_key().digest_with_key(b"privacy-key");
        assert_eq!(
            to_hex(digest),
            "4918bc64727d00bab80c09d4885fc7c61bed0e61ae6fa84e7f875bd8c6591813"
        );
    }

    #[test]
    fn session_key_type_serde_round_trips_known_variant() {
        let json = serde_json::to_string(&SessionKeyType::PduSession).unwrap();
        assert_eq!(json, "\"pdu-session\"");

        let round_trip: SessionKeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, SessionKeyType::PduSession);
    }

    #[test]
    fn session_key_type_serde_round_trips_unknown_variant() {
        let value = SessionKeyType::Other("custom-session-key".into());
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"custom-session-key\"");

        let round_trip: SessionKeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, value);
    }

    #[test]
    fn state_class_serde_uses_rfc_kebab_case_for_every_variant() {
        let cases = [
            (
                StateClass::AuthoritativeSession,
                "\"authoritative-session\"",
            ),
            (StateClass::DataplaneLookup, "\"dataplane-lookup\""),
            (StateClass::ReplicatedDr, "\"replicated-dr\""),
            (StateClass::TelemetryDerived, "\"telemetry-derived\""),
            (StateClass::EphemeralProcedure, "\"ephemeral-procedure\""),
        ];

        for (value, expected_json) in cases {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(json, expected_json);

            let round_trip: StateClass = serde_json::from_str(expected_json).unwrap();
            assert_eq!(round_trip, value);
        }
    }

    #[test]
    fn session_key_debug_redacts_stable_id() {
        let raw_stable_id = "imsi-001010000000001";
        let key = SessionKey {
            tenant: TenantId::new("tenant-a").unwrap(),
            nf_kind: NetworkFunctionKind::new("smf").unwrap(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::copy_from_slice(raw_stable_id.as_bytes()),
        };

        let rendered = format!("{key:?}");

        assert!(rendered.contains("stable_id"));
        assert!(rendered.contains("[20 bytes]"));
        assert!(!rendered.contains(raw_stable_id));
    }

    #[test]
    fn lease_guard_and_record_debug_inherit_redacted_session_key() {
        let raw_stable_id = "imsi-001010000000001";
        let key = SessionKey {
            tenant: TenantId::new("tenant-a").unwrap(),
            nf_kind: NetworkFunctionKind::new("smf").unwrap(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::copy_from_slice(raw_stable_id.as_bytes()),
        };
        let owner = OwnerId::new("owner-a").unwrap();
        let lease = LeaseGuard::new(
            key.clone(),
            owner.clone(),
            FenceToken::new(7),
            opc_types::Timestamp::now_utc(),
            opc_types::Timestamp::now_utc(),
            42,
        );
        let record = StoredSessionRecord {
            key,
            generation: Generation::new(3),
            owner,
            fence: FenceToken::new(7),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("test").unwrap(),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from_static(b"payload")),
        };

        let lease_rendered = format!("{lease:?}");
        let record_rendered = format!("{record:?}");

        assert!(lease_rendered.contains("[20 bytes]"));
        assert!(record_rendered.contains("[20 bytes]"));
        assert!(!lease_rendered.contains(raw_stable_id));
        assert!(!record_rendered.contains(raw_stable_id));
    }

    #[test]
    fn handover_phase_serde_uses_kebab_case_variants() {
        let stable_json = serde_json::to_string(&HandoverPhase::Stable).unwrap();
        assert_eq!(stable_json, "\"stable\"");

        let owner = OwnerId::new("owner-a").unwrap();
        let active = HandoverPhase::Active {
            owner: owner.clone(),
        };
        let active_json = serde_json::to_string(&active).unwrap();
        assert_eq!(active_json, r#"{"active":{"owner":"owner-a"}}"#);

        let stable_round_trip: HandoverPhase = serde_json::from_str(&stable_json).unwrap();
        assert_eq!(stable_round_trip, HandoverPhase::Stable);

        let active_round_trip: HandoverPhase = serde_json::from_str(&active_json).unwrap();
        assert_eq!(active_round_trip, HandoverPhase::Active { owner });
    }
}
