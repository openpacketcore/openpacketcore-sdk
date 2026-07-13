//! Core session-state vocabulary (RFC 004 §4–§5, §8–§10): tenant-scoped
//! session keys, monotonic generations and fence tokens, owner identities,
//! consistency state classes, and the generic handover phase machine.
//!
//! These types carry the crate's correctness invariants: `Generation` orders
//! versions of one session without wall-clock comparison, and `FenceToken`
//! orders owners of one session so that a stale owner can never overwrite a
//! newer one.

use std::fmt;
use std::str::FromStr;

use bytes::Bytes;
use hmac::{Hmac, Mac};
use opc_types::{NetworkFunctionKind, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum UTF-8 encoded length accepted for a [`StateType`].
pub const STATE_TYPE_MAX_BYTES: usize = 128;

/// Maximum UTF-8 encoded length accepted for a deployment-specific
/// [`SessionKeyType`].
pub const SESSION_KEY_TYPE_MAX_BYTES: usize = 128;

/// Maximum UTF-8 encoded length accepted for an [`OwnerId`].
pub const OWNER_ID_MAX_BYTES: usize = 128;

/// Minimum encoded width of a production [`StableId`].
pub const STABLE_ID_MIN_BYTES: usize = 1;

/// Maximum encoded width of a production [`StableId`].
///
/// This model-wide limit is shared by local, durable, cache, quorum, restore,
/// replication, watch, and session-network boundaries. It deliberately
/// matches the session-network v4 contract so a locally admitted key is
/// always representable by a production peer.
pub const STABLE_ID_MAX_BYTES: usize = 64;

/// Width of the canonical tenant-scoped HMAC-SHA256 stable identifier.
pub const STABLE_ID_HMAC_SHA256_BYTES: usize = 32;

/// Minimum accepted tenant privacy-key width for stable-ID derivation.
pub const STABLE_ID_PRIVACY_KEY_MIN_BYTES: usize = 16;

/// Maximum accepted tenant privacy-key width for stable-ID derivation.
pub const STABLE_ID_PRIVACY_KEY_MAX_BYTES: usize = 64;

/// Maximum canonical subject bytes hashed by one stable-ID derivation.
pub const STABLE_ID_CANONICAL_SUBJECT_MAX_BYTES: usize = 256;

const STABLE_ID_HMAC_SHA256_DOMAIN: &[u8] = b"openpacketcore/session-stable-id/hmac-sha256/v1";

/// Redaction-safe reason that stable-identifier construction failed.
///
/// The error never contains the rejected bytes, a subscriber identifier, or
/// the supplied privacy key, so it is safe to cross SDK and operator-facing
/// boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum StableIdError {
    /// The identifier was empty or exceeded the production width.
    #[error("stable session identifier must contain 1 to 64 bytes")]
    InvalidWidth,
    /// Keyed derivation used a privacy key outside the supported width.
    #[error("stable session identifier privacy key must contain 16 to 64 bytes")]
    InvalidPrivacyKeyWidth,
    /// Keyed derivation was requested with an empty canonical subject.
    #[error("stable session identifier canonical subject must not be empty")]
    EmptyCanonicalSubject,
    /// Keyed derivation used an oversized canonical subject.
    #[error("stable session identifier canonical subject exceeds 256 bytes")]
    CanonicalSubjectTooLong,
}

/// Bounded opaque identifier within a session key's tenant/NF/type scope.
///
/// Values contain exactly `1..=64` bytes. The private representation makes
/// that production invariant structural across direct Rust construction,
/// Serde, persistence hydration, caches, quorum commands, restore pages,
/// replication entries, watches, and network facades.
///
/// Raw SUPI/GPSI values are forbidden. Subscriber-derived identifiers should
/// be created with [`StableId::derive_hmac_sha256`], using a tenant-specific
/// privacy key and one canonical input representation. The supported keyed
/// digest profile is HMAC-SHA256 at its full 32-byte width; truncation is not
/// supported because it weakens collision resistance and creates divergent
/// identities across callers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableId(Bytes);

impl StableId {
    /// Minimum accepted encoded width.
    pub const MIN_BYTES: usize = STABLE_ID_MIN_BYTES;

    /// Maximum accepted encoded width.
    pub const MAX_BYTES: usize = STABLE_ID_MAX_BYTES;

    /// Validate and construct an opaque stable identifier.
    pub fn new(value: impl Into<Bytes>) -> Result<Self, StableIdError> {
        let value = value.into();
        if !(STABLE_ID_MIN_BYTES..=STABLE_ID_MAX_BYTES).contains(&value.len()) {
            return Err(StableIdError::InvalidWidth);
        }
        Ok(Self(value))
    }

    /// Derive the canonical privacy-preserving stable identifier.
    ///
    /// The HMAC input is domain-separated and length-prefixes both the tenant
    /// and the caller's canonical subject bytes. Deployments MUST use a
    /// tenant-specific secret from their KMS/HSM and MUST normalize each
    /// identifier type to one canonical byte representation before calling
    /// this method. Neither input is retained.
    pub fn derive_hmac_sha256(
        tenant_privacy_key: &[u8],
        tenant: &TenantId,
        canonical_subject: &[u8],
    ) -> Result<Self, StableIdError> {
        if !(STABLE_ID_PRIVACY_KEY_MIN_BYTES..=STABLE_ID_PRIVACY_KEY_MAX_BYTES)
            .contains(&tenant_privacy_key.len())
        {
            return Err(StableIdError::InvalidPrivacyKeyWidth);
        }
        if canonical_subject.is_empty() {
            return Err(StableIdError::EmptyCanonicalSubject);
        }
        if canonical_subject.len() > STABLE_ID_CANONICAL_SUBJECT_MAX_BYTES {
            return Err(StableIdError::CanonicalSubjectTooLong);
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(tenant_privacy_key)
            .map_err(|_| StableIdError::InvalidPrivacyKeyWidth)?;
        mac.update(STABLE_ID_HMAC_SHA256_DOMAIN);
        update_len_prefixed_mac(&mut mac, tenant.as_str().as_bytes());
        update_len_prefixed_mac(&mut mac, canonical_subject);
        Ok(Self(Bytes::copy_from_slice(&mac.finalize().into_bytes())))
    }

    /// Borrow the validated opaque bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Encoded identifier width.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false for a constructed value; provided for collection-like
    /// compatibility at read-only call sites.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for StableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StableId([redacted])")
    }
}

impl AsRef<[u8]> for StableId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::ops::Deref for StableId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl TryFrom<Bytes> for StableId {
    type Error = StableIdError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<Vec<u8>> for StableId {
    type Error = StableIdError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&[u8]> for StableId {
    type Error = StableIdError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::new(Bytes::copy_from_slice(value))
    }
}

impl From<[u8; STABLE_ID_HMAC_SHA256_BYTES]> for StableId {
    fn from(value: [u8; STABLE_ID_HMAC_SHA256_BYTES]) -> Self {
        Self(Bytes::copy_from_slice(&value))
    }
}

impl Serialize for StableId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StableIdVisitor;

        impl<'de> serde::de::Visitor<'de> for StableIdVisitor {
            type Value = StableId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a stable session identifier containing 1 to 64 bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                StableId::try_from(value).map_err(E::custom)
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                StableId::try_from(value).map_err(E::custom)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or(0).min(STABLE_ID_MAX_BYTES);
                let mut bytes = Vec::with_capacity(capacity);
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == STABLE_ID_MAX_BYTES {
                        return Err(serde::de::Error::custom(StableIdError::InvalidWidth));
                    }
                    bytes.push(byte);
                }
                StableId::try_from(bytes).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_bytes(StableIdVisitor)
    }
}

fn update_len_prefixed_mac(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

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
    /// Maximum UTF-8 encoded length accepted by [`StateType::new`].
    pub const MAX_BYTES: usize = STATE_TYPE_MAX_BYTES;

    /// Validate and construct a state type.
    ///
    /// Returns an error for the empty string or values longer than
    /// [`STATE_TYPE_MAX_BYTES`] UTF-8 encoded bytes; the bound keeps the value
    /// safe to embed in backend rows and AEAD AAD without truncation.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("state type cannot be empty".into());
        }
        if value.len() > STATE_TYPE_MAX_BYTES {
            return Err("state type must be at most 128 bytes".into());
        }
        Ok(Self(value))
    }

    /// Create from a known-valid `&'static str`.
    ///
    /// # Panics
    ///
    /// Panics if `value` is empty or longer than [`STATE_TYPE_MAX_BYTES`]
    /// UTF-8 encoded bytes. Intended for deterministic literals in tests and
    /// reference code; use `new` for runtime input.
    pub fn from_static(value: &'static str) -> Self {
        Self::new(value).unwrap_or_else(|e| panic!("invalid state type: {e}"))
    }

    /// The validated string form, as persisted in backend rows and bound into
    /// the payload encryption AAD.
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

/// Validated name for a deployment-specific [`SessionKeyType`].
///
/// The private storage makes the non-empty, byte-length, and canonical-name
/// invariants structural: callers cannot construct a custom value that
/// serializes to the same persisted identity as a well-known variant.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomSessionKeyType(String);

impl CustomSessionKeyType {
    /// Maximum UTF-8 encoded length accepted by
    /// [`CustomSessionKeyType::new`].
    pub const MAX_BYTES: usize = SESSION_KEY_TYPE_MAX_BYTES;

    /// Validate a deployment-specific session key type name.
    ///
    /// Names are non-empty UTF-8 strings of at most
    /// [`SESSION_KEY_TYPE_MAX_BYTES`] encoded bytes. The five well-known
    /// spellings are reserved so every persisted string has exactly one
    /// in-memory representation.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("custom session key type cannot be empty".into());
        }
        if value.len() > SESSION_KEY_TYPE_MAX_BYTES {
            return Err("custom session key type must be at most 128 bytes".into());
        }
        if is_well_known_session_key_type(&value) {
            return Err("custom session key type must not use a reserved well-known name".into());
        }
        Ok(Self(value))
    }

    /// The validated custom name as persisted and included in key digests.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CustomSessionKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustomSessionKeyType([redacted])")
    }
}

impl fmt::Display for CustomSessionKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CustomSessionKeyType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for CustomSessionKeyType {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for CustomSessionKeyType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for CustomSessionKeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CustomSessionKeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Well-known and validated deployment-specific categories of session key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SessionKeyType {
    /// Subscriber-level context keyed by a SUPI-derived identifier (the
    /// `stable_id` must be a derived digest, never the raw SUPI/GPSI).
    SubscriberContext,
    /// Per-PDU-session state, typically keyed by PDU session ID plus a
    /// subscriber-identifier hash.
    PduSession,
    /// GTP-U TEID to session mapping used for data-plane lookup.
    TeidMapping,
    /// PFCP session state keyed by the session endpoint identifier (SEID).
    PfcpSeid,
    /// Ephemeral handover transaction state, scoped to a `HandoverTxId` and
    /// normally stored with a TTL.
    HandoverTransaction,
    /// Deployment-specific key category. Construct it through
    /// [`SessionKeyType::other`] so it cannot collide with a well-known
    /// kebab-case name.
    ///
    /// ```compile_fail
    /// use opc_session_store::SessionKeyType;
    /// let _ = SessionKeyType::Other("unchecked".to_owned());
    /// ```
    Other(CustomSessionKeyType),
}

impl SessionKeyType {
    /// Validate and construct a deployment-specific key category.
    ///
    /// ```
    /// use opc_session_store::SessionKeyType;
    /// # fn main() -> Result<(), String> {
    /// let key_type = SessionKeyType::other("vendor-session")?;
    /// assert_eq!(key_type.as_str(), "vendor-session");
    /// # Ok(())
    /// # }
    /// ```
    pub fn other(value: impl Into<String>) -> Result<Self, String> {
        CustomSessionKeyType::new(value).map(Self::Other)
    }

    /// Canonical persisted form used for JSON, SQLite keys, ordering, and key
    /// digest input.
    pub fn as_str(&self) -> &str {
        match self {
            Self::SubscriberContext => "subscriber-context",
            Self::PduSession => "pdu-session",
            Self::TeidMapping => "teid-mapping",
            Self::PfcpSeid => "pfcp-seid",
            Self::HandoverTransaction => "handover-transaction",
            Self::Other(value) => value.as_str(),
        }
    }
}

impl fmt::Display for SessionKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialOrd for SessionKeyType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SessionKeyType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl FromStr for SessionKeyType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(well_known) = well_known_session_key_type(value) {
            Ok(well_known)
        } else {
            Self::other(value)
        }
    }
}

impl Serialize for SessionKeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

fn is_well_known_session_key_type(value: &str) -> bool {
    well_known_session_key_type(value).is_some()
}

fn well_known_session_key_type(value: &str) -> Option<SessionKeyType> {
    match value {
        "subscriber-context" => Some(SessionKeyType::SubscriberContext),
        "pdu-session" => Some(SessionKeyType::PduSession),
        "teid-mapping" => Some(SessionKeyType::TeidMapping),
        "pfcp-seid" => Some(SessionKeyType::PfcpSeid),
        "handover-transaction" => Some(SessionKeyType::HandoverTransaction),
        _ => None,
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
    /// Tenant that owns the session. Length-prefixed into the digest input,
    /// so identical `stable_id` bytes under different tenants can never
    /// collide on a shared backend.
    pub tenant: TenantId,
    /// Network function kind (e.g. AMF, SMF, UPF) the state belongs to; part
    /// of the key so different NFs never share a record namespace.
    pub nf_kind: NetworkFunctionKind,
    /// Category of the key (PDU session, TEID mapping, ...), separating
    /// records of different shapes that share the same `stable_id`.
    pub key_type: SessionKeyType,
    /// Stable identifying bytes within the tenant/NF/type scope. MUST NOT be
    /// a raw SUPI/GPSI in production; use a derived identifier and rely on
    /// `SessionKey::digest_with_key` for backend keys. The `Debug` impl
    /// redacts these bytes to keep subscriber identifiers out of logs.
    pub stable_id: StableId,
}

impl SessionKey {
    pub(crate) fn canonical_digest_input(&self) -> Vec<u8> {
        let key_type = self.key_type.as_str();
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
    /// Wrap a raw counter value, e.g. when rehydrating a record from a
    /// backend row. New sessions conventionally start at generation 1.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Raw counter value, for persistence and for binding into the payload
    /// encryption AAD.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The successor generation to write in a compare-and-set update.
    ///
    /// Returns `None` on `u64` overflow instead of wrapping: a wrapped
    /// generation would compare lower than the current one and break the
    /// monotonic-version invariant, so callers must surface overflow as an
    /// error rather than continue.
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
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct OwnerId(String);

impl OwnerId {
    /// Maximum UTF-8 encoded length accepted by [`OwnerId::new`].
    pub const MAX_BYTES: usize = OWNER_ID_MAX_BYTES;

    /// Validate and construct an owner identity.
    ///
    /// Rejects the empty string and values over [`OWNER_ID_MAX_BYTES`] UTF-8
    /// encoded bytes. The value must be stable for the lifetime of a replica
    /// and unique across replicas: lease managers compare it verbatim to
    /// decide whether an acquire attempt is a re-acquire by the holder or a
    /// conflict.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("owner id cannot be empty".into());
        }
        if value.len() > OWNER_ID_MAX_BYTES {
            return Err("owner id must be at most 128 bytes".into());
        }
        Ok(Self(value))
    }

    /// The validated string form, as compared by lease managers and recorded
    /// in `StoredSessionRecord::owner`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerId([redacted])")
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

impl<'de> Deserialize<'de> for OwnerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Monotonic fencing token for a session key. Backends reject writes with a
/// token lower than the current recorded token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FenceToken(u64);

impl FenceToken {
    /// Wrap a raw token value. Only lease managers should mint new values;
    /// they must be strictly increasing per session key across acquisitions.
    /// Token 0 conventionally means "no fence recorded yet".
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Raw token value, for persistence, ordering comparisons, and binding
    /// into the payload encryption AAD.
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
    /// No handover in progress; the record's `owner` field is the single
    /// authoritative writer.
    Stable,
    /// The source owner has started a handover under its current lease but
    /// the target has not yet confirmed. Transitions forward to `Prepared`
    /// for the same `tx` or to `Aborting`.
    Preparing {
        /// Idempotency token for this handover transaction; all subsequent
        /// steps must present the same id or they are rejected as conflicts.
        tx: HandoverTxId,
        /// Replica that will take ownership if the handover activates.
        target: OwnerId,
    },
    /// The target has written its readiness with its own (strictly higher)
    /// fence token; activation may now proceed.
    Prepared {
        /// Transaction this preparation belongs to.
        tx: HandoverTxId,
        /// Replica that confirmed readiness and will become owner.
        target: OwnerId,
    },
    /// The target's fenced CAS toward ownership is in flight. Recoverable:
    /// re-running activation for the same `tx` is a no-op.
    Activating {
        /// Transaction being activated.
        tx: HandoverTxId,
        /// Replica taking ownership.
        target: OwnerId,
    },
    /// Handover completed; from here on, writes from the old source carry a
    /// lower fence token and are rejected by the backend.
    Active {
        /// The replica that now holds authoritative ownership.
        owner: OwnerId,
    },
    /// A prepared-but-not-activated handover is being rolled back toward
    /// `Stable` (RFC 004 §10.3 step 7).
    Aborting {
        /// Transaction being aborted; abort steps are idempotent by this id.
        tx: HandoverTxId,
    },
}

/// Unique identifier for a handover transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HandoverTxId(uuid::Uuid);

impl HandoverTxId {
    /// Mint a fresh random (UUID v4) transaction id. Generate exactly one id
    /// per handover attempt and reuse it for every step of that attempt —
    /// step idempotency is keyed on this value.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Wrap an externally supplied UUID, e.g. one carried in a 3GPP procedure
    /// message, so that retries and peer NFs converge on the same
    /// transaction identity.
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
    use proptest::prelude::*;

    fn test_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("tenant-a").unwrap(),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"same-id")
                .try_into()
                .expect("valid stable ID"),
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
    fn stable_id_constructor_boundaries_are_exact() {
        for (length, accepted) in [
            (0, false),
            (STABLE_ID_MIN_BYTES, true),
            (STABLE_ID_MAX_BYTES, true),
            (STABLE_ID_MAX_BYTES + 1, false),
        ] {
            let result = StableId::new(Bytes::from(vec![0xa5; length]));
            assert_eq!(result.is_ok(), accepted, "stable ID length {length}");
        }
    }

    #[test]
    fn stable_id_json_reuses_bounds_and_redacts_failures() {
        for (length, accepted) in [
            (0, false),
            (STABLE_ID_MIN_BYTES, true),
            (STABLE_ID_MAX_BYTES, true),
            (STABLE_ID_MAX_BYTES + 1, false),
        ] {
            let raw = vec![0xa5_u8; length];
            let encoded = serde_json::to_string(&raw).unwrap();
            let decoded = serde_json::from_str::<StableId>(&encoded);
            assert_eq!(decoded.is_ok(), accepted, "stable ID length {length}");
            if let Err(error) = decoded {
                let rendered = error.to_string();
                assert!(!rendered.contains("165"));
                assert!(!rendered.contains(&encoded));
            }
        }

        let stable_id = StableId::new(Bytes::from_static(b"subscriber-secret")).unwrap();
        assert_eq!(format!("{stable_id:?}"), "StableId([redacted])");
        assert!(!format!("{stable_id:?}").contains("subscriber-secret"));
    }

    #[test]
    fn stable_id_keyed_derivation_is_tenant_scoped_and_full_width() {
        let tenant_a = TenantId::from_static("tenant-a");
        let tenant_b = TenantId::from_static("tenant-b");
        let first = StableId::derive_hmac_sha256(
            b"tenant-a-privacy-key",
            &tenant_a,
            b"canonical-supi-001010000000001",
        )
        .unwrap();
        let repeated = StableId::derive_hmac_sha256(
            b"tenant-a-privacy-key",
            &tenant_a,
            b"canonical-supi-001010000000001",
        )
        .unwrap();
        let other_tenant = StableId::derive_hmac_sha256(
            b"tenant-a-privacy-key",
            &tenant_b,
            b"canonical-supi-001010000000001",
        )
        .unwrap();

        assert_eq!(first, repeated);
        assert_ne!(first, other_tenant);
        assert_eq!(first.len(), STABLE_ID_HMAC_SHA256_BYTES);
        assert_eq!(
            first
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "c16a015f5237260ac501cd987c8c45e43b8bfb642a94c10bc245d2b2e9ab7676"
        );
        assert_eq!(
            StableId::derive_hmac_sha256(b"", &tenant_a, b"canonical-supi-001010000000001"),
            Err(StableIdError::InvalidPrivacyKeyWidth)
        );
        assert_eq!(
            StableId::derive_hmac_sha256(b"tenant-a-privacy-key", &tenant_a, b""),
            Err(StableIdError::EmptyCanonicalSubject)
        );
        assert_eq!(
            StableId::derive_hmac_sha256(
                b"tenant-a-privacy-key",
                &tenant_a,
                &vec![0xa5; STABLE_ID_CANONICAL_SUBJECT_MAX_BYTES + 1],
            ),
            Err(StableIdError::CanonicalSubjectTooLong)
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
        let value = SessionKeyType::other("custom-session-key").unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"custom-session-key\"");

        let round_trip: SessionKeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, value);
    }

    #[test]
    fn session_identity_bounds_use_utf8_encoded_bytes() {
        assert!(OwnerId::new("o".repeat(OWNER_ID_MAX_BYTES)).is_ok());
        assert!(OwnerId::new("o".repeat(OWNER_ID_MAX_BYTES + 1)).is_err());
        assert!(OwnerId::new("é".repeat(OWNER_ID_MAX_BYTES / 2)).is_ok());
        assert!(OwnerId::new("é".repeat((OWNER_ID_MAX_BYTES / 2) + 1)).is_err());

        assert!(SessionKeyType::other("k".repeat(SESSION_KEY_TYPE_MAX_BYTES)).is_ok());
        assert!(SessionKeyType::other("k".repeat(SESSION_KEY_TYPE_MAX_BYTES + 1)).is_err());
        assert!(SessionKeyType::other("é".repeat(SESSION_KEY_TYPE_MAX_BYTES / 2)).is_ok());
        assert!(SessionKeyType::other("é".repeat((SESSION_KEY_TYPE_MAX_BYTES / 2) + 1)).is_err());

        assert!(StateType::new("s".repeat(STATE_TYPE_MAX_BYTES)).is_ok());
        assert!(StateType::new("s".repeat(STATE_TYPE_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn owner_deserialization_reuses_constructor_and_redacts_failures() {
        for invalid in [String::new(), "owner-secret".repeat(16)] {
            assert!(OwnerId::new(invalid.clone()).is_err());
            let encoded = serde_json::to_string(&invalid).unwrap();
            let error = serde_json::from_str::<OwnerId>(&encoded).unwrap_err();
            let rendered = error.to_string();
            if !invalid.is_empty() {
                assert!(!rendered.contains(&invalid));
            }
        }

        let owner = OwnerId::new("owner-secret").unwrap();
        assert_eq!(serde_json::to_string(&owner).unwrap(), "\"owner-secret\"");
        assert_eq!(format!("{owner:?}"), "OwnerId([redacted])");
        assert!(!format!("{owner:?}").contains(owner.as_str()));
    }

    #[test]
    fn custom_key_types_cannot_alias_well_known_variants() {
        let cases = [
            ("subscriber-context", SessionKeyType::SubscriberContext),
            ("pdu-session", SessionKeyType::PduSession),
            ("teid-mapping", SessionKeyType::TeidMapping),
            ("pfcp-seid", SessionKeyType::PfcpSeid),
            ("handover-transaction", SessionKeyType::HandoverTransaction),
        ];

        for (persisted, expected) in cases {
            assert!(CustomSessionKeyType::new(persisted).is_err());
            assert!(SessionKeyType::other(persisted).is_err());
            assert_eq!(SessionKeyType::from_str(persisted).unwrap(), expected);
            assert_eq!(expected.as_str(), persisted);
            assert_eq!(
                serde_json::to_string(&expected).unwrap(),
                format!("\"{persisted}\"")
            );
        }
    }

    #[test]
    fn custom_key_type_deserialization_is_bounded_and_redacted() {
        for invalid in [String::new(), "custom-secret".repeat(16)] {
            assert!(SessionKeyType::from_str(&invalid).is_err());
            let encoded = serde_json::to_string(&invalid).unwrap();
            let error = serde_json::from_str::<SessionKeyType>(&encoded).unwrap_err();
            let rendered = error.to_string();
            if !invalid.is_empty() {
                assert!(!rendered.contains(&invalid));
            }
        }

        let custom = CustomSessionKeyType::new("custom-secret").unwrap();
        assert_eq!(format!("{custom:?}"), "CustomSessionKeyType([redacted])");
        assert!(!format!("{custom:?}").contains(custom.as_str()));
    }

    #[test]
    fn session_key_type_order_matches_persisted_text_order() {
        let mut values = [
            SessionKeyType::SubscriberContext,
            SessionKeyType::PduSession,
            SessionKeyType::TeidMapping,
            SessionKeyType::PfcpSeid,
            SessionKeyType::HandoverTransaction,
            SessionKeyType::other("aaa-custom").unwrap(),
            SessionKeyType::other("zzz-custom").unwrap(),
        ];
        let mut persisted = values
            .iter()
            .map(|value| value.as_str().to_string())
            .collect::<Vec<_>>();

        values.sort();
        persisted.sort();

        assert_eq!(
            values
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>(),
            persisted.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn custom_session_key_keeps_legacy_canonical_digest_input() {
        let key = SessionKey {
            key_type: SessionKeyType::other("custom-session-key").unwrap(),
            ..test_key()
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&8_u64.to_be_bytes());
        expected.extend_from_slice(b"tenant-a");
        expected.extend_from_slice(&3_u64.to_be_bytes());
        expected.extend_from_slice(b"smf");
        expected.extend_from_slice(&18_u64.to_be_bytes());
        expected.extend_from_slice(b"custom-session-key");
        expected.extend_from_slice(&7_u64.to_be_bytes());
        expected.extend_from_slice(b"same-id");

        assert_eq!(key.canonical_digest_input(), expected);
    }

    proptest! {
        #[test]
        fn owner_constructor_and_serde_accept_the_same_strings(
            chars in proptest::collection::vec(any::<char>(), 0..140),
        ) {
            let value = chars.into_iter().collect::<String>();
            let constructed = OwnerId::new(value.clone());
            let encoded = serde_json::to_string(&value).unwrap();
            let decoded = serde_json::from_str::<OwnerId>(&encoded);
            prop_assert_eq!(constructed.is_ok(), decoded.is_ok());
            if let (Ok(constructed), Ok(decoded)) = (constructed, decoded) {
                prop_assert_eq!(constructed, decoded);
            }
        }

        #[test]
        fn session_key_type_parse_and_serde_are_canonical(
            left_chars in proptest::collection::vec(any::<char>(), 0..140),
            right_chars in proptest::collection::vec(any::<char>(), 0..140),
        ) {
            let left_raw = left_chars.into_iter().collect::<String>();
            let right_raw = right_chars.into_iter().collect::<String>();
            let left = SessionKeyType::from_str(&left_raw);
            let encoded = serde_json::to_string(&left_raw).unwrap();
            let decoded = serde_json::from_str::<SessionKeyType>(&encoded);
            prop_assert_eq!(left.is_ok(), decoded.is_ok());
            if let (Ok(left), Ok(decoded)) = (&left, decoded) {
                prop_assert_eq!(left, &decoded);
                prop_assert_eq!(decoded.as_str(), left_raw.as_str());
            }

            if let (Ok(left), Ok(right)) = (left, SessionKeyType::from_str(&right_raw)) {
                prop_assert_eq!(left == right, left.as_str() == right.as_str());
            }
        }
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
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::copy_from_slice(raw_stable_id.as_bytes())
                .try_into()
                .expect("valid stable ID"),
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
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::copy_from_slice(raw_stable_id.as_bytes())
                .try_into()
                .expect("valid stable ID"),
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
