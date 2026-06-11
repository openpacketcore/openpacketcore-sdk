//! Alarm model types: severity taxonomy, probable causes, affected objects,
//! and the canonical [`Alarm`] struct.
//!
//! See RFC 013 for design rationale and 3GPP FM alignment.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt;
use std::str::FromStr;
use time::OffsetDateTime;

/// The version of the OpenPacketCore alarm taxonomy.
///
/// ## Compatibility Rules for Severity/Probable-Cause Changes:
/// 1. Adding a new variant to `Severity` or `ProbableCause` is a backwards-compatible addition (minor version bump).
/// 2. Modifying the serialization behavior, meaning/interpretation, or removing any variant from `Severity` or `ProbableCause` is a breaking change (major version bump).
/// 3. Standard parsing of legacy enum names must remain stable (e.g. `peer-unreachable` will always map to `ProbableCause::PeerUnreachable`).
/// 4. Extensible namespaced causes mapped to `ProbableCause::Other(String)` must adhere to the `other:<nf>.<cause>` prefix rule to prevent name clashes with future core additions.
pub const TAXONOMY_VERSION: &str = "1.0.0";

/// Region identifier for region-scoped alarm records per RFC 010 §9.
///
/// Phase-1 validation currently enforces only non-empty input with a maximum
/// length of 128 bytes; it does not yet enforce a stricter slug grammar. When
/// `opc-types` is available as a workspace dependency, this type will be
/// replaced with an import of `opc_types::RegionId`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RegionId(String);

/// Validation error returned by [`RegionId::try_new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidRegionId {
    Empty,
    TooLong { len: usize, max: usize },
}

impl fmt::Display for InvalidRegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidRegionId::Empty => write!(f, "region id must not be empty"),
            InvalidRegionId::TooLong { len, max } => {
                write!(f, "region id exceeds maximum length of {max} (got {len})")
            }
        }
    }
}

impl std::error::Error for InvalidRegionId {}

impl RegionId {
    /// Creates a region identifier from trusted input.
    ///
    /// Prefer [`RegionId::try_new`] for operator-provided or otherwise untrusted
    /// values.
    ///
    /// # Panics
    ///
    /// Panics if the value is empty or longer than 128 bytes.
    pub fn new(value: impl Into<String>) -> Self {
        Self::try_new(value).unwrap_or_else(|err| panic!("{err}"))
    }

    /// Creates a region identifier from potentially invalid input.
    pub fn try_new(value: impl Into<String>) -> Result<Self, InvalidRegionId> {
        let v = value.into();
        if v.is_empty() {
            return Err(InvalidRegionId::Empty);
        }
        if v.len() > 128 {
            return Err(InvalidRegionId::TooLong {
                len: v.len(),
                max: 128,
            });
        }
        Ok(Self(v))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for RegionId {
    type Error = InvalidRegionId;

    fn try_from(v: String) -> Result<Self, Self::Error> {
        Self::try_new(v)
    }
}

impl<'de> Deserialize<'de> for RegionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

/// Canonical alarm identifier.
///
/// Must be stable for the same active fault instance so that repeated raises
/// with identical inputs update (not duplicate) the active alarm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlarmId(String);

impl AlarmId {
    /// Creates a new alarm ID from a raw string value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AlarmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for AlarmId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AlarmId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(raw))
    }
}

/// Alarm type identifier for categorization.
///
/// Per-NF alarm types should be namespaced (e.g., `"upf.interface.down"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlarmType(String);

impl AlarmType {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AlarmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Alarm severity level per RFC 013 and 3GPP FM standards.
///
/// Variant order encodes severity ranking: Cleared < Indeterminate < Warning <
/// Minor < Major < Critical. A manual `Ord` impl ensures `Cleared` is the
/// lowest rank; callers that want most-severe-first ordering should sort in
/// descending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Fault is no longer active (rank 0, least severe).
    Cleared,
    /// Fault detected but impact is unknown (rank 1).
    Indeterminate,
    /// Approaching a fault threshold or policy exception (rank 2).
    Warning,
    /// Limited impairment with a workaround available (rank 3).
    Minor,
    /// Serious degradation or redundancy loss (rank 4).
    Major,
    /// Service outage, data loss, or security boundary failure (rank 5, most severe).
    Critical,
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Rank values: Cleared=0, Indeterminate=1, Warning=2, Minor=3, Major=4, Critical=5
        let rank = |s: &Severity| match s {
            Severity::Cleared => 0,
            Severity::Indeterminate => 1,
            Severity::Warning => 2,
            Severity::Minor => 3,
            Severity::Major => 4,
            Severity::Critical => 5,
        };
        rank(self).cmp(&rank(other))
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Critical => "critical",
            Severity::Major => "major",
            Severity::Minor => "minor",
            Severity::Warning => "warning",
            Severity::Indeterminate => "indeterminate",
            Severity::Cleared => "cleared",
        };
        f.write_str(s)
    }
}

/// Versioned taxonomy of probable causes for alarms.
///
/// Per-NF causes MUST be namespaced (e.g., `"upf.gtp.PortExhaustion"`).
///
/// Serialization uses the RFC 013 canonical string form (e.g., `peer-unreachable`),
/// not the Rust variant name (e.g., `PeerUnreachable`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProbableCause {
    // ── Config & Identity ────────────────────────────────────────────────────
    ConfigApplyFailed,
    ConfigDriftDetected,
    CertificateExpiring,
    CertificateExpired,
    IdentityUnavailable,
    AuthorizationPolicyInvalid,

    // ── Session & State ───────────────────────────────────────────────────────
    SessionStoreUnavailable,
    LeaseLost,

    // ── Backend & SBI ─────────────────────────────────────────────────────────
    BackendTimeout,
    NrfUnreachable,
    SbiOverload,
    PeerUnreachable,

    // ── Data Plane ────────────────────────────────────────────────────────────
    PacketDropThreshold,
    DataplanePreflightFailed,

    // ── Storage & Integrity ────────────────────────────────────────────────────
    StorageCorruption,
    AuditChainInvalid,

    // ── Security ───────────────────────────────────────────────────────────────
    KeyUnavailable,

    // ── LI, Charging, Privacy ─────────────────────────────────────────────────
    LiDeliveryFailed,
    ChargingExportFailed,
    PrivacyPolicyViolation,
    SecurityBreakGlass,

    // ── Extensible per-NF namespace ───────────────────────────────────────────
    Other(String),
}

// Custom serde: RFC 013 canonical string form.
impl Serialize for ProbableCause {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProbableCause {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for ProbableCause {
    type Err = ParseProbableCauseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "config-apply-failed" => Ok(ProbableCause::ConfigApplyFailed),
            "config-drift-detected" => Ok(ProbableCause::ConfigDriftDetected),
            "certificate-expiring" => Ok(ProbableCause::CertificateExpiring),
            "certificate-expired" => Ok(ProbableCause::CertificateExpired),
            "identity-unavailable" => Ok(ProbableCause::IdentityUnavailable),
            "authorization-policy-invalid" => Ok(ProbableCause::AuthorizationPolicyInvalid),
            "session-store-unavailable" => Ok(ProbableCause::SessionStoreUnavailable),
            "lease-lost" => Ok(ProbableCause::LeaseLost),
            "backend-timeout" => Ok(ProbableCause::BackendTimeout),
            "nrf-unreachable" => Ok(ProbableCause::NrfUnreachable),
            "sbi-overload" => Ok(ProbableCause::SbiOverload),
            "peer-unreachable" => Ok(ProbableCause::PeerUnreachable),
            "packet-drop-threshold" => Ok(ProbableCause::PacketDropThreshold),
            "dataplane-preflight-failed" => Ok(ProbableCause::DataplanePreflightFailed),
            "storage-corruption" => Ok(ProbableCause::StorageCorruption),
            "audit-chain-invalid" => Ok(ProbableCause::AuditChainInvalid),
            "key-unavailable" => Ok(ProbableCause::KeyUnavailable),
            "li-delivery-failed" => Ok(ProbableCause::LiDeliveryFailed),
            "charging-export-failed" => Ok(ProbableCause::ChargingExportFailed),
            "privacy-policy-violation" => Ok(ProbableCause::PrivacyPolicyViolation),
            "security-break-glass" => Ok(ProbableCause::SecurityBreakGlass),
            other => {
                let prefix = "other:";
                if let Some(ns) = other.strip_prefix(prefix) {
                    let normalized = ns.trim();
                    let namespaced = normalized.contains('.')
                        && normalized.split('.').all(|segment| {
                            !segment.is_empty() && !segment.chars().any(char::is_whitespace)
                        });

                    if normalized.is_empty() || !namespaced {
                        Err(ParseProbableCauseError(s.to_string()))
                    } else {
                        Ok(ProbableCause::Other(normalized.to_string()))
                    }
                } else {
                    Err(ParseProbableCauseError(s.to_string()))
                }
            }
        }
    }
}

/// Error returned when a string does not match any known probable cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProbableCauseError(String);

impl ParseProbableCauseError {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ParseProbableCauseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown probable cause: {}", self.0)
    }
}

impl std::error::Error for ParseProbableCauseError {}

impl fmt::Display for ProbableCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbableCause::ConfigApplyFailed => write!(f, "config-apply-failed"),
            ProbableCause::ConfigDriftDetected => write!(f, "config-drift-detected"),
            ProbableCause::CertificateExpiring => write!(f, "certificate-expiring"),
            ProbableCause::CertificateExpired => write!(f, "certificate-expired"),
            ProbableCause::IdentityUnavailable => write!(f, "identity-unavailable"),
            ProbableCause::AuthorizationPolicyInvalid => {
                write!(f, "authorization-policy-invalid")
            }
            ProbableCause::SessionStoreUnavailable => write!(f, "session-store-unavailable"),
            ProbableCause::LeaseLost => write!(f, "lease-lost"),
            ProbableCause::BackendTimeout => write!(f, "backend-timeout"),
            ProbableCause::NrfUnreachable => write!(f, "nrf-unreachable"),
            ProbableCause::SbiOverload => write!(f, "sbi-overload"),
            ProbableCause::PeerUnreachable => write!(f, "peer-unreachable"),
            ProbableCause::PacketDropThreshold => write!(f, "packet-drop-threshold"),
            ProbableCause::DataplanePreflightFailed => write!(f, "dataplane-preflight-failed"),
            ProbableCause::StorageCorruption => write!(f, "storage-corruption"),
            ProbableCause::AuditChainInvalid => write!(f, "audit-chain-invalid"),
            ProbableCause::KeyUnavailable => write!(f, "key-unavailable"),
            ProbableCause::LiDeliveryFailed => write!(f, "li-delivery-failed"),
            ProbableCause::ChargingExportFailed => write!(f, "charging-export-failed"),
            ProbableCause::PrivacyPolicyViolation => write!(f, "privacy-policy-violation"),
            ProbableCause::SecurityBreakGlass => write!(f, "security-break-glass"),
            ProbableCause::Other(s) => write!(f, "other:{s}"),
        }
    }
}

/// Canonical alarm deduplication key.
///
/// Computed as a truncated SHA-256 digest: the first 16 bytes (128 bits) of
/// `SHA-256(length-prefixed(alarm_type || probable_cause || affected_object ||
/// tenant || slice || region))`.
///
/// Length-prefixing prevents collision between fields that contain `|` characters.
/// Raw subscriber identifiers MUST NOT appear in any component.
///
/// The dedup key includes region to satisfy RFC 010 §9 (boundary metadata in storage keys).
/// Alarms in different regions are separate entities and do not merge or clear each other.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DedupKey(String);

impl DedupKey {
    /// Computes the dedup key from structured inputs.
    ///
    /// All inputs are non-sensitive: `alarm_type` and `probable_cause` are
    /// taxonomy identifiers, and `affected_object` uses structured names that
    /// exclude subscriber data per RFC 013 §7.
    ///
    /// Uses length-prefixed binary encoding to avoid collision when field
    /// values themselves contain `|` or `:` separator characters.
    ///
    /// The stored key is a 128-bit digest formed by truncating SHA-256 to the
    /// first 16 bytes before hex encoding.
    ///
    /// `region` is included so that the same fault in different regions produces
    /// distinct dedup keys (RFC 010 §9 boundary metadata).
    pub fn compute(
        alarm_type: &AlarmType,
        probable_cause: &ProbableCause,
        affected_object: &AffectedObject,
        tenant: Option<&str>,
        slice: Option<&str>,
        region: Option<&str>,
    ) -> Self {
        use sha2::Sha256;

        let mut hasher = Sha256::new();

        // Length-prefix each field to eliminate separator collision risk.
        fn feed(hasher: &mut sha2::Sha256, field: &str) {
            let bytes = field.as_bytes();
            hasher.update((bytes.len() as u32).to_be_bytes());
            hasher.update(bytes);
        }

        // Encode optional fields with a presence byte so None and Some("") cannot alias.
        fn feed_opt(hasher: &mut sha2::Sha256, opt: Option<&str>) {
            match opt {
                Some(v) => {
                    hasher.update([1u8]);
                    feed(hasher, v);
                }
                None => {
                    hasher.update([0u8]);
                }
            }
        }

        feed(&mut hasher, alarm_type.as_str());
        feed(&mut hasher, &probable_cause.to_string());
        // AffectedObject is encoded structurally (variant tag + length-prefixed fields)
        // to prevent collision when field values contain `:` characters.
        affected_object.feed_to_hasher(&mut hasher);
        feed_opt(&mut hasher, tenant);
        feed_opt(&mut hasher, slice);
        feed_opt(&mut hasher, region);

        let hash = hasher.finalize();
        Self(hex::encode(&hash[..16])) // first 16 bytes = 128-bit key
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DedupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Structured affected-object naming per RFC 013 §7.
///
/// Raw subscriber identifiers MUST NOT appear as affected-object names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AffectedObject {
    /// Network function instance.
    NfInstance { kind: String, instance: String },
    /// Network interface on an NF instance.
    Interface { nf: String, name: String },
    /// Peer entity.
    Peer { nf: String, peer_id: String },
    /// Session store shard.
    SessionStore { nf: String, shard: Option<String> },
    /// Network slice.
    Slice { snssai: String },
    /// Tenant.
    Tenant { tenant: String },
    /// Cryptographic key or certificate.
    Certificate { key_id: String },
    /// Data-plane queue.
    DataPlaneQueue {
        nf: String,
        interface: String,
        queue: u16,
    },
}

impl fmt::Display for AffectedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AffectedObject::NfInstance { kind, instance } => {
                write!(f, "nf:{kind}:{instance}")
            }
            AffectedObject::Interface { nf, name } => {
                write!(f, "interface:{nf}:{name}")
            }
            AffectedObject::Peer { nf, peer_id } => {
                write!(f, "peer:{nf}:{peer_id}")
            }
            AffectedObject::SessionStore { nf, shard } => {
                if let Some(s) = shard {
                    write!(f, "session-store:{nf}:shard={s}")
                } else {
                    write!(f, "session-store:{nf}")
                }
            }
            AffectedObject::Slice { snssai } => {
                write!(f, "slice:{snssai}")
            }
            AffectedObject::Tenant { tenant } => {
                write!(f, "tenant:{tenant}")
            }
            AffectedObject::Certificate { key_id } => {
                write!(f, "certificate:{key_id}")
            }
            AffectedObject::DataPlaneQueue {
                nf,
                interface,
                queue,
            } => {
                write!(f, "dp-queue:{nf}:{interface}:q{queue}")
            }
        }
    }
}

/// Feeds the affected object into a SHA-256 hasher using structural encoding
/// (variant tag + length-prefixed fields) so that distinct variants and fields
/// never collide even when values contain `:` characters.
///
/// Example: `NfInstance { kind: "a:b", instance: "c" }` and
/// `NfInstance { kind: "a", instance: "b:c" }` produce different hashes.
impl AffectedObject {
    pub(crate) fn feed_to_hasher(&self, hasher: &mut sha2::Sha256) {
        // Length-prefixed helper
        fn feed_field(hasher: &mut sha2::Sha256, field: &str) {
            let bytes = field.as_bytes();
            hasher.update((bytes.len() as u32).to_be_bytes());
            hasher.update(bytes);
        }

        fn feed_variant_and_fields(hasher: &mut sha2::Sha256, tag: &str, fields: &[&str]) {
            feed_field(hasher, tag);
            for &f in fields {
                feed_field(hasher, f);
            }
        }

        // Encode optional fields with presence byte so None and Some("") cannot alias.
        fn feed_opt(hasher: &mut sha2::Sha256, opt: Option<&str>) {
            match opt {
                Some(v) => {
                    hasher.update([1u8]);
                    feed_field(hasher, v);
                }
                None => {
                    hasher.update([0u8]);
                }
            }
        }

        match self {
            AffectedObject::NfInstance { kind, instance } => {
                feed_variant_and_fields(hasher, "NfInstance", &[kind, instance]);
            }
            AffectedObject::Interface { nf, name } => {
                feed_variant_and_fields(hasher, "Interface", &[nf, name]);
            }
            AffectedObject::Peer { nf, peer_id } => {
                feed_variant_and_fields(hasher, "Peer", &[nf, peer_id]);
            }
            AffectedObject::SessionStore { nf, shard } => {
                feed_variant_and_fields(hasher, "SessionStore", &[nf]);
                feed_opt(hasher, shard.as_deref());
            }
            AffectedObject::Slice { snssai } => {
                feed_variant_and_fields(hasher, "Slice", &[snssai]);
            }
            AffectedObject::Tenant { tenant } => {
                feed_variant_and_fields(hasher, "Tenant", &[tenant]);
            }
            AffectedObject::Certificate { key_id } => {
                feed_variant_and_fields(hasher, "Certificate", &[key_id]);
            }
            AffectedObject::DataPlaneQueue {
                nf,
                interface,
                queue,
            } => {
                feed_variant_and_fields(
                    hasher,
                    "DataPlaneQueue",
                    &[nf, interface, &queue.to_string()],
                );
            }
        }
    }
}

/// Alarm lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlarmState {
    Raised,
    Updated,
    Acknowledged,
    Suppressed,
    Cleared,
    Expired,
}

impl AlarmState {
    /// Returns true for states that represent an active (non-terminal) alarm.
    ///
    /// Active states: Raised, Updated, Acknowledged, Suppressed.
    /// Inactive (terminal) states: Cleared, Expired.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            AlarmState::Raised
                | AlarmState::Updated
                | AlarmState::Acknowledged
                | AlarmState::Suppressed
        )
    }
}

impl fmt::Display for AlarmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            AlarmState::Raised => "raised",
            AlarmState::Updated => "updated",
            AlarmState::Acknowledged => "acknowledged",
            AlarmState::Suppressed => "suppressed",
            AlarmState::Cleared => "cleared",
            AlarmState::Expired => "expired",
        };
        f.write_str(s)
    }
}

/// Placeholder for alarm-specific details.
///
/// Replace with generated or structured detail types as NF models mature.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlarmDetails(Option<serde_json::Value>);

impl AlarmDetails {
    pub fn empty() -> Self {
        Self(None)
    }

    pub fn with_value(value: serde_json::Value) -> Self {
        Self(Some(value))
    }

    pub fn as_value(&self) -> Option<&serde_json::Value> {
        self.0.as_ref()
    }
}

/// Readiness impact policy per RFC 013 §12.
///
/// Determines how active alarms influence Kubernetes pod readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessImpact {
    /// Active alarm forces Ready=False on the pod.
    ForceNotReady,
    /// Active alarm sets Degraded=True but does not force not-ready.
    DegradedOnly,
    /// Active alarm is logged but does not affect readiness.
    #[default]
    NoImpact,
}

/// Newtype wrapper for alarm text that enforces the RFC 010 redaction contract.
///
/// Callers MUST pre-redact any sensitive identifiers (SUPI, IMSI, MSISDN,
/// IP addresses, etc.) before constructing this value. The type does not
/// inspect or modify the inner text; it documents the caller's obligation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RedactedText(String);

impl RedactedText {
    /// Wraps pre-redacted text. Callers are responsible for redaction per RFC 010.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RedactedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonical alarm struct per RFC 013 §4.
///
/// The `text` field MUST contain redacted content per RFC 010.
/// Raw subscriber identifiers MUST NOT appear in any field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alarm {
    pub alarm_id: AlarmId,
    pub alarm_type: AlarmType,
    pub severity: Severity,
    pub probable_cause: ProbableCause,
    pub affected_object: AffectedObject,
    pub tenant: Option<String>,
    pub slice: Option<String>,
    /// Region boundary metadata per RFC 010 §9 (region-scoped records).
    pub region: Option<RegionId>,
    /// Human-readable alarm text. MUST be pre-redacted per RFC 010. Use [`RedactedText::new`].
    pub text: RedactedText,
    pub details: AlarmDetails,
    pub state: AlarmState,
    pub raised_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub cleared_at: Option<OffsetDateTime>,
    pub correlation_id: Option<uuid::Uuid>,
}

impl Alarm {
    /// Computes the stable deduplication key for this alarm.
    ///
    /// Includes region so that the same fault in different regions produces
    /// distinct dedup keys (RFC 010 §9).
    pub fn dedup_key(&self) -> DedupKey {
        DedupKey::compute(
            &self.alarm_type,
            &self.probable_cause,
            &self.affected_object,
            self.tenant.as_deref(),
            self.slice.as_deref(),
            self.region.as_ref().map(|r| r.as_str()),
        )
    }

    /// Determines readiness impact based on current severity.
    ///
    /// Only active (non-terminal) alarms drive readiness. Cleared and Expired alarms
    /// always return `NoImpact` regardless of severity.
    ///
    /// Policy:
    /// - `critical` + active → `ForceNotReady`
    /// - `major` + active → `DegradedOnly`
    /// - all others or inactive → `NoImpact`
    pub fn readiness_impact(&self) -> ReadinessImpact {
        if !self.state.is_active() {
            return ReadinessImpact::NoImpact;
        }
        match self.severity {
            Severity::Critical => ReadinessImpact::ForceNotReady,
            Severity::Major => ReadinessImpact::DegradedOnly,
            Severity::Minor | Severity::Warning | Severity::Indeterminate | Severity::Cleared => {
                ReadinessImpact::NoImpact
            }
        }
    }
}

// ── hex encoding helper (no_std compatible, avoids external dep) ─────────────

mod hex {
    /// Encodes a byte slice as a lowercase hex string.
    pub fn encode(slice: &[u8]) -> String {
        slice
            .iter()
            .fold(String::with_capacity(slice.len() * 2), |mut acc, &b| {
                acc.push(HEX[(b >> 4) as usize] as char);
                acc.push(HEX[(b & 0xf) as usize] as char);
                acc
            })
    }

    const HEX: &[u8; 16] = b"0123456789abcdef";
}

#[cfg(test)]
mod tests {
    use super::{AlarmDetails, InvalidRegionId, RegionId};
    use std::convert::TryFrom;

    #[test]
    fn region_id_try_new_accepts_valid_input() {
        let region = RegionId::try_new("region-east").expect("valid region id");
        assert_eq!(region.as_str(), "region-east");
    }

    #[test]
    fn region_id_try_new_rejects_invalid_input() {
        assert_eq!(RegionId::try_new(""), Err(InvalidRegionId::Empty));

        let too_long = "a".repeat(129);
        assert_eq!(
            RegionId::try_new(too_long),
            Err(InvalidRegionId::TooLong { len: 129, max: 128 })
        );
    }

    #[test]
    fn region_id_try_from_string_rejects_invalid_input() {
        assert_eq!(
            RegionId::try_from(String::new()),
            Err(InvalidRegionId::Empty)
        );
    }

    #[test]
    fn region_id_serde_round_trips_valid_input() {
        let region = RegionId::try_new("region-east").expect("valid region id");
        let json = serde_json::to_string(&region).expect("serialize region id");
        assert_eq!(json, "\"region-east\"");

        let round_trip: RegionId = serde_json::from_str(&json).expect("deserialize region id");
        assert_eq!(round_trip, region);
    }

    #[test]
    fn region_id_serde_rejects_empty_input() {
        let err = serde_json::from_str::<RegionId>("\"\"").expect_err("empty region id");
        assert!(
            err.to_string().contains("region id must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn region_id_serde_rejects_overlong_input() {
        let raw = format!("\"{}\"", "a".repeat(129));
        let err = serde_json::from_str::<RegionId>(&raw).expect_err("overlong region id");
        assert!(
            err.to_string()
                .contains("region id exceeds maximum length of 128"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn alarm_details_accessors_preserve_optional_payload() {
        let empty = AlarmDetails::empty();
        assert_eq!(empty.as_value(), None);

        let value = serde_json::json!({
            "alarm": "link.down",
            "context": {
                "peer": "upf-1"
            }
        });
        let details = AlarmDetails::with_value(value.clone());
        assert_eq!(details.as_value(), Some(&value));
    }
}
