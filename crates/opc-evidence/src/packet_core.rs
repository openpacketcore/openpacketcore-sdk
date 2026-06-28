//! Packet-core evidence pack schemas for protocol fixtures, attach procedures,
//! and kernel dataplane/XFRM proof.
//!
//! These schemas are **experimental** and versioned within RFC 006. Downstream
//! products such as ePDG smoke artifacts may map into this format for
//! comparability; doing so does not imply SDK or product certification.
//!
//! # Redaction
//!
//! All human-readable identifier fields MUST be redacted before they are placed
//! in evidence. [`PacketCoreEvidencePack::validate_redaction`] walks the
//! serialized pack and fails closed if it finds raw IMSI, MSISDN, IMEI, NAI,
//! Session-Id, LI identifiers, or key material.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::EvidenceError;

/// Stable version identifier for packet-core evidence schemas.
pub const PACKET_CORE_SCHEMA_VERSION: &str = "rfc006/v1/packet-core-experimental";

/// Top-level evidence pack that groups packet-core evidence by category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketCoreEvidencePack {
    pub schema_version: String,
    pub pack_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub generated_by: String,
    /// Whether this pack is experimental and therefore not a stable external
    /// contract. Callers MUST keep this `true` until the schema graduates.
    pub experimental: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub protocol_evidence: Vec<PacketCoreProtocolEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attach_evidence: Vec<AttachProcedureEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub kernel_dataplane_evidence: Vec<KernelDataplaneEvidence>,
}

/// Evidence captured from a protocol fixture or trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketCoreProtocolEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub protocol: String,
    pub scenario: String,
    pub message_direction: PacketCoreMessageDirection,
    /// Human-readable summary of the payload. MUST NOT contain raw subscriber
    /// identifiers or key material.
    pub payload_summary: String,
    /// Cryptographic digest of the raw payload bytes. This is the safe way to
    /// reference a captured message; the digest itself is not redacted.
    pub payload_digest: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub conformance_tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub requirements: Vec<String>,
    /// Source of the fixture, e.g. a spec section or an independent capture.
    pub fixture_source: String,
    /// Provenance explaining how the fixture was obtained and why it is
    /// trustworthy (independent capture, hand-authored from spec, etc.).
    pub fixture_provenance: String,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub captured_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Direction of a packet-core protocol message relative to the network function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PacketCoreMessageDirection {
    Uplink,
    Downlink,
    ControlPlane,
    UserPlane,
}

/// Result of an attach or session-establishment procedure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachProcedureEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub procedure: String,
    pub result: AttachProcedureResult,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub steps: Vec<AttachStep>,
    /// Redacted UE identifier. MUST NOT be a raw IMSI, MSISDN, IMEI, NAI, or
    /// any other subscriber identifier.
    pub ue_identifier_redacted: String,
    /// Redacted session identifier, if any. MUST NOT be a raw Diameter
    /// Session-Id or similar traceable value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id_redacted: Option<String>,
    pub serving_node: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub requirements: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Outcome of an attach or session-establishment procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachProcedureResult {
    Success,
    Failure,
    Partial,
}

/// A single step inside an attach procedure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachStep {
    pub name: String,
    pub result: AttachStepResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Outcome of a single attach step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachStepResult {
    Success,
    Failure,
    Skipped,
}

/// Evidence captured from the kernel dataplane, including XFRM, routing, and
/// firewall state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelDataplaneEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub interface_name: String,
    pub xfrm_state_count: u64,
    pub xfrm_policy_count: u64,
    pub routing_entries: u64,
    pub iptables_rules: u64,
    pub nftables_rules: u64,
    pub observed_packets: u64,
    pub dropped_packets: u64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub counters: Vec<DataplaneCounter>,
    /// Summaries of XFRM state entries. MUST NOT contain raw peer IP addresses
    /// or SPI values that identify a subscriber session.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub xfrm_state_summary: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub requirements: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// A named dataplane counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataplaneCounter {
    pub name: String,
    pub value: u64,
}

impl PacketCoreEvidencePack {
    /// Validates that the pack contains no raw sensitive identifiers in its
    /// serialized string fields.
    ///
    /// Digest fields (`payload_digest`, `message_digest`, and values that are
    /// well-formed `sha256:` digests) are skipped because they are safe by
    /// construction. All other string fields are checked for raw IMSI, MSISDN,
    /// IMEI, NAI, Session-Id, LI identifiers, and key material markers.
    ///
    /// Returns [`EvidenceError::InvalidTag`] with a descriptive message when a
    /// violation is found.
    pub fn validate_redaction(&self) -> Result<(), EvidenceError> {
        let value = serde_json::to_value(self).map_err(|e| {
            EvidenceError::InvalidTag(format!("failed to serialize evidence pack: {e}"))
        })?;
        if let Some(err) = validate_value_redaction(&value, "<root>", "") {
            return Err(EvidenceError::InvalidTag(err));
        }
        Ok(())
    }
}

fn validate_value_redaction(
    value: &serde_json::Value,
    path: &str,
    parent_field: &str,
) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if let Some(err) = validate_value_redaction(child, &child_path, key) {
                    return Some(err);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                if let Some(err) = validate_value_redaction(child, &child_path, parent_field) {
                    return Some(err);
                }
            }
            None
        }
        serde_json::Value::String(s) => {
            let skip = parent_field.ends_with("_digest")
                || parent_field.ends_with("_digests")
                || is_sha256_digest(s);
            if skip {
                return None;
            }
            if let Some(reason) = has_raw_sensitive_identifier(s) {
                let preview = if s.len() > 64 {
                    format!("{}...", &s[..64])
                } else {
                    s.clone()
                };
                return Some(format!(
                    "redaction violation at {path}: {reason}; value: {preview:?}"
                ));
            }
            None
        }
        _ => None,
    }
}

fn is_sha256_digest(s: &str) -> bool {
    let rest = s.strip_prefix("sha256:");
    if let Some(rest) = rest {
        rest.len() == 64
            && rest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    } else {
        false
    }
}

/// Returns the reason a string is considered to contain a raw sensitive
/// identifier, or `None` if it appears safe.
///
/// This check is intentionally conservative. It flags:
///
/// * Common subscriber identifier markers (`imsi`, `msisdn`, `imei`, ...).
/// * NAI-like values (`user@realm`).
/// * International MSISDN-like values (`+` followed by several digits).
/// * Long runs of digits (8 or more) that could be IMSI, IMEI, or MSISDN.
/// * Key-material markers (`BEGIN`, `PRIVATE KEY`, `SECRET`, ...).
/// * LI identifier markers (`liid`, `x1`, `x2`, `x3`).
pub fn has_raw_sensitive_identifier(s: &str) -> Option<&'static str> {
    let lower = s.to_ascii_lowercase();

    // 1. Explicit markers for subscriber / session identifiers.
    const MARKERS: &[&str] = &[
        "imsi",
        "msisdn",
        "imei",
        "imeisv",
        "supi",
        "gpsi",
        "pei",
        "nai",
        "session-id",
        "session_id",
        "liid",
        "x1-trace",
        "x2-trace",
        "x3-trace",
    ];
    for marker in MARKERS {
        if lower.contains(marker) {
            // Allow explicit redaction placeholders such as `<imsi-redacted>`
            // without disabling the other checks below.
            if lower.contains("redacted") {
                continue;
            }
            return Some("contains sensitive identifier marker");
        }
    }

    // 2. NAI-like (contains '@' between non-trivial parts).
    if looks_like_nai(s) {
        return Some("contains NAI-like value");
    }

    // 3. International MSISDN-like.
    if has_international_msisdn(s) {
        return Some("contains MSISDN-like value");
    }

    // 4. Long digit runs that could be IMSI/IMEI/MSISDN.
    if has_long_digit_run(s) {
        return Some("contains long digit run");
    }

    // 5. Key material markers.
    if lower.contains("-----begin")
        || lower.contains("private key")
        || lower.contains("secret key")
        || lower.contains("shared secret")
        || lower.contains("secret=")
        || lower.contains("token=")
        || lower.contains("bearer ")
        || lower.contains("authorization:")
    {
        return Some("contains key material marker");
    }

    None
}

fn looks_like_nai(s: &str) -> bool {
    // NAI: user@realm. Require non-trivial local and host parts, and forbid
    // obvious placeholders like "<user>@<realm>".
    if let Some(at) = s.find('@') {
        let local = &s[..at];
        let host = &s[at + 1..];
        if local.len() >= 2 && host.len() >= 2 && !local.starts_with('<') && !host.ends_with('>') {
            return true;
        }
    }
    false
}

fn has_international_msisdn(s: &str) -> bool {
    // Look for '+' followed by 7-15 digits with optional separators.
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            let mut digits = 0;
            let mut j = i + 1;
            while j < bytes.len() {
                let c = bytes[j];
                if c.is_ascii_digit() {
                    digits += 1;
                } else if c == b' ' || c == b'-' || c == b'.' {
                    // allow separators
                } else {
                    break;
                }
                j += 1;
            }
            if (7..=15).contains(&digits) {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn has_long_digit_run(s: &str) -> bool {
    let mut run = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_digest_is_recognized() {
        assert!(is_sha256_digest(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_sha256_digest("sha256:0123"));
        assert!(!is_sha256_digest("not a digest"));
    }

    #[test]
    fn detects_raw_imsi() {
        assert!(has_raw_sensitive_identifier("208950000000001").is_some());
        assert!(has_raw_sensitive_identifier("imsi 208950000000001").is_some());
    }

    #[test]
    fn detects_raw_msisdn() {
        assert!(has_raw_sensitive_identifier("+14155552671").is_some());
        assert!(has_raw_sensitive_identifier("msisdn +1-415-555-2671").is_some());
    }

    #[test]
    fn detects_raw_imei() {
        assert!(has_raw_sensitive_identifier("490154203237518").is_some());
        assert!(has_raw_sensitive_identifier("IMEISV 4901542032375181").is_some());
    }

    #[test]
    fn detects_nai() {
        assert!(has_raw_sensitive_identifier("user@example.com").is_some());
        assert!(has_raw_sensitive_identifier("<user>@<realm>").is_none());
    }

    #[test]
    fn detects_session_id() {
        assert!(has_raw_sensitive_identifier("Session-Id 12345").is_some());
        assert!(has_raw_sensitive_identifier("session_id=abc").is_some());
    }

    #[test]
    fn detects_li_identifier() {
        assert!(has_raw_sensitive_identifier("liid-12345").is_some());
        assert!(has_raw_sensitive_identifier("x1-trace enabled").is_some());
    }

    #[test]
    fn detects_key_material_markers() {
        assert!(has_raw_sensitive_identifier("-----BEGIN PRIVATE KEY-----").is_some());
        assert!(has_raw_sensitive_identifier("shared secret 1234").is_some());
    }

    #[test]
    fn redacted_values_are_safe() {
        assert!(has_raw_sensitive_identifier("<imsi-redacted>").is_none());
        assert!(has_raw_sensitive_identifier("<ue-id>").is_none());
        assert!(has_raw_sensitive_identifier("<msisdn-redacted>").is_none());
        assert!(has_raw_sensitive_identifier("no sensitive content").is_none());
    }
}
