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
//! Session-Id, LI identifiers, SPI values, or key material.

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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// Validates the pack before it may be included in an evidence bundle.
    ///
    /// Checks:
    ///
    /// 1. The pack is marked `experimental: true` while the schema is
    ///    experimental (see [`PACKET_CORE_SCHEMA_VERSION`]).
    /// 2. No serialized string field contains a raw IMSI, MSISDN, IMEI, NAI,
    ///    Session-Id, LI identifier, SPI, or key material.
    ///
    /// Well-formed `sha256:` digests are skipped because they are safe by
    /// construction.
    ///
    /// Returns [`EvidenceError::RedactionViolation`] with a descriptive message
    /// when a violation is found.
    pub fn validate_redaction(&self) -> Result<(), EvidenceError> {
        if !self.experimental {
            return Err(EvidenceError::RedactionViolation(
                "packet-core evidence pack must be marked experimental while the schema is experimental".into(),
            ));
        }

        let value = serde_json::to_value(self).map_err(|e| {
            EvidenceError::InvalidTag(format!("failed to serialize evidence pack: {e}"))
        })?;
        if let Some(err) = validate_value_redaction(&value, "<root>") {
            return Err(EvidenceError::RedactionViolation(err));
        }
        Ok(())
    }
}

fn validate_value_redaction(value: &serde_json::Value, path: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if let Some(err) = validate_value_redaction(child, &child_path) {
                    return Some(err);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                if let Some(err) = validate_value_redaction(child, &child_path) {
                    return Some(err);
                }
            }
            None
        }
        serde_json::Value::String(s) => {
            if is_sha256_digest(s) {
                return None;
            }
            if let Some(reason) = has_raw_sensitive_identifier(s) {
                let preview: String = s.chars().take(64).collect();
                let preview = if s.chars().count() > 64 {
                    format!("{preview}...")
                } else {
                    preview
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
/// * Short subscriber identifier markers (`nai`, `supi`, `pei`, `gpsi`) on
///   word boundaries to avoid false positives in ordinary prose.
/// * NAI-like values (`user@realm`).
/// * International MSISDN-like values (`+` followed by several digits).
/// * Long runs of digits (8 or more) that could be IMSI, IMEI, or MSISDN.
///   This includes hyphen-less dates and numeric IDs, so free-text fields such
///   as `notes` and `payload_summary` may trip the check by design.
/// * Key-material markers (`BEGIN`, `PRIVATE KEY`, `SECRET`, ...).
/// * LI identifier markers (`liid`, `x1`, `x2`, `x3`).
/// * Raw SPI values (`spi=...`).
/// * Raw IPv4/IPv6 addresses.
pub fn has_raw_sensitive_identifier(s: &str) -> Option<&'static str> {
    let lower = s.to_ascii_lowercase();

    // 1. Explicit markers for subscriber / session identifiers.
    //
    // Long markers are matched as substrings so that values such as
    // `session_id=abc` are still caught. Short markers are matched on word
    // boundaries so that ordinary words like `snail`/`supine` are not flagged.
    const SUBSTRING_MARKERS: &[&str] = &[
        "imsi",
        "msisdn",
        "imei",
        "imeisv",
        "session-id",
        "session_id",
        "liid",
        "x1-trace",
        "x2-trace",
        "x3-trace",
        "spi=",
    ];
    const WORD_BOUNDARY_MARKERS: &[&str] = &["supi", "gpsi", "pei", "nai"];
    for marker in SUBSTRING_MARKERS {
        if lower.contains(marker) && !marker_is_redacted(&lower, marker) {
            return Some("contains sensitive identifier marker");
        }
    }
    for marker in WORD_BOUNDARY_MARKERS {
        if has_word_boundary_match(&lower, marker) && !marker_is_redacted(&lower, marker) {
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

    // 6. Raw IP addresses (e.g. peer addresses in XFRM summaries).
    if has_ip_address(s) {
        return Some("contains IP address");
    }

    None
}

/// Returns true when `lower` contains `marker` as a whole token, i.e. bounded
/// by the start/end of the string or by a non-alphanumeric character.
fn has_word_boundary_match(lower: &str, marker: &str) -> bool {
    lower.match_indices(marker).any(|(idx, _)| {
        let before = idx == 0 || !lower.as_bytes()[idx - 1].is_ascii_alphanumeric();
        let after_end = idx + marker.len();
        let after =
            after_end == lower.len() || !lower.as_bytes()[after_end].is_ascii_alphanumeric();
        before && after
    })
}

/// Returns the byte ranges of all redaction placeholders in `lower`.
/// A placeholder is a `<...redacted...>` span.
fn redaction_placeholder_ranges(lower: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while let Some(open) = lower[start..].find('<') {
        let open_abs = start + open;
        if let Some(close_rel) = lower[open_abs..].find('>') {
            let close_abs = open_abs + close_rel + 1;
            let inner = &lower[open_abs + 1..close_abs - 1];
            if inner.contains("redacted") {
                ranges.push((open_abs, close_abs));
            }
            start = close_abs;
        } else {
            break;
        }
    }
    ranges
}

/// Returns true only when every occurrence of `marker` in `lower` is part of a
/// redaction placeholder. A marker occurrence is considered redacted if it lies
/// inside a `<...redacted...>` placeholder anywhere in the string, or if it is
/// immediately followed (with an optional `=`) by such a placeholder.
fn marker_is_redacted(lower: &str, marker: &str) -> bool {
    let ranges = redaction_placeholder_ranges(lower);
    for (idx, matched) in lower.match_indices(marker) {
        if !marker_occurrence_is_redacted(lower, matched, idx, &ranges) {
            return false;
        }
    }
    true
}

fn marker_occurrence_is_redacted(
    lower: &str,
    marker: &str,
    idx: usize,
    ranges: &[(usize, usize)],
) -> bool {
    let end = idx + marker.len();

    // Inside a redaction placeholder anywhere in the string.
    for &(pstart, pend) in ranges {
        if idx >= pstart && end <= pend {
            return true;
        }
    }

    // Adjacent to a redaction placeholder with an optional '=' separator.
    let after = &lower[end..];
    let after = after.trim_start();
    let after = after.strip_prefix('=').unwrap_or(after);
    starts_with_redaction_placeholder(after)
}

fn starts_with_redaction_placeholder(s: &str) -> bool {
    let s = s.trim_start();
    if !s.starts_with('<') {
        return false;
    }
    let Some(end) = s.find('>') else {
        return false;
    };
    s[1..end].to_ascii_lowercase().contains("redacted")
}

fn has_ip_address(s: &str) -> bool {
    has_ipv4_address(s) || has_ipv6_address(s)
}

fn has_ipv4_address(s: &str) -> bool {
    // Candidate tokens contain only digits and dots.
    for token in s.split(|c: char| !c.is_ascii_digit() && c != '.') {
        if looks_like_ipv4(token) {
            return true;
        }
    }
    false
}

fn looks_like_ipv4(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let octets: Vec<&str> = token.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    octets.iter().all(|o| {
        if o.is_empty() || o.len() > 3 {
            return false;
        }
        if !o.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if o.len() > 1 && o.starts_with('0') {
            return false;
        }
        o.parse::<u8>().is_ok()
    })
}

fn has_ipv6_address(s: &str) -> bool {
    // Candidate tokens contain only hex digits and colons.
    for token in s.split(|c: char| !c.is_ascii_hexdigit() && c != ':') {
        if looks_like_ipv6(token) {
            return true;
        }
    }
    false
}

fn looks_like_ipv6(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let colon_count = token.matches(':').count();
    if colon_count == 0 {
        return false;
    }

    // Compressed form (contains ::).
    if token.contains("::") {
        let parts: Vec<&str> = token.split("::").collect();
        if parts.len() != 2 {
            return false;
        }
        let explicit_groups: Vec<&str> = token.split(':').filter(|g| !g.is_empty()).collect();
        // Require at least two explicit groups to avoid matching tokens such as
        // `std::` in ordinary prose.
        if explicit_groups.len() < 2 {
            return false;
        }
        // :: replaces at least one group, so explicit groups must be <= 7.
        if explicit_groups.len() > 7 {
            return false;
        }
        return explicit_groups
            .iter()
            .all(|g| !g.is_empty() && g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // Uncompressed form: exactly 8 groups separated by 7 colons.
    if colon_count == 7 {
        let groups: Vec<&str> = token.split(':').collect();
        return groups.len() == 8
            && groups.iter().all(|g| {
                !g.is_empty() && g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit())
            });
    }

    false
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
        assert!(has_raw_sensitive_identifier("<spi-redacted>").is_none());
        assert!(has_raw_sensitive_identifier("spi=<spi-redacted> mode=tunnel").is_none());
        assert!(has_raw_sensitive_identifier("imsi=<imsi-redacted>").is_none());
    }

    #[test]
    fn detects_raw_spi_values() {
        assert!(has_raw_sensitive_identifier("spi=12345678").is_some());
        assert!(has_raw_sensitive_identifier("spi=0x12345678").is_some());
        assert!(has_raw_sensitive_identifier("xfrm spi=0xdeadbeef").is_some());
    }

    #[test]
    fn preview_does_not_panic_on_multibyte_input() {
        // 22 '€' characters plus "imsi" makes a sensitive value longer than 64
        // bytes where byte 64 falls inside a multi-byte UTF-8 character.
        let value = "€".repeat(22) + "imsi";
        let pack = PacketCoreEvidencePack {
            schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
            pack_id: "preview-test".into(),
            generated_at: OffsetDateTime::UNIX_EPOCH,
            generated_by: "test".into(),
            experimental: true,
            protocol_evidence: Vec::new(),
            attach_evidence: Vec::new(),
            kernel_dataplane_evidence: vec![KernelDataplaneEvidence {
                schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
                evidence_id: "k-1".into(),
                interface_name: "eth0".into(),
                xfrm_state_count: 0,
                xfrm_policy_count: 0,
                routing_entries: 0,
                iptables_rules: 0,
                nftables_rules: 0,
                observed_packets: 0,
                dropped_packets: 0,
                counters: Vec::new(),
                xfrm_state_summary: vec![value],
                timestamp: OffsetDateTime::UNIX_EPOCH,
                requirements: Vec::new(),
                notes: None,
            }],
        };
        let err = pack.validate_redaction().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("redaction violation"));
        assert!(msg.contains("contains sensitive identifier marker"));
    }

    #[test]
    fn validate_redaction_requires_experimental_flag() {
        let mut pack = PacketCoreEvidencePack {
            schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
            pack_id: "experimental-test".into(),
            generated_at: OffsetDateTime::UNIX_EPOCH,
            generated_by: "test".into(),
            experimental: false,
            protocol_evidence: Vec::new(),
            attach_evidence: Vec::new(),
            kernel_dataplane_evidence: Vec::new(),
        };
        let err = pack.validate_redaction().unwrap_err();
        assert!(err.to_string().contains("must be marked experimental"));

        pack.experimental = true;
        pack.validate_redaction().expect("experimental pack passes");
    }

    #[test]
    fn digest_fields_are_not_redaction_bypasses() {
        // A raw identifier placed in a field whose name ends with `_digest`
        // must still be caught; only well-formed sha256 digests are safe.
        let pack = PacketCoreEvidencePack {
            schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
            pack_id: "digest-bypass-test".into(),
            generated_at: OffsetDateTime::UNIX_EPOCH,
            generated_by: "test".into(),
            experimental: true,
            protocol_evidence: vec![PacketCoreProtocolEvidence {
                schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
                evidence_id: "p-1".into(),
                protocol: "IKEv2".into(),
                scenario: "test".into(),
                message_direction: PacketCoreMessageDirection::ControlPlane,
                payload_summary: "summary".into(),
                payload_digest: "imsi 208950000000001".into(),
                conformance_tags: Vec::new(),
                requirements: Vec::new(),
                fixture_source: "test".into(),
                fixture_provenance: "test".into(),
                captured_at: None,
                notes: None,
            }],
            attach_evidence: Vec::new(),
            kernel_dataplane_evidence: Vec::new(),
        };
        let err = pack.validate_redaction().unwrap_err();
        assert!(err.to_string().contains("redaction violation"));
    }

    #[test]
    fn detects_raw_ipv4_address() {
        assert!(has_raw_sensitive_identifier("src=203.0.113.10 dst=198.51.100.20").is_some());
        assert!(has_raw_sensitive_identifier("192.168.1.1").is_some());
        assert!(has_raw_sensitive_identifier("10.0.0.1").is_some());
        // Version-like numbers are flagged by design (fail-closed).
        assert!(has_raw_sensitive_identifier("1.2.3.4").is_some());
        // Invalid IPv4 shapes are not flagged.
        assert!(has_raw_sensitive_identifier("1.2.3").is_none());
        assert!(has_raw_sensitive_identifier("256.0.0.1").is_none());
    }

    #[test]
    fn detects_raw_ipv6_address() {
        assert!(has_raw_sensitive_identifier("2001:db8::1").is_some());
        assert!(has_raw_sensitive_identifier("fe80::1:2:3:4:5:6").is_some());
        assert!(has_raw_sensitive_identifier("2001:0db8:0000:0000:0000:ff00:0042:8329").is_some());
        // MAC addresses and ordinary time/ratio text are not flagged.
        assert!(has_raw_sensitive_identifier("00:1a:2b:3c:4d:5e").is_none());
        assert!(has_raw_sensitive_identifier("12:34:56").is_none());
        assert!(has_raw_sensitive_identifier("std::vector").is_none());
    }

    #[test]
    fn redacted_note_does_not_bypass_unrelated_marker() {
        // The word "redacted" appearing elsewhere in the string must not
        // disable marker checks for an unrelated identifier.
        assert!(has_raw_sensitive_identifier("imsi 208950000000001 (redacted note)").is_some());
        assert!(has_raw_sensitive_identifier("redacted note; Session-Id abcdef").is_some());
        // A properly scoped placeholder is still allowed.
        assert!(has_raw_sensitive_identifier("<imsi-redacted>").is_none());
    }

    #[test]
    fn every_marker_occurrence_must_be_redacted() {
        // A redacted occurrence of a marker must not suppress detection of a
        // later raw occurrence of the same marker.
        assert!(
            has_raw_sensitive_identifier("session-id=<session-redacted>; session-id abcdef")
                .is_some()
        );
        assert!(has_raw_sensitive_identifier("spi=<spi-redacted> spi=0xdeadbeef").is_some());
        assert!(
            has_raw_sensitive_identifier("session-id=<session-redacted> session-id=rawvalue")
                .is_some()
        );
        // A redacted occurrence on its own is still safe.
        assert!(has_raw_sensitive_identifier("session-id=<session-redacted>").is_none());
    }

    #[test]
    fn embedded_redaction_placeholder_is_allowed() {
        // A marker inside a placeholder that is embedded in a larger string
        // must not be flagged.
        assert!(has_raw_sensitive_identifier("foo <imsi-redacted> bar").is_none());
        assert!(has_raw_sensitive_identifier("prefix <session-redacted> suffix").is_none());
        // But a raw marker outside the placeholder must still be caught.
        assert!(has_raw_sensitive_identifier("<imsi-redacted> session-id abc>").is_some());
    }

    #[test]
    fn short_markers_respect_word_boundaries() {
        // Ordinary words that contain short markers must not be flagged.
        assert!(has_raw_sensitive_identifier("snail").is_none());
        assert!(has_raw_sensitive_identifier("nail").is_none());
        assert!(has_raw_sensitive_identifier("supine").is_none());
        // Stand-alone short markers or key=value forms are still caught.
        assert!(has_raw_sensitive_identifier("nai user@example.com").is_some());
        assert!(has_raw_sensitive_identifier("supi=xxx").is_some());
        assert!(has_raw_sensitive_identifier("pei 12345").is_some());
        assert!(has_raw_sensitive_identifier("gpsi").is_some());
    }

    #[test]
    fn validate_redaction_uses_redaction_violation_variant() {
        let mut pack = sample_pack_for_tests();
        pack.attach_evidence[0].ue_identifier_redacted = "208950000000001".into();
        let err = pack.validate_redaction().unwrap_err();
        assert!(matches!(err, EvidenceError::RedactionViolation(_)));
    }

    fn sample_pack_for_tests() -> PacketCoreEvidencePack {
        PacketCoreEvidencePack {
            schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
            pack_id: "test-pack".into(),
            generated_at: OffsetDateTime::UNIX_EPOCH,
            generated_by: "test".into(),
            experimental: true,
            protocol_evidence: Vec::new(),
            attach_evidence: vec![AttachProcedureEvidence {
                schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
                evidence_id: "a-1".into(),
                procedure: "initial-attach".into(),
                result: AttachProcedureResult::Success,
                steps: Vec::new(),
                ue_identifier_redacted: "<supi-redacted>".into(),
                session_id_redacted: None,
                serving_node: "epdg-0".into(),
                timestamp: OffsetDateTime::UNIX_EPOCH,
                duration_ms: None,
                requirements: Vec::new(),
                notes: None,
            }],
            kernel_dataplane_evidence: Vec::new(),
        }
    }
}
