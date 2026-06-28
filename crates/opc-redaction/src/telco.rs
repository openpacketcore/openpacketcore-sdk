//! Telco identifier classification and redaction helpers.
//!
//! Recognizes IMSI, MSISDN, IMEI, NAI, SIP URI, APN, TEID, SPI, Diameter
//! Session-Id, and LI ID values so they can be redacted with the correct
//! [`IdentifierType`] and [`DataClass`].

use opc_data_governance::{DataClass, IdentifierType, TelcoIdentifierClass};
use std::fmt;

use crate::{compute_digest, redact, DigestKey, RedactedValue, RedactionLevel};

/// Known telco marker prefixes recognized by [`TelcoIdentifier::classify`] and
/// the support-bundle scanner. Each marker may be followed by `-`, `_`, `:`, `=`,
/// or `.` in `match_marker`.
pub const TELCO_MARKER_KEYS: &[&str] = &[
    "imsi",
    "msisdn",
    "imei",
    "liid",
    "li-id",
    "li_id",
    "li-warrant-id",
    "li_warrant_id",
    "liwarrantid",
    "li-correlation-id",
    "li_correlation_id",
    "licorrelationid",
    "delivery-address",
    "delivery_address",
    "deliveryaddress",
    "teid",
    "spi",
    "diameter-session-id",
    "diameter.session.id",
    "diameter_session_id",
    "diameterSessionId",
    "apn",
    "dnn",
    "nai",
];

/// Maps a known telco marker to its canonical [`IdentifierType`].
///
/// Returns `None` for markers that are not explicitly mapped. This prevents a
/// newly-added marker from being silently misclassified as an IMSI/subscriber
/// identifier.
pub(crate) fn marker_to_identifier_type(marker: &str) -> Option<IdentifierType> {
    match marker {
        "imsi" => Some(IdentifierType::Imsi),
        "msisdn" => Some(IdentifierType::Msisdn),
        "imei" => Some(IdentifierType::Imei),
        "liid" | "li-id" | "li_id" => Some(IdentifierType::LiId),
        "li-warrant-id" | "li_warrant_id" | "liwarrantid" => Some(IdentifierType::LiWarrantId),
        "li-correlation-id" | "li_correlation_id" | "licorrelationid" => {
            Some(IdentifierType::LiCorrelationId)
        }
        "delivery-address" | "delivery_address" | "deliveryaddress" => {
            Some(IdentifierType::DeliveryAddress)
        }
        "teid" => Some(IdentifierType::Teid),
        "spi" => Some(IdentifierType::Spi),
        "diameter-session-id"
        | "diameter.session.id"
        | "diameter_session_id"
        | "diameterSessionId" => Some(IdentifierType::DiameterSessionId),
        "apn" => Some(IdentifierType::Apn),
        "dnn" => Some(IdentifierType::Dnn),
        "nai" => Some(IdentifierType::Nai),
        _ => None,
    }
}

/// A classified telco identifier value.
#[derive(Clone, PartialEq, Eq)]
pub struct TelcoIdentifier {
    /// The canonical identifier type for this value.
    pub id_type: IdentifierType,
    /// The raw identifier value.
    pub value: String,
}

impl fmt::Display for TelcoIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.id_type)
    }
}

impl fmt::Debug for TelcoIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelcoIdentifier")
            .field("id_type", &self.id_type)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl TelcoIdentifier {
    /// Create a classified identifier from its type and raw value.
    pub fn new(id_type: IdentifierType, value: &str) -> Self {
        Self {
            id_type,
            value: value.to_string(),
        }
    }

    /// Classify a raw string as one of the telco identifier types.
    ///
    /// This is a heuristic: it recognizes common wire/format shapes but may
    /// return `None` for ambiguous or malformed values. Callers that already
    /// know the identifier type should use [`TelcoIdentifier::new`] instead.
    pub fn classify(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Marker=value forms for all known telco markers.
        for marker in TELCO_MARKER_KEYS {
            if let Some(value) = match_marker(trimmed, marker) {
                let id_type = marker_to_identifier_type(marker)?;
                return Some(Self::new(id_type, value));
            }
        }

        // SIP URI. Use byte-prefix checks so non-ASCII input cannot land on a
        // UTF-8 char boundary and panic.
        let bytes = trimmed.as_bytes();
        if bytes
            .get(..4)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"sip:"))
            || bytes
                .get(..5)
                .is_some_and(|b| b.eq_ignore_ascii_case(b"sips:"))
        {
            return Some(Self::new(IdentifierType::Sip, trimmed));
        }

        // NAI: user@realm. This heuristic is intentionally broad/fail-closed:
        // any @-bearing token without spaces is treated as a network access
        // identifier and redacted, which may also catch ordinary email
        // addresses in diagnostic text. Tokens that already contain '=' are
        // skipped because they are likely key=value pairs handled by the marker
        // branch above or by support-bundle token splitting.
        if trimmed.contains('@') && !trimmed.contains(' ') && !trimmed.contains('=') {
            return Some(Self::new(IdentifierType::Nai, trimmed));
        }

        // Diameter Session-Id: origin;high;low[;optional].
        if is_valid_diameter_session_id(trimmed) {
            return Some(Self::new(IdentifierType::DiameterSessionId, trimmed));
        }

        // Numeric identifiers.
        let digits_only = trimmed
            .trim_start_matches('+')
            .chars()
            .all(|c| c.is_ascii_digit());
        if digits_only {
            let digit_count = trimmed
                .trim_start_matches('+')
                .chars()
                .filter(|c| c.is_ascii_digit())
                .count();
            if (14..=15).contains(&digit_count) {
                return Some(Self::new(IdentifierType::Imsi, trimmed));
            }
            if (8..=15).contains(&digit_count) {
                return Some(Self::new(IdentifierType::Msisdn, trimmed));
            }
            return None;
        }

        // 32-bit hex values: TEID if prefixed, SPI if not? Prefer TEID as the
        // more common bare hex identifier in logs.
        if let Some(hex) = strip_hex_prefix(trimmed) {
            if is_hex(hex) && hex.len() == 8 {
                return Some(Self::new(IdentifierType::Teid, trimmed));
            }
        }

        None
    }

    /// The telco class for this identifier.
    pub const fn telco_class(&self) -> Option<TelcoIdentifierClass> {
        self.id_type.telco_class()
    }

    /// The default [`DataClass`] for this identifier.
    pub const fn default_data_class(&self) -> DataClass {
        match self.telco_class() {
            Some(class) => class.default_data_class(),
            None => DataClass::SubscriberId,
        }
    }

    /// Redact this identifier using the given level and optional digest key.
    pub fn redact(&self, level: RedactionLevel, digest_key: Option<&DigestKey>) -> RedactedValue {
        redact(
            &self.value,
            self.default_data_class(),
            level,
            Some(self.id_type),
            digest_key,
        )
    }

    /// Compute a keyed digest for this identifier.
    pub fn digest(&self, key: &DigestKey) -> String {
        compute_digest(key, self.default_data_class(), self.id_type, &self.value)
    }
}

fn match_marker<'a>(value: &'a str, marker: &str) -> Option<&'a str> {
    if value.len() <= marker.len() + 1 {
        return None;
    }
    let prefix = value.as_bytes().get(..marker.len())?;
    let marker_bytes = marker.as_bytes();
    if !prefix
        .iter()
        .zip(marker_bytes)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return None;
    }
    let sep = *value.as_bytes().get(marker.len())?;
    if !matches!(sep, b'-' | b'_' | b':' | b'=' | b'.') {
        return None;
    }
    // SAFETY: `marker` is ASCII and `sep` is a single ASCII separator byte, so
    // `marker.len() + 1` is a valid UTF-8 char boundary in the input `&str`.
    let suffix = &value[marker.len() + 1..];
    if !is_valid_marker_value(marker, suffix) {
        return None;
    }
    Some(suffix)
}

fn is_valid_marker_value(marker: &str, value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    match marker {
        "imsi" | "imei" => trimmed.chars().all(|c| c.is_ascii_digit()),
        "msisdn" => {
            let without_plus = trimmed.strip_prefix('+').unwrap_or(trimmed);
            without_plus.chars().all(|c| c.is_ascii_digit())
        }
        "teid" | "spi" => {
            let hex = strip_hex_prefix(trimmed).unwrap_or(trimmed);
            is_hex(hex)
        }
        "diameter-session-id"
        | "diameter.session.id"
        | "diameter_session_id"
        | "diameterSessionId" => {
            // Marker forms only require an origin-host containing a dot; the
            // trailing high/low fields may be supplied in a semicolon-separated
            // subfield scan. Bare values still use the strict validator below.
            let first_part = trimmed.split(';').next().unwrap_or(trimmed);
            !first_part.is_empty() && first_part.contains('.') && !first_part.contains(' ')
        }
        _ => true,
    }
}

/// Minimal validation for Diameter Session-Id: origin-host containing a dot,
/// followed by semicolon-separated high and low numeric fields. This matches
/// the bare-value heuristic used elsewhere and rejects obviously malformed
/// marker values such as `diameter-session-id=foo`.
fn is_valid_diameter_session_id(value: &str) -> bool {
    if !value.contains(';') {
        return false;
    }
    let mut parts = value.split(';');
    let Some(origin) = parts.next() else {
        return false;
    };
    if origin.is_empty() || !origin.contains('.') || origin.contains(' ') || origin.contains('=') {
        return false;
    }
    let high_numeric = parts
        .next()
        .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    let low_numeric = parts
        .next()
        .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    high_numeric && low_numeric
}

fn strip_hex_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telco_classify_imsi() {
        let id = TelcoIdentifier::classify("208950000000001").unwrap();
        assert_eq!(id.id_type, IdentifierType::Imsi);
        assert_eq!(id.value, "208950000000001");
    }

    #[test]
    fn telco_classify_msisdn() {
        let id = TelcoIdentifier::classify("+15551234567").unwrap();
        assert_eq!(id.id_type, IdentifierType::Msisdn);
        assert_eq!(id.value, "+15551234567");
    }

    #[test]
    fn telco_classify_imei() {
        let id = TelcoIdentifier::classify("imei-490154203237518").unwrap();
        assert_eq!(id.id_type, IdentifierType::Imei);
        assert_eq!(id.value, "490154203237518");
    }

    #[test]
    fn telco_classify_nai() {
        let id = TelcoIdentifier::classify("user@operator.com").unwrap();
        assert_eq!(id.id_type, IdentifierType::Nai);
        assert_eq!(id.value, "user@operator.com");

        // Explicit marker should return only the value, not the marker prefix.
        let id = TelcoIdentifier::classify("nai=user@operator.com").unwrap();
        assert_eq!(id.id_type, IdentifierType::Nai);
        assert_eq!(id.value, "user@operator.com");
    }

    #[test]
    fn telco_classify_nai_heuristic_skips_key_value_tokens() {
        // The broad NAI heuristic must not capture key=value tokens, otherwise
        // direct classify() callers would receive a spurious marker prefix.
        assert!(TelcoIdentifier::classify("nai=user@operator.com").is_some());
        let id = TelcoIdentifier::classify("some_key=user@operator.com");
        assert!(id.is_none(), "unexpectedly classified {id:?}");
    }

    #[test]
    fn telco_classify_sip() {
        let id = TelcoIdentifier::classify("sip:+15551234567@operator.com").unwrap();
        assert_eq!(id.id_type, IdentifierType::Sip);
    }

    #[test]
    fn telco_classify_apn() {
        let id = TelcoIdentifier::classify("apn=internet.operator.com").unwrap();
        assert_eq!(id.id_type, IdentifierType::Apn);
        assert_eq!(id.value, "internet.operator.com");
    }

    #[test]
    fn telco_classify_dnn() {
        let id = TelcoIdentifier::classify("dnn=internet").unwrap();
        assert_eq!(id.id_type, IdentifierType::Dnn);
        assert_eq!(id.value, "internet");

        let id = TelcoIdentifier::classify("dnn-internet").unwrap();
        assert_eq!(id.id_type, IdentifierType::Dnn);
        assert_eq!(id.value, "internet");
    }

    #[test]
    fn telco_classify_teid() {
        let id = TelcoIdentifier::classify("teid=0x12345678").unwrap();
        assert_eq!(id.id_type, IdentifierType::Teid);
        assert_eq!(id.value, "0x12345678");
    }

    #[test]
    fn telco_classify_spi() {
        let id = TelcoIdentifier::classify("spi=0x9abcdef0").unwrap();
        assert_eq!(id.id_type, IdentifierType::Spi);
        assert_eq!(id.value, "0x9abcdef0");
    }

    #[test]
    fn telco_classify_diameter_session_id() {
        let id = TelcoIdentifier::classify("operator.example.com;1234567890;0").unwrap();
        assert_eq!(id.id_type, IdentifierType::DiameterSessionId);
    }

    #[test]
    fn telco_classify_li_id() {
        let id = TelcoIdentifier::classify("li-id=target-42").unwrap();
        assert_eq!(id.id_type, IdentifierType::LiId);
        assert_eq!(id.value, "target-42");
    }

    #[test]
    fn telco_classify_li_warrant_id() {
        let id = TelcoIdentifier::classify("li-warrant-id=war-42").unwrap();
        assert_eq!(id.id_type, IdentifierType::LiWarrantId);
        assert_eq!(id.value, "war-42");

        let id = TelcoIdentifier::classify("li_warrant_id=war-42").unwrap();
        assert_eq!(id.id_type, IdentifierType::LiWarrantId);
        assert_eq!(id.value, "war-42");
    }

    #[test]
    fn telco_classify_li_correlation_id() {
        let id = TelcoIdentifier::classify("li-correlation-id=corr-42").unwrap();
        assert_eq!(id.id_type, IdentifierType::LiCorrelationId);
        assert_eq!(id.value, "corr-42");

        let id = TelcoIdentifier::classify("licorrelationid=corr-42").unwrap();
        assert_eq!(id.id_type, IdentifierType::LiCorrelationId);
        assert_eq!(id.value, "corr-42");
    }

    #[test]
    fn telco_classify_delivery_address() {
        let id = TelcoIdentifier::classify("delivery-address=mdf").unwrap();
        assert_eq!(id.id_type, IdentifierType::DeliveryAddress);
        assert_eq!(id.value, "mdf");

        let id = TelcoIdentifier::classify("delivery_address=mdf").unwrap();
        assert_eq!(id.id_type, IdentifierType::DeliveryAddress);
        assert_eq!(id.value, "mdf");
    }

    #[test]
    fn telco_classify_diameter_session_id_with_marker() {
        let id =
            TelcoIdentifier::classify("diameter-session-id=operator.example.com;123;0").unwrap();
        assert_eq!(id.id_type, IdentifierType::DiameterSessionId);
        assert_eq!(id.value, "operator.example.com;123;0");
    }

    #[test]
    fn telco_classify_li_id_alternate_marker() {
        let id = TelcoIdentifier::classify("li_id=target-42").unwrap();
        assert_eq!(id.id_type, IdentifierType::LiId);
        assert_eq!(id.value, "target-42");
    }

    #[test]
    fn telco_classify_diameter_session_id_alternate_marker() {
        let id =
            TelcoIdentifier::classify("diameter.session.id=operator.example.com;123;0").unwrap();
        assert_eq!(id.id_type, IdentifierType::DiameterSessionId);
        assert_eq!(id.value, "operator.example.com;123;0");
    }

    #[test]
    fn telco_classify_diameter_session_id_snake_case_marker() {
        let id = TelcoIdentifier::classify("diameter_session_id=op.example.com;123;0").unwrap();
        assert_eq!(id.id_type, IdentifierType::DiameterSessionId);
        assert_eq!(id.value, "op.example.com;123;0");
    }

    #[test]
    fn telco_classify_diameter_session_id_camel_case_marker() {
        let id = TelcoIdentifier::classify("diameterSessionId=op.example.com;123;0").unwrap();
        assert_eq!(id.id_type, IdentifierType::DiameterSessionId);
        assert_eq!(id.value, "op.example.com;123;0");
    }

    #[test]
    fn telco_classifier_does_not_panic_on_multibyte_token() {
        // Bare non-ASCII tokens must not panic on the SIP-prefix byte check.
        assert!(TelcoIdentifier::classify("日本").is_none());
        assert!(TelcoIdentifier::classify("éaé").is_none());
    }

    #[test]
    fn telco_classifier_rejects_empty_or_invalid_marker_values() {
        // Markers with no value, or values in the wrong format, must not match.
        assert!(TelcoIdentifier::classify("imsi=").is_none());
        assert!(TelcoIdentifier::classify("imsi=abc").is_none());
        assert!(TelcoIdentifier::classify("msisdn=abc").is_none());
        assert!(TelcoIdentifier::classify("imei=abc").is_none());
        assert!(TelcoIdentifier::classify("teid=foo").is_none());
        assert!(TelcoIdentifier::classify("spi=foo").is_none());
        assert!(TelcoIdentifier::classify("teid=").is_none());

        // Diameter Session-Id marker values must have an origin-host containing
        // a dot. The high/low fields may be supplied by a semicolon-separated
        // subfield scan, so partial marker forms are accepted here (fail-closed).
        assert!(TelcoIdentifier::classify("diameter-session-id=foo").is_none());
        assert!(TelcoIdentifier::classify("diameter-session-id=foo;bar").is_none());
        assert!(TelcoIdentifier::classify("diameter-session-id=op.example.com").is_some());
        assert!(TelcoIdentifier::classify("diameter-session-id=op.example.com;123;0").is_some());

        // Valid marker formats still match.
        assert!(TelcoIdentifier::classify("imsi=208950000000001").is_some());
        assert!(TelcoIdentifier::classify("msisdn=+15551234567").is_some());
        assert!(TelcoIdentifier::classify("teid=0x12345678").is_some());
    }

    #[test]
    fn telco_classifier_does_not_panic_on_case_expanding_unicode() {
        // Turkish dotted capital I lowercases to "i" plus a combining dot,
        // which previously caused byte-length arithmetic to underflow. The
        // classifier must not panic, even though the value is not a valid IMSI.
        let input = format!("imsi:{}", "İ".repeat(6));
        let _ = TelcoIdentifier::classify(&input);
    }

    #[test]
    fn telco_redact_all_required_identifiers() {
        let key = DigestKey::new([0xcd; 32]);
        let cases: &[(IdentifierType, &str)] = &[
            (IdentifierType::Imsi, "208950000000001"),
            (IdentifierType::Msisdn, "+15551234567"),
            (IdentifierType::Imei, "490154203237518"),
            (IdentifierType::Nai, "user@operator.com"),
            (IdentifierType::Sip, "sip:+15551234567@operator.com"),
            (IdentifierType::Apn, "internet.operator.com"),
            (IdentifierType::Dnn, "internet"),
            (IdentifierType::Teid, "0x12345678"),
            (IdentifierType::Spi, "0x9abcdef0"),
            (
                IdentifierType::DiameterSessionId,
                "operator.example.com;1234567890;0",
            ),
            (IdentifierType::LiId, "li-target-42"),
            (IdentifierType::LiWarrantId, "war-42"),
            (IdentifierType::LiCorrelationId, "corr-42"),
            (IdentifierType::DeliveryAddress, "mdf"),
        ];

        for (id_type, value) in cases {
            let id = TelcoIdentifier::new(*id_type, value);
            let masked = id.redact(RedactionLevel::Mask, None);
            assert_eq!(masked, RedactedValue::Mask);

            let digested = id.redact(RedactionLevel::Digest, Some(&key));
            assert!(
                matches!(digested, RedactedValue::Digest(_)),
                "{id_type:?} digest failed"
            );
            assert!(!digested.to_string().contains(value));

            let class = id.redact(RedactionLevel::Class, None);
            assert!(!class.to_string().contains(value));
        }
    }

    #[test]
    fn telco_digest_is_stable() {
        let key = DigestKey::new([0xab; 32]);
        let id = TelcoIdentifier::new(IdentifierType::Imsi, "208950000000001");
        assert_eq!(id.digest(&key), id.digest(&key));
        assert_eq!(id.digest(&key).len(), 64);
    }

    #[test]
    fn telco_digest_changes_with_identifier_type() {
        let key = DigestKey::new([0xab; 32]);
        let imsi = TelcoIdentifier::new(IdentifierType::Imsi, "same");
        let msisdn = TelcoIdentifier::new(IdentifierType::Msisdn, "same");
        assert_ne!(imsi.digest(&key), msisdn.digest(&key));
    }

    #[test]
    fn telco_class_lawful_intercept_denies_cleartext() {
        let id = TelcoIdentifier::new(IdentifierType::LiId, "li-target-42");
        let r = id.redact(RedactionLevel::Cleartext, None);
        assert_eq!(r, RedactedValue::Mask);
    }

    #[test]
    fn telco_class_security_association_denies_cleartext() {
        // SPI is mapped to SecurityAssociation -> SecuritySecret.
        let id = TelcoIdentifier::new(IdentifierType::Spi, "0x9abcdef0");
        let r = id.redact(RedactionLevel::Cleartext, None);
        assert_eq!(r, RedactedValue::Mask);
    }

    #[test]
    fn telco_identifier_display_never_leaks_value() {
        let id = TelcoIdentifier::new(IdentifierType::Imsi, "208950000000001");
        let debug = format!("{id:?}");
        let display = format!("{id}");
        assert!(!debug.contains("208950000000001"));
        assert!(!display.contains("208950000000001"));
    }
}
