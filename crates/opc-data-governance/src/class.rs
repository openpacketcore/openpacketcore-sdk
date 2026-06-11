use serde::{Deserialize, Serialize};
use std::fmt;

/// Ten-class data taxonomy from RFC 010 §4.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataClass {
    Public,
    Operational,
    NetworkSensitive,
    SubscriberId,
    SubscriberSession,
    SecuritySecret,
    ChargingRecord,
    LawfulIntercept,
    AnalyticsSensitive,
    AuditRegulated,
}

impl DataClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::NetworkSensitive => "network-sensitive",
            Self::SubscriberId => "subscriber-id",
            Self::SubscriberSession => "subscriber-session",
            Self::SecuritySecret => "security-secret",
            Self::ChargingRecord => "charging-record",
            Self::LawfulIntercept => "lawful-intercept",
            Self::AnalyticsSensitive => "analytics-sensitive",
            Self::AuditRegulated => "audit-regulated",
        }
    }

    /// Whether this class permits cleartext rendering.
    ///
    /// Per RFC 010 §6, cleartext is forbidden for `security-secret` and
    /// restricted for `lawful-intercept`. All other classes may show cleartext
    /// only by explicit policy.
    pub const fn allows_cleartext(self) -> bool {
        !matches!(self, Self::SecuritySecret | Self::LawfulIntercept)
    }

    /// Whether this class is a subscriber identifier type that must always be
    /// redacted in output.
    pub const fn is_subscriber_identifier(self) -> bool {
        matches!(self, Self::SubscriberId)
    }
}

impl fmt::Display for DataClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical identifier types used in digest and redaction contexts.
///
/// This is not an exhaustive 3GPP enumeration; it covers the identifiers that
/// RFC 010 §5 explicitly requires to be digested or redacted.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentifierType {
    Supi,
    Gpsi,
    Msisdn,
    Pei,
    Imsi,
    Guti,
    IpAddress,
    Dnn,
}

impl IdentifierType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supi => "supi",
            Self::Gpsi => "gpsi",
            Self::Msisdn => "msisdn",
            Self::Pei => "pei",
            Self::Imsi => "imsi",
            Self::Guti => "guti",
            Self::IpAddress => "ip-address",
            Self::Dnn => "dnn",
        }
    }
}

impl fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_class_display_matches_kebab_name() {
        assert_eq!(DataClass::Public.to_string(), "public");
        assert_eq!(DataClass::SubscriberId.to_string(), "subscriber-id");
        assert_eq!(DataClass::LawfulIntercept.to_string(), "lawful-intercept");
    }

    #[test]
    fn subscriber_id_class_is_flagged_correctly() {
        assert!(DataClass::SubscriberId.is_subscriber_identifier());
        assert!(!DataClass::Public.is_subscriber_identifier());
        assert!(!DataClass::SecuritySecret.is_subscriber_identifier());
    }

    #[test]
    fn security_secret_and_lawful_intercept_deny_cleartext() {
        assert!(!DataClass::SecuritySecret.allows_cleartext());
        assert!(!DataClass::LawfulIntercept.allows_cleartext());
        assert!(DataClass::Public.allows_cleartext());
        assert!(DataClass::Operational.allows_cleartext());
        assert!(DataClass::SubscriberId.allows_cleartext());
    }

    #[test]
    fn identifier_type_display_matches_kebab_name() {
        assert_eq!(IdentifierType::Supi.to_string(), "supi");
        assert_eq!(IdentifierType::Msisdn.to_string(), "msisdn");
        assert_eq!(IdentifierType::IpAddress.to_string(), "ip-address");
    }
}
