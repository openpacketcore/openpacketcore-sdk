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
/// RFC 010 explicitly requires to be digested or redacted, plus additional
/// telco-specific identifiers used across the OpenPacketCore SDK.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentifierType {
    Supi,
    Suci,
    Gpsi,
    Msisdn,
    Pei,
    Imsi,
    Guti,
    #[serde(rename = "5g-tmsi")]
    FiveGTmsi,
    IpAddress,
    MacAddress,
    Dnn,
    Imei,
    Imeisv,
    Nai,
    Sip,
    Apn,
    Teid,
    Spi,
    DiameterSessionId,
    Tai,
    Ecgi,
    Cgi,
    LiId,
    LiWarrantId,
    LiCorrelationId,
    DeliveryAddress,
}

impl IdentifierType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supi => "supi",
            Self::Suci => "suci",
            Self::Gpsi => "gpsi",
            Self::Msisdn => "msisdn",
            Self::Pei => "pei",
            Self::Imsi => "imsi",
            Self::Guti => "guti",
            Self::FiveGTmsi => "5g-tmsi",
            Self::IpAddress => "ip-address",
            Self::MacAddress => "mac-address",
            Self::Dnn => "dnn",
            Self::Imei => "imei",
            Self::Imeisv => "imeisv",
            Self::Nai => "nai",
            Self::Sip => "sip",
            Self::Apn => "apn",
            Self::Teid => "teid",
            Self::Spi => "spi",
            Self::DiameterSessionId => "diameter-session-id",
            Self::Tai => "tai",
            Self::Ecgi => "ecgi",
            Self::Cgi => "cgi",
            Self::LiId => "li-id",
            Self::LiWarrantId => "li-warrant-id",
            Self::LiCorrelationId => "li-correlation-id",
            Self::DeliveryAddress => "delivery-address",
        }
    }

    /// Returns the telco class for this identifier, if it is a telco identifier.
    pub const fn telco_class(self) -> Option<TelcoIdentifierClass> {
        match self {
            Self::Imsi
            | Self::Msisdn
            | Self::Imei
            | Self::Imeisv
            | Self::Nai
            | Self::Supi
            | Self::Suci
            | Self::Gpsi
            | Self::Guti
            | Self::FiveGTmsi
            | Self::Pei => Some(TelcoIdentifierClass::Subscriber),
            Self::Teid
            | Self::IpAddress
            | Self::MacAddress
            | Self::Tai
            | Self::Ecgi
            | Self::Cgi => Some(TelcoIdentifierClass::SessionEndpoint),
            Self::Spi => Some(TelcoIdentifierClass::SecurityAssociation),
            Self::Apn | Self::Dnn | Self::Sip | Self::DiameterSessionId => {
                Some(TelcoIdentifierClass::Application)
            }
            Self::LiId | Self::LiWarrantId | Self::LiCorrelationId | Self::DeliveryAddress => {
                Some(TelcoIdentifierClass::LawfulIntercept)
            }
        }
    }

    /// Returns `true` if this identifier type is a telco identifier.
    pub const fn is_telco(self) -> bool {
        self.telco_class().is_some()
    }
}

impl fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Privacy-relevant telco identifier classes.
///
/// Each class groups identifiers that share the same redaction policy and
/// operational sensitivity.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelcoIdentifierClass {
    Subscriber,
    SessionEndpoint,
    SecurityAssociation,
    Application,
    LawfulIntercept,
}

impl TelcoIdentifierClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subscriber => "subscriber",
            Self::SessionEndpoint => "session-endpoint",
            Self::SecurityAssociation => "security-association",
            Self::Application => "application",
            Self::LawfulIntercept => "lawful-intercept",
        }
    }

    /// Returns the default [`DataClass`] for this telco identifier class.
    pub const fn default_data_class(self) -> DataClass {
        match self {
            Self::Subscriber => DataClass::SubscriberId,
            Self::SessionEndpoint => DataClass::SubscriberSession,
            Self::SecurityAssociation => DataClass::SecuritySecret,
            Self::Application => DataClass::NetworkSensitive,
            Self::LawfulIntercept => DataClass::LawfulIntercept,
        }
    }
}

impl fmt::Display for TelcoIdentifierClass {
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
        assert_eq!(IdentifierType::Suci.to_string(), "suci");
        assert_eq!(IdentifierType::Msisdn.to_string(), "msisdn");
        assert_eq!(IdentifierType::FiveGTmsi.to_string(), "5g-tmsi");
        assert_eq!(IdentifierType::IpAddress.to_string(), "ip-address");
        assert_eq!(IdentifierType::MacAddress.to_string(), "mac-address");
        assert_eq!(IdentifierType::Imeisv.to_string(), "imeisv");
        assert_eq!(
            IdentifierType::DiameterSessionId.to_string(),
            "diameter-session-id"
        );
        assert_eq!(IdentifierType::Tai.to_string(), "tai");
        assert_eq!(IdentifierType::Ecgi.to_string(), "ecgi");
        assert_eq!(IdentifierType::Cgi.to_string(), "cgi");
        assert_eq!(IdentifierType::LiId.to_string(), "li-id");
        assert_eq!(IdentifierType::LiWarrantId.to_string(), "li-warrant-id");
        assert_eq!(
            IdentifierType::LiCorrelationId.to_string(),
            "li-correlation-id"
        );
        assert_eq!(
            IdentifierType::DeliveryAddress.to_string(),
            "delivery-address"
        );
    }

    #[test]
    fn telco_identifier_classes_cover_required_identifiers() {
        let all_required_identifiers = [
            IdentifierType::Supi,
            IdentifierType::Suci,
            IdentifierType::Gpsi,
            IdentifierType::Msisdn,
            IdentifierType::Pei,
            IdentifierType::Imsi,
            IdentifierType::Guti,
            IdentifierType::FiveGTmsi,
            IdentifierType::IpAddress,
            IdentifierType::MacAddress,
            IdentifierType::Dnn,
            IdentifierType::Imei,
            IdentifierType::Imeisv,
            IdentifierType::Nai,
            IdentifierType::Sip,
            IdentifierType::Apn,
            IdentifierType::Teid,
            IdentifierType::Spi,
            IdentifierType::DiameterSessionId,
            IdentifierType::Tai,
            IdentifierType::Ecgi,
            IdentifierType::Cgi,
            IdentifierType::LiId,
            IdentifierType::LiWarrantId,
            IdentifierType::LiCorrelationId,
            IdentifierType::DeliveryAddress,
        ];
        for id_type in all_required_identifiers {
            assert!(
                id_type.telco_class().is_some(),
                "{id_type} must have a telco class"
            );
        }

        // IMSI/MSISDN/IMEI/NAI/SIP/APN/TEID/SPI/Diameter Session-Id/LI ID
        assert_eq!(
            IdentifierType::Imsi.telco_class(),
            Some(TelcoIdentifierClass::Subscriber)
        );
        assert_eq!(
            IdentifierType::Msisdn.telco_class(),
            Some(TelcoIdentifierClass::Subscriber)
        );
        assert_eq!(
            IdentifierType::Imei.telco_class(),
            Some(TelcoIdentifierClass::Subscriber)
        );
        assert_eq!(
            IdentifierType::Imeisv.telco_class(),
            Some(TelcoIdentifierClass::Subscriber)
        );
        assert_eq!(
            IdentifierType::Suci.telco_class(),
            Some(TelcoIdentifierClass::Subscriber)
        );
        assert_eq!(
            IdentifierType::FiveGTmsi.telco_class(),
            Some(TelcoIdentifierClass::Subscriber)
        );
        assert_eq!(
            IdentifierType::Nai.telco_class(),
            Some(TelcoIdentifierClass::Subscriber)
        );
        assert_eq!(
            IdentifierType::Sip.telco_class(),
            Some(TelcoIdentifierClass::Application)
        );
        assert_eq!(
            IdentifierType::Apn.telco_class(),
            Some(TelcoIdentifierClass::Application)
        );
        assert_eq!(
            IdentifierType::Teid.telco_class(),
            Some(TelcoIdentifierClass::SessionEndpoint)
        );
        assert_eq!(
            IdentifierType::IpAddress.telco_class(),
            Some(TelcoIdentifierClass::SessionEndpoint)
        );
        assert_eq!(
            IdentifierType::MacAddress.telco_class(),
            Some(TelcoIdentifierClass::SessionEndpoint)
        );
        assert_eq!(
            IdentifierType::Tai.telco_class(),
            Some(TelcoIdentifierClass::SessionEndpoint)
        );
        assert_eq!(
            IdentifierType::Ecgi.telco_class(),
            Some(TelcoIdentifierClass::SessionEndpoint)
        );
        assert_eq!(
            IdentifierType::Cgi.telco_class(),
            Some(TelcoIdentifierClass::SessionEndpoint)
        );
        assert_eq!(
            IdentifierType::Spi.telco_class(),
            Some(TelcoIdentifierClass::SecurityAssociation)
        );
        assert_eq!(
            IdentifierType::DiameterSessionId.telco_class(),
            Some(TelcoIdentifierClass::Application)
        );
        assert_eq!(
            IdentifierType::LiId.telco_class(),
            Some(TelcoIdentifierClass::LawfulIntercept)
        );
        assert_eq!(
            IdentifierType::LiWarrantId.telco_class(),
            Some(TelcoIdentifierClass::LawfulIntercept)
        );
        assert_eq!(
            IdentifierType::LiCorrelationId.telco_class(),
            Some(TelcoIdentifierClass::LawfulIntercept)
        );
        assert_eq!(
            IdentifierType::DeliveryAddress.telco_class(),
            Some(TelcoIdentifierClass::LawfulIntercept)
        );
        // DNN is the 5G equivalent of APN and belongs to the same telco class.
        assert_eq!(
            IdentifierType::Dnn.telco_class(),
            Some(TelcoIdentifierClass::Application)
        );
        assert!(IdentifierType::Dnn.is_telco());
    }

    #[test]
    fn telco_class_default_data_class_is_sensible() {
        assert_eq!(
            TelcoIdentifierClass::Subscriber.default_data_class(),
            DataClass::SubscriberId
        );
        assert_eq!(
            IdentifierType::IpAddress
                .telco_class()
                .map(TelcoIdentifierClass::default_data_class),
            Some(DataClass::SubscriberSession)
        );
        assert_eq!(
            TelcoIdentifierClass::LawfulIntercept.default_data_class(),
            DataClass::LawfulIntercept
        );
    }
}
