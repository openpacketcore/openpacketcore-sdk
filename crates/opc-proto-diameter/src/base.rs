//! RFC 6733 base Diameter dictionary skeleton.
//!
//! The base feature provides metadata for common messages and AVPs needed by
//! later codec and peer-helper work. The entries are dictionary scaffolding and
//! are not yet a complete conformance corpus.

use opc_protocol::SpecRef;

use crate::dictionary::{
    ApplicationDefinition, AvpCardinality, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey,
    CommandAvpRule, CommandDefinition, CommandKind, Dictionary,
};
use crate::{ApplicationId, AvpCode, CommandCode};

/// Diameter Common Messages application identifier.
pub const APPLICATION_ID_COMMON_MESSAGES: ApplicationId = ApplicationId::new(0);
/// Diameter Relay Application identifier advertised by relay agents.
pub const APPLICATION_ID_RELAY: ApplicationId = ApplicationId::new(u32::MAX);
/// Capabilities-Exchange command code.
pub const COMMAND_CAPABILITIES_EXCHANGE: CommandCode = CommandCode::new(257);
/// Device-Watchdog command code.
pub const COMMAND_DEVICE_WATCHDOG: CommandCode = CommandCode::new(280);
/// Disconnect-Peer command code.
pub const COMMAND_DISCONNECT_PEER: CommandCode = CommandCode::new(282);

/// User-Name AVP code.
pub const AVP_USER_NAME: AvpCode = AvpCode::new(1);
/// Proxy-State AVP code.
pub const AVP_PROXY_STATE: AvpCode = AvpCode::new(33);
/// Host-IP-Address AVP code.
pub const AVP_HOST_IP_ADDRESS: AvpCode = AvpCode::new(257);
/// Auth-Application-Id AVP code.
pub const AVP_AUTH_APPLICATION_ID: AvpCode = AvpCode::new(258);
/// Acct-Application-Id AVP code.
pub const AVP_ACCT_APPLICATION_ID: AvpCode = AvpCode::new(259);
/// Vendor-Specific-Application-Id AVP code.
pub const AVP_VENDOR_SPECIFIC_APPLICATION_ID: AvpCode = AvpCode::new(260);
/// Session-Id AVP code.
pub const AVP_SESSION_ID: AvpCode = AvpCode::new(263);
/// Origin-Host AVP code.
pub const AVP_ORIGIN_HOST: AvpCode = AvpCode::new(264);
/// Supported-Vendor-Id AVP code.
pub const AVP_SUPPORTED_VENDOR_ID: AvpCode = AvpCode::new(265);
/// Vendor-Id AVP code.
pub const AVP_VENDOR_ID: AvpCode = AvpCode::new(266);
/// Firmware-Revision AVP code.
pub const AVP_FIRMWARE_REVISION: AvpCode = AvpCode::new(267);
/// Result-Code AVP code.
pub const AVP_RESULT_CODE: AvpCode = AvpCode::new(268);
/// Product-Name AVP code.
pub const AVP_PRODUCT_NAME: AvpCode = AvpCode::new(269);
/// Disconnect-Cause AVP code.
pub const AVP_DISCONNECT_CAUSE: AvpCode = AvpCode::new(273);
/// Origin-State-Id AVP code.
pub const AVP_ORIGIN_STATE_ID: AvpCode = AvpCode::new(278);
/// Failed-AVP AVP code.
pub const AVP_FAILED_AVP: AvpCode = AvpCode::new(279);
/// Proxy-Host AVP code.
pub const AVP_PROXY_HOST: AvpCode = AvpCode::new(280);
/// Error-Message AVP code.
pub const AVP_ERROR_MESSAGE: AvpCode = AvpCode::new(281);
/// Route-Record AVP code.
pub const AVP_ROUTE_RECORD: AvpCode = AvpCode::new(282);
/// Destination-Realm AVP code.
pub const AVP_DESTINATION_REALM: AvpCode = AvpCode::new(283);
/// Proxy-Info AVP code.
pub const AVP_PROXY_INFO: AvpCode = AvpCode::new(284);
/// Destination-Host AVP code.
pub const AVP_DESTINATION_HOST: AvpCode = AvpCode::new(293);
/// Error-Reporting-Host AVP code.
pub const AVP_ERROR_REPORTING_HOST: AvpCode = AvpCode::new(294);
/// Origin-Realm AVP code.
pub const AVP_ORIGIN_REALM: AvpCode = AvpCode::new(296);
/// Experimental-Result AVP code.
pub const AVP_EXPERIMENTAL_RESULT: AvpCode = AvpCode::new(297);
/// Experimental-Result-Code AVP code.
pub const AVP_EXPERIMENTAL_RESULT_CODE: AvpCode = AvpCode::new(298);
/// Inband-Security-Id AVP code.
pub const AVP_INBAND_SECURITY_ID: AvpCode = AvpCode::new(299);

/// Diameter success result code.
pub const RESULT_CODE_DIAMETER_SUCCESS: u32 = 2001;
/// Command unsupported protocol-error result code.
pub const RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED: u32 = 3001;
/// Application unsupported protocol-error result code.
pub const RESULT_CODE_DIAMETER_APPLICATION_UNSUPPORTED: u32 = 3007;
/// Invalid Diameter header bits protocol-error result code.
pub const RESULT_CODE_DIAMETER_INVALID_HDR_BITS: u32 = 3008;
/// Invalid AVP flag bits protocol-error result code.
pub const RESULT_CODE_DIAMETER_INVALID_AVP_BITS: u32 = 3009;
/// Unsupported mandatory AVP permanent-failure result code.
pub const RESULT_CODE_DIAMETER_AVP_UNSUPPORTED: u32 = 5001;
/// Invalid AVP value permanent-failure result code.
pub const RESULT_CODE_DIAMETER_INVALID_AVP_VALUE: u32 = 5004;
/// Missing mandatory AVP permanent-failure result code.
pub const RESULT_CODE_DIAMETER_MISSING_AVP: u32 = 5005;
/// Forbidden AVP permanent-failure result code.
pub const RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED: u32 = 5008;
/// Excess AVP occurrence permanent-failure result code.
pub const RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES: u32 = 5009;
/// No common application permanent-failure result code.
pub const RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION: u32 = 5010;
/// Unsupported Diameter version permanent-failure result code.
pub const RESULT_CODE_DIAMETER_UNSUPPORTED_VERSION: u32 = 5011;
/// Invalid reserved or otherwise incorrect Diameter header bit permanent-failure result code.
pub const RESULT_CODE_DIAMETER_INVALID_BIT_IN_HEADER: u32 = 5013;
/// Invalid AVP length permanent-failure result code.
pub const RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH: u32 = 5014;
/// Inband-Security-Id value for no in-band security.
pub const INBAND_SECURITY_ID_NO_INBAND_SECURITY: u32 = 0;
/// Inband-Security-Id value for TLS.
pub const INBAND_SECURITY_ID_TLS: u32 = 1;

const BASE_APPLICATIONS: [ApplicationDefinition; 1] = [ApplicationDefinition::new(
    APPLICATION_ID_COMMON_MESSAGES,
    "Diameter Common Messages",
    None,
    SpecRef::new("ietf", "RFC6733", "3"),
)];

// RFC 6733 sections 5.3.1 and 5.3.2 use the same explicit repeatable
// capability fields for CER and CEA. The trailing extension AVP wildcard is
// intentionally not modeled as blanket repeatability: an extension needs its
// own trusted command profile before it can bypass duplicate rejection.
const CAPABILITIES_EXCHANGE_REPEATABLE_AVP_RULES: [CommandAvpRule; 6] = [
    CommandAvpRule::new(
        AvpKey::ietf(AVP_HOST_IP_ADDRESS),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_SUPPORTED_VENDOR_ID),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_AUTH_APPLICATION_ID),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_INBAND_SECURITY_ID),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_ACCT_APPLICATION_ID),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID),
        AvpCardinality::ZeroOrMore,
    ),
];

const PROXY_INFO_AVP_RULES: [CommandAvpRule; 2] = [
    CommandAvpRule::new(AvpKey::ietf(AVP_PROXY_HOST), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_PROXY_STATE), AvpCardinality::ZeroOrOne),
];

const BASE_COMMANDS: [CommandDefinition; 6] = [
    CommandDefinition::new(
        COMMAND_CAPABILITIES_EXCHANGE,
        "Capabilities-Exchange-Request",
        CommandKind::Request,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.3.1"),
    )
    .with_avp_rules(&CAPABILITIES_EXCHANGE_REPEATABLE_AVP_RULES),
    CommandDefinition::new(
        COMMAND_CAPABILITIES_EXCHANGE,
        "Capabilities-Exchange-Answer",
        CommandKind::Answer,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.3.2"),
    )
    .with_avp_rules(&CAPABILITIES_EXCHANGE_REPEATABLE_AVP_RULES),
    CommandDefinition::new(
        COMMAND_DEVICE_WATCHDOG,
        "Device-Watchdog-Request",
        CommandKind::Request,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.5.1"),
    ),
    CommandDefinition::new(
        COMMAND_DEVICE_WATCHDOG,
        "Device-Watchdog-Answer",
        CommandKind::Answer,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.5.2"),
    ),
    CommandDefinition::new(
        COMMAND_DISCONNECT_PEER,
        "Disconnect-Peer-Request",
        CommandKind::Request,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.4.1"),
    ),
    CommandDefinition::new(
        COMMAND_DISCONNECT_PEER,
        "Disconnect-Peer-Answer",
        CommandKind::Answer,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.4.2"),
    ),
];

const BASE_AVPS: [AvpDefinition; 27] = [
    AvpDefinition::new(
        AvpKey::ietf(AVP_USER_NAME),
        "User-Name",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "8.14"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_PROXY_STATE),
        "Proxy-State",
        AvpDataType::OctetString,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.7.4"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_HOST_IP_ADDRESS),
        "Host-IP-Address",
        AvpDataType::Address,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "5.3.5"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_AUTH_APPLICATION_ID),
        "Auth-Application-Id",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.8"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ACCT_APPLICATION_ID),
        "Acct-Application-Id",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.9"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID),
        "Vendor-Specific-Application-Id",
        AvpDataType::Grouped,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.11"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SESSION_ID),
        "Session-Id",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "8.8"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ORIGIN_HOST),
        "Origin-Host",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SUPPORTED_VENDOR_ID),
        "Supported-Vendor-Id",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "5.3.6"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_VENDOR_ID),
        "Vendor-Id",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "5.3.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_FIRMWARE_REVISION),
        "Firmware-Revision",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_must_not_set_m(),
        SpecRef::new("ietf", "RFC6733", "5.3.4"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_RESULT_CODE),
        "Result-Code",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "7.1"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_PRODUCT_NAME),
        "Product-Name",
        AvpDataType::Utf8String,
        AvpFlagRules::base_must_not_set_m(),
        SpecRef::new("ietf", "RFC6733", "5.3.7"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_DISCONNECT_CAUSE),
        "Disconnect-Cause",
        AvpDataType::Enumerated,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "5.4.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ORIGIN_STATE_ID),
        "Origin-State-Id",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "8.16"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_FAILED_AVP),
        "Failed-AVP",
        AvpDataType::Grouped,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "7.5"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_PROXY_HOST),
        "Proxy-Host",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.7.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ERROR_MESSAGE),
        "Error-Message",
        AvpDataType::Utf8String,
        AvpFlagRules::base_must_not_set_m(),
        SpecRef::new("ietf", "RFC6733", "7.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ROUTE_RECORD),
        "Route-Record",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.7.1"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_DESTINATION_REALM),
        "Destination-Realm",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.6"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_PROXY_INFO),
        "Proxy-Info",
        AvpDataType::Grouped,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.7.2"),
    )
    .with_grouped_avp_rules(&PROXY_INFO_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_DESTINATION_HOST),
        "Destination-Host",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.5"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ERROR_REPORTING_HOST),
        "Error-Reporting-Host",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_must_not_set_m(),
        SpecRef::new("ietf", "RFC6733", "7.4"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ORIGIN_REALM),
        "Origin-Realm",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.4"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_EXPERIMENTAL_RESULT),
        "Experimental-Result",
        AvpDataType::Grouped,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "7.6"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_EXPERIMENTAL_RESULT_CODE),
        "Experimental-Result-Code",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "7.7"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_INBAND_SECURITY_ID),
        "Inband-Security-Id",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.10"),
    ),
];

/// Static RFC 6733 base dictionary scaffold.
pub static BASE_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-base-rfc6733-scaffold",
    &BASE_APPLICATIONS,
    &BASE_COMMANDS,
    &BASE_AVPS,
);

/// Return the static RFC 6733 base dictionary scaffold.
pub const fn dictionary() -> &'static Dictionary {
    &BASE_DICTIONARY
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::{CommandKind, FlagRequirement};

    #[test]
    fn base_dictionary_contains_peer_commands() {
        let dictionary = dictionary();
        assert!(dictionary
            .find_command(
                APPLICATION_ID_COMMON_MESSAGES,
                COMMAND_CAPABILITIES_EXCHANGE,
                CommandKind::Request,
            )
            .is_some());
        assert!(dictionary
            .find_command(
                APPLICATION_ID_COMMON_MESSAGES,
                COMMAND_DEVICE_WATCHDOG,
                CommandKind::Answer,
            )
            .is_some());
    }

    #[test]
    fn capabilities_exchange_declares_only_rfc_repeatable_avps() {
        let repeatable = [
            AVP_HOST_IP_ADDRESS,
            AVP_SUPPORTED_VENDOR_ID,
            AVP_AUTH_APPLICATION_ID,
            AVP_INBAND_SECURITY_ID,
            AVP_ACCT_APPLICATION_ID,
            AVP_VENDOR_SPECIFIC_APPLICATION_ID,
        ];
        let singletons = [
            AVP_ORIGIN_HOST,
            AVP_ORIGIN_REALM,
            AVP_VENDOR_ID,
            AVP_PRODUCT_NAME,
            AVP_RESULT_CODE,
            AVP_FAILED_AVP,
        ];

        for kind in [CommandKind::Request, CommandKind::Answer] {
            let command = dictionary()
                .find_command(
                    APPLICATION_ID_COMMON_MESSAGES,
                    COMMAND_CAPABILITIES_EXCHANGE,
                    kind,
                )
                .unwrap_or_else(|| panic!("capabilities command missing for {kind:?}"));
            assert_eq!(command.avp_rules().len(), repeatable.len());
            for code in repeatable {
                assert!(
                    command.allows_multiple(AvpKey::ietf(code)),
                    "{kind:?} must allow AVP {} to repeat",
                    code.get()
                );
            }
            for code in singletons {
                assert!(
                    !command.allows_multiple(AvpKey::ietf(code)),
                    "{kind:?} must keep AVP {} singleton",
                    code.get()
                );
            }
        }
    }

    #[test]
    fn watchdog_and_disconnect_commands_declare_no_repeatable_base_avps() {
        for code in [COMMAND_DEVICE_WATCHDOG, COMMAND_DISCONNECT_PEER] {
            for kind in [CommandKind::Request, CommandKind::Answer] {
                let command = dictionary()
                    .find_command(APPLICATION_ID_COMMON_MESSAGES, code, kind)
                    .unwrap_or_else(|| panic!("base command {} missing for {kind:?}", code.get()));
                assert!(
                    command.avp_rules().is_empty(),
                    "base command {} {kind:?} must retain singleton known AVPs",
                    code.get()
                );
            }
        }
    }

    #[test]
    fn base_dictionary_contains_origin_host() {
        let dictionary = dictionary();
        let origin_host = dictionary.find_avp(AvpKey::ietf(AVP_ORIGIN_HOST));
        assert!(matches!(origin_host, Some(definition) if definition.name() == "Origin-Host"));
    }

    #[test]
    fn base_dictionary_contains_normative_proxy_routing_definitions() {
        for (code, name, data_type) in [
            (AVP_PROXY_STATE, "Proxy-State", AvpDataType::OctetString),
            (AVP_PROXY_HOST, "Proxy-Host", AvpDataType::DiameterIdentity),
            (
                AVP_ROUTE_RECORD,
                "Route-Record",
                AvpDataType::DiameterIdentity,
            ),
            (AVP_PROXY_INFO, "Proxy-Info", AvpDataType::Grouped),
        ] {
            let definition = dictionary()
                .find_avp(AvpKey::ietf(code))
                .unwrap_or_else(|| panic!("{name} missing from base dictionary"));
            assert_eq!(definition.name(), name);
            assert_eq!(definition.data_type(), data_type);
            assert_eq!(
                definition.flags(),
                AvpFlagRules::base_mandatory(),
                "{name} must use RFC 6733 M=1, V=0, P=0 flags"
            );
        }
    }

    /// Regression test for RFC 6733 §4.5 M-bit flag rules.
    ///
    /// User-Name is the only one of these four base AVPs whose M-bit must be set;
    /// the other three must not set the M-bit.
    #[test]
    fn base_dictionary_user_name_requires_m_bit() {
        let dictionary = dictionary();
        let user_name = match dictionary.find_avp(AvpKey::ietf(AVP_USER_NAME)) {
            Some(definition) => definition,
            None => panic!("User-Name missing from base dictionary"),
        };
        assert_eq!(user_name.name(), "User-Name");
        let flags = user_name.flags();
        assert_eq!(flags.vendor(), FlagRequirement::MustBeUnset);
        assert_eq!(flags.mandatory(), FlagRequirement::MustBeSet);
        assert_eq!(flags.protected(), FlagRequirement::MustBeUnset);
    }

    /// Regression test for RFC 6733 §4.5 M-bit flag rules.
    ///
    /// Product-Name, Error-Message, and Error-Reporting-Host must not set the
    /// M-bit in base Diameter messages.
    #[test]
    fn base_dictionary_avps_must_not_set_m_bit() {
        let dictionary = dictionary();
        for (code, name) in [
            (AVP_PRODUCT_NAME, "Product-Name"),
            (AVP_ERROR_MESSAGE, "Error-Message"),
            (AVP_ERROR_REPORTING_HOST, "Error-Reporting-Host"),
        ] {
            let definition = dictionary
                .find_avp(AvpKey::ietf(code))
                .unwrap_or_else(|| panic!("{name} missing from base dictionary"));
            assert_eq!(definition.name(), name);
            let flags = definition.flags();
            assert_eq!(
                flags.vendor(),
                FlagRequirement::MustBeUnset,
                "{name} vendor bit must not be set"
            );
            assert_eq!(
                flags.mandatory(),
                FlagRequirement::MustBeUnset,
                "{name} M-bit must not be set"
            );
            assert_eq!(
                flags.protected(),
                FlagRequirement::MustBeUnset,
                "{name} protected bit must not be set"
            );
        }
    }
}
