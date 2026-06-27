//! RFC 6733 base Diameter dictionary skeleton.
//!
//! The base feature provides metadata for common messages and AVPs needed by
//! later codec and peer-helper work. The entries are dictionary scaffolding and
//! are not yet a complete conformance corpus.

use opc_protocol::SpecRef;

use crate::dictionary::{
    ApplicationDefinition, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandDefinition,
    CommandKind, Dictionary,
};
use crate::{ApplicationId, AvpCode, CommandCode};

/// Diameter Common Messages application identifier.
pub const APPLICATION_ID_COMMON_MESSAGES: ApplicationId = ApplicationId::new(0);
/// Capabilities-Exchange command code.
pub const COMMAND_CAPABILITIES_EXCHANGE: CommandCode = CommandCode::new(257);
/// Device-Watchdog command code.
pub const COMMAND_DEVICE_WATCHDOG: CommandCode = CommandCode::new(280);
/// Disconnect-Peer command code.
pub const COMMAND_DISCONNECT_PEER: CommandCode = CommandCode::new(282);

const AVP_USER_NAME: AvpCode = AvpCode::new(1);
const AVP_HOST_IP_ADDRESS: AvpCode = AvpCode::new(257);
const AVP_AUTH_APPLICATION_ID: AvpCode = AvpCode::new(258);
const AVP_ACCT_APPLICATION_ID: AvpCode = AvpCode::new(259);
const AVP_VENDOR_SPECIFIC_APPLICATION_ID: AvpCode = AvpCode::new(260);
const AVP_SESSION_ID: AvpCode = AvpCode::new(263);
const AVP_ORIGIN_HOST: AvpCode = AvpCode::new(264);
const AVP_SUPPORTED_VENDOR_ID: AvpCode = AvpCode::new(265);
const AVP_VENDOR_ID: AvpCode = AvpCode::new(266);
const AVP_FIRMWARE_REVISION: AvpCode = AvpCode::new(267);
const AVP_RESULT_CODE: AvpCode = AvpCode::new(268);
const AVP_PRODUCT_NAME: AvpCode = AvpCode::new(269);
const AVP_DISCONNECT_CAUSE: AvpCode = AvpCode::new(273);
const AVP_ORIGIN_STATE_ID: AvpCode = AvpCode::new(278);
const AVP_FAILED_AVP: AvpCode = AvpCode::new(279);
const AVP_ERROR_MESSAGE: AvpCode = AvpCode::new(281);
const AVP_DESTINATION_REALM: AvpCode = AvpCode::new(283);
const AVP_ERROR_REPORTING_HOST: AvpCode = AvpCode::new(294);
const AVP_DESTINATION_HOST: AvpCode = AvpCode::new(293);
const AVP_ORIGIN_REALM: AvpCode = AvpCode::new(296);
const AVP_EXPERIMENTAL_RESULT: AvpCode = AvpCode::new(297);
const AVP_EXPERIMENTAL_RESULT_CODE: AvpCode = AvpCode::new(298);
const AVP_INBAND_SECURITY_ID: AvpCode = AvpCode::new(299);

const BASE_APPLICATIONS: [ApplicationDefinition; 1] = [ApplicationDefinition::new(
    APPLICATION_ID_COMMON_MESSAGES,
    "Diameter Common Messages",
    None,
    SpecRef::new("ietf", "RFC6733", "3"),
)];

const BASE_COMMANDS: [CommandDefinition; 6] = [
    CommandDefinition::new(
        COMMAND_CAPABILITIES_EXCHANGE,
        "Capabilities-Exchange-Request",
        CommandKind::Request,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.3.1"),
    ),
    CommandDefinition::new(
        COMMAND_CAPABILITIES_EXCHANGE,
        "Capabilities-Exchange-Answer",
        CommandKind::Answer,
        APPLICATION_ID_COMMON_MESSAGES,
        false,
        SpecRef::new("ietf", "RFC6733", "5.3.2"),
    ),
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

const BASE_AVPS: [AvpDefinition; 23] = [
    AvpDefinition::new(
        AvpKey::ietf(AVP_USER_NAME),
        "User-Name",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "8.14"),
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
        AvpKey::ietf(AVP_ERROR_MESSAGE),
        "Error-Message",
        AvpDataType::Utf8String,
        AvpFlagRules::base_must_not_set_m(),
        SpecRef::new("ietf", "RFC6733", "7.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_DESTINATION_REALM),
        "Destination-Realm",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "6.6"),
    ),
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
            .find_command(COMMAND_CAPABILITIES_EXCHANGE, CommandKind::Request)
            .is_some());
        assert!(dictionary
            .find_command(COMMAND_DEVICE_WATCHDOG, CommandKind::Answer)
            .is_some());
    }

    #[test]
    fn base_dictionary_contains_origin_host() {
        let dictionary = dictionary();
        let origin_host = dictionary.find_avp(AvpKey::ietf(AVP_ORIGIN_HOST));
        assert!(matches!(origin_host, Some(definition) if definition.name() == "Origin-Host"));
    }

    /// Regression test for RFC 6733 §4.5 M-bit flag rules.
    ///
    /// User-Name is the only one of these four base AVPs whose M-bit must be set;
    /// the other three must not set the M-bit.
    #[test]
    fn base_dictionary_user_name_requires_m_bit() {
        let dictionary = dictionary();
        let user_name = dictionary
            .find_avp(AvpKey::ietf(AVP_USER_NAME))
            .expect("User-Name missing from base dictionary");
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
