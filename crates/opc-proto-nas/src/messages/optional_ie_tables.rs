//! Optional 5GMM IE framing, pinned to TS 24.501 V18.11.1 (Release 18).
//!
//! Bounds count the complete IE, including its identifier and length octets.
//! An open-ended `n` in a message table is capped by its u8/u16 length field.
//! Nested containers are opaque; these are the top-level message-content rows.

use super::OptionalIeFormat;
use crate::MmMessageType;

use OptionalIeFormat::{Type1, Type3, Type4, Type6};

#[derive(Debug, Clone, Copy)]
pub(super) struct OptionalIeDescriptor {
    pub iei: u8,
    pub format: OptionalIeFormat,
    pub min_len: usize,
    pub max_len: usize,
    pub section: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct OptionalIeTable {
    pub section: &'static str,
    pub entries: &'static [OptionalIeDescriptor],
}

const TLV_MAX: usize = 257;
const TLVE_MAX: usize = 65538;

const fn ie(
    iei: u8,
    format: OptionalIeFormat,
    min_len: usize,
    max_len: usize,
    section: &'static str,
) -> OptionalIeDescriptor {
    OptionalIeDescriptor {
        iei,
        format,
        min_len,
        max_len,
        section,
    }
}

/// Table 8.2.6.1.1: 42 optional elements.
const REGISTRATION_REQUEST: OptionalIeTable = OptionalIeTable {
    section: "8.2.6",
    entries: &[
        ie(0xc0, Type1, 1, 1, "9.11.3.32"),   // Non-current native NAS KSI
        ie(0x10, Type4, 3, 15, "9.11.3.1"),   // 5GMM capability
        ie(0x2e, Type4, 4, 10, "9.11.3.54"),  // UE security capability
        ie(0x2f, Type4, 4, 74, "9.11.3.37"),  // Requested NSSAI
        ie(0x52, Type3(6), 7, 7, "9.11.3.8"), // Last visited registered TAI
        ie(0x17, Type4, 4, 15, "9.11.3.48"),  // S1 UE network capability
        ie(0x40, Type4, 4, 34, "9.11.3.57"),  // Uplink data status
        ie(0x50, Type4, 4, 34, "9.11.3.44"),  // PDU session status
        ie(0xb0, Type1, 1, 1, "9.11.3.31"),   // MICO indication
        ie(0x2b, Type4, 3, 3, "9.11.3.56"),   // UE status
        ie(0x77, Type6, 14, 14, "9.11.3.4"),  // Additional GUTI
        ie(0x25, Type4, 4, 34, "9.11.3.13"),  // Allowed PDU session status
        ie(0x18, Type4, 3, 3, "9.11.3.55"),   // UE usage setting
        ie(0x51, Type4, 3, 3, "9.11.3.2A"),   // Requested DRX parameters
        ie(0x70, Type6, 4, TLVE_MAX, "9.11.3.24"), // EPS NAS message container
        ie(0x74, Type6, 3, 811, "9.11.3.29"), // LADN indication
        ie(0x80, Type1, 1, 1, "9.11.3.40"),   // Payload container type
        ie(0x7b, Type6, 4, 65538, "9.11.3.39"), // Payload container
        ie(0x90, Type1, 1, 1, "9.11.3.36"),   // Network slicing indication
        ie(0x53, Type4, 3, 3, "9.11.3.9A"),   // 5GS update type
        ie(0x41, Type4, 5, 5, "9.11.3.31C"),  // Mobile station classmark 2
        ie(0x42, Type4, 5, TLV_MAX, "9.11.3.51A"), // Supported codecs
        ie(0x71, Type6, 4, TLVE_MAX, "9.11.3.33"), // NAS message container
        ie(0x60, Type4, 4, 4, "9.11.3.23A"),  // EPS bearer context status
        ie(0x6e, Type4, 3, 4, "9.11.3.26A"),  // Requested extended DRX
        ie(0x6a, Type4, 3, 3, "9.11.2.5"),    // T3324
        ie(0x67, Type4, 3, TLV_MAX, "9.11.3.68"), // UE radio capability ID
        ie(0x35, Type4, 3, 42, "9.11.3.31B"), // Requested mapped NSSAI
        ie(0x48, Type4, 3, 3, "9.11.3.12A"),  // Additional information requested
        ie(0x1a, Type4, 3, TLV_MAX, "9.11.3.71"), // Requested WUS assistance
        ie(0xa0, Type1, 1, 1, "9.11.3.72"),   // N5GC indication
        ie(0x30, Type4, 3, 3, "9.11.3.73"),   // Requested NB-N1 mode DRX
        ie(0x29, Type4, 3, 3, "9.11.3.76"),   // UE request type
        ie(0x28, Type4, 3, 35, "9.11.3.77"),  // Paging restriction
        ie(0x72, Type6, 4, 65538, "9.11.2.10"), // Service-level-AA container
        ie(0x32, Type4, 8, 8, "9.11.3.79"),   // NID
        ie(0x16, Type4, 5, 5, "9.11.3.85"),   // UE determined PLMN with disaster condition
        ie(0x2a, Type4, 3, TLV_MAX, "9.11.3.80"), // Requested PEIPS assistance
        ie(0x3b, Type4, 3, 3, "9.11.2.5"),    // Requested T3512
        ie(0x3c, Type4, 3, 9, "9.11.2.20"),   // Unavailability information
        ie(0x3f, Type4, 3, 3, "9.11.3.102"),  // Non-3GPP path switching information
        ie(0x56, Type4, 3, 3, "9.11.3.104"),  // AUN3 indication
    ],
};

/// Table 8.2.7.1.1: 60 optional elements.
const REGISTRATION_ACCEPT: OptionalIeTable = OptionalIeTable {
    section: "8.2.7",
    entries: &[
        ie(0x77, Type6, 14, 14, "9.11.3.4"),         // 5G-GUTI
        ie(0x4a, Type4, 5, 47, "9.11.3.45"),         // Equivalent PLMNs
        ie(0x54, Type4, 9, 114, "9.11.3.9"),         // TAI list
        ie(0x15, Type4, 4, 74, "9.11.3.37"),         // Allowed NSSAI
        ie(0x11, Type4, 4, 42, "9.11.3.46"),         // Rejected NSSAI
        ie(0x31, Type4, 4, 146, "9.11.3.37"),        // Configured NSSAI
        ie(0x21, Type4, 3, 6, "9.11.3.5"),           // 5GS network feature support
        ie(0x50, Type4, 4, 34, "9.11.3.44"),         // PDU session status
        ie(0x26, Type4, 4, 34, "9.11.3.42"),         // PDU session reactivation result
        ie(0x72, Type6, 5, 515, "9.11.3.43"),        // Reactivation result error cause
        ie(0x79, Type6, 13, 1715, "9.11.3.30"),      // LADN information
        ie(0xb0, Type1, 1, 1, "9.11.3.31"),          // MICO indication
        ie(0x90, Type1, 1, 1, "9.11.3.36"),          // Network slicing indication
        ie(0x27, Type4, 6, 114, "9.11.3.49"),        // Service area list
        ie(0x5e, Type4, 3, 3, "9.11.2.5"),           // T3512
        ie(0x5d, Type4, 3, 3, "9.11.2.4"),           // Non-3GPP deregistration timer
        ie(0x16, Type4, 3, 3, "9.11.2.4"),           // T3502
        ie(0x34, Type4, 5, 50, "9.11.3.23"),         // Emergency number list
        ie(0x7a, Type6, 7, 65538, "9.11.3.26"),      // Extended emergency number list
        ie(0x73, Type6, 20, TLVE_MAX, "9.11.3.51"),  // SOR transparent container
        ie(0x78, Type6, 7, 1503, "9.11.2.2"),        // EAP message
        ie(0xa0, Type1, 1, 1, "9.11.3.37A"),         // NSSAI inclusion mode
        ie(0x76, Type6, 3, 8323, "9.11.3.38"),       // Operator-defined access categories
        ie(0x51, Type4, 3, 3, "9.11.3.2A"),          // Negotiated DRX parameters
        ie(0xd0, Type1, 1, 1, "9.11.3.36A"),         // Non-3GPP network policies
        ie(0x60, Type4, 4, 4, "9.11.3.23A"),         // EPS bearer context status
        ie(0x6e, Type4, 3, 4, "9.11.3.26A"),         // Negotiated extended DRX
        ie(0x6c, Type4, 3, 3, "9.11.2.5"),           // T3447
        ie(0x6b, Type4, 3, 3, "9.11.2.4"),           // T3448
        ie(0x6a, Type4, 3, 3, "9.11.2.5"),           // T3324
        ie(0x67, Type4, 3, TLV_MAX, "9.11.3.68"),    // UE radio capability ID
        ie(0xe0, Type1, 1, 1, "9.11.3.69"),          // Radio capability ID deletion indication
        ie(0x39, Type4, 4, 146, "9.11.3.37"),        // Pending NSSAI
        ie(0x74, Type6, 34, TLVE_MAX, "9.11.3.18C"), // Ciphering key data
        ie(0x75, Type6, 3, TLVE_MAX, "9.11.3.18A"),  // CAG information list
        ie(0x1b, Type4, 3, 3, "9.11.3.70"),          // Truncated 5G-S-TMSI configuration
        ie(0x1c, Type4, 3, TLV_MAX, "9.11.3.71"),    // Negotiated WUS assistance
        ie(0x29, Type4, 3, 3, "9.11.3.73"),          // Negotiated NB-N1 mode DRX
        ie(0x68, Type4, 5, 90, "9.11.3.75"),         // Extended rejected NSSAI
        ie(0x7b, Type6, 4, 65538, "9.11.2.10"),      // Service-level-AA container
        ie(0x33, Type4, 3, TLV_MAX, "9.11.3.80"),    // Negotiated PEIPS assistance
        ie(0x35, Type4, 3, 3, "9.11.3.81"),          // Additional request result
        ie(0x70, Type6, 7, 4099, "9.11.3.82"),       // NSSRG information
        ie(0x14, Type4, 4, 4, "9.11.3.84"),          // Disaster roaming wait range
        ie(0x2c, Type4, 4, 4, "9.11.3.84"),          // Disaster return wait range
        ie(0x13, Type4, 2, TLV_MAX, "9.11.3.83"),    // PLMNs for disaster condition
        ie(0x1d, Type4, 9, 114, "9.11.3.9"),         // Forbidden TAIs for roaming
        ie(0x1e, Type4, 9, 114, "9.11.3.9"),         // Forbidden TAIs for regional service
        ie(0x71, Type6, 3, TLVE_MAX, "9.11.3.86"),   // Extended CAG information list
        ie(0x7c, Type6, 9, 3143, "9.11.3.87"),       // NSAG information
        ie(0x3d, Type4, 11, 137, "9.11.3.92"),       // Equivalent SNPNs
        ie(0x32, Type4, 8, 8, "9.11.3.79"),          // NID
        ie(0x7d, Type6, 6, 65538, "9.11.3.98"),      // Registration accept type 6 IE container
        ie(0x4b, Type4, 3, 3, "9.11.3.95"),          // RAN timing synchronization
        ie(0x4c, Type4, 2, 146, "9.11.3.97"),        // Alternative NSSAI
        ie(0x4f, Type4, 3, 3, "9.11.2.5"),           // Maximum time offset
        ie(0x5b, Type4, 23, 257, "9.11.3.101"),      // S-NSSAI time validity
        ie(0x3c, Type4, 3, 6, "9.11.2.21"),          // Unavailability configuration
        ie(0x5c, Type4, 3, 257, "9.11.3.105"),       // Feature authorization indication
        ie(0x61, Type4, 5, 210, "9.11.3.108"),       // On-demand NSSAI
    ],
};

/// Table 8.2.25.1.1: 7 optional elements.
const SECURITY_MODE_COMMAND: OptionalIeTable = OptionalIeTable {
    section: "8.2.25",
    entries: &[
        ie(0xe0, Type1, 1, 1, "9.11.3.28"),       // IMEISV request
        ie(0x57, Type3(1), 2, 2, "9.11.3.25"),    // Selected EPS NAS algorithms
        ie(0x36, Type4, 3, 3, "9.11.3.12"),       // Additional 5G security information
        ie(0x78, Type6, 7, 1503, "9.11.2.2"),     // EAP message
        ie(0x38, Type4, 4, TLV_MAX, "9.11.3.10"), // ABBA
        ie(0x19, Type4, 4, 7, "9.11.3.48A"),      // Replayed S1 UE security capability
        ie(0x55, Type4, 36, 257, "9.11.3.107"),   // AUN3 device security key
    ],
};

/// Table 8.2.26.1.1: 3 optional elements.
const SECURITY_MODE_COMPLETE: OptionalIeTable = OptionalIeTable {
    section: "8.2.26",
    entries: &[
        ie(0x77, Type6, 12, 12, "9.11.3.4"),       // IMEISV
        ie(0x71, Type6, 4, TLVE_MAX, "9.11.3.33"), // NAS message container
        ie(0x78, Type6, 7, TLVE_MAX, "9.11.3.4"),  // Non-IMEISV PEI
    ],
};

/// Table 8.2.19.1.1: 44 optional elements.
const CONFIGURATION_UPDATE_COMMAND: OptionalIeTable = OptionalIeTable {
    section: "8.2.19",
    entries: &[
        ie(0xd0, Type1, 1, 1, "9.11.3.18"), // Configuration update indication
        ie(0x77, Type6, 14, 14, "9.11.3.4"), // 5G-GUTI
        ie(0x54, Type4, 9, 114, "9.11.3.9"), // TAI list
        ie(0x15, Type4, 4, 74, "9.11.3.37"), // Allowed NSSAI
        ie(0x27, Type4, 6, 114, "9.11.3.49"), // Service area list
        ie(0x43, Type4, 3, TLV_MAX, "9.11.3.35"), // Full network name
        ie(0x45, Type4, 3, TLV_MAX, "9.11.3.35"), // Short network name
        ie(0x46, Type3(1), 2, 2, "9.11.3.52"), // Local time zone
        ie(0x47, Type3(7), 8, 8, "9.11.3.53"), // Universal time and local time zone
        ie(0x49, Type4, 3, 3, "9.11.3.19"), // Network daylight saving time
        ie(0x79, Type6, 3, 1715, "9.11.3.30"), // LADN information
        ie(0xb0, Type1, 1, 1, "9.11.3.31"), // MICO indication
        ie(0x90, Type1, 1, 1, "9.11.3.36"), // Network slicing indication
        ie(0x31, Type4, 4, 146, "9.11.3.37"), // Configured NSSAI
        ie(0x11, Type4, 4, 42, "9.11.3.46"), // Rejected NSSAI
        ie(0x76, Type6, 3, 8323, "9.11.3.38"), // Operator-defined access categories
        ie(0xf0, Type1, 1, 1, "9.11.3.50A"), // SMS indication
        ie(0x6c, Type4, 3, 3, "9.11.2.5"),  // T3447
        ie(0x75, Type6, 3, TLVE_MAX, "9.11.3.18A"), // CAG information list
        ie(0x67, Type4, 3, TLV_MAX, "9.11.3.68"), // UE radio capability ID
        ie(0xa0, Type1, 1, 1, "9.11.3.69"), // Radio capability ID deletion indication
        ie(0x44, Type4, 3, 3, "9.11.3.6"),  // 5GS registration result
        ie(0x1b, Type4, 3, 3, "9.11.3.70"), // Truncated 5G-S-TMSI configuration
        ie(0xc0, Type1, 1, 1, "9.11.3.74"), // Additional configuration indication
        ie(0x68, Type4, 5, 90, "9.11.3.75"), // Extended rejected NSSAI
        ie(0x72, Type6, 4, 65538, "9.11.2.10"), // Service-level-AA container
        ie(0x70, Type6, 7, 4099, "9.11.3.82"), // NSSRG information
        ie(0x14, Type4, 4, 4, "9.11.3.84"), // Disaster roaming wait range
        ie(0x2c, Type4, 4, 4, "9.11.3.84"), // Disaster return wait range
        ie(0x13, Type4, 2, TLV_MAX, "9.11.3.83"), // PLMNs for disaster condition
        ie(0x71, Type6, 3, TLVE_MAX, "9.11.3.86"), // Extended CAG information list
        ie(0x1f, Type4, 3, TLV_MAX, "9.11.3.80"), // Updated PEIPS assistance
        ie(0x73, Type6, 9, 3143, "9.11.3.87"), // NSAG information
        ie(0xe0, Type1, 1, 1, "9.11.3.91"), // Priority indicator
        ie(0x4b, Type4, 3, 3, "9.11.3.95"), // RAN timing synchronization
        ie(0x78, Type6, 3, 1787, "9.11.3.96"), // Extended LADN information
        ie(0x4c, Type4, 2, 146, "9.11.3.97"), // Alternative NSSAI
        ie(0x7b, Type6, 17, 38611, "9.11.3.100"), // S-NSSAI location validity
        ie(0x5b, Type4, 23, 257, "9.11.3.101"), // S-NSSAI time validity
        ie(0x4f, Type4, 3, 3, "9.11.2.5"),  // Maximum time offset
        ie(0x74, Type6, 3, 808, "9.11.3.103"), // Partially allowed NSSAI
        ie(0x7a, Type6, 3, 808, "9.11.3.103"), // Partially rejected NSSAI
        ie(0x5c, Type4, 3, 257, "9.11.3.105"), // Feature authorization indication
        ie(0x61, Type4, 5, 210, "9.11.3.108"), // On-demand NSSAI
    ],
};

/// Table 8.2.20.1.1 has no optional elements. It is still a typed message.
const CONFIGURATION_UPDATE_COMPLETE: OptionalIeTable = OptionalIeTable {
    section: "8.2.20",
    entries: &[],
};

pub(super) fn for_message(message_type: MmMessageType) -> Option<OptionalIeTable> {
    Some(match message_type {
        MmMessageType::RegistrationRequest => REGISTRATION_REQUEST,
        MmMessageType::RegistrationAccept => REGISTRATION_ACCEPT,
        MmMessageType::SecurityModeCommand => SECURITY_MODE_COMMAND,
        MmMessageType::SecurityModeComplete => SECURITY_MODE_COMPLETE,
        MmMessageType::ConfigurationUpdateCommand => CONFIGURATION_UPDATE_COMMAND,
        MmMessageType::ConfigurationUpdateComplete => CONFIGURATION_UPDATE_COMPLETE,
        _ => return None,
    })
}
