//! Independently authored framing fixtures from TS 24.501 V18.11.1.
//!
//! Source: https://www.etsi.org/deliver/etsi_ts/124500_124599/124501/18.11.01_60/ts_124501v181101p.pdf
//! Tables 8.2.6.1.1, 8.2.7.1.1, 8.2.19.1.1, 8.2.20.1.1,
//! 8.2.25.1.1 and 8.2.26.1.1. Each literal occupies the row's minimum
//! total length. Optional values are synthetic and opaque: these fixtures
//! qualify framing, not IE-content semantics or procedure presence rules.
//! Neither bytes nor expected bounds are obtained from the codec's registry.

pub struct Ie {
    pub wire: &'static [u8],
    pub header_len: usize,
    pub max_len: usize,
    pub section: &'static str,
}

const fn ie(wire: &'static [u8], header_len: usize, max_len: usize, section: &'static str) -> Ie {
    Ie {
        wire,
        header_len,
        max_len,
        section,
    }
}

pub struct Message {
    pub kind: u8,
    pub mandatory: &'static [u8],
    pub section: &'static str,
    pub ies: &'static [Ie],
}

pub const REQUEST: Message = Message {
    kind: 0x41,
    mandatory: &[
        0x01, 0x00, 0x0a, 0x01, 0x02, 0xf8, 0x39, 0x21, 0xf3, 0x00, 0x00, 0x13, 0x57,
    ],
    section: "8.2.6",
    ies: &[
        ie(&[0xc1], 1, 1, "9.11.3.32"),       // Non-current native NAS KSI
        ie(&[0x10, 1, 1], 2, 15, "9.11.3.1"), // 5GMM capability
        ie(&[0x2e, 2, 0x80, 0], 2, 10, "9.11.3.54"), // UE security capability
        ie(&[0x2f, 2, 1, 1], 2, 74, "9.11.3.37"), // Requested NSSAI
        ie(&[0x52, 2, 0xf8, 0x39, 0, 0, 1], 1, 7, "9.11.3.8"), // Last visited TAI
        ie(&[0x17, 2, 0, 0], 2, 15, "9.11.3.48"), // S1 UE network capability
        ie(&[0x40, 2, 1, 0], 2, 34, "9.11.3.57"), // Uplink data status
        ie(&[0x50, 2, 1, 0], 2, 34, "9.11.3.44"), // PDU session status
        ie(&[0xb1], 1, 1, "9.11.3.31"),       // MICO indication
        ie(&[0x2b, 1, 1], 2, 3, "9.11.3.56"), // UE status
        ie(
            &[0x77, 0, 11, 0xf2, 2, 0xf8, 0x39, 1, 0, 1, 2, 3, 4, 5],
            3,
            14,
            "9.11.3.4",
        ), // Additional GUTI
        ie(&[0x25, 2, 1, 0], 2, 34, "9.11.3.13"), // Allowed PDU session status
        ie(&[0x18, 1, 0], 2, 3, "9.11.3.55"), // UE usage setting
        ie(&[0x51, 1, 1], 2, 3, "9.11.3.2A"), // Requested DRX
        ie(&[0x70, 0, 1, 0], 3, 65538, "9.11.3.24"), // EPS NAS container
        ie(&[0x74, 0, 0], 3, 811, "9.11.3.29"), // LADN indication
        ie(&[0x81], 1, 1, "9.11.3.40"),       // Payload container type
        ie(&[0x7b, 0, 1, 0], 3, 65538, "9.11.3.39"), // Payload container
        ie(&[0x99], 1, 1, "9.11.3.36"),       // Network slicing indication
        ie(&[0x53, 1, 0], 2, 3, "9.11.3.9A"), // 5GS update type
        ie(&[0x41, 3, 0, 0, 0], 2, 5, "9.11.3.31C"), // Mobile station classmark 2
        ie(&[0x42, 3, 0, 0, 0], 2, 257, "9.11.3.51A"), // Supported codecs
        ie(&[0x71, 0, 1, 0], 3, 65538, "9.11.3.33"), // NAS message container
        ie(&[0x60, 2, 0, 0], 2, 4, "9.11.3.23A"), // EPS bearer context status
        ie(&[0x6e, 1, 0], 2, 4, "9.11.3.26A"), // Requested extended DRX
        ie(&[0x6a, 1, 1], 2, 3, "9.11.2.5"),  // T3324
        ie(&[0x67, 1, 0], 2, 257, "9.11.3.68"), // UE radio capability ID
        ie(&[0x35, 1, 0], 2, 42, "9.11.3.31B"), // Requested mapped NSSAI
        ie(&[0x48, 1, 1], 2, 3, "9.11.3.12A"), // Additional information requested
        ie(&[0x1a, 1, 0], 2, 257, "9.11.3.71"), // Requested WUS assistance
        ie(&[0xa1], 1, 1, "9.11.3.72"),       // N5GC indication
        ie(&[0x30, 1, 1], 2, 3, "9.11.3.73"), // Requested NB-N1 DRX
        ie(&[0x29, 1, 1], 2, 3, "9.11.3.76"), // UE request type
        ie(&[0x28, 1, 0], 2, 35, "9.11.3.77"), // Paging restriction
        ie(&[0x72, 0, 1, 0], 3, 65538, "9.11.2.10"), // Service-level-AA container
        ie(&[0x32, 6, 0, 0, 0, 0, 0, 1], 2, 8, "9.11.3.79"), // NID
        ie(&[0x16, 3, 2, 0xf8, 0x39], 2, 5, "9.11.3.85"), // UE determined PLMN
        ie(&[0x2a, 1, 0], 2, 257, "9.11.3.80"), // Requested PEIPS assistance
        ie(&[0x3b, 1, 1], 2, 3, "9.11.2.5"),  // Requested T3512
        ie(&[0x3c, 1, 0], 2, 9, "9.11.2.20"), // Unavailability information
        ie(&[0x3f, 1, 0], 2, 3, "9.11.3.102"), // Non-3GPP path switching
        ie(&[0x56, 1, 1], 2, 3, "9.11.3.104"), // AUN3 indication
    ],
};

pub const ACCEPT: Message = Message {
    kind: 0x42,
    mandatory: &[1, 1],
    section: "8.2.7",
    ies: &[
        ie(
            &[0x77, 0, 11, 0xf2, 2, 0xf8, 0x39, 1, 0, 1, 2, 3, 4, 5],
            3,
            14,
            "9.11.3.4",
        ), // 5G-GUTI
        ie(&[0x4a, 3, 2, 0xf8, 0x39], 2, 47, "9.11.3.45"), // Equivalent PLMNs
        ie(&[0x54, 7, 0, 2, 0xf8, 0x39, 0, 0, 1], 2, 114, "9.11.3.9"), // TAI list
        ie(&[0x15, 2, 1, 1], 2, 74, "9.11.3.37"),          // Allowed NSSAI
        ie(&[0x11, 2, 0x10, 1], 2, 42, "9.11.3.46"),       // Rejected NSSAI
        ie(&[0x31, 2, 1, 1], 2, 146, "9.11.3.37"),         // Configured NSSAI
        ie(&[0x21, 1, 0], 2, 6, "9.11.3.5"),               // 5GS network feature support
        ie(&[0x50, 2, 1, 0], 2, 34, "9.11.3.44"),          // PDU session status
        ie(&[0x26, 2, 1, 0], 2, 34, "9.11.3.42"),          // PDU session reactivation result
        ie(&[0x72, 0, 2, 1, 0x26], 3, 515, "9.11.3.43"),   // Reactivation error cause
        ie(
            &[0x79, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            3,
            1715,
            "9.11.3.30",
        ), // LADN information
        ie(&[0xb1], 1, 1, "9.11.3.31"),                    // MICO
        ie(&[0x91], 1, 1, "9.11.3.36"),                    // Network slicing indication
        ie(&[0x27, 4, 0, 2, 0xf8, 0x39], 2, 114, "9.11.3.49"), // Service area list
        ie(&[0x5e, 1, 1], 2, 3, "9.11.2.5"),               // T3512
        ie(&[0x5d, 1, 1], 2, 3, "9.11.2.4"),               // Non-3GPP deregistration timer
        ie(&[0x16, 1, 1], 2, 3, "9.11.2.4"),               // T3502
        ie(&[0x34, 3, 2, 1, 0x11], 2, 50, "9.11.3.23"),    // Emergency numbers
        ie(&[0x7a, 0, 4, 0, 0, 0, 0], 3, 65538, "9.11.3.26"), // Extended emergency numbers
        ie(
            &[
                0x73, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            3,
            65538,
            "9.11.3.51",
        ), // SOR container
        ie(&[0x78, 0, 4, 3, 1, 0, 4], 3, 1503, "9.11.2.2"), // EAP
        ie(&[0xa1], 1, 1, "9.11.3.37A"),                   // NSSAI inclusion mode
        ie(&[0x76, 0, 0], 3, 8323, "9.11.3.38"),           // Operator-defined access categories
        ie(&[0x51, 1, 1], 2, 3, "9.11.3.2A"),              // Negotiated DRX
        ie(&[0xd1], 1, 1, "9.11.3.36A"),                   // Non-3GPP network policies
        ie(&[0x60, 2, 0, 0], 2, 4, "9.11.3.23A"),          // EPS bearer context status
        ie(&[0x6e, 1, 0], 2, 4, "9.11.3.26A"),             // Negotiated extended DRX
        ie(&[0x6c, 1, 1], 2, 3, "9.11.2.5"),               // T3447
        ie(&[0x6b, 1, 1], 2, 3, "9.11.2.4"),               // T3448
        ie(&[0x6a, 1, 1], 2, 3, "9.11.2.5"),               // T3324
        ie(&[0x67, 1, 0], 2, 257, "9.11.3.68"),            // UE radio capability ID
        ie(&[0xe1], 1, 1, "9.11.3.69"),                    // Radio capability ID deletion
        ie(&[0x39, 2, 1, 1], 2, 146, "9.11.3.37"),         // Pending NSSAI
        ie(
            &[
                0x74, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            3,
            65538,
            "9.11.3.18C",
        ), // Ciphering key data
        ie(&[0x75, 0, 0], 3, 65538, "9.11.3.18A"),         // CAG information
        ie(&[0x1b, 1, 0], 2, 3, "9.11.3.70"),              // Truncated 5G-S-TMSI configuration
        ie(&[0x1c, 1, 0], 2, 257, "9.11.3.71"),            // Negotiated WUS assistance
        ie(&[0x29, 1, 1], 2, 3, "9.11.3.73"),              // Negotiated NB-N1 DRX
        ie(&[0x68, 3, 0, 0, 0], 2, 90, "9.11.3.75"),       // Extended rejected NSSAI
        ie(&[0x7b, 0, 1, 0], 3, 65538, "9.11.2.10"),       // Service-level-AA container
        ie(&[0x33, 1, 0], 2, 257, "9.11.3.80"),            // Negotiated PEIPS assistance
        ie(&[0x35, 1, 0], 2, 3, "9.11.3.81"),              // Additional request result
        ie(&[0x70, 0, 4, 0, 0, 0, 0], 3, 4099, "9.11.3.82"), // NSSRG information
        ie(&[0x14, 2, 1, 2], 2, 4, "9.11.3.84"),           // Disaster roaming wait range
        ie(&[0x2c, 2, 1, 2], 2, 4, "9.11.3.84"),           // Disaster return wait range
        ie(&[0x13, 0], 2, 257, "9.11.3.83"),               // PLMNs for disaster condition
        ie(&[0x1d, 7, 0, 2, 0xf8, 0x39, 0, 0, 1], 2, 114, "9.11.3.9"), // Forbidden TAI roaming
        ie(&[0x1e, 7, 0, 2, 0xf8, 0x39, 0, 0, 1], 2, 114, "9.11.3.9"), // Forbidden TAI regional service
        ie(&[0x71, 0, 0], 3, 65538, "9.11.3.86"),                      // Extended CAG information
        ie(&[0x7c, 0, 6, 0, 0, 0, 0, 0, 0], 3, 3143, "9.11.3.87"),     // NSAG information
        ie(&[0x3d, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 137, "9.11.3.92"), // Equivalent SNPNs
        ie(&[0x32, 6, 0, 0, 0, 0, 0, 1], 2, 8, "9.11.3.79"),           // NID
        ie(&[0x7d, 0, 3, 0, 0, 0], 3, 65538, "9.11.3.98"), // Registration accept type 6 IE container
        ie(&[0x4b, 1, 0], 2, 3, "9.11.3.95"),              // RAN timing synchronization
        ie(&[0x4c, 0], 2, 146, "9.11.3.97"),               // Alternative NSSAI
        ie(&[0x4f, 1, 1], 2, 3, "9.11.2.5"),               // Maximum time offset
        ie(
            &[
                0x5b, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            2,
            257,
            "9.11.3.101",
        ), // S-NSSAI time validity
        ie(&[0x3c, 1, 0], 2, 6, "9.11.2.21"),              // Unavailability configuration
        ie(&[0x5c, 1, 0], 2, 257, "9.11.3.105"),           // Feature authorization
        ie(&[0x61, 3, 0, 0, 0], 2, 210, "9.11.3.108"),     // On-demand NSSAI
    ],
};

pub const SECURITY_COMMAND: Message = Message {
    kind: 0x5d,
    mandatory: &[0x22, 0, 2, 0x80, 0],
    section: "8.2.25",
    ies: &[
        ie(&[0xe1], 1, 1, "9.11.3.28"),                     // IMEISV request
        ie(&[0x57, 0x22], 1, 2, "9.11.3.25"),               // Selected EPS NAS algorithms
        ie(&[0x36, 1, 1], 2, 3, "9.11.3.12"),               // Additional 5G security information
        ie(&[0x78, 0, 4, 3, 1, 0, 4], 3, 1503, "9.11.2.2"), // EAP
        ie(&[0x38, 2, 0, 0], 2, 257, "9.11.3.10"),          // ABBA
        ie(&[0x19, 2, 0x80, 0], 2, 7, "9.11.3.48A"),        // Replayed S1 security capability
        ie(
            &[
                0x55, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            2,
            257,
            "9.11.3.107",
        ), // AUN3 device key
    ],
};

pub const SECURITY_COMPLETE: Message = Message {
    kind: 0x5e,
    mandatory: &[],
    section: "8.2.26",
    ies: &[
        ie(
            &[
                0x77, 0, 9, 0x15, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xf6,
            ],
            3,
            12,
            "9.11.3.4",
        ), // IMEISV
        ie(&[0x71, 0, 1, 0], 3, 65538, "9.11.3.33"), // NAS container
        ie(&[0x78, 0, 4, 0, 0, 0, 0], 3, 65538, "9.11.3.4"), // Non-IMEISV PEI
    ],
};

pub const CONFIGURATION_COMMAND: Message = Message {
    kind: 0x54,
    mandatory: &[],
    section: "8.2.19",
    ies: &[
        ie(&[0xd1], 1, 1, "9.11.3.18"), // Configuration update indication
        ie(
            &[0x77, 0, 11, 0xf2, 2, 0xf8, 0x39, 1, 0, 1, 2, 3, 4, 5],
            3,
            14,
            "9.11.3.4",
        ), // 5G-GUTI
        ie(&[0x54, 7, 0, 2, 0xf8, 0x39, 0, 0, 1], 2, 114, "9.11.3.9"), // TAI list
        ie(&[0x15, 2, 1, 1], 2, 74, "9.11.3.37"), // Allowed NSSAI
        ie(&[0x27, 4, 0, 2, 0xf8, 0x39], 2, 114, "9.11.3.49"), // Service area list
        ie(&[0x43, 1, 0x80], 2, 257, "9.11.3.35"), // Full network name
        ie(&[0x45, 1, 0x80], 2, 257, "9.11.3.35"), // Short network name
        ie(&[0x46, 0], 1, 2, "9.11.3.52"), // Local time zone
        ie(
            &[0x47, 0x62, 0x01, 0x11, 0x21, 0x00, 0x00, 0],
            1,
            8,
            "9.11.3.53",
        ), // Universal time and local zone
        ie(&[0x49, 1, 0], 2, 3, "9.11.3.19"), // Daylight saving time
        ie(&[0x79, 0, 0], 3, 1715, "9.11.3.30"), // LADN information (empty permitted here)
        ie(&[0xb1], 1, 1, "9.11.3.31"), // MICO
        ie(&[0x91], 1, 1, "9.11.3.36"), // Network slicing indication
        ie(&[0x31, 2, 1, 1], 2, 146, "9.11.3.37"), // Configured NSSAI
        ie(&[0x11, 2, 0x10, 1], 2, 42, "9.11.3.46"), // Rejected NSSAI
        ie(&[0x76, 0, 0], 3, 8323, "9.11.3.38"), // Operator-defined access categories
        ie(&[0xf1], 1, 1, "9.11.3.50A"), // SMS indication
        ie(&[0x6c, 1, 1], 2, 3, "9.11.2.5"), // T3447
        ie(&[0x75, 0, 0], 3, 65538, "9.11.3.18A"), // CAG information
        ie(&[0x67, 1, 0], 2, 257, "9.11.3.68"), // UE radio capability ID
        ie(&[0xa1], 1, 1, "9.11.3.69"), // Radio capability ID deletion
        ie(&[0x44, 1, 1], 2, 3, "9.11.3.6"), // Registration result
        ie(&[0x1b, 1, 0], 2, 3, "9.11.3.70"), // Truncated 5G-S-TMSI configuration
        ie(&[0xc1], 1, 1, "9.11.3.74"), // Additional configuration indication
        ie(&[0x68, 3, 0, 0, 0], 2, 90, "9.11.3.75"), // Extended rejected NSSAI
        ie(&[0x72, 0, 1, 0], 3, 65538, "9.11.2.10"), // Service-level-AA container
        ie(&[0x70, 0, 4, 0, 0, 0, 0], 3, 4099, "9.11.3.82"), // NSSRG information
        ie(&[0x14, 2, 1, 2], 2, 4, "9.11.3.84"), // Disaster roaming wait range
        ie(&[0x2c, 2, 1, 2], 2, 4, "9.11.3.84"), // Disaster return wait range
        ie(&[0x13, 0], 2, 257, "9.11.3.83"), // PLMNs for disaster condition
        ie(&[0x71, 0, 0], 3, 65538, "9.11.3.86"), // Extended CAG information
        ie(&[0x1f, 1, 0], 2, 257, "9.11.3.80"), // Updated PEIPS assistance
        ie(&[0x73, 0, 6, 0, 0, 0, 0, 0, 0], 3, 3143, "9.11.3.87"), // NSAG information
        ie(&[0xe1], 1, 1, "9.11.3.91"), // Priority indicator
        ie(&[0x4b, 1, 0], 2, 3, "9.11.3.95"), // RAN timing synchronization
        ie(&[0x78, 0, 0], 3, 1787, "9.11.3.96"), // Extended LADN information
        ie(&[0x4c, 0], 2, 146, "9.11.3.97"), // Alternative NSSAI
        ie(
            &[0x7b, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            3,
            38611,
            "9.11.3.100",
        ), // S-NSSAI location validity
        ie(
            &[
                0x5b, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            2,
            257,
            "9.11.3.101",
        ), // S-NSSAI time validity
        ie(&[0x4f, 1, 1], 2, 3, "9.11.2.5"), // Maximum time offset
        ie(&[0x74, 0, 0], 3, 808, "9.11.3.103"), // Partially allowed NSSAI
        ie(&[0x7a, 0, 0], 3, 808, "9.11.3.103"), // Partially rejected NSSAI
        ie(&[0x5c, 1, 0], 2, 257, "9.11.3.105"), // Feature authorization
        ie(&[0x61, 3, 0, 0, 0], 2, 210, "9.11.3.108"), // On-demand NSSAI
    ],
};

pub const CONFIGURATION_COMPLETE: Message = Message {
    kind: 0x55,
    mandatory: &[],
    section: "8.2.20",
    ies: &[],
};

pub const MESSAGES: &[Message] = &[
    REQUEST,
    ACCEPT,
    SECURITY_COMMAND,
    SECURITY_COMPLETE,
    CONFIGURATION_COMMAND,
    CONFIGURATION_COMPLETE,
];
