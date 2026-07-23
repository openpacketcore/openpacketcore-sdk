use thiserror::Error;

/// Stable, redaction-safe EAP-AKA projection failure.
///
/// Every field is bounded protocol metadata. No variant retains or reports
/// packet contents, subscriber identities, authentication material, or a
/// packet-derived hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EapAkaError {
    /// The complete EAP packet is shorter than the method header.
    #[error("eap_aka_packet_too_short: actual={actual} minimum={minimum}")]
    PacketTooShort {
        /// Received packet length.
        actual: usize,
        /// Required minimum length.
        minimum: usize,
    },
    /// The packet is not an EAP Request or Response.
    #[error("eap_aka_unsupported_code: actual={actual}")]
    UnsupportedCode {
        /// Received EAP Code.
        actual: u8,
    },
    /// The EAP header length does not describe the complete supplied packet.
    #[error("eap_aka_length_mismatch: declared={declared} actual={actual}")]
    LengthMismatch {
        /// Length declared in the EAP header.
        declared: usize,
        /// Supplied slice length.
        actual: usize,
    },
    /// The EAP method is neither EAP-AKA nor EAP-AKA-prime.
    #[error("eap_aka_unsupported_method: actual={actual}")]
    UnsupportedMethod {
        /// Received EAP method Type.
        actual: u8,
    },
    /// The two-octet AKA method-header reserved field was nonzero.
    #[error("eap_aka_reserved_field_nonzero")]
    ReservedFieldNonZero,
    /// The AKA subtype is not defined for this projection.
    #[error("eap_aka_unsupported_subtype: actual={actual}")]
    UnsupportedSubtype {
        /// Received subtype.
        actual: u8,
    },
    /// The subtype is not legal for the packet direction.
    #[error("eap_aka_invalid_direction: code={code} subtype={subtype}")]
    InvalidDirection {
        /// Received EAP Code.
        code: u8,
        /// Received AKA subtype.
        subtype: u8,
    },
    /// An attribute header is truncated.
    #[error("eap_aka_attribute_header_truncated: offset={offset} remaining={remaining}")]
    AttributeHeaderTruncated {
        /// Byte offset from the start of the EAP packet.
        offset: usize,
        /// Bytes remaining at the offset.
        remaining: usize,
    },
    /// An attribute used the prohibited zero length.
    #[error("eap_aka_zero_length_attribute: attribute_type={attribute_type} offset={offset}")]
    ZeroLengthAttribute {
        /// Attribute Type.
        attribute_type: u8,
        /// Byte offset from the start of the EAP packet.
        offset: usize,
    },
    /// An attribute extends beyond the complete EAP packet.
    #[error(
        "eap_aka_attribute_truncated: attribute_type={attribute_type} offset={offset} declared={declared} remaining={remaining}"
    )]
    AttributeTruncated {
        /// Attribute Type.
        attribute_type: u8,
        /// Byte offset from the start of the EAP packet.
        offset: usize,
        /// Declared attribute length in octets.
        declared: usize,
        /// Octets available from the attribute offset.
        remaining: usize,
    },
    /// The configured parser attribute-count bound was exceeded.
    #[error("eap_aka_too_many_attributes: maximum={maximum}")]
    TooManyAttributes {
        /// Maximum accepted attribute count.
        maximum: usize,
    },
    /// An unknown non-skippable attribute was received.
    #[error(
        "eap_aka_unknown_mandatory_attribute: attribute_type={attribute_type} offset={offset}"
    )]
    UnknownMandatoryAttribute {
        /// Attribute Type.
        attribute_type: u8,
        /// Byte offset from the start of the EAP packet.
        offset: usize,
    },
    /// A known attribute is prohibited in this method packet.
    #[error(
        "eap_aka_prohibited_attribute: attribute_type={attribute_type} code={code} subtype={subtype}"
    )]
    ProhibitedAttribute {
        /// Attribute Type.
        attribute_type: u8,
        /// EAP Code.
        code: u8,
        /// AKA subtype.
        subtype: u8,
    },
    /// A singleton attribute appeared more than once.
    #[error("eap_aka_duplicate_singleton_attribute: attribute_type={attribute_type}")]
    DuplicateSingletonAttribute {
        /// Attribute Type.
        attribute_type: u8,
    },
    /// A known attribute used an invalid encoded length.
    #[error("eap_aka_invalid_attribute_length: attribute_type={attribute_type} actual={actual}")]
    InvalidAttributeLength {
        /// Attribute Type.
        attribute_type: u8,
        /// Encoded length in octets.
        actual: usize,
    },
    /// A length-bearing attribute used an invalid actual-value length.
    #[error(
        "eap_aka_invalid_actual_value_length: attribute_type={attribute_type} actual={actual} available={available}"
    )]
    InvalidActualValueLength {
        /// Attribute Type.
        attribute_type: u8,
        /// Declared actual-value length.
        actual: usize,
        /// Available value capacity after the actual-length field.
        available: usize,
    },
    /// A length-bearing attribute had nonzero alignment padding.
    #[error("eap_aka_nonzero_attribute_padding: attribute_type={attribute_type}")]
    NonzeroAttributePadding {
        /// Attribute Type.
        attribute_type: u8,
    },
    /// A standardized text value was not valid UTF-8.
    #[error("eap_aka_invalid_utf8: attribute_type={attribute_type}")]
    InvalidUtf8 {
        /// Attribute Type.
        attribute_type: u8,
    },
    /// A standardized text value contained a prohibited NUL octet.
    #[error("eap_aka_nul_in_text_value: attribute_type={attribute_type}")]
    NulInTextValue {
        /// Attribute Type.
        attribute_type: u8,
    },
    /// A required singleton attribute is absent.
    #[error(
        "eap_aka_missing_attribute: attribute_type={attribute_type} code={code} subtype={subtype}"
    )]
    MissingAttribute {
        /// Attribute Type.
        attribute_type: u8,
        /// EAP Code.
        code: u8,
        /// AKA subtype.
        subtype: u8,
    },
    /// A packet contained an illegal combination of otherwise valid fields.
    #[error("eap_aka_invalid_attribute_combination: reason={reason}")]
    InvalidAttributeCombination {
        /// Stable machine-readable combination reason.
        reason: EapAkaCombinationError,
    },
}

impl EapAkaError {
    /// Return a stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PacketTooShort { .. } => "eap_aka_packet_too_short",
            Self::UnsupportedCode { .. } => "eap_aka_unsupported_code",
            Self::LengthMismatch { .. } => "eap_aka_length_mismatch",
            Self::UnsupportedMethod { .. } => "eap_aka_unsupported_method",
            Self::ReservedFieldNonZero => "eap_aka_reserved_field_nonzero",
            Self::UnsupportedSubtype { .. } => "eap_aka_unsupported_subtype",
            Self::InvalidDirection { .. } => "eap_aka_invalid_direction",
            Self::AttributeHeaderTruncated { .. } => "eap_aka_attribute_header_truncated",
            Self::ZeroLengthAttribute { .. } => "eap_aka_zero_length_attribute",
            Self::AttributeTruncated { .. } => "eap_aka_attribute_truncated",
            Self::TooManyAttributes { .. } => "eap_aka_too_many_attributes",
            Self::UnknownMandatoryAttribute { .. } => "eap_aka_unknown_mandatory_attribute",
            Self::ProhibitedAttribute { .. } => "eap_aka_prohibited_attribute",
            Self::DuplicateSingletonAttribute { .. } => "eap_aka_duplicate_singleton_attribute",
            Self::InvalidAttributeLength { .. } => "eap_aka_invalid_attribute_length",
            Self::InvalidActualValueLength { .. } => "eap_aka_invalid_actual_value_length",
            Self::NonzeroAttributePadding { .. } => "eap_aka_nonzero_attribute_padding",
            Self::InvalidUtf8 { .. } => "eap_aka_invalid_utf8",
            Self::NulInTextValue { .. } => "eap_aka_nul_in_text_value",
            Self::MissingAttribute { .. } => "eap_aka_missing_attribute",
            Self::InvalidAttributeCombination { .. } => "eap_aka_invalid_attribute_combination",
        }
    }
}

/// Stable reason for an invalid combination of valid EAP-AKA fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EapAkaCombinationError {
    /// AT_IV and AT_ENCR_DATA were not present as a pair.
    EncryptionPairIncomplete,
    /// Identity request selectors were not mutually exclusive.
    IdentityRequestNotExclusive,
    /// An EAP-AKA-prime KDF list contained an illegal duplicate.
    InvalidKdfDuplicate,
    /// An AT_KDF used reserved value zero.
    ReservedKdf,
    /// The bounded KDF-list limit was exceeded.
    TooManyKdfAttributes,
    /// An EAP-AKA-prime Challenge response mixed KDF negotiation and auth data.
    KdfNegotiationMixedWithAuthentication,
    /// AT_KDF_INPUT was missing from an EAP-AKA-prime Challenge Request.
    KdfInputMissing,
    /// Notification S/P bits described an impossible phase/result combination.
    InvalidNotificationPhase,
    /// A pre-authentication Notification carried prohibited AT_MAC.
    PreAuthenticationNotificationMacPresent,
    /// AT_RES used a bit length outside 32 through 128.
    InvalidResBitLength,
    /// AT_RES contained nonzero unused bits or alignment padding.
    InvalidResPadding,
}

impl EapAkaCombinationError {
    /// Return a stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EncryptionPairIncomplete => "encryption_pair_incomplete",
            Self::IdentityRequestNotExclusive => "identity_request_not_exclusive",
            Self::InvalidKdfDuplicate => "invalid_kdf_duplicate",
            Self::ReservedKdf => "reserved_kdf",
            Self::TooManyKdfAttributes => "too_many_kdf_attributes",
            Self::KdfNegotiationMixedWithAuthentication => {
                "kdf_negotiation_mixed_with_authentication"
            }
            Self::KdfInputMissing => "kdf_input_missing",
            Self::InvalidNotificationPhase => "invalid_notification_phase",
            Self::PreAuthenticationNotificationMacPresent => {
                "pre_authentication_notification_mac_present"
            }
            Self::InvalidResBitLength => "invalid_res_bit_length",
            Self::InvalidResPadding => "invalid_res_padding",
        }
    }
}

impl std::fmt::Display for EapAkaCombinationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
