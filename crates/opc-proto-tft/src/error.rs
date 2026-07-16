use thiserror::Error;

/// Stable classification for TFT decode, validation, and encode failures.
///
/// Variants contain only public numeric metadata and fixed field names. They
/// never retain packet bytes, addresses, authorization tokens, or other
/// subscriber data, so both `Debug` and `Display` are safe for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TftErrorKind {
    /// The complete value length is outside the TS 24.008 bounds.
    #[error("TFT value length {actual} is outside {minimum}..={maximum}")]
    InvalidValueLength {
        /// Observed value length.
        actual: usize,
        /// Minimum accepted value length.
        minimum: usize,
        /// Maximum accepted value length.
        maximum: usize,
    },
    /// Input ended before a named field was complete.
    #[error("TFT input is truncated in {field}")]
    Truncated {
        /// Fixed, non-sensitive field name.
        field: &'static str,
    },
    /// A checked length or offset operation overflowed.
    #[error("TFT length calculation overflowed")]
    LengthOverflow,
    /// The caller's configured element limit was exceeded.
    #[error("TFT element count exceeds configured limit {limit}")]
    ElementLimitExceeded {
        /// Configured element limit.
        limit: usize,
    },
    /// TFT operation code 7 is reserved.
    #[error("reserved TFT operation code {value}")]
    ReservedOperation {
        /// Observed three-bit operation code.
        value: u8,
    },
    /// The operation header carries an illegal E-bit/count combination.
    #[error("invalid TFT operation header for operation {operation}")]
    InvalidOperationHeader {
        /// Three-bit operation code.
        operation: u8,
    },
    /// The model contains the wrong packet-filter-list representation.
    #[error("packet filter list form is invalid for TFT operation {operation}")]
    InvalidPacketFilterList {
        /// Three-bit operation code.
        operation: u8,
    },
    /// A required packet-filter or identifier list is empty or too large.
    #[error("packet filter count {count} is invalid for TFT operation {operation}")]
    InvalidPacketFilterCount {
        /// Three-bit operation code.
        operation: u8,
        /// Observed count.
        count: usize,
    },
    /// Bytes remain where the E bit says no parameter list exists.
    #[error("unexpected trailing TFT data")]
    UnexpectedTrailingData,
    /// The E bit is set but no parameter TLV is present.
    #[error("TFT parameter list is empty")]
    EmptyParameterList,
    /// Spare bits required to be zero are non-zero.
    #[error("non-zero spare bits in {field}")]
    NonZeroSpareBits {
        /// Fixed, non-sensitive field name.
        field: &'static str,
    },
    /// A packet-filter identifier does not fit in four bits.
    #[error("packet filter identifier {value} exceeds 4 bits")]
    InvalidPacketFilterIdentifier {
        /// Observed identifier value.
        value: u8,
    },
    /// A packet-filter identifier occurs more than once in one operation.
    #[error("duplicate packet filter identifier {identifier}")]
    DuplicatePacketFilterIdentifier {
        /// Duplicate four-bit identifier.
        identifier: u8,
    },
    /// An evaluation precedence occurs more than once in one operation.
    #[error("duplicate packet filter evaluation precedence {precedence}")]
    DuplicateEvaluationPrecedence {
        /// Duplicate precedence value.
        precedence: u8,
    },
    /// A full packet filter contains no components.
    #[error("packet filter contents are empty")]
    EmptyPacketFilterContents,
    /// Component bytes exceed the one-octet packet-filter-content length.
    #[error("packet filter content length {actual} exceeds {maximum}")]
    PacketFilterContentsTooLong {
        /// Encoded component length.
        actual: usize,
        /// Maximum encodable component length.
        maximum: usize,
    },
    /// A reserved component identifier was observed.
    #[error("reserved packet filter component type {component_type:#04x}")]
    ReservedComponentType {
        /// Observed component type identifier.
        component_type: u8,
    },
    /// A component's fixed-size value is incomplete.
    #[error("component {component_type:#04x} requires {expected} value octets, found {actual}")]
    InvalidComponentLength {
        /// Component type identifier.
        component_type: u8,
        /// Normative fixed value length.
        expected: usize,
        /// Available value length.
        actual: usize,
    },
    /// The same component type occurs twice in one filter.
    #[error("duplicate packet filter component type {component_type:#04x}")]
    DuplicateComponent {
        /// Duplicate component type identifier.
        component_type: u8,
    },
    /// Two standardized components cannot coexist in one packet filter.
    #[error("conflicting packet filter components {first:#04x} and {second:#04x}")]
    ConflictingComponents {
        /// First component type identifier.
        first: u8,
        /// Conflicting component type identifier.
        second: u8,
    },
    /// An IPv6 prefix length exceeds 128 bits.
    #[error("IPv6 prefix length {value} exceeds 128")]
    InvalidIpv6PrefixLength {
        /// Observed prefix length.
        value: u8,
    },
    /// A port range's low endpoint is greater than its high endpoint.
    #[error("port range low endpoint exceeds high endpoint")]
    InvalidPortRange,
    /// An IPv6 flow label exceeds 20 bits.
    #[error("IPv6 flow label {value} exceeds 20 bits")]
    InvalidFlowLabel {
        /// Observed flow-label value.
        value: u32,
    },
    /// An IEEE 802.1Q VLAN identifier exceeds 12 bits.
    #[error("VLAN identifier {value} exceeds 12 bits")]
    InvalidVlanIdentifier {
        /// Observed VLAN identifier.
        value: u16,
    },
    /// An IEEE 802.1Q PCP exceeds three bits.
    #[error("VLAN priority {value} exceeds 3 bits")]
    InvalidVlanPriority {
        /// Observed PCP value.
        value: u8,
    },
    /// A known TFT parameter has an invalid content length.
    #[error("TFT parameter {identifier:#04x} length {actual} is outside {minimum}..={maximum}")]
    InvalidParameterLength {
        /// Parameter identifier.
        identifier: u8,
        /// Observed content length.
        actual: usize,
        /// Minimum content length.
        minimum: usize,
        /// Maximum content length.
        maximum: usize,
    },
    /// An unknown-parameter wrapper used a standardized identifier.
    #[error("standardized parameter {identifier:#04x} cannot use the unknown representation")]
    StandardParameterAsUnknown {
        /// Parameter identifier.
        identifier: u8,
    },
    /// Packet-filter identifiers inside parameter 3 are duplicated.
    #[error("duplicate identifier {identifier} in packet-filter-identifier parameter")]
    DuplicateParameterPacketFilterIdentifier {
        /// Duplicate four-bit identifier.
        identifier: u8,
    },
    /// An Authorization Token is not immediately followed by a Flow Identifier.
    #[error(
        "authorization token parameter at index {parameter_index} has no following flow identifier"
    )]
    AuthorizationTokenWithoutFlowIdentifier {
        /// Zero-based parameter-list index.
        parameter_index: usize,
    },
    /// An internal encoded-size invariant failed without exposing data.
    #[error("TFT encoded length invariant failed")]
    EncodedLengthMismatch,
}

/// Structured, redaction-safe TFT error with an optional value-relative offset.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct TftError {
    kind: TftErrorKind,
    offset: Option<usize>,
}

impl TftError {
    /// Construct a model/validation error without a wire offset.
    pub const fn new(kind: TftErrorKind) -> Self {
        Self { kind, offset: None }
    }

    /// Return the stable error classification.
    pub const fn kind(&self) -> &TftErrorKind {
        &self.kind
    }

    /// Return the byte offset relative to the TFT value, when decoding supplied one.
    pub const fn offset(&self) -> Option<usize> {
        self.offset
    }

    pub(crate) const fn at(mut self, offset: usize) -> Self {
        if self.offset.is_none() {
            self.offset = Some(offset);
        }
        self
    }
}

impl From<TftErrorKind> for TftError {
    fn from(kind: TftErrorKind) -> Self {
        Self::new(kind)
    }
}
