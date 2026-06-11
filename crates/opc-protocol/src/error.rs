use thiserror::Error;

/// Reference to a specification clause for traceability (RFC 006 evidence).
///
/// Every public PDU, IE, field enum, and procedure-relevant constant SHOULD
/// cite a `SpecRef` so that conformance extraction can map implementation
/// artifacts back to the 3GPP / IETF documents they implement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpecRef {
    body: &'static str,
    doc: &'static str,
    section: &'static str,
    table: Option<&'static str>,
}

impl SpecRef {
    /// Create a new specification reference.
    ///
    /// # Example
    /// ```
    /// use opc_protocol::SpecRef;
    /// let r = SpecRef::new("3gpp", "TS 29.281", "5.1").with_table("5.1-1");
    /// ```
    pub const fn new(body: &'static str, doc: &'static str, section: &'static str) -> Self {
        Self {
            body,
            doc,
            section,
            table: None,
        }
    }

    /// Attach an optional table or figure identifier.
    pub const fn with_table(mut self, table: &'static str) -> Self {
        self.table = Some(table);
        self
    }

    /// Standards body (e.g. `"3gpp"`, `"ietf"`).
    pub const fn body(&self) -> &'static str {
        self.body
    }

    /// Document number (e.g. `"TS 29.281"`, `"RFC 8966"`).
    pub const fn doc(&self) -> &'static str {
        self.doc
    }

    /// Section or clause within the document.
    pub const fn section(&self) -> &'static str {
        self.section
    }

    /// Table or figure identifier, if applicable.
    pub const fn table(&self) -> Option<&'static str> {
        self.table
    }
}

/// Classification of decode failures.
///
/// Errors are safe to expose in logs and metrics. They never include raw
/// packet payload unless debug packet capture is explicitly enabled by a
/// separate flag outside this crate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeErrorCode {
    /// Input ended mid-field (e.g. a fixed-width header or TLV value was cut
    /// off before its declared length was consumed).
    #[error("input truncated")]
    Truncated,
    /// A length field in the input violates the protocol specification
    /// (e.g. exceeds parent length, is misaligned, or is smaller than the
    /// fixed header size).
    #[error("length field invalid: {reason}")]
    InvalidLength {
        /// Human-readable reason the length field is invalid.
        reason: &'static str,
    },
    /// An integer overflow occurred while computing a length or offset.
    #[error("integer overflow in length calculation")]
    LengthOverflow,
    /// Nested IE depth exceeded the configured `DecodeContext::max_depth` limit.
    #[error("nested IE depth exceeded limit")]
    DepthExceeded,
    /// Total IE count exceeded the configured `DecodeContext::max_ies` limit.
    #[error("IE count exceeded limit")]
    IeCountExceeded,
    /// Message byte length exceeded the configured `DecodeContext::max_message_len` limit.
    #[error("message length exceeded limit")]
    MessageLengthExceeded,
    /// An unknown IE was encountered with the critical flag set and the
    /// current `DecodeContext::unknown_ie_policy` does not allow it.
    #[error("unknown IE with critical flag")]
    UnknownCriticalIe,
    /// A duplicate IE was encountered where the current
    /// `DecodeContext::duplicate_ie_policy` forbids duplicates.
    #[error("duplicate IE where forbidden")]
    DuplicateIe,
    /// An enum field contained a value outside the defined valid range.
    #[error("invalid enum value {value} for field {field}")]
    InvalidEnumValue {
        /// Name of the field containing the invalid enum value.
        field: &'static str,
        /// The out-of-range enum value.
        value: u64,
    },
    /// Structural validation failed (e.g. missing mandatory IE, wrong
    /// container type, or invalid padding).
    #[error("structural validation failed: {reason}")]
    Structural {
        /// Human-readable reason structural validation failed.
        reason: &'static str,
    },
    /// A known-length message was declared but the available buffer is shorter
    /// than the declared length. Distinct from `Truncated`: `Incomplete` means
    /// the boundary is known but the data has not yet arrived; `Truncated`
    /// means the input definitively ended inside a field.
    #[error("incomplete input")]
    Incomplete,
}

/// Classification of encode failures.
///
/// Errors are safe to expose in logs and metrics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeErrorCode {
    /// Required output capacity exceeds the available or configured maximum.
    #[error("capacity exceeded: required {required}, available {available}")]
    CapacityExceeded {
        /// Bytes required to complete the encode.
        required: usize,
        /// Bytes available in the output buffer.
        available: usize,
    },
    /// An integer overflow occurred while computing wire length.
    #[error("integer overflow in length calculation")]
    LengthOverflow,
    /// Structural validation failed before encoding could begin.
    #[error("structural validation failed: {reason}")]
    Structural {
        /// Human-readable reason structural validation failed.
        reason: &'static str,
    },
}

/// Structured decode error with offset and optional spec reference.
///
/// # Safety for logging
///
/// `DecodeError` never stores raw packet bytes. The `offset` field is a
/// byte position, not a slice, so accidental payload leakage is impossible.
///
/// # Note on field visibility
///
/// RFC 005 §5.2 shows `code`, `offset`, and `spec_ref` as public fields.
/// This crate intentionally uses private fields with accessor methods for
/// encapsulation, allowing future internal changes without breaking the API.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code} at offset {offset}")]
pub struct DecodeError {
    code: DecodeErrorCode,
    offset: usize,
    spec_ref: Option<SpecRef>,
}

impl DecodeError {
    /// Create a decode error at the given byte offset.
    pub const fn new(code: DecodeErrorCode, offset: usize) -> Self {
        Self {
            code,
            offset,
            spec_ref: None,
        }
    }

    /// Attach a specification reference for evidence traceability.
    pub const fn with_spec_ref(mut self, spec_ref: SpecRef) -> Self {
        self.spec_ref = Some(spec_ref);
        self
    }

    /// The error classification.
    pub const fn code(&self) -> &DecodeErrorCode {
        &self.code
    }

    /// Byte offset in the input where parsing failed.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Optional specification reference.
    pub const fn spec_ref(&self) -> Option<&SpecRef> {
        self.spec_ref.as_ref()
    }
}

/// Structured encode error.
///
/// # Safety for logging
///
/// `EncodeError` never stores raw packet bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}")]
pub struct EncodeError {
    code: EncodeErrorCode,
    spec_ref: Option<SpecRef>,
}

impl EncodeError {
    /// Create an encode error.
    pub const fn new(code: EncodeErrorCode) -> Self {
        Self {
            code,
            spec_ref: None,
        }
    }

    /// Convenience constructor for a length-overflow error.
    pub const fn length_overflow() -> Self {
        Self::new(EncodeErrorCode::LengthOverflow)
    }

    /// Attach a specification reference for evidence traceability.
    pub const fn with_spec_ref(mut self, spec_ref: SpecRef) -> Self {
        self.spec_ref = Some(spec_ref);
        self
    }

    /// The error classification.
    pub const fn code(&self) -> &EncodeErrorCode {
        &self.code
    }

    /// Optional specification reference.
    pub const fn spec_ref(&self) -> Option<&SpecRef> {
        self.spec_ref.as_ref()
    }
}
