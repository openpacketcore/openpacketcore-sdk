//! Request-bound RFC 6733 error-answer inspection and construction.
//!
//! This boundary deliberately complements, rather than weakens, the ordinary
//! Diameter decoder. It retains only the bounded request metadata that RFC
//! 6733 requires in an answer: the fixed identifiers, one Session-Id, ordered
//! Proxy-Info AVPs, and at most one selected Failed-AVP hierarchy. Subscriber
//! and proxy-state octets remain in types whose diagnostic formatting is
//! redacted.
//!
//! @spec IETF RFC6733 6.2, 7.1.3, 7.1.5, 7.2, 7.5
//! @req REQ-IETF-RFC6733-ERROR-ANSWER-001

use core::fmt;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, UnknownIePolicy, ValidationLevel,
};
use sha2::{Digest, Sha256};

use crate::base::{
    AVP_FAILED_AVP, AVP_ORIGIN_HOST, AVP_ORIGIN_REALM, AVP_PROXY_HOST, AVP_PROXY_INFO,
    AVP_PROXY_STATE, AVP_RESULT_CODE, AVP_SESSION_ID, RESULT_CODE_DIAMETER_APPLICATION_UNSUPPORTED,
    RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED, RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES,
    RESULT_CODE_DIAMETER_AVP_UNSUPPORTED, RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
    RESULT_CODE_DIAMETER_INVALID_AVP_BITS, RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH,
    RESULT_CODE_DIAMETER_INVALID_AVP_VALUE, RESULT_CODE_DIAMETER_INVALID_BIT_IN_HEADER,
    RESULT_CODE_DIAMETER_INVALID_HDR_BITS, RESULT_CODE_DIAMETER_MISSING_AVP,
    RESULT_CODE_DIAMETER_UNSUPPORTED_VERSION,
};
use crate::parser_error::{DiameterGroupedAvpSetFailureKind, DiameterParserError};
use crate::{
    ApplicationId, AvpCardinality, AvpCode, AvpDataType, AvpDefinition, AvpFlags, AvpHeader,
    AvpKey, CommandCode, CommandDefinition, CommandFlags, CommandKind, CommandLookupError,
    DictionarySet, FlagRequirement, Header, OwnedMessage, RawAvp, VendorId, AVP_HEADER_LEN,
    AVP_VENDOR_HEADER_LEN, DIAMETER_HEADER_LEN, DIAMETER_VERSION, MAX_U24,
};

fn spec_ref(section: &'static str) -> SpecRef {
    SpecRef::new("ietf", "RFC6733", section)
}

fn structural_encode_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason }).with_spec_ref(spec_ref(section))
}

const MAX_FAILED_AVP_HIERARCHY_DEPTH: usize = 16;

#[derive(Clone, PartialEq, Eq)]
enum FailedAvpAncestorProvenance {
    Received {
        key: AvpKey,
        offset: usize,
        wire_len: usize,
        wire_digest: [u8; 32],
    },
    Missing {
        key: AvpKey,
    },
}

#[derive(Clone, PartialEq, Eq)]
struct FailedAvpReceivedChildProvenance {
    key: AvpKey,
    offset: usize,
    wire_len: usize,
    wire_digest: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
enum FailedAvpSiblingSetProvenance {
    Missing {
        keys: Box<[AvpKey]>,
    },
    Received {
        children: Box<[FailedAvpReceivedChildProvenance]>,
    },
}

/// Sensitive AVP bytes retained for RFC 6733 answer construction.
///
/// `Debug` and `Display` intentionally reveal only wire metadata. There is no
/// public raw-value accessor; the request-bound answer builder is the
/// authorized path that can copy the retained value back to the wire. A
/// Session-Id retains its exact value; a Proxy-Info retains a canonical
/// re-encoding of the same ordered opaque child values.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterSensitiveAvp {
    code: AvpCode,
    vendor_id: Option<VendorId>,
    offset: usize,
    declared_len: u32,
    value: Bytes,
    wire: Bytes,
}

impl DiameterSensitiveAvp {
    fn from_complete_wire(
        wire: &[u8],
        header: &AvpHeader,
        offset: usize,
    ) -> Result<Self, EncodeError> {
        let value_start = header.header_len();
        let value_end =
            usize::try_from(header.length).map_err(|_| EncodeError::length_overflow())?;
        if value_start > value_end || value_end > wire.len() {
            return Err(structural_encode_error(
                "diameter retained AVP bounds are inconsistent",
                "7.5",
            ));
        }
        let wire = Bytes::copy_from_slice(wire);
        let value = wire.slice(value_start..value_end);
        Ok(Self {
            code: header.code,
            vendor_id: header.vendor_id,
            offset,
            declared_len: header.length,
            value,
            wire,
        })
    }

    fn value(&self) -> &[u8] {
        &self.value
    }

    fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// AVP code retained in this sensitive value.
    #[must_use]
    pub const fn code(&self) -> AvpCode {
        self.code
    }

    /// Vendor identifier retained in this sensitive value.
    #[must_use]
    pub const fn vendor_id(&self) -> Option<VendorId> {
        self.vendor_id
    }

    /// Byte offset of the AVP relative to the request start.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Length from the AVP header, excluding padding.
    #[must_use]
    pub const fn declared_len(&self) -> u32 {
        self.declared_len
    }

    /// Retained wire length, including canonical padding.
    #[must_use]
    pub fn retained_wire_len(&self) -> usize {
        self.wire.len()
    }
}

impl fmt::Debug for DiameterSensitiveAvp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterSensitiveAvp")
            .field("code", &self.code)
            .field("vendor_id", &self.vendor_id)
            .field("offset", &self.offset)
            .field("declared_len", &self.declared_len)
            .field("retained_wire_len", &self.wire.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for DiameterSensitiveAvp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "diameter_sensitive_avp(code={},vendor={},offset={},length={},value=<redacted>)",
            self.code.get(),
            self.vendor_id.map_or(0, VendorId::get),
            self.offset,
            self.declared_len
        )
    }
}

/// Bounded, redaction-safe AVP value used inside `Failed-AVP`.
///
/// A value can be copied from a successfully framed AVP, synthesized for a
/// missing or malformed AVP, and wrapped in one or more grouped ancestors.
/// The encoded hierarchy is private so formatting can never reveal its value.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterFailedAvp {
    leaf_code: AvpCode,
    leaf_vendor_id: Option<VendorId>,
    leaf_offset: Option<usize>,
    ordering_offset: Option<usize>,
    reported_len: Option<u32>,
    hierarchy_depth: usize,
    wire: Bytes,
    source_wire_digest: Option<[u8; 32]>,
    source_wire_len: Option<usize>,
    malformed_header: Option<Bytes>,
    ancestors: Vec<FailedAvpAncestorProvenance>,
    sibling_set: Option<FailedAvpSiblingSetProvenance>,
}

impl DiameterFailedAvp {
    /// Copy one complete offending AVP, including its value, under `ctx`'s
    /// explicit message-size bound.
    pub fn copied(
        avp: &RawAvp<'_>,
        offset: usize,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        let wire = encode_raw_avp(avp.header.clone(), avp.value, avp.padding, true, ctx)?;
        let source_wire_digest = Some(digest_request(&wire));
        let source_wire_len = Some(wire.len());
        Ok(Self {
            leaf_code: avp.header.code,
            leaf_vendor_id: avp.header.vendor_id,
            leaf_offset: Some(offset),
            ordering_offset: Some(offset),
            reported_len: Some(avp.header.length),
            hierarchy_depth: 0,
            wire,
            source_wire_digest,
            source_wire_len,
            malformed_header: None,
            ancestors: Vec::new(),
            sibling_set: None,
        })
    }

    /// Synthesize the RFC 6733 missing-AVP shape with a zero-filled minimum
    /// value and the supplied Vendor-Id, when applicable.
    pub fn missing(
        header: AvpHeader,
        minimum_value_len: usize,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        let required = header
            .header_len()
            .checked_add(minimum_value_len)
            .ok_or_else(EncodeError::length_overflow)?;
        check_avp_declared_len(required)?;
        ctx.check_capacity(required)?;
        let zeros = vec![0_u8; minimum_value_len];
        let wire = encode_raw_avp(header.clone(), &zeros, &[], false, ctx)?;
        Ok(Self {
            leaf_code: header.code,
            leaf_vendor_id: header.vendor_id,
            leaf_offset: None,
            ordering_offset: None,
            reported_len: None,
            hierarchy_depth: 0,
            wire,
            source_wire_digest: None,
            source_wire_len: None,
            malformed_header: None,
            ancestors: Vec::new(),
            sibling_set: None,
        })
    }

    /// Synthesize a missing AVP directly from trusted dictionary metadata.
    ///
    /// Fixed-width data types receive their normative minimum zero-filled
    /// value. Variable-width and Grouped types use an empty minimum value.
    pub fn missing_for_definition(
        definition: &AvpDefinition,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        let header = header_for_definition(definition);
        Self::missing(header, minimum_value_len(definition.data_type()), ctx)
    }

    fn missing_sibling_set_within_group(
        definitions: &[&AvpDefinition],
        group: &RawAvp<'_>,
        group_offset: usize,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        if definitions.len() < 2 || definitions.len() > MAX_FAILED_AVP_HIERARCHY_DEPTH {
            return Err(structural_encode_error(
                "diameter Failed-AVP sibling set has invalid cardinality",
                "7.5",
            ));
        }
        let mut keys = Vec::with_capacity(definitions.len());
        let mut children = BytesMut::new();
        for definition in definitions {
            let key = definition.key();
            if keys.contains(&key) {
                return Err(structural_encode_error(
                    "diameter Failed-AVP sibling set contains duplicate definitions",
                    "7.5",
                ));
            }
            let child = Self::missing_for_definition(definition, ctx)?;
            children.extend_from_slice(child.wire());
            keys.push(key);
        }
        let source_wire =
            encode_raw_avp(group.header.clone(), group.value, group.padding, true, ctx)?;
        let wire = encode_raw_avp(group.header.clone(), &children, &[], false, ctx)?;
        let first = definitions
            .first()
            .ok_or_else(|| structural_encode_error("empty Failed-AVP sibling set", "7.5"))?;
        Ok(Self {
            leaf_code: first.key().code(),
            leaf_vendor_id: first.key().vendor_id(),
            leaf_offset: None,
            ordering_offset: Some(group_offset),
            reported_len: None,
            hierarchy_depth: 1,
            wire,
            source_wire_digest: None,
            source_wire_len: None,
            malformed_header: None,
            ancestors: vec![FailedAvpAncestorProvenance::Received {
                key: group.header.key(),
                offset: group_offset,
                wire_len: source_wire.len(),
                wire_digest: digest_request(&source_wire),
            }],
            sibling_set: Some(FailedAvpSiblingSetProvenance::Missing {
                keys: keys.into_boxed_slice(),
            }),
        })
    }

    fn copied_sibling_set_within_group(
        selected: &[(RawAvp<'_>, usize)],
        group: &RawAvp<'_>,
        group_offset: usize,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        if selected.len() < 2 || selected.len() > MAX_FAILED_AVP_HIERARCHY_DEPTH {
            return Err(structural_encode_error(
                "diameter Failed-AVP sibling set has invalid cardinality",
                "7.5",
            ));
        }
        let first_reported_len = selected
            .first()
            .map(|(child, _)| child.header.length)
            .ok_or_else(|| {
                structural_encode_error("empty Failed-AVP received sibling set", "7.5")
            })?;
        let mut children_wire = BytesMut::new();
        let mut children = Vec::with_capacity(selected.len());
        let mut previous_offset = None;
        for (child, offset) in selected {
            if previous_offset.is_some_and(|previous| previous >= *offset)
                || children
                    .iter()
                    .any(|provenance: &FailedAvpReceivedChildProvenance| {
                        provenance.key == child.header.key()
                    })
            {
                return Err(structural_encode_error(
                    "diameter Failed-AVP received sibling set is not unique wire order",
                    "7.5",
                ));
            }
            let child_wire =
                encode_raw_avp(child.header.clone(), child.value, child.padding, true, ctx)?;
            children_wire.extend_from_slice(&child_wire);
            children.push(FailedAvpReceivedChildProvenance {
                key: child.header.key(),
                offset: *offset,
                wire_len: child_wire.len(),
                wire_digest: digest_request(&child_wire),
            });
            previous_offset = Some(*offset);
        }
        let source_wire =
            encode_raw_avp(group.header.clone(), group.value, group.padding, true, ctx)?;
        let wire = encode_raw_avp(group.header.clone(), &children_wire, &[], false, ctx)?;
        let first = children.first().ok_or_else(|| {
            structural_encode_error("empty Failed-AVP received sibling set", "7.5")
        })?;
        Ok(Self {
            leaf_code: first.key.code(),
            leaf_vendor_id: first.key.vendor_id(),
            leaf_offset: Some(first.offset),
            ordering_offset: Some(group_offset),
            reported_len: Some(first_reported_len),
            hierarchy_depth: 1,
            wire,
            source_wire_digest: None,
            source_wire_len: None,
            malformed_header: None,
            ancestors: vec![FailedAvpAncestorProvenance::Received {
                key: group.header.key(),
                offset: group_offset,
                wire_len: source_wire.len(),
                wire_digest: digest_request(&source_wire),
            }],
            sibling_set: Some(FailedAvpSiblingSetProvenance::Received {
                children: children.into_boxed_slice(),
            }),
        })
    }

    /// Synthesize an RFC 6733 invalid-length context from an incomplete or
    /// contradictory AVP header.
    ///
    /// At most the fixed AVP header is inspected. Missing header octets are
    /// treated as zero, and no suffix or declared value bytes are copied.
    pub fn malformed(
        available_header: &[u8],
        offset: usize,
        minimum_value_len: usize,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        let retained_header = available_header
            .get(..available_header.len().min(AVP_VENDOR_HEADER_LEN))
            .unwrap_or_default();
        let mut fixed = [0_u8; AVP_VENDOR_HEADER_LEN];
        let copied = retained_header.len();
        fixed[..copied].copy_from_slice(retained_header);
        let code = AvpCode::new(u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]));
        let flags = AvpFlags::from_bits(fixed[4]);
        let reported_len =
            (available_header.len() >= AVP_HEADER_LEN).then(|| read_u24(&fixed[5..8]));
        let vendor_id = flags.is_vendor_specific().then(|| {
            VendorId::new(u32::from_be_bytes([
                fixed[8], fixed[9], fixed[10], fixed[11],
            ]))
        });
        let header = AvpHeader {
            code,
            flags,
            length: if flags.is_vendor_specific() {
                AVP_VENDOR_HEADER_LEN as u32
            } else {
                AVP_HEADER_LEN as u32
            },
            vendor_id,
        };
        let required = header
            .header_len()
            .checked_add(minimum_value_len)
            .ok_or_else(EncodeError::length_overflow)?;
        check_avp_declared_len(required)?;
        ctx.check_capacity(required)?;
        let zeros = vec![0_u8; minimum_value_len];
        let wire = encode_raw_avp(header, &zeros, &[], false, raw_encode_context(ctx))?;
        Ok(Self {
            leaf_code: code,
            leaf_vendor_id: vendor_id,
            leaf_offset: Some(offset),
            ordering_offset: Some(offset),
            reported_len,
            hierarchy_depth: 0,
            wire,
            source_wire_digest: None,
            source_wire_len: None,
            malformed_header: Some(Bytes::copy_from_slice(retained_header)),
            ancestors: Vec::new(),
            sibling_set: None,
        })
    }

    /// Synthesize invalid-length context using a trusted dictionary's minimum
    /// value length while retaining the received fixed-header identity.
    pub fn malformed_for_definition(
        available_header: &[u8],
        offset: usize,
        definition: &AvpDefinition,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        Self::malformed(
            available_header,
            offset,
            minimum_value_len(definition.data_type()),
            ctx,
        )
    }

    /// Wrap this failure in one received grouped AVP header, retaining only
    /// the hierarchy down to the selected first failure.
    pub fn within_group(
        self,
        group: &RawAvp<'_>,
        group_offset: usize,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        if self
            .leaf_offset
            .is_some_and(|leaf_offset| group_offset > leaf_offset)
        {
            return Err(structural_encode_error(
                "diameter Failed-AVP grouped ancestor offset follows its leaf",
                "7.5",
            ));
        }
        let depth = self
            .hierarchy_depth
            .checked_add(1)
            .ok_or_else(EncodeError::length_overflow)?;
        if depth > MAX_FAILED_AVP_HIERARCHY_DEPTH {
            return Err(structural_encode_error(
                "diameter Failed-AVP grouped hierarchy exceeds its fixed depth bound",
                "7.5",
            ));
        }
        let source_wire =
            encode_raw_avp(group.header.clone(), group.value, group.padding, true, ctx)?;
        let wire = encode_raw_avp(group.header.clone(), &self.wire, &[], false, ctx)?;
        let mut ancestors = self.ancestors;
        ancestors.push(FailedAvpAncestorProvenance::Received {
            key: group.header.key(),
            offset: group_offset,
            wire_len: source_wire.len(),
            wire_digest: digest_request(&source_wire),
        });
        Ok(Self {
            leaf_code: self.leaf_code,
            leaf_vendor_id: self.leaf_vendor_id,
            leaf_offset: self.leaf_offset,
            ordering_offset: Some(group_offset),
            reported_len: self.reported_len,
            hierarchy_depth: depth,
            wire,
            source_wire_digest: self.source_wire_digest,
            source_wire_len: self.source_wire_len,
            malformed_header: self.malformed_header,
            ancestors,
            sibling_set: self.sibling_set,
        })
    }

    /// Wrap a synthesized missing leaf in a synthesized grouped ancestor.
    ///
    /// Neither the leaf nor the ancestor is assigned a fictitious request
    /// offset. Repeated calls build an RFC 6733 section 7.5 parent-relative
    /// hierarchy for a missing child nested in one or more Grouped AVPs.
    pub fn within_missing_group(
        self,
        definition: &AvpDefinition,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        if definition.data_type() != AvpDataType::Grouped {
            return Err(structural_encode_error(
                "diameter Failed-AVP missing ancestor must be Grouped",
                "7.5",
            ));
        }
        let depth = self
            .hierarchy_depth
            .checked_add(1)
            .ok_or_else(EncodeError::length_overflow)?;
        if depth > MAX_FAILED_AVP_HIERARCHY_DEPTH {
            return Err(structural_encode_error(
                "diameter Failed-AVP grouped hierarchy exceeds its fixed depth bound",
                "7.5",
            ));
        }
        let wire = encode_raw_avp(
            header_for_definition(definition),
            &self.wire,
            &[],
            false,
            ctx,
        )?;
        let mut ancestors = self.ancestors;
        ancestors.push(FailedAvpAncestorProvenance::Missing {
            key: definition.key(),
        });
        Ok(Self {
            leaf_code: self.leaf_code,
            leaf_vendor_id: self.leaf_vendor_id,
            leaf_offset: self.leaf_offset,
            ordering_offset: self.ordering_offset,
            reported_len: self.reported_len,
            hierarchy_depth: depth,
            wire,
            source_wire_digest: self.source_wire_digest,
            source_wire_len: self.source_wire_len,
            malformed_header: self.malformed_header,
            ancestors,
            sibling_set: self.sibling_set,
        })
    }

    fn from_sensitive(value: DiameterSensitiveAvp) -> Self {
        Self {
            leaf_code: value.code,
            leaf_vendor_id: value.vendor_id,
            leaf_offset: Some(value.offset),
            ordering_offset: Some(value.offset),
            reported_len: Some(value.declared_len),
            hierarchy_depth: 0,
            source_wire_digest: Some(digest_request(&value.wire)),
            source_wire_len: Some(value.wire.len()),
            wire: value.wire,
            malformed_header: None,
            ancestors: Vec::new(),
            sibling_set: None,
        }
    }

    fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// First evidence-child AVP code represented by this failure context.
    ///
    /// Ordinary evidence has one leaf. A missing sibling set reports its first
    /// normative example; a received sibling set reports its first wire-order
    /// child.
    #[must_use]
    pub const fn leaf_code(&self) -> AvpCode {
        self.leaf_code
    }

    /// Vendor-Id of the first evidence child represented by this context.
    #[must_use]
    pub const fn leaf_vendor_id(&self) -> Option<VendorId> {
        self.leaf_vendor_id
    }

    /// Request offset of the first selected evidence child, when received.
    ///
    /// Synthesized missing AVPs return `None`; they have no honest absolute
    /// location in the request.
    #[must_use]
    pub const fn leaf_offset(&self) -> Option<usize> {
        self.leaf_offset
    }

    /// Received AVP length when a complete length field was available.
    #[must_use]
    pub const fn reported_len(&self) -> Option<u32> {
        self.reported_len
    }

    /// Number of grouped ancestors retained around one or more evidence children.
    #[must_use]
    pub const fn hierarchy_depth(&self) -> usize {
        self.hierarchy_depth
    }

    /// Encoded hierarchy length placed inside `Failed-AVP`.
    #[must_use]
    pub fn retained_wire_len(&self) -> usize {
        self.wire.len()
    }
}

impl fmt::Debug for DiameterFailedAvp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterFailedAvp")
            .field("leaf_code", &self.leaf_code)
            .field("leaf_vendor_id", &self.leaf_vendor_id)
            .field("leaf_offset", &self.leaf_offset)
            .field("reported_len", &self.reported_len)
            .field("hierarchy_depth", &self.hierarchy_depth)
            .field("retained_wire_len", &self.wire.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for DiameterFailedAvp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "diameter_failed_avp(code={},vendor={},offset={:?},length={:?},depth={},value=<redacted>)",
            self.leaf_code.get(),
            self.leaf_vendor_id.map_or(0, VendorId::get),
            self.leaf_offset,
            self.reported_len,
            self.hierarchy_depth
        )
    }
}

/// Typed RFC 6733 request failure selected for an error answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiameterRequestFailure {
    /// Unsupported command code (`DIAMETER_COMMAND_UNSUPPORTED`, 3001).
    UnknownCommand,
    /// Unsupported application (`DIAMETER_APPLICATION_UNSUPPORTED`, 3007).
    UnsupportedApplication,
    /// Invalid request-header flag combination (3008).
    InvalidHeaderBits,
    /// Invalid AVP flag bits (3009).
    InvalidAvpBits(DiameterFailedAvp),
    /// Unsupported AVP carrying the Mandatory bit (5001).
    UnsupportedMandatoryAvp(DiameterFailedAvp),
    /// Invalid AVP value (5004).
    InvalidAvpValue(DiameterFailedAvp),
    /// Missing required AVP (5005).
    MissingMandatoryAvp(DiameterFailedAvp),
    /// AVP forbidden by the command grammar (5008).
    ForbiddenAvp(DiameterFailedAvp),
    /// First AVP occurrence beyond a singleton cardinality (5009).
    ExcessSingleton(DiameterFailedAvp),
    /// Mutually exclusive grouped children were present together (5009).
    MutuallyExclusiveAvps(DiameterFailedAvp),
    /// Unsupported Diameter version (5011).
    UnsupportedVersion,
    /// A reserved Diameter header bit was set (5013).
    InvalidBitInHeader,
    /// Invalid AVP length (5014).
    InvalidAvpLength(DiameterFailedAvp),
}

impl DiameterRequestFailure {
    /// RFC 6733 Result-Code value for this failure.
    #[must_use]
    pub const fn result_code(&self) -> u32 {
        match self {
            Self::UnknownCommand => RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
            Self::UnsupportedApplication => RESULT_CODE_DIAMETER_APPLICATION_UNSUPPORTED,
            Self::InvalidHeaderBits => RESULT_CODE_DIAMETER_INVALID_HDR_BITS,
            Self::InvalidAvpBits(_) => RESULT_CODE_DIAMETER_INVALID_AVP_BITS,
            Self::UnsupportedMandatoryAvp(_) => RESULT_CODE_DIAMETER_AVP_UNSUPPORTED,
            Self::InvalidAvpValue(_) => RESULT_CODE_DIAMETER_INVALID_AVP_VALUE,
            Self::MissingMandatoryAvp(_) => RESULT_CODE_DIAMETER_MISSING_AVP,
            Self::ForbiddenAvp(_) => RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED,
            Self::ExcessSingleton(_) | Self::MutuallyExclusiveAvps(_) => {
                RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES
            }
            Self::UnsupportedVersion => RESULT_CODE_DIAMETER_UNSUPPORTED_VERSION,
            Self::InvalidBitInHeader => RESULT_CODE_DIAMETER_INVALID_BIT_IN_HEADER,
            Self::InvalidAvpLength(_) => RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH,
        }
    }

    /// Stable redaction-safe failure code for logs and metrics.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownCommand => "diameter_command_unsupported",
            Self::UnsupportedApplication => "diameter_application_unsupported",
            Self::InvalidHeaderBits => "diameter_invalid_header_bits",
            Self::InvalidAvpBits(_) => "diameter_invalid_avp_bits",
            Self::UnsupportedMandatoryAvp(_) => "diameter_avp_unsupported",
            Self::InvalidAvpValue(_) => "diameter_invalid_avp_value",
            Self::MissingMandatoryAvp(_) => "diameter_missing_avp",
            Self::ForbiddenAvp(_) => "diameter_avp_not_allowed",
            Self::ExcessSingleton(_) | Self::MutuallyExclusiveAvps(_) => {
                "diameter_avp_occurs_too_many_times"
            }
            Self::UnsupportedVersion => "diameter_unsupported_version",
            Self::InvalidBitInHeader => "diameter_invalid_bit_in_header",
            Self::InvalidAvpLength(_) => "diameter_invalid_avp_length",
        }
    }

    /// Return whether RFC 6733 requires the Error bit for this result class.
    #[must_use]
    pub const fn is_protocol_error(&self) -> bool {
        let code = self.result_code();
        code >= 3000 && code < 4000
    }

    /// Selected `Failed-AVP` context, when this result requires one.
    #[must_use]
    pub const fn failed_avp(&self) -> Option<&DiameterFailedAvp> {
        match self {
            Self::InvalidAvpBits(value)
            | Self::UnsupportedMandatoryAvp(value)
            | Self::InvalidAvpValue(value)
            | Self::MissingMandatoryAvp(value)
            | Self::ForbiddenAvp(value)
            | Self::ExcessSingleton(value)
            | Self::MutuallyExclusiveAvps(value)
            | Self::InvalidAvpLength(value) => Some(value),
            Self::UnknownCommand
            | Self::UnsupportedApplication
            | Self::InvalidHeaderBits
            | Self::UnsupportedVersion
            | Self::InvalidBitInHeader => None,
        }
    }

    /// Map a generic decoder failure only after proving its request, command,
    /// AVP, offset, and local-policy provenance.
    ///
    /// `request` must be the exact bytes used to create `envelope` and to
    /// produce `error`. The function fails closed when a header-origin error,
    /// dictionary ambiguity, optional-unknown local rejection, repeatable
    /// duplicate, or imprecise offset could otherwise be mislabeled as a peer
    /// error. No caller-supplied `Failed-AVP` can be paired with an unrelated
    /// decoder error.
    pub fn from_decode_error(
        envelope: &DiameterRequestEnvelope,
        request: &[u8],
        error: &DecodeError,
        decode_ctx: DecodeContext,
        dictionaries: DictionarySet<'_>,
        encode_ctx: EncodeContext,
    ) -> Result<DiameterBoundRequestFailure, DiameterFailureMappingError> {
        envelope.verify_request(request)?;
        if let Some(failure) = envelope
            .classify(request, dictionaries)
            .map_err(DiameterFailureMappingError::from_classification)?
        {
            if failure_precedes_offset(failure.failure(), error.offset()) {
                return Ok(failure);
            }
        }
        let command = dictionaries
            .resolve_command(
                envelope.application_id,
                envelope.command_code,
                CommandKind::Request,
            )
            .map_err(|lookup| match lookup {
                CommandLookupError::Missing => DiameterFailureMappingError::CommandMissing,
                CommandLookupError::Ambiguous => DiameterFailureMappingError::CommandAmbiguous,
            })?;
        let location = match error.code() {
            DecodeErrorCode::UnknownCriticalIe | DecodeErrorCode::DuplicateIe => {
                AvpErrorLocation::Header
            }
            DecodeErrorCode::InvalidEnumValue { .. } => AvpErrorLocation::Value,
            DecodeErrorCode::InvalidLength { .. } => AvpErrorLocation::HeaderOrValue,
            DecodeErrorCode::Structural { .. } => AvpErrorLocation::Header,
            _ => return Err(DiameterFailureMappingError::Unclassified),
        };
        let located = locate_complete_top_level_avp(request, error.offset(), location)?;

        let failed = || {
            DiameterFailedAvp::copied(&located.avp, located.offset, encode_ctx)
                .map_err(DiameterFailureMappingError::FailedAvpEncoding)
        };
        let at_header = error.offset() == located.offset;
        let value_offset = located
            .offset
            .checked_add(located.avp.header.header_len())
            .ok_or(DiameterFailureMappingError::OffsetAmbiguous)?;
        let at_value = error.offset() == value_offset;
        let failure = match error.code() {
            DecodeErrorCode::UnknownCriticalIe if at_header => {
                let key = located.avp.header.key();
                match unique_avp_definition(dictionaries, key)? {
                    Some(_) => match command.find_avp_rule(key).map(|rule| rule.cardinality()) {
                        Some(AvpCardinality::Forbidden) => Self::ForbiddenAvp(failed()?),
                        Some(AvpCardinality::ZeroOrOne | AvpCardinality::ZeroOrMore) => {
                            return Err(DiameterFailureMappingError::ProvenanceMismatch);
                        }
                        None => return Err(DiameterFailureMappingError::CommandAvpRuleAbsent),
                    },
                    None if located.avp.header.flags.is_mandatory() => {
                        Self::UnsupportedMandatoryAvp(failed()?)
                    }
                    None if decode_ctx.unknown_ie_policy == UnknownIePolicy::Reject => {
                        return Err(DiameterFailureMappingError::LocalUnknownOptionalRejected);
                    }
                    None => return Err(DiameterFailureMappingError::ProvenanceMismatch),
                }
            }
            DecodeErrorCode::DuplicateIe if at_header => {
                let key = located.avp.header.key();
                if earlier_top_level_key_count(request, located.offset, key)? != 1 {
                    return Err(DiameterFailureMappingError::ProvenanceMismatch);
                }
                match command.find_avp_rule(key).map(|rule| rule.cardinality()) {
                    Some(AvpCardinality::ZeroOrOne) => Self::ExcessSingleton(failed()?),
                    Some(AvpCardinality::ZeroOrMore) => {
                        return Err(DiameterFailureMappingError::RepeatableDuplicate);
                    }
                    Some(AvpCardinality::Forbidden) => {
                        return Err(DiameterFailureMappingError::ProvenanceMismatch);
                    }
                    None => return Err(DiameterFailureMappingError::CommandAvpRuleAbsent),
                }
            }
            DecodeErrorCode::InvalidEnumValue { .. } if at_value => {
                Self::InvalidAvpValue(failed()?)
            }
            DecodeErrorCode::InvalidLength { .. } if at_value || at_header => {
                let failed = match unique_avp_definition(dictionaries, located.avp.header.key())? {
                    Some(definition) => DiameterFailedAvp::malformed_for_definition(
                        located_avp_wire(request, &located)?,
                        located.offset,
                        definition,
                        encode_ctx,
                    )
                    .map_err(DiameterFailureMappingError::FailedAvpEncoding)?,
                    None => DiameterFailedAvp::malformed(
                        located_avp_wire(request, &located)?,
                        located.offset,
                        0,
                        encode_ctx,
                    )
                    .map_err(DiameterFailureMappingError::FailedAvpEncoding)?,
                };
                Self::InvalidAvpLength(failed)
            }
            // A truncation offset normally points to the unavailable suffix,
            // not to a complete AVP identity. Inspection owns those cases.
            DecodeErrorCode::Truncated => {
                return Err(DiameterFailureMappingError::OffsetAmbiguous);
            }
            _ => return Err(DiameterFailureMappingError::Unclassified),
        };
        Ok(envelope.bind_failure(failure))
    }

    /// Map an SDK typed-parser failure to an exact request-bound error answer.
    ///
    /// Missing mandatory AVPs are accepted only from sealed SDK parser
    /// provenance tied to the byte-identical declared Diameter message boundary
    /// (not bytes following that boundary in the supplied input). The parser's application,
    /// command, request role, and exact vendor-aware AVP schema must match the
    /// inspected envelope and exactly one supplied dictionary definition. The
    /// resulting `Failed-AVP` minimum value and Vendor-Id are derived from that
    /// definition, then the ordinary checked application binder proves the AVP
    /// is absent.
    /// Earlier header, application, command, P-bit, framing, flag, forbidden,
    /// excess, or unsupported-AVP failures always win.
    ///
    /// Typed parser errors without missing-AVP provenance delegate to
    /// [`Self::from_decode_error`] and retain all of its offset and local-policy
    /// checks.
    pub fn from_parser_error(
        envelope: &DiameterRequestEnvelope,
        request: &[u8],
        error: &DiameterParserError,
        decode_ctx: DecodeContext,
        dictionaries: DictionarySet<'_>,
        encode_ctx: EncodeContext,
    ) -> Result<DiameterBoundRequestFailure, DiameterFailureMappingError> {
        envelope.verify_request(request)?;
        if !error.matches_request(request) {
            return Err(DiameterFailureMappingError::ParserRequestMismatch);
        }
        if error.missing_avp().is_none() && error.grouped_avp_set_provenance().is_none() {
            return Self::from_decode_error(
                envelope,
                request,
                error.decode_error(),
                decode_ctx,
                dictionaries,
                encode_ctx,
            );
        };
        if let Some(failure) = envelope
            .classify(request, dictionaries)
            .map_err(DiameterFailureMappingError::from_classification)?
        {
            return Ok(failure);
        }
        if !matches!(
            error.decode_error().code(),
            DecodeErrorCode::Structural { .. }
        ) {
            return Err(DiameterFailureMappingError::ParserProvenanceMismatch);
        }
        if let Some(missing) = error.missing_avp() {
            verify_parser_command(
                envelope,
                missing.application_id(),
                missing.command_code(),
                missing.command_kind(),
                dictionaries,
            )?;
            let definition =
                resolve_parser_definition(dictionaries, missing.key(), missing.definition())?;
            let failed = if let Some(parent) = missing.parent() {
                let located = locate_exact_top_level_avp(request, parent.offset(), parent.key())?;
                let parent_definition =
                    resolve_parser_definition(dictionaries, parent.key(), parent.definition())?;
                if parent_definition.data_type() != AvpDataType::Grouped
                    || error.decode_error().offset()
                        != parent
                            .offset()
                            .checked_add(located.avp.header.header_len())
                            .ok_or(DiameterFailureMappingError::ParserProvenanceMismatch)?
                {
                    return Err(DiameterFailureMappingError::ParserProvenanceMismatch);
                }
                DiameterFailedAvp::missing_for_definition(definition, encode_ctx)
                    .and_then(|failed| {
                        failed.within_group(&located.avp, located.offset, encode_ctx)
                    })
                    .map_err(DiameterFailureMappingError::FailedAvpEncoding)?
            } else {
                if error.decode_error().offset() != DIAMETER_HEADER_LEN {
                    return Err(DiameterFailureMappingError::ParserProvenanceMismatch);
                }
                DiameterFailedAvp::missing_for_definition(definition, encode_ctx)
                    .map_err(DiameterFailureMappingError::FailedAvpEncoding)?
            };
            return envelope
                .bind_application_failure(request, Self::MissingMandatoryAvp(failed), dictionaries)
                .map_err(DiameterFailureMappingError::from_classification);
        }

        let grouped = error
            .grouped_avp_set_provenance()
            .ok_or(DiameterFailureMappingError::ParserProvenanceMismatch)?;
        verify_parser_command(
            envelope,
            grouped.application_id(),
            grouped.command_code(),
            grouped.command_kind(),
            dictionaries,
        )?;
        if grouped.definitions().len() < 2
            || grouped.definitions().len() > MAX_FAILED_AVP_HIERARCHY_DEPTH
        {
            return Err(DiameterFailureMappingError::ParserProvenanceMismatch);
        }
        let parent = grouped.parent();
        let located = locate_exact_top_level_avp(request, parent.offset(), parent.key())?;
        let parent_definition =
            resolve_parser_definition(dictionaries, parent.key(), parent.definition())?;
        if parent_definition.data_type() != AvpDataType::Grouped
            || error.decode_error().offset()
                != parent
                    .offset()
                    .checked_add(located.avp.header.header_len())
                    .ok_or(DiameterFailureMappingError::ParserProvenanceMismatch)?
        {
            return Err(DiameterFailureMappingError::ParserProvenanceMismatch);
        }
        let mut definitions = Vec::with_capacity(grouped.definitions().len());
        for definition in grouped.definitions() {
            let resolved = resolve_parser_definition(dictionaries, definition.key(), definition)?;
            if definitions
                .iter()
                .any(|existing: &&AvpDefinition| existing.key() == resolved.key())
                || parent_definition
                    .find_grouped_avp_rule(resolved.key())
                    .is_none_or(|rule| rule.cardinality().is_forbidden())
            {
                return Err(DiameterFailureMappingError::ParserProvenanceMismatch);
            }
            definitions.push(resolved);
        }
        let failure = match grouped.failure_kind() {
            DiameterGroupedAvpSetFailureKind::MissingOneOf => {
                let failed = DiameterFailedAvp::missing_sibling_set_within_group(
                    &definitions,
                    &located.avp,
                    located.offset,
                    encode_ctx,
                )
                .map_err(DiameterFailureMappingError::FailedAvpEncoding)?;
                Self::MissingMandatoryAvp(failed)
            }
            DiameterGroupedAvpSetFailureKind::MutuallyExclusivePresent => {
                let selected =
                    select_direct_grouped_children(&located.avp, located.offset, &definitions)?;
                let failed = DiameterFailedAvp::copied_sibling_set_within_group(
                    &selected,
                    &located.avp,
                    located.offset,
                    encode_ctx,
                )
                .map_err(DiameterFailureMappingError::FailedAvpEncoding)?;
                Self::MutuallyExclusiveAvps(failed)
            }
        };
        envelope
            .bind_application_failure(request, failure, dictionaries)
            .map_err(DiameterFailureMappingError::from_classification)
    }
}

/// A typed failure cryptographically bound to one inspected request envelope.
///
/// Values can be produced only by request classification, decoder-error
/// mapping, or the checked application-failure binding API. This prevents a
/// copied `Failed-AVP` from another request from being reflected in an answer.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterBoundRequestFailure {
    failure: DiameterRequestFailure,
    request_digest: [u8; 32],
    request_wire_len: usize,
}

impl DiameterBoundRequestFailure {
    /// Borrow the selected RFC 6733 failure.
    #[must_use]
    pub const fn failure(&self) -> &DiameterRequestFailure {
        &self.failure
    }

    /// RFC 6733 Result-Code value for the selected failure.
    #[must_use]
    pub const fn result_code(&self) -> u32 {
        self.failure.result_code()
    }

    /// Stable redaction-safe failure code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.failure.as_str()
    }

    fn matches(&self, envelope: &DiameterRequestEnvelope) -> bool {
        self.request_wire_len == envelope.request_wire_len
            && self.request_digest == envelope.request_digest
    }
}

impl fmt::Debug for DiameterBoundRequestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterBoundRequestFailure")
            .field("failure", &self.failure)
            .field("request_wire_len", &self.request_wire_len)
            .field("request_digest", &"<redacted>")
            .finish()
    }
}

/// Failure to map a generic decoder error without guessing protocol meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiameterFailureMappingError {
    /// The supplied request is not byte-identical to the inspected request.
    RequestMismatch,
    /// The typed parser failure was produced from a different request.
    ParserRequestMismatch,
    /// The parser's application, command, or role does not match the request.
    ParserCommandMismatch,
    /// Missing-field provenance is inconsistent with an SDK parser result.
    ParserProvenanceMismatch,
    /// No trusted command grammar exists for the request.
    CommandMissing,
    /// More than one non-identical application definition matches the request.
    ApplicationAmbiguous,
    /// More than one trusted command grammar matches the request.
    CommandAmbiguous,
    /// More than one AVP definition matches the received vendor-aware key.
    AvpDefinitionAmbiguous,
    /// No dictionary definition matches the parser's missing AVP schema key.
    MissingAvpDefinitionMissing,
    /// The resolved AVP definition differs from the parser's sealed SDK schema.
    MissingAvpDefinitionMismatch,
    /// The decoder rejected an optional unknown AVP only because of local policy.
    LocalUnknownOptionalRejected,
    /// The command grammar explicitly permits the duplicated AVP to repeat.
    RepeatableDuplicate,
    /// The command profile has no explicit occurrence rule for this AVP.
    CommandAvpRuleAbsent,
    /// The decoder offset cannot identify exactly one AVP start or value start.
    OffsetAmbiguous,
    /// The decoder category, flags, and exact offset do not have matching provenance.
    ProvenanceMismatch,
    /// The request AVP region is no longer structurally trustworthy.
    RequestAvpFramingInvalid,
    /// Bounded construction of the proven Failed-AVP failed.
    FailedAvpEncoding(EncodeError),
    /// The generic category is insufficient to choose an RFC 6733 result.
    Unclassified,
}

impl DiameterFailureMappingError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RequestMismatch => "diameter_error_mapping_request_mismatch",
            Self::ParserRequestMismatch => "diameter_error_mapping_parser_request_mismatch",
            Self::ParserCommandMismatch => "diameter_error_mapping_parser_command_mismatch",
            Self::ParserProvenanceMismatch => "diameter_error_mapping_parser_provenance_mismatch",
            Self::CommandMissing => "diameter_error_mapping_command_missing",
            Self::ApplicationAmbiguous => "diameter_error_mapping_application_ambiguous",
            Self::CommandAmbiguous => "diameter_error_mapping_command_ambiguous",
            Self::AvpDefinitionAmbiguous => "diameter_error_mapping_avp_definition_ambiguous",
            Self::MissingAvpDefinitionMissing => {
                "diameter_error_mapping_missing_avp_definition_missing"
            }
            Self::MissingAvpDefinitionMismatch => {
                "diameter_error_mapping_missing_avp_definition_mismatch"
            }
            Self::LocalUnknownOptionalRejected => {
                "diameter_error_mapping_local_unknown_optional_rejected"
            }
            Self::RepeatableDuplicate => "diameter_error_mapping_repeatable_duplicate",
            Self::CommandAvpRuleAbsent => "diameter_error_mapping_command_avp_rule_absent",
            Self::OffsetAmbiguous => "diameter_error_mapping_offset_ambiguous",
            Self::ProvenanceMismatch => "diameter_error_mapping_provenance_mismatch",
            Self::RequestAvpFramingInvalid => "diameter_error_mapping_request_avp_framing_invalid",
            Self::FailedAvpEncoding(_) => "diameter_error_mapping_failed_avp_encoding",
            Self::Unclassified => "diameter_decode_failure_unclassified",
        }
    }

    fn from_classification(error: DiameterRequestClassificationError) -> Self {
        match error {
            DiameterRequestClassificationError::RequestMismatch => Self::RequestMismatch,
            DiameterRequestClassificationError::ApplicationAmbiguous => Self::ApplicationAmbiguous,
            DiameterRequestClassificationError::CommandAmbiguous => Self::CommandAmbiguous,
            DiameterRequestClassificationError::AvpDefinitionAmbiguous => {
                Self::AvpDefinitionAmbiguous
            }
            DiameterRequestClassificationError::RequestAvpFramingInvalid => {
                Self::RequestAvpFramingInvalid
            }
            DiameterRequestClassificationError::FailureProvenanceMismatch => {
                Self::ProvenanceMismatch
            }
            DiameterRequestClassificationError::FailedAvpEncoding(error) => {
                Self::FailedAvpEncoding(error)
            }
        }
    }
}

impl fmt::Display for DiameterFailureMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DiameterFailureMappingError {}

/// Local failure to classify an inspected request without guessing peer fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiameterRequestClassificationError {
    /// The supplied bytes are not the exact inspected request.
    RequestMismatch,
    /// Multiple dictionaries define the selected application.
    ApplicationAmbiguous,
    /// Multiple dictionaries define the selected request command.
    CommandAmbiguous,
    /// Multiple dictionaries define a received vendor-aware AVP key.
    AvpDefinitionAmbiguous,
    /// The inspected AVP region could not be framed again exactly.
    RequestAvpFramingInvalid,
    /// Supplied application failure evidence does not belong to this request.
    FailureProvenanceMismatch,
    /// Bounded construction of a proven Failed-AVP failed.
    FailedAvpEncoding(EncodeError),
}

impl DiameterRequestClassificationError {
    /// Stable redaction-safe error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RequestMismatch => "diameter_request_classification_request_mismatch",
            Self::ApplicationAmbiguous => "diameter_request_classification_application_ambiguous",
            Self::CommandAmbiguous => "diameter_request_classification_command_ambiguous",
            Self::AvpDefinitionAmbiguous => {
                "diameter_request_classification_avp_definition_ambiguous"
            }
            Self::RequestAvpFramingInvalid => "diameter_request_classification_avp_framing_invalid",
            Self::FailureProvenanceMismatch => {
                "diameter_request_classification_failure_provenance_mismatch"
            }
            Self::FailedAvpEncoding(_) => "diameter_request_classification_failed_avp_encoding",
        }
    }
}

impl fmt::Display for DiameterRequestClassificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DiameterRequestClassificationError {}

/// Standards-based reason an input cannot safely receive an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterUnanswerableReason {
    /// The fixed 20-octet Diameter header is incomplete.
    TooShortForHeader,
    /// The Diameter header did not describe a request.
    NotARequest,
    /// The declared message length is shorter than the header or incomplete.
    UntrustworthyMessageBoundary,
    /// The declared message exceeds the caller's configured bound.
    MessageLengthExceeded,
    /// AVP count exceeded the caller's configured bound before all routing
    /// copies could be collected.
    AvpCountExceeded,
    /// Proxy-Info descent exceeded the caller's configured nesting bound.
    NestingDepthExceeded,
    /// A Proxy-Info routing AVP could not be safely canonicalized for copying.
    UntrustworthyProxyInfo,
}

impl DiameterUnanswerableReason {
    /// Stable redaction-safe reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooShortForHeader => "diameter_error_answer_too_short",
            Self::NotARequest => "diameter_error_answer_not_request",
            Self::UntrustworthyMessageBoundary => {
                "diameter_error_answer_untrustworthy_message_boundary"
            }
            Self::MessageLengthExceeded => "diameter_error_answer_message_length_exceeded",
            Self::AvpCountExceeded => "diameter_error_answer_avp_count_exceeded",
            Self::NestingDepthExceeded => "diameter_error_answer_nesting_depth_exceeded",
            Self::UntrustworthyProxyInfo => "diameter_error_answer_untrustworthy_proxy_info",
        }
    }
}

/// Bounded request metadata safe for RFC 6733 error-answer construction.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterRequestEnvelope {
    version: u8,
    command_code: CommandCode,
    application_id: ApplicationId,
    proxiable: bool,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    request_wire_len: usize,
    supplied_input_len: usize,
    request_digest: [u8; 32],
    max_depth: usize,
    session_id: Option<DiameterSensitiveAvp>,
    proxy_infos: Vec<DiameterSensitiveAvp>,
    first_failure: Option<DiameterRequestFailure>,
}

impl DiameterRequestEnvelope {
    /// Received Diameter version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Request command code.
    #[must_use]
    pub const fn command_code(&self) -> CommandCode {
        self.command_code
    }

    /// Request Application-Id.
    #[must_use]
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Request P-bit value.
    #[must_use]
    pub const fn is_proxiable(&self) -> bool {
        self.proxiable
    }

    /// Request Hop-by-Hop Identifier.
    #[must_use]
    pub const fn hop_by_hop_identifier(&self) -> u32 {
        self.hop_by_hop_identifier
    }

    /// Request End-to-End Identifier.
    #[must_use]
    pub const fn end_to_end_identifier(&self) -> u32 {
        self.end_to_end_identifier
    }

    /// Complete request boundary declared by the trusted header.
    #[must_use]
    pub const fn request_wire_len(&self) -> usize {
        self.request_wire_len
    }

    /// Bytes supplied to inspection, including any following stream data.
    #[must_use]
    pub const fn supplied_input_len(&self) -> usize {
        self.supplied_input_len
    }

    /// Retained Session-Id metadata, if one was present.
    #[must_use]
    pub const fn session_id(&self) -> Option<&DiameterSensitiveAvp> {
        self.session_id.as_ref()
    }

    /// Ordered retained Proxy-Info metadata.
    #[must_use]
    pub fn proxy_infos(&self) -> &[DiameterSensitiveAvp] {
        &self.proxy_infos
    }

    /// Provisional framing failure found by bounded inspection.
    ///
    /// This value is not request-bound and must not be passed directly to an
    /// answer builder. Use [`Self::classify`] or
    /// [`Self::bind_application_failure`] to obtain the checked, bound token.
    #[must_use]
    pub const fn first_failure(&self) -> Option<&DiameterRequestFailure> {
        self.first_failure.as_ref()
    }

    /// Select and bind the first boundary, dictionary, command-bit, or AVP-bit
    /// failure to this exact request.
    ///
    /// `request` must be the exact request inspected into this envelope. A
    /// missing application maps to 3007 and a missing command to 3001. Local
    /// dictionary ambiguity is returned as an error and never mislabeled as a
    /// peer failure. Once a unique command is resolved, the request P bit and
    /// all dictionary-known AVP M/P/V rules are validated.
    pub fn classify(
        &self,
        request: &[u8],
        dictionaries: DictionarySet<'_>,
    ) -> Result<Option<DiameterBoundRequestFailure>, DiameterRequestClassificationError> {
        self.verify_request(request)
            .map_err(|_| DiameterRequestClassificationError::RequestMismatch)?;
        if self
            .first_failure
            .as_ref()
            .is_some_and(is_header_inspection_failure)
        {
            let failure = self
                .first_failure
                .clone()
                .ok_or(DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
            let failure =
                finalize_malformed_failure(failure, dictionaries, envelope_encode_context(self))?;
            return Ok(Some(self.bind_failure(failure)));
        }
        match application_match_count(dictionaries, self.application_id) {
            0 => {
                return Ok(Some(
                    self.bind_failure(DiameterRequestFailure::UnsupportedApplication),
                ));
            }
            1 => {}
            _ => return Err(DiameterRequestClassificationError::ApplicationAmbiguous),
        }
        let command = match dictionaries.resolve_command(
            self.application_id,
            self.command_code,
            CommandKind::Request,
        ) {
            Ok(command) => command,
            Err(CommandLookupError::Missing) => {
                return Ok(Some(
                    self.bind_failure(DiameterRequestFailure::UnknownCommand),
                ));
            }
            Err(CommandLookupError::Ambiguous) => {
                return Err(DiameterRequestClassificationError::CommandAmbiguous);
            }
        };
        if command.proxiable() != self.proxiable {
            return Ok(Some(
                self.bind_failure(DiameterRequestFailure::InvalidHeaderBits),
            ));
        }
        let mut selected = self
            .first_failure
            .clone()
            .map(|failure| {
                finalize_malformed_failure(failure, dictionaries, envelope_encode_context(self))
            })
            .transpose()?
            .and_then(|failure| normalize_inspected_failure(failure, command));
        let scan_end = selected
            .as_ref()
            .and_then(DiameterRequestFailure::failed_avp)
            .and_then(|failed| failed.ordering_offset)
            .unwrap_or(self.request_wire_len);
        let avps = top_level_avps_before(request, scan_end)
            .map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
        let mut seen_singletons = Vec::new();
        for located in avps {
            let located = located
                .map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
            if invalid_dictionary_flags(&located.avp.header, dictionaries).map_err(|error| {
                match error {
                    DiameterFailureMappingError::AvpDefinitionAmbiguous => {
                        DiameterRequestClassificationError::AvpDefinitionAmbiguous
                    }
                    _ => DiameterRequestClassificationError::RequestAvpFramingInvalid,
                }
            })? {
                let candidate = DiameterRequestFailure::InvalidAvpBits(
                    DiameterFailedAvp::copied(
                        &located.avp,
                        located.offset,
                        envelope_encode_context(self),
                    )
                    .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?,
                );
                selected = Some(select_earlier_avp_failure(selected, candidate));
                continue;
            }
            if vendor_id_zero(&located.avp.header) {
                let candidate = DiameterRequestFailure::InvalidAvpValue(
                    DiameterFailedAvp::copied(
                        &located.avp,
                        located.offset,
                        envelope_encode_context(self),
                    )
                    .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?,
                );
                selected = Some(select_earlier_avp_failure(selected, candidate));
                continue;
            }
            let key = located.avp.header.key();
            let definition = unique_avp_definition_for_classification(dictionaries, key)?;
            if definition.is_none() && located.avp.header.flags.is_mandatory() {
                let candidate = DiameterRequestFailure::UnsupportedMandatoryAvp(
                    DiameterFailedAvp::copied(
                        &located.avp,
                        located.offset,
                        envelope_encode_context(self),
                    )
                    .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?,
                );
                selected = Some(select_earlier_avp_failure(selected, candidate));
                continue;
            }
            match command.find_avp_rule(key).map(|rule| rule.cardinality()) {
                Some(AvpCardinality::Forbidden) => {
                    let candidate = DiameterRequestFailure::ForbiddenAvp(
                        DiameterFailedAvp::copied(
                            &located.avp,
                            located.offset,
                            envelope_encode_context(self),
                        )
                        .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?,
                    );
                    selected = Some(select_earlier_avp_failure(selected, candidate));
                }
                Some(AvpCardinality::ZeroOrOne) => {
                    if seen_singletons.contains(&key) {
                        let candidate = DiameterRequestFailure::ExcessSingleton(
                            DiameterFailedAvp::copied(
                                &located.avp,
                                located.offset,
                                envelope_encode_context(self),
                            )
                            .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?,
                        );
                        selected = Some(select_earlier_avp_failure(selected, candidate));
                    } else {
                        seen_singletons.push(key);
                    }
                }
                Some(AvpCardinality::ZeroOrMore) | None => {}
            }
            if let Some(definition) = definition.filter(|definition| {
                definition.data_type() == AvpDataType::Grouped
                    && !definition.grouped_avp_rules().is_empty()
                    && command
                        .find_avp_rule(key)
                        .is_some_and(|rule| !rule.cardinality().is_forbidden())
            }) {
                if let Some(candidate) = classify_direct_grouped_failure(
                    &located.avp,
                    located.offset,
                    definition,
                    dictionaries,
                    envelope_encode_context(self),
                )? {
                    selected = Some(select_earlier_avp_failure(selected, candidate));
                }
            }
        }
        Ok(selected.map(|failure| self.bind_failure(failure)))
    }

    /// Bind a command-specific application failure to this exact request.
    ///
    /// The request is reclassified first, so an earlier header, application,
    /// command, P-bit, framing, or dictionary failure always wins. Received
    /// `Failed-AVP` evidence must byte-match the AVP at its retained request
    /// offset; missing-AVP evidence must resolve to exactly one dictionary
    /// definition. This is the application-parser path for 5004/5005/5008/5009
    /// results that cannot be inferred from generic framing alone.
    pub fn bind_application_failure(
        &self,
        request: &[u8],
        failure: DiameterRequestFailure,
        dictionaries: DictionarySet<'_>,
    ) -> Result<DiameterBoundRequestFailure, DiameterRequestClassificationError> {
        if let Some(first) = self.classify(request, dictionaries)? {
            if failure_precedes_candidate(first.failure(), &failure) {
                return Ok(first);
            }
        }
        let command = dictionaries
            .resolve_command(self.application_id, self.command_code, CommandKind::Request)
            .map_err(|error| match error {
                CommandLookupError::Missing => {
                    DiameterRequestClassificationError::RequestAvpFramingInvalid
                }
                CommandLookupError::Ambiguous => {
                    DiameterRequestClassificationError::CommandAmbiguous
                }
            })?;
        validate_application_failure(request, &failure, dictionaries, command, self.max_depth)?;
        Ok(self.bind_failure(failure))
    }

    fn bind_failure(&self, failure: DiameterRequestFailure) -> DiameterBoundRequestFailure {
        DiameterBoundRequestFailure {
            failure,
            request_digest: self.request_digest,
            request_wire_len: self.request_wire_len,
        }
    }

    fn verify_request(&self, request: &[u8]) -> Result<(), DiameterFailureMappingError> {
        let wire = request
            .get(..self.request_wire_len)
            .ok_or(DiameterFailureMappingError::RequestMismatch)?;
        if request.len() != self.supplied_input_len || digest_request(wire) != self.request_digest {
            return Err(DiameterFailureMappingError::RequestMismatch);
        }
        Ok(())
    }

    fn retained_routing_bytes(&self) -> usize {
        self.session_id
            .iter()
            .chain(self.proxy_infos.iter())
            .map(DiameterSensitiveAvp::retained_wire_len)
            .fold(0usize, usize::saturating_add)
    }

    fn retained_sensitive_bytes(&self) -> usize {
        let routing_bytes = self.retained_routing_bytes();
        self.first_failure
            .as_ref()
            .and_then(DiameterRequestFailure::failed_avp)
            .map_or(routing_bytes, |failure| {
                routing_bytes.saturating_add(failure.retained_wire_len())
            })
    }
}

impl fmt::Debug for DiameterRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterRequestEnvelope")
            .field("version", &self.version)
            .field("command_code", &self.command_code)
            .field("application_id", &self.application_id)
            .field("proxiable", &self.proxiable)
            .field("hop_by_hop_identifier", &self.hop_by_hop_identifier)
            .field("end_to_end_identifier", &self.end_to_end_identifier)
            .field("request_wire_len", &self.request_wire_len)
            .field("supplied_input_len", &self.supplied_input_len)
            .field("has_session_id", &self.session_id.is_some())
            .field("proxy_info_count", &self.proxy_infos.len())
            .field("retained_sensitive_bytes", &self.retained_sensitive_bytes())
            .field("first_failure", &self.first_failure)
            .finish()
    }
}

/// Result of bounded request inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiameterRequestInspection {
    /// No response may be constructed because correlation or the boundary is
    /// untrustworthy.
    Unanswerable(DiameterUnanswerableReason),
    /// A bounded request envelope is safe for typed error construction.
    Request(Box<DiameterRequestEnvelope>),
}

/// Inspect a Diameter request under caller-supplied decode limits.
///
/// The function never trusts a declared message length beyond the available
/// input or `ctx.max_message_len`. It copies no arbitrary AVP suffix: only one
/// Session-Id, ordered Proxy-Info AVPs, and one selected failure context are
/// retained, with aggregate size bounded by the trusted message boundary.
#[must_use]
pub fn inspect_diameter_request(input: &[u8], ctx: DecodeContext) -> DiameterRequestInspection {
    if input.len() < DIAMETER_HEADER_LEN {
        return DiameterRequestInspection::Unanswerable(
            DiameterUnanswerableReason::TooShortForHeader,
        );
    }
    let flags = CommandFlags::from_bits(input[4]);
    if !flags.is_request() {
        return DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::NotARequest);
    }
    let request_wire_len = read_u24(&input[1..4]) as usize;
    if request_wire_len < DIAMETER_HEADER_LEN || request_wire_len > input.len() {
        return DiameterRequestInspection::Unanswerable(
            DiameterUnanswerableReason::UntrustworthyMessageBoundary,
        );
    }
    if request_wire_len > ctx.max_message_len {
        return DiameterRequestInspection::Unanswerable(
            DiameterUnanswerableReason::MessageLengthExceeded,
        );
    }

    let version = input[0];
    let command_code = CommandCode::new(read_u24(&input[5..8]));
    let application_id = ApplicationId::new(u32::from_be_bytes([
        input[8], input[9], input[10], input[11],
    ]));
    let hop_by_hop_identifier = u32::from_be_bytes([input[12], input[13], input[14], input[15]]);
    let end_to_end_identifier = u32::from_be_bytes([input[16], input[17], input[18], input[19]]);
    let mut first_failure = if version != DIAMETER_VERSION {
        Some(DiameterRequestFailure::UnsupportedVersion)
    } else if flags.reserved_bits() != 0 {
        Some(DiameterRequestFailure::InvalidBitInHeader)
    } else if flags.is_error() {
        Some(DiameterRequestFailure::InvalidHeaderBits)
    } else {
        None
    };
    let mut session_id = None;
    let mut proxy_infos = Vec::new();
    let mut relative_offset = DIAMETER_HEADER_LEN;
    let mut avp_count = 0usize;
    while relative_offset < request_wire_len {
        avp_count = match avp_count.checked_add(1) {
            Some(value) => value,
            None => {
                return DiameterRequestInspection::Unanswerable(
                    DiameterUnanswerableReason::AvpCountExceeded,
                );
            }
        };
        if avp_count > ctx.max_ies {
            return DiameterRequestInspection::Unanswerable(
                DiameterUnanswerableReason::AvpCountExceeded,
            );
        }
        let remaining = &input[relative_offset..request_wire_len];
        if remaining.len() < AVP_HEADER_LEN {
            if first_failure.is_none() {
                match DiameterFailedAvp::malformed(
                    remaining,
                    relative_offset,
                    0,
                    encode_context_for_decode(ctx),
                ) {
                    Ok(failed) => {
                        first_failure = Some(DiameterRequestFailure::InvalidAvpLength(failed));
                    }
                    Err(_) => {
                        return DiameterRequestInspection::Unanswerable(
                            DiameterUnanswerableReason::UntrustworthyMessageBoundary,
                        );
                    }
                }
            }
            break;
        }
        let code = AvpCode::new(u32::from_be_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
        ]));
        let avp_flags = AvpFlags::from_bits(remaining[4]);
        let header_len = if avp_flags.is_vendor_specific() {
            AVP_VENDOR_HEADER_LEN
        } else {
            AVP_HEADER_LEN
        };
        let declared_len = read_u24(&remaining[5..8]);
        if remaining.len() < header_len || declared_len < header_len as u32 {
            if first_failure.is_none() {
                match DiameterFailedAvp::malformed(
                    remaining,
                    relative_offset,
                    0,
                    encode_context_for_decode(ctx),
                ) {
                    Ok(failed) => {
                        first_failure = Some(DiameterRequestFailure::InvalidAvpLength(failed));
                    }
                    Err(_) => {
                        return DiameterRequestInspection::Unanswerable(
                            DiameterUnanswerableReason::UntrustworthyMessageBoundary,
                        );
                    }
                }
            }
            break;
        }
        let declared_len_usize = declared_len as usize;
        let Some(padded_len) = align4(declared_len_usize) else {
            return DiameterRequestInspection::Unanswerable(
                DiameterUnanswerableReason::UntrustworthyMessageBoundary,
            );
        };
        if padded_len > remaining.len() {
            if first_failure.is_none() {
                match DiameterFailedAvp::malformed(
                    remaining,
                    relative_offset,
                    0,
                    encode_context_for_decode(ctx),
                ) {
                    Ok(failed) => {
                        first_failure = Some(DiameterRequestFailure::InvalidAvpLength(failed));
                    }
                    Err(_) => {
                        return DiameterRequestInspection::Unanswerable(
                            DiameterUnanswerableReason::UntrustworthyMessageBoundary,
                        );
                    }
                }
            }
            break;
        }
        let vendor_id = avp_flags.is_vendor_specific().then(|| {
            VendorId::new(u32::from_be_bytes([
                remaining[8],
                remaining[9],
                remaining[10],
                remaining[11],
            ]))
        });
        let header = AvpHeader {
            code,
            flags: avp_flags,
            length: declared_len,
            vendor_id,
        };
        let sensitive = match DiameterSensitiveAvp::from_complete_wire(
            &remaining[..padded_len],
            &header,
            relative_offset,
        ) {
            Ok(value) => value,
            Err(_) => {
                return DiameterRequestInspection::Unanswerable(
                    DiameterUnanswerableReason::UntrustworthyMessageBoundary,
                );
            }
        };
        if first_failure.is_none() && avp_flags.reserved_bits() != 0 {
            first_failure = Some(DiameterRequestFailure::InvalidAvpBits(
                DiameterFailedAvp::from_sensitive(sensitive.clone()),
            ));
        }
        if first_failure.is_none()
            && remaining[declared_len_usize..padded_len]
                .iter()
                .any(|byte| *byte != 0)
        {
            first_failure = Some(DiameterRequestFailure::InvalidAvpValue(
                DiameterFailedAvp::from_sensitive(sensitive.clone()),
            ));
        }
        if vendor_id.is_none() && code == AVP_SESSION_ID {
            if session_id.is_none() {
                session_id = Some(sensitive);
            } else if first_failure.is_none() {
                first_failure = Some(DiameterRequestFailure::ExcessSingleton(
                    DiameterFailedAvp::from_sensitive(sensitive),
                ));
            }
        } else if code == AVP_PROXY_INFO
            && (vendor_id.is_none() || vendor_id == Some(VendorId::new(0)))
        {
            match canonicalize_proxy_info(
                sensitive,
                &header,
                &remaining[..padded_len],
                ctx,
                encode_context_for_decode(ctx),
            ) {
                Ok((canonical, proxy_failure)) => {
                    if first_failure.is_none() {
                        first_failure = proxy_failure;
                    }
                    proxy_infos.push(canonical);
                }
                Err(error) => {
                    return DiameterRequestInspection::Unanswerable(error.reason());
                }
            }
        }
        relative_offset = match relative_offset.checked_add(padded_len) {
            Some(value) => value,
            None => {
                return DiameterRequestInspection::Unanswerable(
                    DiameterUnanswerableReason::UntrustworthyMessageBoundary,
                );
            }
        };
    }

    DiameterRequestInspection::Request(Box::new(DiameterRequestEnvelope {
        version,
        command_code,
        application_id,
        proxiable: flags.is_proxiable(),
        hop_by_hop_identifier,
        end_to_end_identifier,
        request_wire_len,
        supplied_input_len: input.len(),
        request_digest: digest_request(&input[..request_wire_len]),
        max_depth: ctx.max_depth.min(MAX_FAILED_AVP_HIERARCHY_DEPTH),
        session_id,
        proxy_infos,
        first_failure,
    }))
}

#[derive(Debug)]
enum ProxyInfoInspectionError {
    NestingDepthExceeded,
    AvpCountExceeded,
    Untrustworthy,
}

impl ProxyInfoInspectionError {
    const fn reason(&self) -> DiameterUnanswerableReason {
        match self {
            Self::NestingDepthExceeded => DiameterUnanswerableReason::NestingDepthExceeded,
            Self::AvpCountExceeded => DiameterUnanswerableReason::AvpCountExceeded,
            Self::Untrustworthy => DiameterUnanswerableReason::UntrustworthyProxyInfo,
        }
    }
}

impl From<EncodeError> for ProxyInfoInspectionError {
    fn from(_: EncodeError) -> Self {
        Self::Untrustworthy
    }
}

fn canonicalize_proxy_info(
    received: DiameterSensitiveAvp,
    received_header: &AvpHeader,
    received_wire: &[u8],
    decode_ctx: DecodeContext,
    encode_ctx: EncodeContext,
) -> Result<(DiameterSensitiveAvp, Option<DiameterRequestFailure>), ProxyInfoInspectionError> {
    if decode_ctx.max_depth < 1 {
        return Err(ProxyInfoInspectionError::NestingDepthExceeded);
    }
    let mut first_failure = if vendor_id_zero(received_header) {
        Some(DiameterRequestFailure::InvalidAvpValue(
            DiameterFailedAvp::from_sensitive(received.clone()),
        ))
    } else if received_header.vendor_id.is_some()
        || received_header.flags.bits() != AvpFlags::MANDATORY
    {
        Some(DiameterRequestFailure::InvalidAvpBits(
            DiameterFailedAvp::from_sensitive(received.clone()),
        ))
    } else {
        None
    };

    let outer_declared = usize::try_from(received_header.length)
        .map_err(|_| ProxyInfoInspectionError::Untrustworthy)?;
    let outer_padding = received_wire
        .get(outer_declared..)
        .ok_or(ProxyInfoInspectionError::Untrustworthy)?;
    let raw_group = RawAvp {
        header: received_header.clone(),
        value: received.value(),
        padding: outer_padding,
    };
    let mut canonical_children = BytesMut::new();
    let mut remaining = received.value();
    let mut relative_offset = 0usize;
    let mut proxy_host_count = 0usize;
    let mut proxy_state_count = 0usize;
    let mut child_count = 0usize;
    while !remaining.is_empty() {
        child_count = child_count
            .checked_add(1)
            .ok_or(ProxyInfoInspectionError::AvpCountExceeded)?;
        if child_count > decode_ctx.max_ies {
            return Err(ProxyInfoInspectionError::AvpCountExceeded);
        }
        if remaining.len() < AVP_HEADER_LEN {
            return Err(ProxyInfoInspectionError::Untrustworthy);
        }
        let flags = AvpFlags::from_bits(remaining[4]);
        let header_len = if flags.is_vendor_specific() {
            AVP_VENDOR_HEADER_LEN
        } else {
            AVP_HEADER_LEN
        };
        let declared = read_u24(&remaining[5..8]) as usize;
        let padded = align4(declared).ok_or(ProxyInfoInspectionError::Untrustworthy)?;
        if remaining.len() < header_len || declared < header_len || padded > remaining.len() {
            return Err(ProxyInfoInspectionError::Untrustworthy);
        }
        let code = AvpCode::new(u32::from_be_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
        ]));
        let vendor_id = flags.is_vendor_specific().then(|| {
            VendorId::new(u32::from_be_bytes([
                remaining[8],
                remaining[9],
                remaining[10],
                remaining[11],
            ]))
        });
        let child_header = AvpHeader {
            code,
            flags,
            length: u32::try_from(declared).map_err(|_| ProxyInfoInspectionError::Untrustworthy)?,
            vendor_id,
        };
        let child_offset = received
            .offset
            .checked_add(received_header.header_len())
            .and_then(|offset| offset.checked_add(relative_offset))
            .ok_or(ProxyInfoInspectionError::Untrustworthy)?;
        let child_wire = &remaining[..padded];
        let child = RawAvp {
            header: child_header.clone(),
            value: &remaining[header_len..declared],
            padding: &remaining[declared..padded],
        };
        let known_proxy_child =
            vendor_id.is_none() && matches!(code, AVP_PROXY_HOST | AVP_PROXY_STATE);
        let invalid_flags = flags.reserved_bits() != 0
            || flags.is_protected()
            || (known_proxy_child && !flags.is_mandatory());
        if first_failure.is_none() && invalid_flags {
            let failed = DiameterFailedAvp::copied(&child, child_offset, encode_ctx)?
                .within_group(&raw_group, received.offset, encode_ctx)?;
            first_failure = Some(DiameterRequestFailure::InvalidAvpBits(failed));
        }
        if first_failure.is_none() && vendor_id_zero(&child_header) {
            let failed = DiameterFailedAvp::copied(&child, child_offset, encode_ctx)?
                .within_group(&raw_group, received.offset, encode_ctx)?;
            first_failure = Some(DiameterRequestFailure::InvalidAvpValue(failed));
        }
        if first_failure.is_none() && child.padding.iter().any(|byte| *byte != 0) {
            let failed = DiameterFailedAvp::copied(&child, child_offset, encode_ctx)?
                .within_group(&raw_group, received.offset, encode_ctx)?;
            first_failure = Some(DiameterRequestFailure::InvalidAvpValue(failed));
        }

        if vendor_id.is_none() && code == AVP_PROXY_HOST {
            proxy_host_count = proxy_host_count
                .checked_add(1)
                .ok_or(ProxyInfoInspectionError::Untrustworthy)?;
            if first_failure.is_none() && proxy_host_count > 1 {
                let failed = DiameterFailedAvp::copied(&child, child_offset, encode_ctx)?
                    .within_group(&raw_group, received.offset, encode_ctx)?;
                first_failure = Some(DiameterRequestFailure::ExcessSingleton(failed));
            }
            if first_failure.is_none()
                && (child.value.is_empty() || core::str::from_utf8(child.value).is_err())
            {
                let failed = DiameterFailedAvp::copied(&child, child_offset, encode_ctx)?
                    .within_group(&raw_group, received.offset, encode_ctx)?;
                first_failure = Some(DiameterRequestFailure::InvalidAvpValue(failed));
            }
        } else if vendor_id.is_none() && code == AVP_PROXY_STATE {
            proxy_state_count = proxy_state_count
                .checked_add(1)
                .ok_or(ProxyInfoInspectionError::Untrustworthy)?;
            if first_failure.is_none() && proxy_state_count > 1 {
                let failed = DiameterFailedAvp::copied(&child, child_offset, encode_ctx)?
                    .within_group(&raw_group, received.offset, encode_ctx)?;
                first_failure = Some(DiameterRequestFailure::ExcessSingleton(failed));
            }
        }

        let canonical_header = if known_proxy_child {
            AvpHeader::ietf(code, true)
        } else if vendor_id == Some(VendorId::new(0)) {
            AvpHeader::ietf(code, flags.is_mandatory())
        } else {
            AvpHeader {
                code,
                flags: AvpFlags::new(vendor_id.is_some(), flags.is_mandatory(), false),
                length: if vendor_id.is_some() {
                    AVP_VENDOR_HEADER_LEN as u32
                } else {
                    AVP_HEADER_LEN as u32
                },
                vendor_id,
            }
        };
        append_avp(
            &mut canonical_children,
            canonical_header,
            child.value,
            encode_ctx,
        )?;
        relative_offset = relative_offset
            .checked_add(child_wire.len())
            .ok_or(ProxyInfoInspectionError::Untrustworthy)?;
        remaining = &remaining[padded..];
    }

    if first_failure.is_none() && proxy_host_count == 0 {
        first_failure = Some(DiameterRequestFailure::MissingMandatoryAvp(
            missing_proxy_child(AVP_PROXY_HOST, &raw_group, received.offset, encode_ctx)?,
        ));
    }
    if first_failure.is_none() && proxy_state_count == 0 {
        first_failure = Some(DiameterRequestFailure::MissingMandatoryAvp(
            missing_proxy_child(AVP_PROXY_STATE, &raw_group, received.offset, encode_ctx)?,
        ));
    }

    let canonical_header = AvpHeader::ietf(AVP_PROXY_INFO, true);
    let mut canonical_wire = BytesMut::new();
    append_avp(
        &mut canonical_wire,
        canonical_header.clone(),
        &canonical_children,
        encode_ctx,
    )?;
    let declared_len = canonical_header
        .header_len()
        .checked_add(canonical_children.len())
        .ok_or(ProxyInfoInspectionError::Untrustworthy)?;
    let canonical_header = AvpHeader {
        length: u32::try_from(declared_len).map_err(|_| ProxyInfoInspectionError::Untrustworthy)?,
        ..canonical_header
    };
    let canonical = DiameterSensitiveAvp::from_complete_wire(
        &canonical_wire,
        &canonical_header,
        received.offset,
    )?;
    Ok((canonical, first_failure))
}

fn missing_proxy_child(
    code: AvpCode,
    parent: &RawAvp<'_>,
    parent_offset: usize,
    ctx: EncodeContext,
) -> Result<DiameterFailedAvp, EncodeError> {
    let child = crate::base::dictionary()
        .find_avp(AvpKey::ietf(code))
        .ok_or_else(|| {
            structural_encode_error(
                "diameter base Proxy-Info child definition is missing",
                "6.7.2",
            )
        })?;
    DiameterFailedAvp::missing_for_definition(child, ctx)?.within_group(parent, parent_offset, ctx)
}

/// Local Origin-Host and Origin-Realm used by error answers.
///
/// Diagnostic output never exposes either identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DiameterErrorOrigin {
    origin_host: String,
    origin_realm: String,
}

impl DiameterErrorOrigin {
    /// Validate and construct the local error-answer origin.
    pub fn new(
        origin_host: impl Into<String>,
        origin_realm: impl Into<String>,
    ) -> Result<Self, DiameterErrorOriginError> {
        let origin_host = origin_host.into();
        let origin_realm = origin_realm.into();
        if origin_host.is_empty() {
            return Err(DiameterErrorOriginError::EmptyOriginHost);
        }
        if origin_realm.is_empty() {
            return Err(DiameterErrorOriginError::EmptyOriginRealm);
        }
        Ok(Self {
            origin_host,
            origin_realm,
        })
    }
}

impl fmt::Debug for DiameterErrorOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterErrorOrigin")
            .field("origin_host", &"<redacted>")
            .field("origin_realm", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for DiameterErrorOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiameterErrorOrigin(<redacted>)")
    }
}

/// Invalid local Origin identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterErrorOriginError {
    /// Origin-Host is empty.
    EmptyOriginHost,
    /// Origin-Realm is empty.
    EmptyOriginRealm,
}

impl DiameterErrorOriginError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyOriginHost => "diameter_error_origin_host_empty",
            Self::EmptyOriginRealm => "diameter_error_origin_realm_empty",
        }
    }
}

impl fmt::Display for DiameterErrorOriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DiameterErrorOriginError {}

/// Grammar selected for a request-bound negative answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiameterErrorAnswerGrammar {
    /// Use the command's ordinary application answer grammar. Permanent
    /// failures do not set E.
    Application,
    /// RFC 6733 section 7.2 E-bit grammar. Protocol errors always use this
    /// grammar; permanent failures use it only when deliberately selected as
    /// the section 7.1.5 fallback.
    Rfc6733ErrorBitFallback,
}

/// Redaction-safe response sizing for caller admission and rate policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiameterAmplificationMetadata {
    /// Trusted request boundary in octets.
    pub request_wire_len: usize,
    /// Exact planned response length in octets.
    pub planned_response_len: usize,
    /// Routing and Failed-AVP context bytes retained or synthesized while
    /// planning. Missing-AVP zero-fill is included conservatively.
    pub retained_request_bytes: usize,
}

/// Fully built, request-bound Diameter error answer.
///
/// The raw AVPs remain private and `Debug` is redacted. `to_owned_message` is
/// an explicit escape to the crate's existing raw forwarding surface.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterErrorAnswerPlan {
    header: Header,
    raw_avps: Bytes,
    request_wire_len: usize,
    retained_request_bytes: usize,
    result_code: u32,
    failure_code: &'static str,
    grammar: DiameterErrorAnswerGrammar,
}

impl DiameterErrorAnswerPlan {
    /// Result-Code carried by the answer.
    #[must_use]
    pub const fn result_code(&self) -> u32 {
        self.result_code
    }

    /// Stable selected failure code.
    #[must_use]
    pub const fn failure_code(&self) -> &'static str {
        self.failure_code
    }

    /// Effective wire grammar.
    ///
    /// Protocol errors always report the RFC 6733 section 7.2 grammar because
    /// every 3xxx answer necessarily sets E, even if the caller requested the
    /// ordinary application grammar.
    #[must_use]
    pub const fn grammar(&self) -> DiameterErrorAnswerGrammar {
        self.grammar
    }

    /// Whether the encoded answer sets RFC 6733's E bit.
    #[must_use]
    pub const fn has_error_bit(&self) -> bool {
        self.header.flags.is_error()
    }

    /// Exact planned response length.
    #[must_use]
    pub const fn planned_response_len(&self) -> usize {
        self.header.length as usize
    }

    /// Return bounded response-amplification metadata.
    #[must_use]
    pub const fn amplification_metadata(&self) -> DiameterAmplificationMetadata {
        DiameterAmplificationMetadata {
            request_wire_len: self.request_wire_len,
            planned_response_len: self.header.length as usize,
            retained_request_bytes: self.retained_request_bytes,
        }
    }

    /// Convert to the crate's explicit raw owned-message surface.
    ///
    /// # Logging safety
    ///
    /// Unlike this plan's redacted `Debug`, [`OwnedMessage`] exposes raw AVP
    /// bytes in its derived `Debug`. Treat the returned value as sensitive and
    /// never log or format it in production.
    #[must_use]
    pub fn to_owned_message(&self) -> OwnedMessage {
        OwnedMessage {
            header: self.header.clone(),
            raw_avps: self.raw_avps.clone(),
        }
    }
}

impl fmt::Debug for DiameterErrorAnswerPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterErrorAnswerPlan")
            .field("command_code", &self.header.command_code)
            .field("application_id", &self.header.application_id)
            .field("proxiable", &self.header.flags.is_proxiable())
            .field("error", &self.header.flags.is_error())
            .field("hop_by_hop_identifier", &self.header.hop_by_hop_identifier)
            .field("end_to_end_identifier", &self.header.end_to_end_identifier)
            .field("result_code", &self.result_code)
            .field("failure_code", &self.failure_code)
            .field("grammar", &self.grammar)
            .field("request_wire_len", &self.request_wire_len)
            .field("planned_response_len", &self.header.length)
            .field("retained_request_bytes", &self.retained_request_bytes)
            .field("avps", &"<redacted>")
            .finish()
    }
}

impl Encode for DiameterErrorAnswerPlan {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        ctx.check_capacity(self.planned_response_len())?;
        self.header.encode(dst, ctx)?;
        dst.put_slice(&self.raw_avps);
        Ok(())
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        ctx.check_capacity(self.planned_response_len())?;
        Ok(self.planned_response_len())
    }
}

/// Build one RFC 6733 request-bound error answer.
///
/// R and T are cleared, P and both identifiers are copied, Session-Id and
/// ordered Proxy-Info are retained, and request-only destination/routing AVPs
/// are never reflected. Protocol errors always use E. Permanent failures use E
/// only when [`DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback`] is chosen.
/// `failure` must be a token produced from this exact envelope by
/// [`DiameterRequestEnvelope::classify`],
/// [`DiameterRequestEnvelope::bind_application_failure`], or
/// [`DiameterRequestFailure::from_decode_error`].
pub fn build_diameter_error_answer(
    envelope: &DiameterRequestEnvelope,
    failure: &DiameterBoundRequestFailure,
    origin: &DiameterErrorOrigin,
    grammar: DiameterErrorAnswerGrammar,
    ctx: EncodeContext,
) -> Result<DiameterErrorAnswerPlan, EncodeError> {
    if !failure.matches(envelope) {
        return Err(structural_encode_error(
            "diameter error failure token does not match the request envelope",
            "7.2",
        ));
    }
    let failure = failure.failure();
    let error_bit = failure.is_protocol_error()
        || matches!(grammar, DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback);
    let effective_grammar = if error_bit {
        DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback
    } else {
        DiameterErrorAnswerGrammar::Application
    };
    let mut raw_avps_len = envelope.session_id.as_ref().map_or(Ok(0), |session_id| {
        ietf_avp_wire_len(session_id.value().len())
    })?;
    for value_len in [
        origin.origin_host.len(),
        origin.origin_realm.len(),
        core::mem::size_of::<u32>(),
    ] {
        raw_avps_len = raw_avps_len
            .checked_add(ietf_avp_wire_len(value_len)?)
            .ok_or_else(EncodeError::length_overflow)?;
    }
    if let Some(failed_avp) = failure.failed_avp() {
        raw_avps_len = raw_avps_len
            .checked_add(ietf_avp_wire_len(failed_avp.retained_wire_len())?)
            .ok_or_else(EncodeError::length_overflow)?;
    }
    for proxy_info in &envelope.proxy_infos {
        raw_avps_len = raw_avps_len
            .checked_add(proxy_info.retained_wire_len())
            .ok_or_else(EncodeError::length_overflow)?;
    }
    let length = DIAMETER_HEADER_LEN
        .checked_add(raw_avps_len)
        .ok_or_else(EncodeError::length_overflow)?;
    if length > MAX_U24 as usize {
        return Err(EncodeError::length_overflow().with_spec_ref(spec_ref("7.2")));
    }
    ctx.check_capacity(length)?;

    let mut raw_avps = BytesMut::with_capacity(raw_avps_len);
    if let Some(session_id) = envelope.session_id.as_ref() {
        append_avp(
            &mut raw_avps,
            AvpHeader::ietf(AVP_SESSION_ID, true),
            session_id.value(),
            ctx,
        )?;
    }
    append_avp(
        &mut raw_avps,
        AvpHeader::ietf(AVP_ORIGIN_HOST, true),
        origin.origin_host.as_bytes(),
        ctx,
    )?;
    append_avp(
        &mut raw_avps,
        AvpHeader::ietf(AVP_ORIGIN_REALM, true),
        origin.origin_realm.as_bytes(),
        ctx,
    )?;
    append_avp(
        &mut raw_avps,
        AvpHeader::ietf(AVP_RESULT_CODE, true),
        &failure.result_code().to_be_bytes(),
        ctx,
    )?;
    if let Some(failed_avp) = failure.failed_avp() {
        append_avp(
            &mut raw_avps,
            AvpHeader::ietf(AVP_FAILED_AVP, true),
            failed_avp.wire(),
            ctx,
        )?;
    }
    for proxy_info in &envelope.proxy_infos {
        raw_avps.put_slice(proxy_info.wire());
    }
    if raw_avps.len() != raw_avps_len {
        return Err(structural_encode_error(
            "diameter error-answer planned and encoded AVP lengths differ",
            "7.2",
        ));
    }
    let length = u32::try_from(length).map_err(|_| EncodeError::length_overflow())?;
    let header = Header::new(
        CommandFlags::answer(envelope.proxiable, error_bit),
        envelope.command_code,
        envelope.application_id,
        envelope.hop_by_hop_identifier,
        envelope.end_to_end_identifier,
    )
    .with_length(length);
    Ok(DiameterErrorAnswerPlan {
        header,
        raw_avps: raw_avps.freeze(),
        request_wire_len: envelope.request_wire_len,
        retained_request_bytes: failure.failed_avp().map_or_else(
            || envelope.retained_routing_bytes(),
            |failed_avp| {
                envelope
                    .retained_routing_bytes()
                    .saturating_add(failed_avp.retained_wire_len())
            },
        ),
        result_code: failure.result_code(),
        failure_code: failure.as_str(),
        grammar: effective_grammar,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AvpErrorLocation {
    Header,
    Value,
    HeaderOrValue,
}

struct LocatedAvp<'a> {
    offset: usize,
    avp: RawAvp<'a>,
}

struct TopLevelAvpIterator<'a> {
    remaining: &'a [u8],
    offset: usize,
    stop_offset: usize,
    failed: bool,
}

impl<'a> Iterator for TopLevelAvpIterator<'a> {
    type Item = Result<LocatedAvp<'a>, DiameterFailureMappingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() || self.offset >= self.stop_offset {
            return None;
        }
        let before = self.remaining.len();
        let decoded = RawAvp::decode(self.remaining, mapping_decode_context());
        let (next, avp) = match decoded {
            Ok(value) => value,
            Err(_) => {
                self.failed = true;
                return Some(Err(DiameterFailureMappingError::RequestAvpFramingInvalid));
            }
        };
        let consumed = match before.checked_sub(next.len()) {
            Some(value) if value != 0 => value,
            _ => {
                self.failed = true;
                return Some(Err(DiameterFailureMappingError::RequestAvpFramingInvalid));
            }
        };
        let offset = self.offset;
        self.offset = match self.offset.checked_add(consumed) {
            Some(value) => value,
            None => {
                self.failed = true;
                return Some(Err(DiameterFailureMappingError::RequestAvpFramingInvalid));
            }
        };
        self.remaining = next;
        Some(Ok(LocatedAvp { offset, avp }))
    }
}

fn top_level_avps(request: &[u8]) -> Result<TopLevelAvpIterator<'_>, DiameterFailureMappingError> {
    if request.len() < DIAMETER_HEADER_LEN {
        return Err(DiameterFailureMappingError::RequestMismatch);
    }
    let wire_len = read_u24(&request[1..4]) as usize;
    let remaining = request
        .get(DIAMETER_HEADER_LEN..wire_len)
        .ok_or(DiameterFailureMappingError::RequestMismatch)?;
    Ok(TopLevelAvpIterator {
        remaining,
        offset: DIAMETER_HEADER_LEN,
        stop_offset: wire_len,
        failed: false,
    })
}

fn verify_parser_command(
    envelope: &DiameterRequestEnvelope,
    application_id: ApplicationId,
    command_code: CommandCode,
    command_kind: CommandKind,
    dictionaries: DictionarySet<'_>,
) -> Result<(), DiameterFailureMappingError> {
    if command_kind != CommandKind::Request
        || application_id != envelope.application_id
        || command_code != envelope.command_code
    {
        return Err(DiameterFailureMappingError::ParserCommandMismatch);
    }
    dictionaries
        .resolve_command(application_id, command_code, command_kind)
        .map(|_| ())
        .map_err(|lookup| match lookup {
            CommandLookupError::Missing => DiameterFailureMappingError::CommandMissing,
            CommandLookupError::Ambiguous => DiameterFailureMappingError::CommandAmbiguous,
        })
}

fn resolve_parser_definition<'a>(
    dictionaries: DictionarySet<'a>,
    key: AvpKey,
    expected: &AvpDefinition,
) -> Result<&'a AvpDefinition, DiameterFailureMappingError> {
    let definition = unique_avp_definition(dictionaries, key)?
        .ok_or(DiameterFailureMappingError::MissingAvpDefinitionMissing)?;
    if definition != expected {
        return Err(DiameterFailureMappingError::MissingAvpDefinitionMismatch);
    }
    Ok(definition)
}

fn locate_exact_top_level_avp<'a>(
    request: &'a [u8],
    expected_offset: usize,
    expected_key: AvpKey,
) -> Result<LocatedAvp<'a>, DiameterFailureMappingError> {
    for located in top_level_avps(request)? {
        let located = located?;
        if located.offset > expected_offset {
            break;
        }
        if located.offset == expected_offset {
            return if located.avp.header.key() == expected_key {
                Ok(located)
            } else {
                Err(DiameterFailureMappingError::ParserProvenanceMismatch)
            };
        }
    }
    Err(DiameterFailureMappingError::ParserProvenanceMismatch)
}

fn select_direct_grouped_children<'a>(
    parent: &RawAvp<'a>,
    parent_offset: usize,
    definitions: &[&AvpDefinition],
) -> Result<Vec<(RawAvp<'a>, usize)>, DiameterFailureMappingError> {
    let mut counts = vec![0usize; definitions.len()];
    let mut selected = Vec::with_capacity(definitions.len());
    let mut remaining = parent.value;
    let mut offset = parent_offset
        .checked_add(parent.header.header_len())
        .ok_or(DiameterFailureMappingError::ParserProvenanceMismatch)?;
    while !remaining.is_empty() {
        let before = remaining.len();
        let (next, child) = RawAvp::decode(remaining, mapping_decode_context())
            .map_err(|_| DiameterFailureMappingError::RequestAvpFramingInvalid)?;
        if let Some((index, _)) = definitions
            .iter()
            .enumerate()
            .find(|(_, definition)| definition.key() == child.header.key())
        {
            counts[index] = counts[index]
                .checked_add(1)
                .ok_or(DiameterFailureMappingError::ParserProvenanceMismatch)?;
            selected.push((child, offset));
        }
        let consumed = before
            .checked_sub(next.len())
            .filter(|consumed| *consumed != 0)
            .ok_or(DiameterFailureMappingError::RequestAvpFramingInvalid)?;
        offset = offset
            .checked_add(consumed)
            .ok_or(DiameterFailureMappingError::ParserProvenanceMismatch)?;
        remaining = next;
    }
    if counts.iter().any(|count| *count != 1) || selected.len() != definitions.len() {
        return Err(DiameterFailureMappingError::ParserProvenanceMismatch);
    }
    Ok(selected)
}

fn top_level_avps_before(
    request: &[u8],
    stop_offset: usize,
) -> Result<TopLevelAvpIterator<'_>, DiameterFailureMappingError> {
    let mut avps = top_level_avps(request)?;
    avps.stop_offset = stop_offset.min(avps.stop_offset);
    Ok(avps)
}

fn locate_complete_top_level_avp<'a>(
    request: &'a [u8],
    error_offset: usize,
    location: AvpErrorLocation,
) -> Result<LocatedAvp<'a>, DiameterFailureMappingError> {
    let mut selected = None;
    for located in top_level_avps(request)? {
        let located = located?;
        let value_offset = located
            .offset
            .checked_add(located.avp.header.header_len())
            .ok_or(DiameterFailureMappingError::OffsetAmbiguous)?;
        let matches = match location {
            AvpErrorLocation::Header => error_offset == located.offset,
            AvpErrorLocation::Value => error_offset == value_offset,
            AvpErrorLocation::HeaderOrValue => {
                error_offset == located.offset || error_offset == value_offset
            }
        };
        if matches {
            if selected.is_some() {
                return Err(DiameterFailureMappingError::OffsetAmbiguous);
            }
            selected = Some(located);
        }
    }
    selected.ok_or(DiameterFailureMappingError::OffsetAmbiguous)
}

fn earlier_top_level_key_count(
    request: &[u8],
    selected_offset: usize,
    key: AvpKey,
) -> Result<usize, DiameterFailureMappingError> {
    let mut count = 0usize;
    for located in top_level_avps(request)? {
        let located = located?;
        if located.offset >= selected_offset {
            return Ok(count);
        }
        if located.avp.header.key() == key {
            count = count
                .checked_add(1)
                .ok_or(DiameterFailureMappingError::RequestAvpFramingInvalid)?;
        }
    }
    Ok(count)
}

fn located_avp_wire<'a>(
    request: &'a [u8],
    located: &LocatedAvp<'_>,
) -> Result<&'a [u8], DiameterFailureMappingError> {
    let declared = usize::try_from(located.avp.header.length)
        .map_err(|_| DiameterFailureMappingError::RequestAvpFramingInvalid)?;
    let padded = align4(declared).ok_or(DiameterFailureMappingError::RequestAvpFramingInvalid)?;
    let end = located
        .offset
        .checked_add(padded)
        .ok_or(DiameterFailureMappingError::RequestAvpFramingInvalid)?;
    request
        .get(located.offset..end)
        .ok_or(DiameterFailureMappingError::RequestAvpFramingInvalid)
}

fn unique_avp_definition<'a>(
    dictionaries: DictionarySet<'a>,
    key: AvpKey,
) -> Result<Option<&'a AvpDefinition>, DiameterFailureMappingError> {
    let mut selected = None;
    for candidate in dictionaries
        .dictionaries()
        .iter()
        .flat_map(|dictionary| dictionary.avps())
        .filter(|candidate| candidate.key() == key)
    {
        if selected.is_some_and(|existing| existing != candidate) {
            return Err(DiameterFailureMappingError::AvpDefinitionAmbiguous);
        }
        selected = Some(candidate);
    }
    Ok(selected)
}

fn unique_avp_definition_for_classification<'a>(
    dictionaries: DictionarySet<'a>,
    key: AvpKey,
) -> Result<Option<&'a AvpDefinition>, DiameterRequestClassificationError> {
    unique_avp_definition(dictionaries, key).map_err(|error| match error {
        DiameterFailureMappingError::AvpDefinitionAmbiguous => {
            DiameterRequestClassificationError::AvpDefinitionAmbiguous
        }
        _ => DiameterRequestClassificationError::RequestAvpFramingInvalid,
    })
}

const fn avp_key(code: AvpCode, vendor_id: Option<VendorId>) -> AvpKey {
    match vendor_id {
        Some(vendor_id) => AvpKey::vendor(code, vendor_id),
        None => AvpKey::ietf(code),
    }
}

fn finalize_malformed_failure(
    failure: DiameterRequestFailure,
    dictionaries: DictionarySet<'_>,
    ctx: EncodeContext,
) -> Result<DiameterRequestFailure, DiameterRequestClassificationError> {
    let DiameterRequestFailure::InvalidAvpLength(failed) = failure else {
        return Ok(failure);
    };
    let Some(header) = failed.malformed_header.as_deref() else {
        return Ok(DiameterRequestFailure::InvalidAvpLength(failed));
    };
    let offset = failed
        .leaf_offset
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let definition = unique_avp_definition(
        dictionaries,
        avp_key(failed.leaf_code, failed.leaf_vendor_id),
    )
    .map_err(|error| match error {
        DiameterFailureMappingError::AvpDefinitionAmbiguous => {
            DiameterRequestClassificationError::AvpDefinitionAmbiguous
        }
        _ => DiameterRequestClassificationError::RequestAvpFramingInvalid,
    })?;
    let finalized = match definition {
        Some(definition) => {
            DiameterFailedAvp::malformed_for_definition(header, offset, definition, ctx)
        }
        None => DiameterFailedAvp::malformed(header, offset, 0, ctx),
    }
    .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?;
    Ok(DiameterRequestFailure::InvalidAvpLength(finalized))
}

fn is_header_inspection_failure(failure: &DiameterRequestFailure) -> bool {
    matches!(
        failure,
        DiameterRequestFailure::UnsupportedVersion
            | DiameterRequestFailure::InvalidBitInHeader
            | DiameterRequestFailure::InvalidHeaderBits
    ) && failure.failed_avp().is_none()
}

fn normalize_inspected_failure(
    failure: DiameterRequestFailure,
    command: &CommandDefinition,
) -> Option<DiameterRequestFailure> {
    let DiameterRequestFailure::ExcessSingleton(failed) = &failure else {
        return Some(failure);
    };
    if failed.hierarchy_depth > 0 {
        return Some(failure);
    }
    let cardinality = command
        .find_avp_rule(avp_key(failed.leaf_code, failed.leaf_vendor_id))
        .map(|rule| rule.cardinality());
    (cardinality == Some(AvpCardinality::ZeroOrOne)).then_some(failure)
}

fn classify_direct_grouped_failure(
    group: &RawAvp<'_>,
    group_offset: usize,
    definition: &AvpDefinition,
    dictionaries: DictionarySet<'_>,
    encode_ctx: EncodeContext,
) -> Result<Option<DiameterRequestFailure>, DiameterRequestClassificationError> {
    let mut remaining = group.value;
    let mut offset = group_offset
        .checked_add(group.header.header_len())
        .ok_or(DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
    let mut seen_singletons = Vec::new();
    while !remaining.is_empty() {
        let before = remaining.len();
        let (next, child) = match RawAvp::decode(remaining, mapping_decode_context()) {
            Ok(decoded) => decoded,
            Err(_) => {
                let malformed = DiameterFailedAvp::malformed(remaining, offset, 0, encode_ctx)
                    .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?;
                let malformed_key = avp_key(malformed.leaf_code, malformed.leaf_vendor_id);
                let failed =
                    match unique_avp_definition_for_classification(dictionaries, malformed_key)? {
                        Some(definition) if definition.data_type() != AvpDataType::Grouped => {
                            DiameterFailedAvp::malformed_for_definition(
                                remaining, offset, definition, encode_ctx,
                            )
                        }
                        Some(_) | None => Ok(malformed),
                    }
                    .and_then(|failed| failed.within_group(group, group_offset, encode_ctx))
                    .map_err(DiameterRequestClassificationError::FailedAvpEncoding)?;
                return Ok(Some(DiameterRequestFailure::InvalidAvpLength(failed)));
            }
        };
        let failed = || {
            DiameterFailedAvp::copied(&child, offset, encode_ctx)
                .and_then(|failed| failed.within_group(group, group_offset, encode_ctx))
                .map_err(DiameterRequestClassificationError::FailedAvpEncoding)
        };
        if invalid_dictionary_flags(&child.header, dictionaries).map_err(|error| match error {
            DiameterFailureMappingError::AvpDefinitionAmbiguous => {
                DiameterRequestClassificationError::AvpDefinitionAmbiguous
            }
            _ => DiameterRequestClassificationError::RequestAvpFramingInvalid,
        })? {
            return Ok(Some(DiameterRequestFailure::InvalidAvpBits(failed()?)));
        }
        if vendor_id_zero(&child.header) || child.padding.iter().any(|byte| *byte != 0) {
            return Ok(Some(DiameterRequestFailure::InvalidAvpValue(failed()?)));
        }
        let key = child.header.key();
        if unique_avp_definition_for_classification(dictionaries, key)?.is_none()
            && child.header.flags.is_mandatory()
        {
            return Ok(Some(DiameterRequestFailure::UnsupportedMandatoryAvp(
                failed()?,
            )));
        }
        match definition
            .find_grouped_avp_rule(key)
            .map(|rule| rule.cardinality())
        {
            Some(AvpCardinality::Forbidden) => {
                return Ok(Some(DiameterRequestFailure::ForbiddenAvp(failed()?)));
            }
            Some(AvpCardinality::ZeroOrOne) if seen_singletons.contains(&key) => {
                return Ok(Some(DiameterRequestFailure::ExcessSingleton(failed()?)));
            }
            Some(AvpCardinality::ZeroOrOne) => seen_singletons.push(key),
            Some(AvpCardinality::ZeroOrMore) | None => {}
        }
        let consumed = before
            .checked_sub(next.len())
            .filter(|consumed| *consumed != 0)
            .ok_or(DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
        offset = offset
            .checked_add(consumed)
            .ok_or(DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
        remaining = next;
    }
    Ok(None)
}

fn select_earlier_avp_failure(
    selected: Option<DiameterRequestFailure>,
    candidate: DiameterRequestFailure,
) -> DiameterRequestFailure {
    let Some(selected) = selected else {
        return candidate;
    };
    let selected_offset = selected
        .failed_avp()
        .and_then(|failed| failed.ordering_offset);
    let candidate_offset = candidate
        .failed_avp()
        .and_then(|failed| failed.ordering_offset);
    match (selected_offset, candidate_offset) {
        (Some(selected_offset), Some(candidate_offset)) if candidate_offset < selected_offset => {
            candidate
        }
        _ => selected,
    }
}

fn failure_precedes_offset(failure: &DiameterRequestFailure, candidate_offset: usize) -> bool {
    failure
        .failed_avp()
        .and_then(|failed| failed.ordering_offset)
        .is_none_or(|offset| offset <= candidate_offset)
}

fn failure_precedes_candidate(
    selected: &DiameterRequestFailure,
    candidate: &DiameterRequestFailure,
) -> bool {
    let candidate_offset = candidate
        .failed_avp()
        .and_then(|failed| failed.ordering_offset);
    candidate_offset.is_none_or(|offset| failure_precedes_offset(selected, offset))
}

fn validate_application_failure(
    request: &[u8],
    failure: &DiameterRequestFailure,
    dictionaries: DictionarySet<'_>,
    command: &CommandDefinition,
    max_depth: usize,
) -> Result<(), DiameterRequestClassificationError> {
    let failed = failure
        .failed_avp()
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    match failure {
        DiameterRequestFailure::MissingMandatoryAvp(_) => {
            if matches!(
                failed.sibling_set,
                Some(FailedAvpSiblingSetProvenance::Missing { .. })
            ) {
                return validate_missing_sibling_set(request, failed, dictionaries, max_depth);
            }
            if failed.leaf_offset.is_some() {
                return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
            }
            let definition = unique_avp_definition(
                dictionaries,
                avp_key(failed.leaf_code, failed.leaf_vendor_id),
            )
            .map_err(|error| match error {
                DiameterFailureMappingError::AvpDefinitionAmbiguous => {
                    DiameterRequestClassificationError::AvpDefinitionAmbiguous
                }
                _ => DiameterRequestClassificationError::FailureProvenanceMismatch,
            })?
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
            validate_missing_failed_avp(request, failed, definition, dictionaries, max_depth)
        }
        DiameterRequestFailure::ForbiddenAvp(_) => {
            validate_received_failed_avp(request, failed, dictionaries, max_depth)?;
            let (cardinality, earlier_occurrences) =
                application_occurrence_context(request, failed, dictionaries, command)?;
            if cardinality == Some(AvpCardinality::Forbidden) && earlier_occurrences == 0 {
                Ok(())
            } else {
                Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
            }
        }
        DiameterRequestFailure::ExcessSingleton(_) => {
            validate_received_failed_avp(request, failed, dictionaries, max_depth)?;
            let (cardinality, earlier_occurrences) =
                application_occurrence_context(request, failed, dictionaries, command)?;
            if cardinality == Some(AvpCardinality::ZeroOrOne) && earlier_occurrences == 1 {
                Ok(())
            } else {
                Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
            }
        }
        DiameterRequestFailure::MutuallyExclusiveAvps(_) => {
            validate_received_sibling_set(request, failed, dictionaries, max_depth)
        }
        DiameterRequestFailure::UnsupportedMandatoryAvp(_) => {
            validate_received_failed_avp(request, failed, dictionaries, max_depth)?;
            if unique_avp_definition(
                dictionaries,
                avp_key(failed.leaf_code, failed.leaf_vendor_id),
            )
            .map_err(|error| match error {
                DiameterFailureMappingError::AvpDefinitionAmbiguous => {
                    DiameterRequestClassificationError::AvpDefinitionAmbiguous
                }
                _ => DiameterRequestClassificationError::FailureProvenanceMismatch,
            })?
            .is_some()
            {
                return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
            }
            let header = failed_leaf_avp(failed)?;
            if header.header.flags.is_mandatory() {
                Ok(())
            } else {
                Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
            }
        }
        DiameterRequestFailure::InvalidAvpBits(_)
        | DiameterRequestFailure::InvalidAvpValue(_)
        | DiameterRequestFailure::InvalidAvpLength(_) => {
            validate_received_failed_avp(request, failed, dictionaries, max_depth)
        }
        DiameterRequestFailure::UnknownCommand
        | DiameterRequestFailure::UnsupportedApplication
        | DiameterRequestFailure::InvalidHeaderBits
        | DiameterRequestFailure::UnsupportedVersion
        | DiameterRequestFailure::InvalidBitInHeader => {
            Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
        }
    }
}

fn application_occurrence_context(
    request: &[u8],
    failed: &DiameterFailedAvp,
    dictionaries: DictionarySet<'_>,
    command: &CommandDefinition,
) -> Result<(Option<AvpCardinality>, usize), DiameterRequestClassificationError> {
    let key = avp_key(failed.leaf_code, failed.leaf_vendor_id);
    let leaf_offset = failed
        .leaf_offset
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let Some(parent) = failed.ancestors.first() else {
        let cardinality = command.find_avp_rule(key).map(|rule| rule.cardinality());
        let earlier = earlier_top_level_key_count(request, leaf_offset, key)
            .map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
        return Ok((cardinality, earlier));
    };
    let FailedAvpAncestorProvenance::Received {
        offset,
        wire_len,
        wire_digest,
        ..
    } = parent
    else {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    };
    let definition = unique_grouped_definition(dictionaries, parent.key())?;
    let cardinality = definition
        .find_grouped_avp_rule(key)
        .map(|rule| rule.cardinality());
    let received = received_avp(request, *offset, *wire_len, *wire_digest, parent.key())?;
    let earlier = direct_child_key_count_before(&received, *offset, leaf_offset, key)?;
    Ok((cardinality, earlier))
}

fn validate_received_failed_avp(
    request: &[u8],
    failed: &DiameterFailedAvp,
    dictionaries: DictionarySet<'_>,
    max_depth: usize,
) -> Result<(), DiameterRequestClassificationError> {
    validate_failed_avp_hierarchy(request, failed, dictionaries, max_depth)?;
    let offset = failed
        .leaf_offset
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let len = failed
        .source_wire_len
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let expected = failed
        .source_wire_digest
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let end = offset
        .checked_add(len)
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let actual = request
        .get(offset..end)
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if digest_request(actual) != expected {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    if failed.ancestors.is_empty() {
        validate_exact_top_level_avp(
            request,
            offset,
            len,
            expected,
            avp_key(failed.leaf_code, failed.leaf_vendor_id),
        )?;
    }
    Ok(())
}

fn validate_missing_failed_avp(
    request: &[u8],
    failed: &DiameterFailedAvp,
    definition: &AvpDefinition,
    dictionaries: DictionarySet<'_>,
    max_depth: usize,
) -> Result<(), DiameterRequestClassificationError> {
    if failed.sibling_set.is_some() {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    validate_failed_avp_hierarchy(request, failed, dictionaries, max_depth)?;
    let leaf = failed_leaf_avp(failed)?;
    if leaf.header.key() != definition.key()
        || leaf.header.flags.bits() != header_for_definition(definition).flags.bits()
        || leaf.value.len() != minimum_value_len(definition.data_type())
        || leaf.value.iter().any(|byte| *byte != 0)
    {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    let missing_root_key = match failed.ancestors.last() {
        Some(FailedAvpAncestorProvenance::Received { .. }) => None,
        Some(FailedAvpAncestorProvenance::Missing { key }) => Some(*key),
        None => Some(definition.key()),
    };
    if let Some(key) = missing_root_key {
        if top_level_key_count(request, key)? != 0 {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
    }
    Ok(())
}

fn validate_missing_sibling_set(
    request: &[u8],
    failed: &DiameterFailedAvp,
    dictionaries: DictionarySet<'_>,
    max_depth: usize,
) -> Result<(), DiameterRequestClassificationError> {
    let Some(FailedAvpSiblingSetProvenance::Missing { keys }) = &failed.sibling_set else {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    };
    if keys.len() < 2
        || keys.len() > MAX_FAILED_AVP_HIERARCHY_DEPTH
        || failed.hierarchy_depth != 1
        || failed.hierarchy_depth > max_depth
        || failed.ancestors.len() != 1
        || failed.leaf_offset.is_some()
        || failed.source_wire_len.is_some()
        || failed.source_wire_digest.is_some()
        || failed.malformed_header.is_some()
        || failed.reported_len.is_some()
        || failed.ordering_offset != failed.ancestors[0].received_range().map(|range| range.0)
        || avp_key(failed.leaf_code, failed.leaf_vendor_id) != keys[0]
    {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    let FailedAvpAncestorProvenance::Received {
        key: parent_key,
        offset: parent_offset,
        wire_len: parent_wire_len,
        wire_digest: parent_digest,
    } = failed.ancestors[0]
    else {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    };
    validate_exact_top_level_avp(
        request,
        parent_offset,
        parent_wire_len,
        parent_digest,
        parent_key,
    )?;
    let received = received_avp(
        request,
        parent_offset,
        parent_wire_len,
        parent_digest,
        parent_key,
    )?;
    let parent_definition = unique_grouped_definition(dictionaries, parent_key)?;
    let (remaining, encoded_parent) = RawAvp::decode(failed.wire(), mapping_decode_context())
        .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if !remaining.is_empty()
        || encoded_parent.header.key() != parent_key
        || encoded_parent.header.flags != received.header.flags
        || encoded_parent.header.vendor_id != received.header.vendor_id
    {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    let mut encoded_children = encoded_parent.grouped_avps(mapping_decode_context());
    for (index, expected_key) in keys.iter().copied().enumerate() {
        if keys[..index].contains(&expected_key) {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        let child = encoded_children
            .next()
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?
            .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        let definition = unique_avp_definition(dictionaries, expected_key)
            .map_err(|error| match error {
                DiameterFailureMappingError::AvpDefinitionAmbiguous => {
                    DiameterRequestClassificationError::AvpDefinitionAmbiguous
                }
                _ => DiameterRequestClassificationError::FailureProvenanceMismatch,
            })?
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        let expected_header = header_for_definition(definition);
        if child.header.key() != expected_key
            || child.header.flags != expected_header.flags
            || child.header.vendor_id != expected_header.vendor_id
            || child.value.len() != minimum_value_len(definition.data_type())
            || child.value.iter().any(|byte| *byte != 0)
        {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        validate_missing_schema_child(parent_definition, expected_key)?;
        validate_direct_child_absent(&received, expected_key)?;
    }
    if encoded_children.next().is_some() {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    Ok(())
}

fn validate_received_sibling_set(
    request: &[u8],
    failed: &DiameterFailedAvp,
    dictionaries: DictionarySet<'_>,
    max_depth: usize,
) -> Result<(), DiameterRequestClassificationError> {
    let Some(FailedAvpSiblingSetProvenance::Received { children }) = &failed.sibling_set else {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    };
    if children.len() < 2
        || children.len() > MAX_FAILED_AVP_HIERARCHY_DEPTH
        || failed.hierarchy_depth != 1
        || failed.hierarchy_depth > max_depth
        || failed.ancestors.len() != 1
        || failed.source_wire_len.is_some()
        || failed.source_wire_digest.is_some()
        || failed.malformed_header.is_some()
        || failed.leaf_offset != Some(children[0].offset)
        || avp_key(failed.leaf_code, failed.leaf_vendor_id) != children[0].key
        || failed.ordering_offset != failed.ancestors[0].received_range().map(|range| range.0)
    {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    let FailedAvpAncestorProvenance::Received {
        key: parent_key,
        offset: parent_offset,
        wire_len: parent_wire_len,
        wire_digest: parent_digest,
    } = failed.ancestors[0]
    else {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    };
    validate_exact_top_level_avp(
        request,
        parent_offset,
        parent_wire_len,
        parent_digest,
        parent_key,
    )?;
    let received = received_avp(
        request,
        parent_offset,
        parent_wire_len,
        parent_digest,
        parent_key,
    )?;
    let parent_definition = unique_grouped_definition(dictionaries, parent_key)?;
    let (remaining, encoded_parent) = RawAvp::decode(failed.wire(), mapping_decode_context())
        .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if !remaining.is_empty()
        || encoded_parent.header.key() != parent_key
        || encoded_parent.header.flags != received.header.flags
        || encoded_parent.header.vendor_id != received.header.vendor_id
    {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    let mut encoded_children = encoded_parent.value;
    for (index, provenance) in children.iter().enumerate() {
        if children[..index]
            .iter()
            .any(|earlier| earlier.key == provenance.key || earlier.offset >= provenance.offset)
        {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        if encoded_children.is_empty() {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        let before = encoded_children.len();
        let (next, child) = RawAvp::decode(encoded_children, mapping_decode_context())
            .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        let consumed = before
            .checked_sub(next.len())
            .filter(|consumed| *consumed != 0)
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        let encoded_wire = encoded_children
            .get(..consumed)
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        let end = provenance
            .offset
            .checked_add(provenance.wire_len)
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        let source = request
            .get(provenance.offset..end)
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        if child.header.key() != provenance.key
            || source.len() != provenance.wire_len
            || digest_request(source) != provenance.wire_digest
            || encoded_wire != source
            || (index == 0 && failed.reported_len != Some(child.header.length))
        {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        validate_direct_received_child(
            &received,
            parent_offset,
            provenance.offset,
            provenance.wire_len,
            provenance.key,
        )?;
        let definition = unique_avp_definition(dictionaries, provenance.key)
            .map_err(|error| match error {
                DiameterFailureMappingError::AvpDefinitionAmbiguous => {
                    DiameterRequestClassificationError::AvpDefinitionAmbiguous
                }
                _ => DiameterRequestClassificationError::FailureProvenanceMismatch,
            })?
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        if definition.key() != provenance.key {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        validate_missing_schema_child(parent_definition, provenance.key)?;
        encoded_children = next;
    }
    if !encoded_children.is_empty() {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    Ok(())
}

fn validate_failed_avp_hierarchy(
    request: &[u8],
    failed: &DiameterFailedAvp,
    dictionaries: DictionarySet<'_>,
    max_depth: usize,
) -> Result<(), DiameterRequestClassificationError> {
    if failed.sibling_set.is_some() {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    if failed.hierarchy_depth != failed.ancestors.len()
        || failed.hierarchy_depth > max_depth
        || failed.hierarchy_depth > MAX_FAILED_AVP_HIERARCHY_DEPTH
    {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }

    let mut encoded_region = failed.wire();
    for provenance in failed.ancestors.iter().rev() {
        let (remaining, encoded_ancestor) =
            RawAvp::decode(encoded_region, mapping_decode_context())
                .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        if !remaining.is_empty() || encoded_ancestor.header.key() != provenance.key() {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        let definition = unique_grouped_definition(dictionaries, provenance.key())?;
        match provenance {
            FailedAvpAncestorProvenance::Received {
                offset,
                wire_len,
                wire_digest,
                ..
            } => {
                let received =
                    received_avp(request, *offset, *wire_len, *wire_digest, provenance.key())?;
                if encoded_ancestor.header.flags != received.header.flags
                    || encoded_ancestor.header.vendor_id != received.header.vendor_id
                {
                    return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
                }
            }
            FailedAvpAncestorProvenance::Missing { .. } => {
                let expected = header_for_definition(definition);
                if encoded_ancestor.header.flags != expected.flags
                    || encoded_ancestor.header.vendor_id != expected.vendor_id
                {
                    return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
                }
            }
        }
        encoded_region = encoded_ancestor.value;
    }
    let (remaining, encoded_leaf) = RawAvp::decode(encoded_region, mapping_decode_context())
        .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if !remaining.is_empty()
        || encoded_leaf.header.key() != avp_key(failed.leaf_code, failed.leaf_vendor_id)
    {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }

    if let Some(FailedAvpAncestorProvenance::Received {
        key,
        offset,
        wire_len,
        wire_digest,
    }) = failed.ancestors.last()
    {
        validate_exact_top_level_avp(request, *offset, *wire_len, *wire_digest, *key)?;
    }

    for (index, parent) in failed.ancestors.iter().enumerate() {
        let parent_definition = unique_grouped_definition(dictionaries, parent.key())?;
        let (child_key, child_source) = if index == 0 {
            (
                avp_key(failed.leaf_code, failed.leaf_vendor_id),
                failed
                    .source_wire_len
                    .zip(failed.leaf_offset)
                    .map(|(wire_len, offset)| (offset, wire_len)),
            )
        } else {
            let child = &failed.ancestors[index - 1];
            (child.key(), child.received_range())
        };

        match parent {
            FailedAvpAncestorProvenance::Received {
                offset,
                wire_len,
                wire_digest,
                ..
            } => {
                let received =
                    received_avp(request, *offset, *wire_len, *wire_digest, parent.key())?;
                if let Some((child_offset, child_wire_len)) = child_source {
                    validate_direct_received_child(
                        &received,
                        *offset,
                        child_offset,
                        child_wire_len,
                        child_key,
                    )?;
                } else {
                    validate_missing_schema_child(parent_definition, child_key)?;
                    validate_direct_child_absent(&received, child_key)?;
                }
            }
            FailedAvpAncestorProvenance::Missing { .. } => {
                if child_source.is_some() {
                    return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
                }
                validate_missing_schema_child(parent_definition, child_key)?;
            }
        }
    }
    Ok(())
}

fn validate_exact_top_level_avp(
    request: &[u8],
    expected_offset: usize,
    expected_wire_len: usize,
    expected_digest: [u8; 32],
    expected_key: AvpKey,
) -> Result<(), DiameterRequestClassificationError> {
    for located in top_level_avps(request)
        .map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?
    {
        let located =
            located.map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
        if located.offset > expected_offset {
            break;
        }
        if located.offset == expected_offset {
            let wire = located_avp_wire(request, &located)
                .map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
            if located.avp.header.key() == expected_key
                && wire.len() == expected_wire_len
                && digest_request(wire) == expected_digest
            {
                return Ok(());
            }
            break;
        }
    }
    Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
}

fn top_level_key_count(
    request: &[u8],
    key: AvpKey,
) -> Result<usize, DiameterRequestClassificationError> {
    let mut count = 0usize;
    for located in top_level_avps(request)
        .map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?
    {
        let located =
            located.map_err(|_| DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
        if located.avp.header.key() == key {
            count = count
                .checked_add(1)
                .ok_or(DiameterRequestClassificationError::RequestAvpFramingInvalid)?;
        }
    }
    Ok(count)
}

impl FailedAvpAncestorProvenance {
    const fn key(&self) -> AvpKey {
        match self {
            Self::Received { key, .. } | Self::Missing { key } => *key,
        }
    }

    const fn received_range(&self) -> Option<(usize, usize)> {
        match self {
            Self::Received {
                offset, wire_len, ..
            } => Some((*offset, *wire_len)),
            Self::Missing { .. } => None,
        }
    }
}

fn unique_grouped_definition<'a>(
    dictionaries: DictionarySet<'a>,
    key: AvpKey,
) -> Result<&'a AvpDefinition, DiameterRequestClassificationError> {
    let definition = unique_avp_definition(dictionaries, key)
        .map_err(|error| match error {
            DiameterFailureMappingError::AvpDefinitionAmbiguous => {
                DiameterRequestClassificationError::AvpDefinitionAmbiguous
            }
            _ => DiameterRequestClassificationError::FailureProvenanceMismatch,
        })?
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if definition.data_type() != AvpDataType::Grouped {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    Ok(definition)
}

fn received_avp<'a>(
    request: &'a [u8],
    offset: usize,
    wire_len: usize,
    expected_digest: [u8; 32],
    expected_key: AvpKey,
) -> Result<RawAvp<'a>, DiameterRequestClassificationError> {
    let request_wire_len = request
        .get(1..4)
        .map(|bytes| read_u24(bytes) as usize)
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let end = offset
        .checked_add(wire_len)
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if offset < DIAMETER_HEADER_LEN || end > request_wire_len {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    let wire = request
        .get(offset..end)
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if digest_request(wire) != expected_digest {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    let (remaining, avp) = RawAvp::decode(wire, mapping_decode_context())
        .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    if !remaining.is_empty() || avp.header.key() != expected_key {
        return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
    }
    Ok(avp)
}

fn validate_direct_received_child(
    parent: &RawAvp<'_>,
    parent_offset: usize,
    child_offset: usize,
    child_wire_len: usize,
    child_key: AvpKey,
) -> Result<(), DiameterRequestClassificationError> {
    let mut remaining = parent.value;
    let mut offset = parent_offset
        .checked_add(parent.header.header_len())
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    while !remaining.is_empty() {
        let before = remaining.len();
        let (next, child) = RawAvp::decode(remaining, mapping_decode_context())
            .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        let consumed = before
            .checked_sub(next.len())
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        if offset == child_offset {
            return if consumed == child_wire_len && child.header.key() == child_key {
                Ok(())
            } else {
                Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
            };
        }
        offset = offset
            .checked_add(consumed)
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        remaining = next;
    }
    Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
}

fn direct_child_key_count_before(
    parent: &RawAvp<'_>,
    parent_offset: usize,
    selected_offset: usize,
    key: AvpKey,
) -> Result<usize, DiameterRequestClassificationError> {
    let mut remaining = parent.value;
    let mut offset = parent_offset
        .checked_add(parent.header.header_len())
        .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
    let mut count = 0usize;
    while !remaining.is_empty() {
        let before = remaining.len();
        let (next, child) = RawAvp::decode(remaining, mapping_decode_context())
            .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        if offset == selected_offset {
            return if child.header.key() == key {
                Ok(count)
            } else {
                Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
            };
        }
        if offset > selected_offset {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        if child.header.key() == key {
            count = count
                .checked_add(1)
                .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        }
        let consumed = before
            .checked_sub(next.len())
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        offset = offset
            .checked_add(consumed)
            .ok_or(DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        remaining = next;
    }
    Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
}

fn validate_direct_child_absent(
    parent: &RawAvp<'_>,
    child_key: AvpKey,
) -> Result<(), DiameterRequestClassificationError> {
    for child in parent.grouped_avps(mapping_decode_context()) {
        let child =
            child.map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        if child.header.key() == child_key {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
    }
    Ok(())
}

fn validate_missing_schema_child(
    parent: &AvpDefinition,
    child_key: AvpKey,
) -> Result<(), DiameterRequestClassificationError> {
    if parent
        .find_grouped_avp_rule(child_key)
        .is_some_and(|rule| !rule.cardinality().is_forbidden())
    {
        Ok(())
    } else {
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    }
}

fn failed_leaf_avp<'a>(
    failed: &'a DiameterFailedAvp,
) -> Result<RawAvp<'a>, DiameterRequestClassificationError> {
    let mut region = failed.wire();
    for depth in 0..=failed.hierarchy_depth {
        let (remaining, avp) = RawAvp::decode(region, mapping_decode_context())
            .map_err(|_| DiameterRequestClassificationError::FailureProvenanceMismatch)?;
        if !remaining.is_empty() {
            return Err(DiameterRequestClassificationError::FailureProvenanceMismatch);
        }
        if depth == failed.hierarchy_depth {
            return Ok(avp);
        }
        region = avp.value;
    }
    Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
}

fn invalid_dictionary_flags(
    header: &AvpHeader,
    dictionaries: DictionarySet<'_>,
) -> Result<bool, DiameterFailureMappingError> {
    if header.flags.reserved_bits() != 0 {
        return Ok(true);
    }
    let mut definition = None;
    for dictionary in dictionaries.dictionaries() {
        for candidate in dictionary
            .avps()
            .iter()
            .filter(|candidate| candidate.key() == header.key())
        {
            if definition.is_some_and(|existing| existing != candidate) {
                return Err(DiameterFailureMappingError::AvpDefinitionAmbiguous);
            }
            definition = Some(candidate);
        }
    }
    let Some(definition) = definition else {
        // RFC 6733 reserves P for a future end-to-end security mechanism. No
        // such mechanism is negotiated by this crate, so reflecting P is not
        // a supported interpretation even for an unknown extension AVP.
        return Ok(header.flags.is_protected());
    };
    let rules = definition.flags();
    Ok(
        !flag_matches(rules.vendor(), header.flags.is_vendor_specific())
            || !flag_matches(rules.mandatory(), header.flags.is_mandatory())
            || !flag_matches(rules.protected(), header.flags.is_protected()),
    )
}

const fn flag_matches(requirement: FlagRequirement, is_set: bool) -> bool {
    match requirement {
        FlagRequirement::MustBeSet => is_set,
        FlagRequirement::MustBeUnset => !is_set,
        FlagRequirement::MayBeSet => true,
    }
}

fn vendor_id_zero(header: &AvpHeader) -> bool {
    header
        .vendor_id
        .is_some_and(|vendor_id| vendor_id.get() == 0)
}

fn application_match_count(dictionaries: DictionarySet<'_>, id: ApplicationId) -> usize {
    let mut selected = None;
    for application in dictionaries
        .dictionaries()
        .iter()
        .flat_map(|dictionary| dictionary.applications())
        .filter(|application| application.id() == id)
    {
        if selected.is_some_and(|existing| existing != application) {
            return 2;
        }
        selected = Some(application);
    }
    usize::from(selected.is_some())
}

fn mapping_decode_context() -> DecodeContext {
    DecodeContext {
        max_message_len: MAX_U24 as usize,
        max_ies: usize::MAX,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        validation_level: ValidationLevel::Structural,
        ..DecodeContext::default()
    }
}

fn envelope_encode_context(envelope: &DiameterRequestEnvelope) -> EncodeContext {
    EncodeContext {
        max_message_len: envelope.request_wire_len.min(MAX_U24 as usize),
        ..EncodeContext::default()
    }
}

fn digest_request(request: &[u8]) -> [u8; 32] {
    Sha256::digest(request).into()
}

fn append_avp(
    dst: &mut BytesMut,
    header: AvpHeader,
    value: &[u8],
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    crate::append_canonical_avp(dst, header, value, ctx)
}

fn encode_raw_avp(
    header: AvpHeader,
    value: &[u8],
    padding: &[u8],
    raw_preserving: bool,
    ctx: EncodeContext,
) -> Result<Bytes, EncodeError> {
    let avp = RawAvp {
        header,
        value,
        padding,
    };
    let encode_ctx = EncodeContext {
        raw_preserving,
        ..ctx
    };
    let wire_len = avp.wire_len(encode_ctx)?;
    ctx.check_capacity(wire_len)?;
    let mut encoded = BytesMut::with_capacity(wire_len);
    avp.encode(&mut encoded, encode_ctx)?;
    Ok(encoded.freeze())
}

fn raw_encode_context(ctx: EncodeContext) -> EncodeContext {
    EncodeContext {
        raw_preserving: true,
        ..ctx
    }
}

fn ietf_avp_wire_len(value_len: usize) -> Result<usize, EncodeError> {
    let unpadded = AVP_HEADER_LEN
        .checked_add(value_len)
        .ok_or_else(EncodeError::length_overflow)?;
    if unpadded > MAX_U24 as usize {
        return Err(EncodeError::length_overflow());
    }
    align4(unpadded).ok_or_else(EncodeError::length_overflow)
}

fn check_avp_declared_len(length: usize) -> Result<(), EncodeError> {
    let padded = align4(length).ok_or_else(EncodeError::length_overflow)?;
    if length > MAX_U24 as usize || padded > MAX_U24 as usize {
        return Err(EncodeError::length_overflow().with_spec_ref(spec_ref("4.1")));
    }
    Ok(())
}

fn encode_context_for_decode(ctx: DecodeContext) -> EncodeContext {
    EncodeContext {
        max_message_len: ctx.max_message_len,
        ..EncodeContext::default()
    }
}

fn read_u24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|padded| padded & !3)
}

fn header_for_definition(definition: &AvpDefinition) -> AvpHeader {
    let rules = definition.flags();
    let vendor_id = definition.key().vendor_id();
    AvpHeader {
        code: definition.key().code(),
        flags: AvpFlags::new(
            vendor_id.is_some(),
            matches!(rules.mandatory(), FlagRequirement::MustBeSet),
            matches!(rules.protected(), FlagRequirement::MustBeSet),
        ),
        length: if vendor_id.is_some() {
            AVP_VENDOR_HEADER_LEN as u32
        } else {
            AVP_HEADER_LEN as u32
        },
        vendor_id,
    }
}

const fn minimum_value_len(data_type: AvpDataType) -> usize {
    match data_type {
        AvpDataType::Integer32
        | AvpDataType::Unsigned32
        | AvpDataType::Float32
        | AvpDataType::Time
        | AvpDataType::Enumerated => 4,
        AvpDataType::Integer64 | AvpDataType::Unsigned64 | AvpDataType::Float64 => 8,
        AvpDataType::Address => 6,
        AvpDataType::OctetString
        | AvpDataType::Grouped
        | AvpDataType::Utf8String
        | AvpDataType::DiameterIdentity
        | AvpDataType::DiameterUri
        | AvpDataType::IpFilterRule
        | AvpDataType::QosFilterRule => 0,
    }
}

#[cfg(test)]
mod parser_provenance_tests {
    use super::*;
    use crate::base::{
        self, APPLICATION_ID_COMMON_MESSAGES, AVP_ORIGIN_HOST, COMMAND_DEVICE_WATCHDOG,
    };
    use crate::dictionary::{AvpFlagRules, Dictionary};
    use crate::parser_error::DiameterParserError;
    use crate::Message;

    const SYNTHETIC_VENDOR_ID: VendorId = VendorId::new(42_424);
    const SYNTHETIC_VENDOR_CODE: AvpCode = AvpCode::new(9_901);
    const SYNTHETIC_VENDOR_DEFINITION: AvpDefinition = AvpDefinition::new(
        AvpKey::vendor(SYNTHETIC_VENDOR_CODE, SYNTHETIC_VENDOR_ID),
        "Synthetic-Vendor-Required",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("ietf", "RFC6733", "7.5"),
    );
    static SYNTHETIC_AVPS: [AvpDefinition; 1] = [SYNTHETIC_VENDOR_DEFINITION];
    static SYNTHETIC_DICTIONARY: Dictionary = Dictionary::new(
        "diameter-parser-provenance-vendor-test",
        &[],
        &[],
        &SYNTHETIC_AVPS,
    );
    static SYNTHETIC_DICTIONARY_REFS: [&Dictionary; 2] =
        [base::dictionary(), &SYNTHETIC_DICTIONARY];
    static SYNTHETIC_DICTIONARIES: DictionarySet<'static> =
        DictionarySet::new(&SYNTHETIC_DICTIONARY_REFS);

    fn empty_dwr() -> ([u8; DIAMETER_HEADER_LEN], Message<'static>) {
        let request = [
            1, 0, 0, 20, 0x80, 0, 1, 24, 0, 0, 0, 0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        ];
        let message = Message {
            header: Header::new(
                CommandFlags::request(false),
                COMMAND_DEVICE_WATCHDOG,
                APPLICATION_ID_COMMON_MESSAGES,
                0x1020_3040,
                0x5060_7080,
            ),
            raw_avps: &[],
            tail: &[],
        };
        (request, message)
    }

    fn request_envelope(request: &[u8]) -> DiameterRequestEnvelope {
        match inspect_diameter_request(request, DecodeContext::conservative()) {
            DiameterRequestInspection::Request(envelope) => *envelope,
            DiameterRequestInspection::Unanswerable(reason) => {
                panic!("empty DWR unexpectedly unanswerable: {}", reason.as_str())
            }
        }
    }

    #[test]
    fn sealed_vendor_provenance_uses_dictionary_header_and_minimum_shape() {
        let (request, message) = empty_dwr();
        let error = DiameterParserError::missing_for_definition(
            &message,
            DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "synthetic missing vendor field",
                },
                DIAMETER_HEADER_LEN,
            ),
            &SYNTHETIC_AVPS[0],
            APPLICATION_ID_COMMON_MESSAGES,
            COMMAND_DEVICE_WATCHDOG,
        );
        let bound = match DiameterRequestFailure::from_parser_error(
            &request_envelope(&request),
            &request,
            &error,
            DecodeContext::conservative(),
            SYNTHETIC_DICTIONARIES,
            EncodeContext::default(),
        ) {
            Ok(bound) => bound,
            Err(mapping) => panic!("synthetic vendor provenance did not map: {mapping}"),
        };
        let DiameterRequestFailure::MissingMandatoryAvp(failed) = bound.failure() else {
            panic!("synthetic vendor provenance did not select 5005");
        };
        let leaf = match failed_leaf_avp(failed) {
            Ok(leaf) => leaf,
            Err(mapping) => panic!("synthetic vendor Failed-AVP did not decode: {mapping}"),
        };
        assert_eq!(leaf.header.code, SYNTHETIC_VENDOR_CODE);
        assert_eq!(leaf.header.vendor_id, Some(SYNTHETIC_VENDOR_ID));
        assert!(leaf.header.flags.is_vendor_specific());
        assert!(leaf.header.flags.is_mandatory());
        assert_eq!(leaf.value, [0_u8; 4]);
    }

    #[test]
    fn forged_internal_command_application_and_category_provenance_is_rejected() {
        let (request, message) = empty_dwr();
        let envelope = request_envelope(&request);
        for (application_id, command_code) in [
            (ApplicationId::new(99), COMMAND_DEVICE_WATCHDOG),
            (
                APPLICATION_ID_COMMON_MESSAGES,
                crate::base::COMMAND_DISCONNECT_PEER,
            ),
        ] {
            let error = DiameterParserError::missing_for_definition(
                &message,
                DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "synthetic mismatched parser grammar",
                    },
                    DIAMETER_HEADER_LEN,
                ),
                base::dictionary()
                    .find_avp(AvpKey::ietf(AVP_ORIGIN_HOST))
                    .unwrap_or(&SYNTHETIC_AVPS[0]),
                application_id,
                command_code,
            );
            assert_eq!(
                DiameterRequestFailure::from_parser_error(
                    &envelope,
                    &request,
                    &error,
                    DecodeContext::conservative(),
                    SYNTHETIC_DICTIONARIES,
                    EncodeContext::default(),
                ),
                Err(DiameterFailureMappingError::ParserCommandMismatch)
            );
        }

        let wrong_category = DiameterParserError::missing_for_definition(
            &message,
            DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "synthetic",
                    value: 7,
                },
                DIAMETER_HEADER_LEN,
            ),
            base::dictionary()
                .find_avp(AvpKey::ietf(AVP_ORIGIN_HOST))
                .unwrap_or(&SYNTHETIC_AVPS[0]),
            APPLICATION_ID_COMMON_MESSAGES,
            COMMAND_DEVICE_WATCHDOG,
        );
        assert_eq!(
            DiameterRequestFailure::from_parser_error(
                &envelope,
                &request,
                &wrong_category,
                DecodeContext::conservative(),
                SYNTHETIC_DICTIONARIES,
                EncodeContext::default(),
            ),
            Err(DiameterFailureMappingError::ParserProvenanceMismatch)
        );

        let untrusted = DiameterParserError::decoded(
            &message,
            DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "synthetic reason-string-only missing field",
                },
                DIAMETER_HEADER_LEN,
            ),
        );
        assert_eq!(
            DiameterRequestFailure::from_parser_error(
                &envelope,
                &request,
                &untrusted,
                DecodeContext::conservative(),
                SYNTHETIC_DICTIONARIES,
                EncodeContext::default(),
            ),
            Err(DiameterFailureMappingError::OffsetAmbiguous)
        );
    }
}
