//! Redaction-safe provenance for typed Diameter request parser failures.
//!
//! Ordinary [`DecodeError`] values intentionally describe only a decode
//! category and byte offset. A missing mandatory AVP has no received byte
//! offset, so request parsers use this sealed error surface to retain the
//! SDK-owned command grammar fact needed by the request-bound error-answer
//! mapper. The declared Diameter-message-boundary fingerprint and constructors
//! remain crate-private:
//! consumers can inspect numeric schema metadata, but cannot manufacture an
//! SDK parser result.

use core::fmt;

use opc_protocol::DecodeError;
use sha2::{Digest, Sha256};

use crate::{
    ApplicationId, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandCode, CommandKind,
    VendorId,
};
#[cfg(any(test, feature = "peer", feature = "app-swm"))]
use crate::{Message, DIAMETER_HEADER_LEN};

/// Why a sealed grouped AVP set failed command-specific validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiameterGroupedAvpSetFailureKind {
    /// RFC 6733 requires one of the listed children, but none was present.
    MissingOneOf,
    /// Mutually exclusive children were present together.
    MutuallyExclusivePresent,
}

/// Exact received grouped-parent identity retained without its value bytes.
///
/// The offset is relative to the start of the Diameter message. The definition
/// and offset can be inspected but this type cannot be constructed downstream.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DiameterGroupedAvpProvenance {
    definition: &'static AvpDefinition,
    offset: usize,
}

impl DiameterGroupedAvpProvenance {
    #[cfg(any(feature = "peer", feature = "app-swm"))]
    const fn new(definition: &'static AvpDefinition, offset: usize) -> Self {
        Self { definition, offset }
    }

    /// Return the exact SDK-owned grouped AVP definition.
    #[must_use]
    pub const fn definition(self) -> &'static AvpDefinition {
        self.definition
    }

    /// Return the vendor-aware grouped AVP key.
    #[must_use]
    pub const fn key(self) -> AvpKey {
        self.definition.key()
    }

    /// Return the received parent offset relative to the Diameter message.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Debug for DiameterGroupedAvpProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterGroupedAvpProvenance")
            .field("avp_code", &self.key().code().get())
            .field("vendor_id", &self.key().vendor_id().map(VendorId::get))
            .field("offset", &self.offset)
            .finish()
    }
}

/// Numeric provenance for one mandatory AVP omitted from a typed request.
///
/// The vendor-aware [`AvpKey`] and exact SDK [`AvpDefinition`] identify the
/// schema. The application, command, and request role identify the SDK-owned
/// grammar that required it. This type has no public constructor and carries
/// no AVP value bytes.
///
/// ```compile_fail
/// use opc_proto_diameter::parser_error::DiameterMissingAvpProvenance;
/// use opc_proto_diameter::{base, ApplicationId, AvpCode, AvpKey, CommandCode, CommandKind};
///
/// // Provenance can be inspected but not constructed by downstream code.
/// let definition = base::dictionary()
///     .find_avp(AvpKey::ietf(AvpCode::new(264)))
///     .unwrap();
/// let _forged = DiameterMissingAvpProvenance::new(
///     definition,
///     None,
///     ApplicationId::new(0),
///     CommandCode::new(280),
///     CommandKind::Request,
/// );
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterMissingAvpProvenance {
    definition: &'static AvpDefinition,
    parent: Option<DiameterGroupedAvpProvenance>,
    application_id: ApplicationId,
    command_code: CommandCode,
    command_kind: CommandKind,
}

impl DiameterMissingAvpProvenance {
    #[cfg(any(test, feature = "peer", feature = "app-swm"))]
    const fn new(
        definition: &'static AvpDefinition,
        parent: Option<DiameterGroupedAvpProvenance>,
        application_id: ApplicationId,
        command_code: CommandCode,
        command_kind: CommandKind,
    ) -> Self {
        Self {
            definition,
            parent,
            application_id,
            command_code,
            command_kind,
        }
    }

    /// Return the exact SDK-owned AVP schema definition.
    #[must_use]
    pub const fn definition(&self) -> &'static AvpDefinition {
        self.definition
    }

    /// Return the vendor-aware AVP schema key.
    #[must_use]
    pub const fn key(&self) -> AvpKey {
        self.definition.key()
    }

    /// Return the AVP code from the schema key.
    #[must_use]
    pub const fn avp_code(&self) -> crate::AvpCode {
        self.definition.key().code()
    }

    /// Return the schema Vendor-Id, when the AVP is vendor-specific.
    #[must_use]
    pub const fn vendor_id(&self) -> Option<VendorId> {
        self.definition.key().vendor_id()
    }

    /// Return the dictionary data type that determines minimum value shape.
    #[must_use]
    pub const fn data_type(&self) -> AvpDataType {
        self.definition.data_type()
    }

    /// Return the dictionary flag rules that determine the Failed-AVP header.
    #[must_use]
    pub const fn flag_rules(&self) -> AvpFlagRules {
        self.definition.flags()
    }

    /// Return the exact received grouped parent for a nested omission.
    #[must_use]
    pub const fn parent(&self) -> Option<DiameterGroupedAvpProvenance> {
        self.parent
    }

    /// Return the application identifier of the requiring parser grammar.
    #[must_use]
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Return the command code of the requiring parser grammar.
    #[must_use]
    pub const fn command_code(&self) -> CommandCode {
        self.command_code
    }

    /// Return the request/answer role of the requiring parser grammar.
    #[must_use]
    pub const fn command_kind(&self) -> CommandKind {
        self.command_kind
    }
}

impl fmt::Debug for DiameterMissingAvpProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterMissingAvpProvenance")
            .field("avp_code", &self.avp_code().get())
            .field("vendor_id", &self.vendor_id().map(crate::VendorId::get))
            .field("data_type", &self.data_type())
            .field("flag_rules", &self.flag_rules())
            .field("parent", &self.parent)
            .field("application_id", &self.application_id.get())
            .field("command_code", &self.command_code.get())
            .field("command_kind", &self.command_kind)
            .finish()
    }
}

/// Sealed provenance for an RFC-defined set of grouped child AVPs.
///
/// This covers grammars such as RFC 6733 `Vendor-Specific-Application-Id`,
/// where exactly one of two child AVPs is required. Definitions are retained
/// in normative Failed-AVP example order; received conflicting children are
/// selected in their original wire order by the checked mapper. No AVP values
/// are retained here, and the type has no public constructor.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterGroupedAvpSetProvenance {
    definitions: Box<[&'static AvpDefinition]>,
    parent: DiameterGroupedAvpProvenance,
    application_id: ApplicationId,
    command_code: CommandCode,
    command_kind: CommandKind,
    failure_kind: DiameterGroupedAvpSetFailureKind,
}

impl DiameterGroupedAvpSetProvenance {
    #[cfg(feature = "peer")]
    pub(crate) fn for_request(
        definitions: &[&'static AvpDefinition],
        parent_definition: &'static AvpDefinition,
        parent_offset: usize,
        application_id: ApplicationId,
        command_code: CommandCode,
        failure_kind: DiameterGroupedAvpSetFailureKind,
    ) -> Self {
        Self {
            definitions: definitions.to_vec().into_boxed_slice(),
            parent: DiameterGroupedAvpProvenance::new(parent_definition, parent_offset),
            application_id,
            command_code,
            command_kind: CommandKind::Request,
            failure_kind,
        }
    }

    /// Return the exact SDK-owned child definitions in normative example order.
    #[must_use]
    pub fn definitions(&self) -> &[&'static AvpDefinition] {
        &self.definitions
    }

    /// Return the exact received grouped parent.
    #[must_use]
    pub const fn parent(&self) -> DiameterGroupedAvpProvenance {
        self.parent
    }

    /// Return the application identifier of the requiring parser grammar.
    #[must_use]
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Return the command code of the requiring parser grammar.
    #[must_use]
    pub const fn command_code(&self) -> CommandCode {
        self.command_code
    }

    /// Return the request/answer role of the requiring parser grammar.
    #[must_use]
    pub const fn command_kind(&self) -> CommandKind {
        self.command_kind
    }

    /// Return the RFC-defined grouped-set failure condition.
    #[must_use]
    pub const fn failure_kind(&self) -> DiameterGroupedAvpSetFailureKind {
        self.failure_kind
    }
}

impl fmt::Debug for DiameterGroupedAvpSetProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<_> = self
            .definitions
            .iter()
            .map(|definition| {
                (
                    definition.key().code().get(),
                    definition.key().vendor_id().map(VendorId::get),
                    definition.data_type(),
                    definition.flags(),
                )
            })
            .collect();
        formatter
            .debug_struct("DiameterGroupedAvpSetProvenance")
            .field("definitions", &keys)
            .field("parent", &self.parent)
            .field("application_id", &self.application_id.get())
            .field("command_code", &self.command_code.get())
            .field("command_kind", &self.command_kind)
            .field("failure_kind", &self.failure_kind)
            .finish()
    }
}

/// Typed failure from an SDK-owned Diameter command parser.
///
/// The original [`DecodeError`] remains available for source-compatible error
/// handling. When [`Self::missing_avp`] is present, its provenance is sealed to
/// the exact parsed request and can be consumed by
/// [`crate::error_answer::DiameterRequestFailure::from_parser_error`]. Neither
/// diagnostic formatting implementation exposes the message fingerprint or
/// any AVP value.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterParserError {
    decode_error: Box<DecodeError>,
    missing_avp: Option<Box<DiameterMissingAvpProvenance>>,
    grouped_avp_set: Option<Box<DiameterGroupedAvpSetProvenance>>,
    request_wire_len: usize,
    request_digest: [u8; 32],
}

impl DiameterParserError {
    #[cfg(any(test, feature = "peer", feature = "app-swm"))]
    pub(crate) fn decoded(message: &Message<'_>, decode_error: DecodeError) -> Self {
        let (request_wire_len, request_digest) = fingerprint_message(message);
        Self {
            decode_error: Box::new(decode_error),
            missing_avp: None,
            grouped_avp_set: None,
            request_wire_len,
            request_digest,
        }
    }

    #[cfg(any(test, feature = "peer", feature = "app-swm"))]
    pub(crate) fn missing_for_definition(
        message: &Message<'_>,
        decode_error: DecodeError,
        definition: &'static AvpDefinition,
        application_id: ApplicationId,
        command_code: CommandCode,
    ) -> Self {
        let (request_wire_len, request_digest) = fingerprint_message(message);
        Self {
            decode_error: Box::new(decode_error),
            missing_avp: Some(Box::new(DiameterMissingAvpProvenance::new(
                definition,
                None,
                application_id,
                command_code,
                CommandKind::Request,
            ))),
            grouped_avp_set: None,
            request_wire_len,
            request_digest,
        }
    }

    #[cfg(any(feature = "peer", feature = "app-swm"))]
    pub(crate) fn missing_with_parent(
        message: &Message<'_>,
        decode_error: DecodeError,
        definition: &'static AvpDefinition,
        parent_definition: &'static AvpDefinition,
        parent_offset: usize,
        application_id: ApplicationId,
        command_code: CommandCode,
    ) -> Self {
        let (request_wire_len, request_digest) = fingerprint_message(message);
        Self {
            decode_error: Box::new(decode_error),
            missing_avp: Some(Box::new(DiameterMissingAvpProvenance::new(
                definition,
                Some(DiameterGroupedAvpProvenance::new(
                    parent_definition,
                    parent_offset,
                )),
                application_id,
                command_code,
                CommandKind::Request,
            ))),
            grouped_avp_set: None,
            request_wire_len,
            request_digest,
        }
    }

    #[cfg(feature = "peer")]
    pub(crate) fn grouped_avp_set(
        message: &Message<'_>,
        decode_error: DecodeError,
        provenance: DiameterGroupedAvpSetProvenance,
    ) -> Self {
        let (request_wire_len, request_digest) = fingerprint_message(message);
        Self {
            decode_error: Box::new(decode_error),
            missing_avp: None,
            grouped_avp_set: Some(Box::new(provenance)),
            request_wire_len,
            request_digest,
        }
    }

    /// Borrow the original structured decode failure.
    #[must_use]
    pub fn decode_error(&self) -> &DecodeError {
        self.decode_error.as_ref()
    }

    /// Consume this typed error and recover the legacy decode failure.
    #[must_use]
    pub fn into_decode_error(self) -> DecodeError {
        *self.decode_error
    }

    /// Return sealed missing-mandatory-AVP metadata, when this parser failure
    /// was produced by an SDK-owned required-field check.
    #[must_use]
    pub fn missing_avp(&self) -> Option<&DiameterMissingAvpProvenance> {
        self.missing_avp.as_deref()
    }

    /// Return sealed grouped-set provenance for an RFC-defined one-of or
    /// mutual-exclusion failure.
    #[must_use]
    pub fn grouped_avp_set_provenance(&self) -> Option<&DiameterGroupedAvpSetProvenance> {
        self.grouped_avp_set.as_deref()
    }

    /// Stable redaction-safe code for logs and metrics.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        if self.missing_avp.is_some() {
            "diameter_parser_missing_mandatory_avp"
        } else if let Some(provenance) = self.grouped_avp_set.as_ref() {
            match provenance.failure_kind() {
                DiameterGroupedAvpSetFailureKind::MissingOneOf => {
                    "diameter_parser_missing_mandatory_avp_set"
                }
                DiameterGroupedAvpSetFailureKind::MutuallyExclusivePresent => {
                    "diameter_parser_mutually_exclusive_avps_present"
                }
            }
        } else {
            "diameter_parser_decode_failure"
        }
    }

    pub(crate) fn matches_request(&self, request: &[u8]) -> bool {
        request
            .get(..self.request_wire_len)
            .is_some_and(|wire| digest(wire) == self.request_digest)
    }
}

impl fmt::Debug for DiameterParserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiameterParserError")
            .field("code", &self.as_str())
            .field("decode_error", &self.decode_error)
            .field("missing_avp", &self.missing_avp)
            .field("grouped_avp_set", &self.grouped_avp_set)
            .field("request_wire_len", &self.request_wire_len)
            .field("request_digest", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for DiameterParserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at offset {}",
            self.as_str(),
            self.decode_error.offset()
        )
    }
}

impl std::error::Error for DiameterParserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.decode_error.as_ref())
    }
}

#[cfg(any(test, feature = "peer", feature = "app-swm"))]
fn fingerprint_message(message: &Message<'_>) -> (usize, [u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update([message.header.version]);
    hasher.update(u24(message.header.length));
    hasher.update([message.header.flags.bits()]);
    hasher.update(u24(message.header.command_code.get()));
    hasher.update(message.header.application_id.get().to_be_bytes());
    hasher.update(message.header.hop_by_hop_identifier.to_be_bytes());
    hasher.update(message.header.end_to_end_identifier.to_be_bytes());
    hasher.update(message.raw_avps);
    (
        DIAMETER_HEADER_LEN.saturating_add(message.raw_avps.len()),
        hasher.finalize().into(),
    )
}

fn digest(wire: &[u8]) -> [u8; 32] {
    Sha256::digest(wire).into()
}

#[cfg(any(test, feature = "peer", feature = "app-swm"))]
const fn u24(value: u32) -> [u8; 3] {
    let bytes = value.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}
