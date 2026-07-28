//! GTPv2-C decode failures that name the Information Element they are about.
//!
//! Element identity is modelled in this crate rather than on the shared
//! [`opc_protocol::DecodeError`] because the shapes genuinely disagree across
//! protocols: GTPv2-C keys an element on a one-octet Type plus a four-bit
//! Instance, PFCP on a `u16`, NGAP on a `u16`, and Diameter on an AVP code plus
//! an *optional* vendor id where absence and vendor zero are distinct. No
//! single field on the shared error could carry all four without either
//! misrepresenting one or degenerating into an opaque integer bag whose
//! interpretation lives outside the type that stores it. The shared crate keeps
//! the vocabulary every protocol shares -- code, offset, spec reference -- and
//! this crate speaks the richer dialect through its own inherent API.
//!
//! @spec 3GPP TS29274 R18 8.2, 8.4
//! @req REQ-3GPP-TS29274-R18-8.2-007

use core::fmt;

use opc_protocol::{DecodeError, DecodeErrorCode, SpecRef};

/// Decoder-held evidence for the wire scope in which an IE failure arose.
///
/// Private by design: callers receive only the checked
/// [`Gtpv2cDecodeError::top_level_offending_ie`] projection. In particular,
/// absence of a grouped-container identity is not allowed to become proof of
/// message-top-level scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IeScopeEvidence {
    /// The decode entry point did not know whether its input was a complete
    /// message IE region or an arbitrary subregion.
    Unknown,
    /// The message decoder positively established that the IE was in the
    /// message's top-level IE region.
    MessageTopLevel,
    /// A grouped decoder positively established that the failure was nested.
    Grouped,
}

/// Type and four-bit Instance of a GTPv2-C Information Element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gtpv2cOffendingIe {
    ie_type: u8,
    instance: u8,
}

impl Gtpv2cOffendingIe {
    /// Validate and construct an offending-IE identity.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cInvalidOffendingIeInstance`] when `instance` is wider
    /// than the four-bit GTPv2-C IE Instance field.
    pub const fn new(ie_type: u8, instance: u8) -> Result<Self, Gtpv2cInvalidOffendingIeInstance> {
        if instance <= 0x0f {
            Ok(Self { ie_type, instance })
        } else {
            Err(Gtpv2cInvalidOffendingIeInstance { instance })
        }
    }

    /// Identity of an element read from the wire.
    ///
    /// Total rather than validating: the callers are frames that decoded a
    /// four-octet header themselves, where the Instance nibble was masked out
    /// of the fourth octet (`input[3] & 0x0f`), so the four-bit bound
    /// [`Self::new`] enforces already holds. The mask restates that invariant
    /// so the constructor cannot construct an out-of-range identity, and it
    /// carries no assertion: a decoder reached from untrusted input must not
    /// have a panic on any path. Crate-private so the type keeps exactly one
    /// public constructor and one failure semantics.
    pub(crate) const fn from_wire(ie_type: u8, instance: u8) -> Self {
        Self {
            ie_type,
            instance: instance & 0x0f,
        }
    }

    /// IE Type octet.
    #[must_use]
    pub const fn ie_type(self) -> u8 {
        self.ie_type
    }

    /// Four-bit IE Instance.
    #[must_use]
    pub const fn instance(self) -> u8 {
        self.instance
    }

    pub(crate) const fn cause_field(self) -> [u8; 4] {
        [self.ie_type, 0, 0, self.instance]
    }
}

/// Error returned for an offending-IE instance wider than four bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cInvalidOffendingIeInstance {
    instance: u8,
}

impl Gtpv2cInvalidOffendingIeInstance {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "gtpv2c_offending_ie_instance_out_of_range"
    }

    /// Return the rejected instance.
    #[must_use]
    pub const fn instance(self) -> u8 {
        self.instance
    }
}

impl fmt::Display for Gtpv2cInvalidOffendingIeInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for Gtpv2cInvalidOffendingIeInstance {}

/// A GTPv2-C decode failure: the shared structured error, plus the identity of
/// the Information Element it is about when the decoder had read enough octets
/// to know it.
///
/// Size on a 64-bit target is 112 bytes, below clippy's 128-byte
/// `large-error-threshold`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cDecodeError {
    error: DecodeError,
    offending_ie: Option<Gtpv2cOffendingIe>,
    enclosing_ie: Option<Gtpv2cOffendingIe>,
    ie_scope: IeScopeEvidence,
}

// clippy::result_large_err's default large-error-threshold is 128 bytes and the
// comparison is `>=`. This type crosses the GTPv2-C decode spine inside a
// Result, so it must stay below that. An inequality, never an equality: 32-bit
// targets lay this out smaller and `==` would fail there. Measured on x86-64:
// DecodeError is 104 and this type is 112.
const _: () = assert!(
    core::mem::size_of::<Gtpv2cDecodeError>() < 128,
    "Gtpv2cDecodeError must stay below clippy's result_large_err threshold"
);

impl Gtpv2cDecodeError {
    /// Wrap a decode error that names no element.
    #[must_use]
    pub const fn new(error: DecodeError) -> Self {
        Self {
            error,
            offending_ie: None,
            enclosing_ie: None,
            ie_scope: IeScopeEvidence::Unknown,
        }
    }

    /// The underlying protocol-neutral decode error.
    #[must_use]
    pub const fn error(&self) -> &DecodeError {
        &self.error
    }

    /// Error classification. Equivalent to `self.error().code()`.
    #[must_use]
    pub const fn code(&self) -> &DecodeErrorCode {
        self.error.code()
    }

    /// Byte offset where parsing failed. Equivalent to `self.error().offset()`.
    ///
    /// The full `usize` range is observable; nothing is narrowed or saturated.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.error.offset()
    }

    /// Specification reference. Equivalent to `self.error().spec_ref()`.
    #[must_use]
    pub const fn spec_ref(&self) -> Option<&SpecRef> {
        self.error.spec_ref()
    }

    /// Type and four-bit Instance of the element this error is about, when a
    /// complete four-octet IE header for that element had been read.
    ///
    /// Identity is attached by the innermost decode frame that had already read
    /// a complete four-octet header for the element the error is about.
    /// A framing error raised before such a header names no element. IE-count,
    /// depth and offset-arithmetic errors name no element wherever they are
    /// raised, because they describe sequence bookkeeping rather than received
    /// IE octets. Inside a grouped IE the enclosing container is reported
    /// separately by [`Self::enclosing_ie`], and at top level such an error
    /// carries no identity at all. **Absence of identity is normal and expected
    /// for those classes.**
    ///
    /// Knowing the offending Type and Instance is *necessary but not
    /// sufficient* to decide that a TS 29.274 error response is owed.
    /// Sufficiency additionally requires request-versus-response, the Echo
    /// exception, the message grammar, slot presence and conditional
    /// verifiability; that decision belongs to
    /// [`crate::Gtpv2cErrorResponsePlanner`], as its own `plan_request_failure`
    /// demonstrates by refusing to answer several inputs that carry a perfectly
    /// valid identity.
    #[must_use]
    pub const fn offending_ie(&self) -> Option<Gtpv2cOffendingIe> {
        self.offending_ie
    }

    /// Return the offending IE only when the decoder positively proved it was
    /// at message top level.
    ///
    /// This is the checked projection for disposition code. In particular, it
    /// returns `None` both for a malformed member of a grouped IE and for an
    /// error produced by [`crate::RawIeIterator`] or
    /// [`crate::validate_ie_region_annotated`] directly. Those generic
    /// subregion decoders do not know whether their input came from message
    /// top level or from inside a group; absence of an enclosing identity is
    /// therefore not proof of top-level scope.
    ///
    /// The Cause encoder currently emits a zero flags octet, which represents
    /// top-level scope, so callers must not bypass this projection when
    /// deriving a Cause offending-IE field.
    /// [`crate::Gtpv2cErrorResponsePlanner::plan_invalid_ie_length_from_decode`]
    /// carries this check through response planning.
    #[must_use]
    pub const fn top_level_offending_ie(&self) -> Option<Gtpv2cOffendingIe> {
        match self.ie_scope {
            IeScopeEvidence::MessageTopLevel => self.offending_ie,
            IeScopeEvidence::Unknown | IeScopeEvidence::Grouped => None,
        }
    }

    /// Type and four-bit Instance of the grouped IE the offending element was
    /// nested in, when it was nested.
    ///
    /// The raw pair remains available for diagnostics. Disposition code should
    /// use [`Self::top_level_offending_ie`] or
    /// [`crate::Gtpv2cErrorResponsePlanner::plan_invalid_ie_length_from_decode`].
    /// Both refuse Unknown or Grouped scope rather than feeding an unproven or
    /// member identity into the current Cause encoder, whose zero flags octet
    /// represents message-top-level scope. Modelling the grouped-IE flag bits
    /// remains disposition-layer work.
    #[must_use]
    pub const fn enclosing_ie(&self) -> Option<Gtpv2cOffendingIe> {
        self.enclosing_ie
    }

    /// Record positive evidence that this failure arose in the message's
    /// top-level IE region.
    ///
    /// Grouped evidence wins: an outer message frame must not erase scope
    /// already established by a nested decoder.
    pub(crate) fn mark_message_top_level(mut self) -> Self {
        if matches!(self.ie_scope, IeScopeEvidence::Unknown) {
            self.ie_scope = IeScopeEvidence::MessageTopLevel;
        }
        self
    }

    /// Discard the GTPv2-C annotation and return the shared decode error.
    #[must_use]
    pub fn into_error(self) -> DecodeError {
        self.error
    }

    /// Attach element identity, replacing anything already recorded.
    ///
    /// Only for a failure constructed in the same frame that read the header.
    pub(crate) fn annotate_offending(mut self, offending: Gtpv2cOffendingIe) -> Self {
        self.offending_ie = Some(offending);
        self
    }

    /// Attach element identity if none is recorded. First annotation wins, so
    /// the innermost frame that knows which element failed keeps it.
    ///
    /// Validating rather than masking, because `instance` reaches here from
    /// [`crate::RawIe::instance`], a public field: a caller that builds a
    /// [`crate::RawIe`] by hand and passes it to
    /// [`crate::TypedIe::decode_from_raw`] can supply a value wider than the
    /// four-bit wire field. Folding such a value into a nibble would name a
    /// different element than the caller described, so an out-of-range
    /// instance names none -- absence of identity is already the documented
    /// outcome wherever no element can be identified.
    pub(crate) fn annotate_offending_if_absent(mut self, ie_type: u8, instance: u8) -> Self {
        if self.offending_ie.is_none() {
            self.offending_ie = Gtpv2cOffendingIe::new(ie_type, instance).ok();
        }
        self
    }

    /// Attach enclosing grouped-IE identity if none is recorded.
    ///
    /// Validating for the same reason as [`Self::annotate_offending_if_absent`]:
    /// the grouped container's instance also originates in a caller-writable
    /// [`crate::RawIe`] field.
    pub(crate) fn annotate_enclosing_if_absent(mut self, ie_type: u8, instance: u8) -> Self {
        // Scope evidence does not depend on whether a caller-constructed
        // RawIe supplied a representable four-bit container Instance.
        self.ie_scope = IeScopeEvidence::Grouped;
        if self.enclosing_ie.is_none() {
            self.enclosing_ie = Gtpv2cOffendingIe::new(ie_type, instance).ok();
        }
        self
    }
}

impl From<DecodeError> for Gtpv2cDecodeError {
    fn from(error: DecodeError) -> Self {
        Self::new(error)
    }
}

// A deliberate, lossy downgrade, invoked implicitly by `?` wherever a rich
// frame feeds a `DecodeError`-returning one -- including the
// `opc_protocol::BorrowDecode` port, whose error type is fixed by design. Any
// new grouped decoder must carry `Gtpv2cDecodeError` end to end or its member
// identity will vanish here with no compile error.
impl From<Gtpv2cDecodeError> for DecodeError {
    fn from(error: Gtpv2cDecodeError) -> Self {
        error.into_error()
    }
}

impl fmt::Display for Gtpv2cDecodeError {
    /// Byte-identical to the inner [`DecodeError`]'s, so `{}` renders exactly
    /// what it did before. Identity is reachable through the accessors and
    /// `Debug` only.
    ///
    /// This holds for `Display` alone. [`std::error::Error::source`] exposes
    /// the inner error, so a reporter that walks and prints the chain renders
    /// that same text once more; see the note on the `Error` impl.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for Gtpv2cDecodeError {
    /// The inner error is exposed as the source so a caller holding this as
    /// `dyn Error` can still downcast to [`DecodeError`] and read the shared
    /// classification. Because `Display` delegates to that same value, a
    /// chain-walking reporter prints the message twice; use [`Self::error`]
    /// rather than the chain when a single rendering is wanted.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_delegates_to_the_shared_error() {
        let inner = DecodeError::new(DecodeErrorCode::Truncated, 7);
        let annotated = Gtpv2cDecodeError::new(inner.clone())
            .annotate_offending(Gtpv2cOffendingIe::from_wire(176, 0));
        assert_eq!(annotated.to_string(), inner.to_string());
    }

    #[test]
    fn an_out_of_range_instance_names_no_element() {
        // `RawIe::instance` is a public field, so `TypedIe::decode_from_raw`
        // can be handed a value wider than the four-bit wire field. Naming
        // instance 15 for a caller who wrote 0xff would identify a different
        // element; naming nothing is the honest answer.
        let inner = DecodeError::new(DecodeErrorCode::Truncated, 0);
        let annotated = Gtpv2cDecodeError::new(inner)
            .annotate_offending_if_absent(176, 0xff)
            .annotate_enclosing_if_absent(93, 0x10);
        assert_eq!(annotated.offending_ie(), None);
        assert_eq!(annotated.enclosing_ie(), None);
    }

    #[test]
    fn grouped_scope_survives_an_unrepresentable_container_identity() {
        let inner = DecodeError::new(DecodeErrorCode::Truncated, 0);
        let annotated = Gtpv2cDecodeError::new(inner)
            .annotate_offending_if_absent(176, 0)
            .annotate_enclosing_if_absent(93, 0x10);
        assert_eq!(
            annotated.offending_ie(),
            Some(Gtpv2cOffendingIe::from_wire(176, 0))
        );
        assert_eq!(annotated.enclosing_ie(), None);
        assert_eq!(
            annotated.top_level_offending_ie(),
            None,
            "failure to represent the container must not erase grouped scope"
        );
    }

    #[test]
    fn first_annotation_wins() {
        let inner = DecodeError::new(DecodeErrorCode::Truncated, 0);
        let annotated = Gtpv2cDecodeError::new(inner)
            .annotate_offending_if_absent(176, 0)
            .annotate_offending_if_absent(93, 1);
        assert_eq!(
            annotated.offending_ie(),
            Some(Gtpv2cOffendingIe::from_wire(176, 0))
        );
    }
}
