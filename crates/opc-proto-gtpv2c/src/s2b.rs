//! S2b-oriented GTPv2-C message views.
//!
//! The S2b surface in this crate is intentionally a typed subset: it decodes
//! Echo plus Create/Modify/Delete/Update Session-oriented GTPv2-C messages,
//! exposes mandatory S2b IE examples through typed values, and keeps
//! unsupported IEs as raw-preserving fallbacks. It is not a full ePDG or PGW
//! control-plane implementation.
//!
//! @spec 3GPP TS29274 R18 S2b procedure use
//! @req REQ-3GPP-TS29274-R18-S2B-001

use core::fmt;

use bytes::BytesMut;
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, SpecRef, ValidationLevel,
};

use crate::header::Header;
pub use crate::header::MessageType;
use crate::ie::{
    decode_typed_ie_sequence, TypedIe, TypedIeValue, IE_TYPE_APN, IE_TYPE_BEARER_CONTEXT,
    IE_TYPE_CAUSE, IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_IMSI, IE_TYPE_PAA, IE_TYPE_PDN_TYPE,
    IE_TYPE_RAT_TYPE, IE_TYPE_RECOVERY, IE_TYPE_SELECTION_MODE, IE_TYPE_SERVING_NETWORK,
};
use crate::Message;

/// Echo Request message type.
pub const ECHO_REQUEST: u8 = 1;

/// Echo Response message type.
pub const ECHO_RESPONSE: u8 = 2;

/// Create Session Request message type.
pub const CREATE_SESSION_REQUEST: u8 = 32;

/// Create Session Response message type.
pub const CREATE_SESSION_RESPONSE: u8 = 33;

/// Modify Bearer Request message type used by the S2b Modify Session view.
pub const MODIFY_BEARER_REQUEST: u8 = 34;

/// Modify Bearer Response message type used by the S2b Modify Session view.
pub const MODIFY_BEARER_RESPONSE: u8 = 35;

/// Delete Session Request message type.
pub const DELETE_SESSION_REQUEST: u8 = 36;

/// Delete Session Response message type.
pub const DELETE_SESSION_RESPONSE: u8 = 37;

/// Update Bearer Request message type used by the S2b Update Session view.
pub const UPDATE_BEARER_REQUEST: u8 = 97;

/// Update Bearer Response message type used by the S2b Update Session view.
pub const UPDATE_BEARER_RESPONSE: u8 = 98;

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "S2b")
}

fn is_procedure_aware(level: ValidationLevel) -> bool {
    matches!(level, ValidationLevel::ProcedureAware)
}

/// Request/response direction for an S2b procedure view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageDirection {
    /// Request message.
    Request,
    /// Response message.
    Response,
}

/// S2b procedure markers with typed support in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Procedure {
    /// Echo request/response exchange.
    Echo,
    /// Create Session request/response exchange.
    CreateSession,
    /// Modify Bearer request/response exchange, exposed as the S2b Modify Session view.
    ModifyBearer,
    /// Delete Session request/response exchange.
    DeleteSession,
    /// Update Bearer request/response exchange, exposed as the S2b Update Session view.
    UpdateSession,
}

impl Procedure {
    /// Return the GTPv2-C request message type for this procedure.
    pub const fn request_type(self) -> u8 {
        match self {
            Self::Echo => ECHO_REQUEST,
            Self::CreateSession => CREATE_SESSION_REQUEST,
            Self::ModifyBearer => MODIFY_BEARER_REQUEST,
            Self::DeleteSession => DELETE_SESSION_REQUEST,
            Self::UpdateSession => UPDATE_BEARER_REQUEST,
        }
    }

    /// Return the GTPv2-C response message type for this procedure.
    pub const fn response_type(self) -> u8 {
        match self {
            Self::Echo => ECHO_RESPONSE,
            Self::CreateSession => CREATE_SESSION_RESPONSE,
            Self::ModifyBearer => MODIFY_BEARER_RESPONSE,
            Self::DeleteSession => DELETE_SESSION_RESPONSE,
            Self::UpdateSession => UPDATE_BEARER_RESPONSE,
        }
    }

    /// Return the typed GTPv2-C request message type for this procedure.
    pub const fn request_message_type(self) -> MessageType {
        MessageType::from_u8(self.request_type())
    }

    /// Return the typed GTPv2-C response message type for this procedure.
    pub const fn response_message_type(self) -> MessageType {
        MessageType::from_u8(self.response_type())
    }
}

/// Return `true` when `message_type` belongs to the S2b typed subset.
pub const fn is_s2b_message_type(message_type: u8) -> bool {
    MessageType::from_u8(message_type).is_s2b()
}

fn procedure_and_direction(message_type: MessageType) -> Option<(Procedure, MessageDirection)> {
    match message_type {
        MessageType::EchoRequest => Some((Procedure::Echo, MessageDirection::Request)),
        MessageType::EchoResponse => Some((Procedure::Echo, MessageDirection::Response)),
        MessageType::CreateSessionRequest => {
            Some((Procedure::CreateSession, MessageDirection::Request))
        }
        MessageType::CreateSessionResponse => {
            Some((Procedure::CreateSession, MessageDirection::Response))
        }
        MessageType::ModifyBearerRequest => {
            Some((Procedure::ModifyBearer, MessageDirection::Request))
        }
        MessageType::ModifyBearerResponse => {
            Some((Procedure::ModifyBearer, MessageDirection::Response))
        }
        MessageType::DeleteSessionRequest => {
            Some((Procedure::DeleteSession, MessageDirection::Request))
        }
        MessageType::DeleteSessionResponse => {
            Some((Procedure::DeleteSession, MessageDirection::Response))
        }
        MessageType::UpdateBearerRequest => {
            Some((Procedure::UpdateSession, MessageDirection::Request))
        }
        MessageType::UpdateBearerResponse => {
            Some((Procedure::UpdateSession, MessageDirection::Response))
        }
        MessageType::Unknown(_) => None,
    }
}

/// A typed S2b GTPv2-C procedure message view.
///
/// `raw_ies` is retained for byte-exact raw-preserving encoding of decoded
/// messages. Canonical encoding emits the typed IE sequence and preserves any
/// unsupported IEs through [`TypedIeValue::Raw`].
///
/// @spec 3GPP TS29274 R18 S2b
/// @req REQ-3GPP-TS29274-R18-S2B-MESSAGE-001
#[derive(Clone, PartialEq, Eq)]
pub struct S2bProcedureMessage<'a> {
    /// Parsed GTPv2-C common header.
    pub header: Header,
    /// S2b procedure represented by this view.
    pub procedure: Procedure,
    /// Request or response direction.
    pub direction: MessageDirection,
    /// Typed IE sequence, with raw fallback for unsupported IEs.
    pub ies: Vec<TypedIe<'a>>,
    /// Original raw IE bytes from a decoded message.
    pub raw_ies: &'a [u8],
    /// Bytes beyond the decoded message boundary.
    pub tail: &'a [u8],
}

impl<'a> S2bProcedureMessage<'a> {
    /// Return this view's typed GTPv2-C message type.
    pub fn message_type(&self) -> MessageType {
        self.header.typed_message_type()
    }

    /// Return `true` if a top-level IE with `ie_type` is present.
    pub fn has_ie(&self, ie_type: u8) -> bool {
        contains_ie(&self.ies, ie_type)
    }

    fn encoded_raw_ies(&self, ctx: EncodeContext) -> Result<BytesMut, EncodeError> {
        if ctx.raw_preserving && !self.raw_ies.is_empty() {
            return Ok(BytesMut::from(self.raw_ies));
        }

        let mut raw_ies = BytesMut::new();
        for ie in &self.ies {
            ie.encode(&mut raw_ies, ctx)?;
        }
        Ok(raw_ies)
    }

    fn encoded_lens(&self, ctx: EncodeContext) -> Result<(usize, u16), EncodeError> {
        let raw_ie_len = if ctx.raw_preserving && !self.raw_ies.is_empty() {
            self.raw_ies.len()
        } else {
            self.ies.iter().try_fold(0usize, |acc, ie| {
                let len = ie.wire_len(ctx)?;
                acc.checked_add(len)
                    .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))
            })?
        };
        let total_len = self
            .header
            .wire_len()
            .checked_add(raw_ie_len)
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        let body_len = total_len.checked_sub(4).ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "message length underflow",
            })
            .with_spec_ref(spec_ref())
        })?;
        let body_len_u16 = u16::try_from(body_len)
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        Ok((total_len, body_len_u16))
    }
}

impl fmt::Debug for S2bProcedureMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S2bProcedureMessage")
            .field("header", &self.header)
            .field("procedure", &self.procedure)
            .field("direction", &self.direction)
            .field("ies", &self.ies)
            .field("raw_ies_len", &self.raw_ies.len())
            .field("tail_len", &self.tail.len())
            .finish()
    }
}

impl Encode for S2bProcedureMessage<'_> {
    /// Encode this S2b view as a GTPv2-C message.
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let (total_len, _) = self.encoded_lens(ctx)?;
        ctx.check_capacity(total_len)?;
        let raw_ies = self.encoded_raw_ies(ctx)?;
        let message = Message {
            header: self.header.clone(),
            raw_ies: &raw_ies,
            tail: &[],
        };
        message.encode(dst, ctx)
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        let (total_len, _) = self.encoded_lens(ctx)?;
        Ok(total_len)
    }
}

/// Typed S2b message view with raw fallback for non-S2b GTPv2-C messages.
///
/// @spec 3GPP TS29274 R18 S2b
/// @req REQ-3GPP-TS29274-R18-S2B-MESSAGE-002
#[derive(Clone, PartialEq, Eq)]
pub enum S2bMessage<'a> {
    /// Echo Request view.
    EchoRequest(S2bProcedureMessage<'a>),
    /// Echo Response view.
    EchoResponse(S2bProcedureMessage<'a>),
    /// Create Session Request view.
    CreateSessionRequest(S2bProcedureMessage<'a>),
    /// Create Session Response view.
    CreateSessionResponse(S2bProcedureMessage<'a>),
    /// Modify Bearer / S2b Modify Session Request view.
    ModifySessionRequest(S2bProcedureMessage<'a>),
    /// Modify Bearer / S2b Modify Session Response view.
    ModifySessionResponse(S2bProcedureMessage<'a>),
    /// Delete Session Request view.
    DeleteSessionRequest(S2bProcedureMessage<'a>),
    /// Delete Session Response view.
    DeleteSessionResponse(S2bProcedureMessage<'a>),
    /// Update Bearer / S2b Update Session Request view.
    UpdateSessionRequest(S2bProcedureMessage<'a>),
    /// Update Bearer / S2b Update Session Response view.
    UpdateSessionResponse(S2bProcedureMessage<'a>),
    /// Non-S2b or unsupported message preserved as the raw shell.
    Raw(Message<'a>),
}

impl fmt::Debug for S2bMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EchoRequest(view) => f.debug_tuple("EchoRequest").field(view).finish(),
            Self::EchoResponse(view) => f.debug_tuple("EchoResponse").field(view).finish(),
            Self::CreateSessionRequest(view) => {
                f.debug_tuple("CreateSessionRequest").field(view).finish()
            }
            Self::CreateSessionResponse(view) => {
                f.debug_tuple("CreateSessionResponse").field(view).finish()
            }
            Self::ModifySessionRequest(view) => {
                f.debug_tuple("ModifySessionRequest").field(view).finish()
            }
            Self::ModifySessionResponse(view) => {
                f.debug_tuple("ModifySessionResponse").field(view).finish()
            }
            Self::DeleteSessionRequest(view) => {
                f.debug_tuple("DeleteSessionRequest").field(view).finish()
            }
            Self::DeleteSessionResponse(view) => {
                f.debug_tuple("DeleteSessionResponse").field(view).finish()
            }
            Self::UpdateSessionRequest(view) => {
                f.debug_tuple("UpdateSessionRequest").field(view).finish()
            }
            Self::UpdateSessionResponse(view) => {
                f.debug_tuple("UpdateSessionResponse").field(view).finish()
            }
            Self::Raw(message) => f
                .debug_struct("Raw")
                .field("header", &message.header)
                .field("raw_ies_len", &message.raw_ies.len())
                .field("tail_len", &message.tail.len())
                .finish(),
        }
    }
}

impl<'a> S2bMessage<'a> {
    /// Decode a typed S2b view from a GTPv2-C byte slice.
    pub fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        <Self as BorrowDecode<'a>>::decode(input, ctx)
    }

    /// Convert a decoded raw [`Message`] into a typed S2b view when possible.
    pub fn from_message(message: Message<'a>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let message_type = message.message_type();
        let Some((procedure, direction)) = procedure_and_direction(message_type) else {
            return Ok(Self::Raw(message));
        };

        let ies = decode_typed_ie_sequence(message.raw_ies, ctx, 0)?;
        let view = S2bProcedureMessage {
            header: message.header,
            procedure,
            direction,
            ies,
            raw_ies: message.raw_ies,
            tail: message.tail,
        };
        validate_required_ies(&view, ctx)?;

        Ok(match (procedure, direction) {
            (Procedure::Echo, MessageDirection::Request) => Self::EchoRequest(view),
            (Procedure::Echo, MessageDirection::Response) => Self::EchoResponse(view),
            (Procedure::CreateSession, MessageDirection::Request) => {
                Self::CreateSessionRequest(view)
            }
            (Procedure::CreateSession, MessageDirection::Response) => {
                Self::CreateSessionResponse(view)
            }
            (Procedure::ModifyBearer, MessageDirection::Request) => {
                Self::ModifySessionRequest(view)
            }
            (Procedure::ModifyBearer, MessageDirection::Response) => {
                Self::ModifySessionResponse(view)
            }
            (Procedure::DeleteSession, MessageDirection::Request) => {
                Self::DeleteSessionRequest(view)
            }
            (Procedure::DeleteSession, MessageDirection::Response) => {
                Self::DeleteSessionResponse(view)
            }
            (Procedure::UpdateSession, MessageDirection::Request) => {
                Self::UpdateSessionRequest(view)
            }
            (Procedure::UpdateSession, MessageDirection::Response) => {
                Self::UpdateSessionResponse(view)
            }
        })
    }

    /// Return the typed procedure view, or `None` for raw fallback messages.
    pub fn as_view(&self) -> Option<&S2bProcedureMessage<'a>> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => Some(view),
            Self::Raw(_) => None,
        }
    }

    /// Return the raw fallback message, or `None` when this is a typed S2b view.
    pub fn as_raw(&self) -> Option<&Message<'a>> {
        match self {
            Self::Raw(message) => Some(message),
            _ => None,
        }
    }

    /// Return this message's typed GTPv2-C message type, including unknown raw fallbacks.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => view.message_type(),
            Self::Raw(message) => message.message_type(),
        }
    }
}

impl<'a> BorrowDecode<'a> for S2bMessage<'a> {
    /// Decode a typed S2b message view, preserving raw fallback messages.
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let (tail, message) = Message::decode(input, ctx)?;
        let view = Self::from_message(message, ctx)?;
        Ok((tail, view))
    }
}

impl Encode for S2bMessage<'_> {
    /// Encode this S2b view or raw fallback message.
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => view.encode(dst, ctx),
            Self::Raw(message) => message.encode(dst, ctx),
        }
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view) => view.wire_len(ctx),
            Self::Raw(message) => message.wire_len(ctx),
        }
    }
}

fn contains_ie(ies: &[TypedIe<'_>], ie_type: u8) -> bool {
    ies.iter().any(|ie| ie.ie_type() == ie_type)
}

fn contains_ie_instance(ies: &[TypedIe<'_>], ie_type: u8, instance: u8) -> bool {
    ies.iter()
        .any(|ie| ie.ie_type() == ie_type && ie.instance == instance)
}

fn contains_bearer_context_with_ebi(ies: &[TypedIe<'_>]) -> bool {
    ies.iter().any(|ie| match &ie.value {
        TypedIeValue::BearerContext(context) => contains_ie(&context.members, IE_TYPE_EBI),
        _ => false,
    })
}

fn missing_ie_error(reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, 0).with_spec_ref(spec_ref())
}

fn require_ie(ies: &[TypedIe<'_>], ie_type: u8, reason: &'static str) -> Result<(), DecodeError> {
    if contains_ie(ies, ie_type) {
        Ok(())
    } else {
        Err(missing_ie_error(reason))
    }
}

fn require_ie_instance(
    ies: &[TypedIe<'_>],
    ie_type: u8,
    instance: u8,
    reason: &'static str,
) -> Result<(), DecodeError> {
    if contains_ie_instance(ies, ie_type, instance) {
        Ok(())
    } else {
        Err(missing_ie_error(reason))
    }
}

fn validate_required_ies(
    view: &S2bProcedureMessage<'_>,
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    if !is_procedure_aware(ctx.validation_level) {
        return Ok(());
    }

    match (view.procedure, view.direction) {
        (Procedure::Echo, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_RECOVERY,
            "Echo Request requires Recovery IE",
        ),
        (Procedure::Echo, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_RECOVERY,
            "Echo Response requires Recovery IE",
        ),
        (Procedure::CreateSession, MessageDirection::Request) => {
            require_ie(
                &view.ies,
                IE_TYPE_IMSI,
                "Create Session Request requires IMSI IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_RAT_TYPE,
                "Create Session Request requires RAT Type IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_SERVING_NETWORK,
                "Create Session Request requires Serving Network IE",
            )?;
            require_ie_instance(
                &view.ies,
                IE_TYPE_F_TEID,
                0,
                "Create Session Request requires Sender F-TEID IE at instance 0",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_APN,
                "Create Session Request requires APN IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_SELECTION_MODE,
                "Create Session Request requires Selection Mode IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_PDN_TYPE,
                "Create Session Request requires PDN Type IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_PAA,
                "Create Session Request requires PAA IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_BEARER_CONTEXT,
                "Create Session Request requires Bearer Context IE",
            )?;
            if contains_bearer_context_with_ebi(&view.ies) {
                Ok(())
            } else {
                Err(missing_ie_error(
                    "Create Session Request Bearer Context requires EBI IE",
                ))
            }
        }
        (Procedure::CreateSession, MessageDirection::Response) => {
            require_ie(
                &view.ies,
                IE_TYPE_CAUSE,
                "Create Session Response requires Cause IE",
            )?;
            require_ie_instance(
                &view.ies,
                IE_TYPE_F_TEID,
                0,
                "Create Session Response requires Sender F-TEID IE at instance 0",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_BEARER_CONTEXT,
                "Create Session Response requires Bearer Context IE",
            )
        }
        (Procedure::ModifyBearer, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_BEARER_CONTEXT,
            "Modify Bearer Request requires Bearer Context IE",
        ),
        (Procedure::ModifyBearer, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Modify Bearer Response requires Cause IE",
        ),
        (Procedure::DeleteSession, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_EBI,
            "Delete Session Request requires linked EBI IE",
        ),
        (Procedure::DeleteSession, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Delete Session Response requires Cause IE",
        ),
        (Procedure::UpdateSession, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_BEARER_CONTEXT,
            "Update Bearer Request requires Bearer Context IE",
        ),
        (Procedure::UpdateSession, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Update Bearer Response requires Cause IE",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procedure_maps_request_and_response_types() {
        assert_eq!(
            Procedure::CreateSession.request_type(),
            CREATE_SESSION_REQUEST
        );
        assert_eq!(
            Procedure::CreateSession.response_type(),
            CREATE_SESSION_RESPONSE
        );
        assert_eq!(
            Procedure::UpdateSession.request_type(),
            UPDATE_BEARER_REQUEST
        );
        assert_eq!(Procedure::Echo.response_type(), ECHO_RESPONSE);
        assert!(is_s2b_message_type(DELETE_SESSION_RESPONSE));
        assert!(is_s2b_message_type(UPDATE_BEARER_RESPONSE));
        assert!(!is_s2b_message_type(3));
    }
}
