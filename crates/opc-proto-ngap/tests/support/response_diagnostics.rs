//! Shared response admission, reconstruction and diagnostic-preservation checks.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::ReleaseMessage;
use opc_proto_ngap::n3iwf::reset_fields::CriticalityDiagnostics;
use opc_proto_ngap::n3iwf::resource_release::{ResourceReleaseMessage, SessionReleaseResponse};
use opc_proto_ngap::n3iwf::resource_setup::{
    InitialContextFailure, InitialContextResponse, ResourceSetupMessage, SessionResourceResponse,
};
use opc_proto_ngap::n3iwf::setup::{NgSetupFailure, NgSetupResponse, SetupMessage};
use opc_proto_ngap::{encode, MessageType, Pdu, PduKind};
use opc_protocol::{DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, OwnedDecode};

pub enum Response {
    Setup(NgSetupResponse),
    SetupFailure(NgSetupFailure),
    Context(InitialContextResponse),
    ContextFailure(InitialContextFailure),
    Session(SessionResourceResponse),
    SessionRelease(SessionReleaseResponse),
    UeRelease(ReleaseMessage),
}
impl Response {
    pub fn diagnostics(&self) -> &Option<CriticalityDiagnostics> {
        match self {
            Self::Setup(v) => &v.diagnostics,
            Self::SetupFailure(v) => &v.diagnostics,
            Self::Context(v) => &v.diagnostics,
            Self::ContextFailure(v) => &v.diagnostics,
            Self::Session(v) => &v.diagnostics,
            Self::SessionRelease(v) => &v.diagnostics,
            Self::UeRelease(ReleaseMessage::Complete { diagnostics, .. }) => diagnostics,
            _ => unreachable!("response only"),
        }
    }
    pub fn set_diagnostics(&mut self, value: Option<CriticalityDiagnostics>) {
        let field = match self {
            Self::Setup(v) => &mut v.diagnostics,
            Self::SetupFailure(v) => &mut v.diagnostics,
            Self::Context(v) => &mut v.diagnostics,
            Self::ContextFailure(v) => &mut v.diagnostics,
            Self::Session(v) => &mut v.diagnostics,
            Self::SessionRelease(v) => &mut v.diagnostics,
            Self::UeRelease(ReleaseMessage::Complete { diagnostics, .. }) => diagnostics,
            _ => unreachable!("response only"),
        };
        *field = value;
    }
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        match self {
            Self::Setup(v) => v.construct(ctx),
            Self::SetupFailure(v) => v.construct(ctx),
            Self::Context(v) => v.construct(ctx),
            Self::ContextFailure(v) => v.construct(ctx),
            Self::Session(v) => v.construct(ctx),
            Self::SessionRelease(v) => ResourceReleaseMessage::Response(v.clone()).construct(ctx),
            Self::UeRelease(v) => v.construct(ctx),
        }
    }
}
pub fn admit(pdu: &Pdu, ctx: DecodeContext) -> Result<(Response, usize, Vec<u16>), DecodeError> {
    let message = match &pdu.kind {
        PduKind::Initiating { message, .. }
        | PduKind::Successful { message, .. }
        | PduKind::Unsuccessful { message, .. } => message,
    };
    match message.message_type() {
        Some(MessageType::NgSetupResponse | MessageType::NgSetupFailure) => {
            let v = SetupMessage::from_pdu(pdu, ctx)?;
            let response = match v.message {
                SetupMessage::Response(v) => Response::Setup(v),
                SetupMessage::Failure(v) => Response::SetupFailure(v),
                _ => unreachable!("response only"),
            };
            Ok((response, v.ignored_ie_count, v.notify_ie_ids))
        }
        Some(
            MessageType::InitialContextSetupResponse
            | MessageType::InitialContextSetupFailure
            | MessageType::PduSessionResourceSetupResponse,
        ) => {
            let v = ResourceSetupMessage::from_pdu(pdu, ctx)?;
            let response = match v.message {
                ResourceSetupMessage::InitialResponse(v) => Response::Context(v),
                ResourceSetupMessage::InitialFailure(v) => Response::ContextFailure(v),
                ResourceSetupMessage::SessionResponse(v) => Response::Session(v),
                _ => unreachable!("response only"),
            };
            Ok((response, v.ignored_ie_count, v.notify_ie_ids))
        }
        Some(MessageType::PduSessionResourceReleaseResponse) => {
            let v = ResourceReleaseMessage::from_pdu(pdu, ctx)?;
            let ResourceReleaseMessage::Response(response) = v.message else {
                unreachable!("response only")
            };
            Ok((
                Response::SessionRelease(response),
                v.ignored_ie_count,
                v.notify_ie_ids,
            ))
        }
        Some(MessageType::UeContextReleaseComplete) => {
            let v = ReleaseMessage::from_pdu(pdu, ctx)?;
            Ok((
                Response::UeRelease(v.message),
                v.ignored_ie_count,
                v.notify_ie_ids,
            ))
        }
        _ => Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "not a qualified response",
            },
            0,
        )),
    }
}
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    let ctx = DecodeContext {
        max_depth: 24,
        max_ies: 256,
        ..ctx
    };
    let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), ctx) else {
        return;
    };
    let Ok((value, _, _)) = admit(&pdu, ctx) else {
        return;
    };
    let wire = encode(&value.construct(ctx).unwrap(), output).unwrap();
    let decoded = Pdu::decode_owned(Bytes::from(wire.clone()), ctx).unwrap();
    let (mut next, ignored, notify) = admit(&decoded, ctx).unwrap();
    assert!(ignored == 0 && notify.is_empty());
    assert!(value.diagnostics() == next.diagnostics());
    assert!(encode(&next.construct(ctx).unwrap(), output).unwrap() == wire);
    // Replacement uses the public field setter path too; absent versus empty
    // must not be collapsed by a later constructor.
    next.set_diagnostics(value.diagnostics().clone());
    assert!(encode(&next.construct(ctx).unwrap(), output).unwrap() == wire);
}
