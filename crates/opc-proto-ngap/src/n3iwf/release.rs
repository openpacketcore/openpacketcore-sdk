//! Typed UE Context Release Command and Complete field admission.
//!
//! TS 38.413 8.3.3 permits an AMF/RAN pair or an AMF-only identifier in the
//! command. This codec checks the admitted fields, without resolving the UE,
//! releasing resources, acknowledging a procedure or changing any backend.
//! Association ownership and procedure ordering remain caller responsibilities.

use super::*;
use crate::{policy, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;
use rasn::types::Enumerated;

/// Standard Cause choice, without the unimplemented choice-extension branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CauseClass {
    /// Radio network cause.
    RadioNetwork,
    /// Transport cause.
    Transport,
    /// NAS cause.
    Nas,
    /// Protocol cause.
    Protocol,
    /// Miscellaneous cause.
    Misc,
}

/// A root Cause enumeration value. Selection/interpretation is caller-owned.
///
/// Root numeric values are those in TS 38.413 9.3.1.2. Extension values and
/// choice extensions are explicitly unsupported in this initial field subset.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cause {
    class: CauseClass,
    code: u8,
}
redacted!(Cause);

impl Cause {
    /// Admit a standard root cause code in its explicit class.
    pub fn new(class: CauseClass, code: u8) -> Result<Self, DecodeError> {
        let maximum = match class {
            CauseClass::RadioNetwork => 44,
            CauseClass::Transport => 1,
            CauseClass::Nas => 3,
            CauseClass::Protocol => 6,
            CauseClass::Misc => 5,
        };
        if code > maximum {
            return Err(invalid("unsupported cause enumeration"));
        }
        Ok(Self { class, code })
    }
    /// Explicit access to the cause class.
    pub const fn class(self) -> CauseClass {
        self.class
    }
    /// Explicit access to the root enumeration code.
    pub const fn code(self) -> u8 {
        self.code
    }
    /// Encode this root value through the generated schema.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let code = isize::from(self.code);
        let value = match self.class {
            CauseClass::RadioNetwork => {
                asn::CauseRadioNetwork::from_discriminant(code).map(asn::Cause::radioNetwork)
            }
            CauseClass::Transport => {
                asn::CauseTransport::from_discriminant(code).map(asn::Cause::transport)
            }
            CauseClass::Nas => asn::CauseNas::from_discriminant(code).map(asn::Cause::nas),
            CauseClass::Protocol => {
                asn::CauseProtocol::from_discriminant(code).map(asn::Cause::protocol)
            }
            CauseClass::Misc => asn::CauseMisc::from_discriminant(code).map(asn::Cause::misc),
        }
        .ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "cause schema mismatch",
            })
        })?;
        encode_leaf(&value, ctx)
    }
    /// Decode a complete root value. Reject extensions before materializing
    /// the generated choice-extension open type.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let first = *input.first().ok_or_else(|| invalid("missing cause"))?;
        if first >> 5 >= 5 || first & 0x10 != 0 {
            return Err(unsupported());
        }
        let (class, code) = match decode_leaf::<asn::Cause>(input)? {
            asn::Cause::radioNetwork(value) => (CauseClass::RadioNetwork, value as u8),
            asn::Cause::transport(value) => (CauseClass::Transport, value as u8),
            asn::Cause::nas(value) => (CauseClass::Nas, value as u8),
            asn::Cause::protocol(value) => (CauseClass::Protocol, value as u8),
            asn::Cause::misc(value) => (CauseClass::Misc, value as u8),
            asn::Cause::choice_Extensions(_) => return Err(unsupported()),
        };
        Self::new(class, code)
    }
}

/// UE identifier choice carried by Release Command. AMF-only is valid when
/// the RAN identifier is unavailable; no association lookup is inferred.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UeIdentifiers {
    /// Both identifiers are available.
    Pair {
        /// Peer AMF identifier.
        amf: AmfUeId,
        /// Local RAN identifier.
        ran: RanUeId,
    },
    /// Only the peer AMF identifier is available.
    AmfOnly(AmfUeId),
}
redacted!(UeIdentifiers);

impl UeIdentifiers {
    /// Encode a root identifier choice without extensions.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let value = match self {
            Self::Pair { amf, ran } => asn::UENGAPIDs::uE_NGAP_ID_pair(asn::UENGAPIDPair::new(
                asn::AMFUENGAPID(amf.value()),
                asn::RANUENGAPID(ran.value()),
                None,
            )),
            Self::AmfOnly(amf) => asn::UENGAPIDs::aMF_UE_NGAP_ID(asn::AMFUENGAPID(amf.value())),
        };
        encode_leaf(&value, ctx)
    }
    /// Decode a complete choice; preflight the fixed choice/SEQUENCE flags
    /// before any unsupported generated extension collection can be allocated.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 3)?;
        let first = *input
            .first()
            .ok_or_else(|| invalid("missing ue identifiers"))?;
        match first >> 6 {
            0 if first & 0x30 == 0 => (),
            1 => (),
            _ => return Err(unsupported()),
        }
        match decode_leaf::<asn::UENGAPIDs>(input)? {
            asn::UENGAPIDs::uE_NGAP_ID_pair(value) => {
                if value.i_e_extensions.is_some() {
                    return Err(unsupported());
                }
                Ok(Self::Pair {
                    amf: AmfUeId::new(value.a_mf_ue_ngap_id.0)?,
                    ran: RanUeId::new(value.r_an_ue_ngap_id.0),
                })
            }
            asn::UENGAPIDs::aMF_UE_NGAP_ID(value) => Ok(Self::AmfOnly(AmfUeId::new(value.0)?)),
            asn::UENGAPIDs::choice_Extensions(_) => Err(unsupported()),
        }
    }
}

/// The admitted UE release field subset. Optional session-resource and
/// criticality-diagnostics IEs require subsequent codecs and fail admission.
pub enum ReleaseMessage {
    /// Initiating Release Command, procedure 41.
    Command {
        /// Available UE identifiers.
        identifiers: UeIdentifiers,
        /// Reason selected by the enclosing procedure.
        cause: Cause,
    },
    /// Successful Release Complete, procedure 41.
    Complete {
        /// Peer AMF identifier.
        amf: AmfUeId,
        /// Local RAN identifier.
        ran: RanUeId,
        /// Optional N3IWF location.
        location: Option<N3iwfLocation>,
    },
}
redacted!(ReleaseMessage);

/// Validated fields and diagnostics for caller-owned procedure processing.
#[derive(Debug)]
pub struct AdmittedRelease {
    /// Fields only; no resource cleanup or acknowledgement has occurred.
    pub message: ReleaseMessage,
    /// Receiver-ignored or unknown-ignore IEs in the filtered view.
    pub ignored_ie_count: usize,
    /// Unknown-notify identifiers, without peer-provided values.
    pub notify_ie_ids: Vec<u16>,
}

impl ReleaseMessage {
    /// Construct a canonical PDU and apply the same required-field admission
    /// used on receive. Caller authorization and procedure state are separate.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        let output = EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        };
        let mut fields = Vec::new();
        let kind = match self {
            Self::Command { identifiers, cause } => {
                fields.push((
                    114,
                    Criticality::reject,
                    identifiers.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    15,
                    Criticality::ignore,
                    cause.encode(output).map_err(encode_error)?,
                ));
                MessageType::UeContextReleaseCommand
            }
            Self::Complete { amf, ran, location } => {
                fields.push((
                    10,
                    Criticality::ignore,
                    amf.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    85,
                    Criticality::ignore,
                    ran.encode(output).map_err(encode_error)?,
                ));
                if let Some(location) = location {
                    fields.push((
                        121,
                        Criticality::ignore,
                        location.encode(output).map_err(encode_error)?,
                    ));
                }
                MessageType::UeContextReleaseComplete
            }
        };
        let ies: Vec<_> = fields
            .iter()
            .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
            .collect();
        let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
        Self::from_pdu(&pdu, ctx)?;
        Ok(pdu)
    }

    /// Validate the generic decoder's policy-filtered view. This revalidates
    /// the mutable wrapper and IE metadata without changing preserved bytes.
    pub fn from_pdu(pdu: &Pdu, ctx: DecodeContext) -> Result<AdmittedRelease, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        })
        .map_err(|_| invalid("release message container policy"))?;
        match &pdu.kind {
            PduKind::Initiating {
                message: Message::UeContextReleaseCommand(value),
                ..
            } => admit(
                true,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id.0, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            PduKind::Successful {
                message: Message::UeContextReleaseComplete(value),
                ..
            } => admit(
                false,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id.0, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            _ => Err(invalid("release message outcome")),
        }
    }
}

fn encode_error(_: EncodeError) -> DecodeError {
    invalid("release field encoding or capacity")
}

fn admit<'a>(
    command: bool,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    ctx: DecodeContext,
) -> Result<AdmittedRelease, DecodeError> {
    let (profile, supported, ignored): (policy::IeProfile, &[u16], &[u16]) = if command {
        (policy::UE_CONTEXT_RELEASE_COMMAND, &[114, 15], &[])
    } else {
        (
            policy::UE_CONTEXT_RELEASE_COMPLETE,
            &[10, 85, 121],
            &[32, 207],
        )
    };
    let leaf_ctx = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
    let (mut identifiers, mut cause, mut amf, mut ran, mut location) =
        (None, None, None, None, None);
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    for (index, (id, crit, value)) in fields.enumerate() {
        if index >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        if ignored.contains(&id) {
            ignored_ie_count += 1;
            continue;
        }
        if !supported.contains(&id) {
            if profile.recognizes(id) {
                return Err(invalid("applicable release ie not admitted"));
            }
            match crit {
                1 => ignored_ie_count += 1,
                2 => notify_ie_ids.push(id),
                _ => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
            }
            continue;
        }
        match id {
            114 => identifiers = Some(UeIdentifiers::decode(value, leaf_ctx)?),
            15 => cause = Some(Cause::decode(value, leaf_ctx)?),
            10 => amf = Some(AmfUeId::decode(value, leaf_ctx)?),
            85 => ran = Some(RanUeId::decode(value, leaf_ctx)?),
            121 => location = Some(N3iwfLocation::decode(value, leaf_ctx)?),
            _ => return Err(invalid("release field dispatch")),
        }
    }
    let message = if command {
        ReleaseMessage::Command {
            identifiers: identifiers.ok_or_else(|| invalid("missing ue identifiers"))?,
            cause: cause.ok_or_else(|| invalid("missing release cause"))?,
        }
    } else {
        ReleaseMessage::Complete {
            amf: amf.ok_or_else(|| invalid("missing amf ue id"))?,
            ran: ran.ok_or_else(|| invalid("missing ran ue id"))?,
            location,
        }
    };
    Ok(AdmittedRelease {
        message,
        ignored_ie_count,
        notify_ie_ids,
    })
}
