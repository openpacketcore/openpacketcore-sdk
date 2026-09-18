//! N3IWF Initial UE and NAS transport field admission (TS 29.413 5.2/5.3).
//!
//! The generic decoder first applies its configured unknown/duplicate policy.
//! [`NasMessage::from_pdu`] validates that resulting view, enforces mandatory
//! fields and returns typed NAS values plus any unknown-notify diagnostics.
//! It does not deliver NAS, select an AMF, bind identifiers or run a procedure.
//! Applicable fields without an admitted codec fail explicitly; their presence
//! cannot silently enable a partial procedure. The source PDU retains all bytes
//! required by its existing raw-preservation contract.

use super::context_fields::AllowedNssai;
use super::setup_fields::AmfName;
use super::*;
use crate::{policy, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// The NGAP establishment-cause enumeration. Selection for non-3GPP access
/// follows TS 24.502; this codec does not select a cause on the caller's behalf.
pub use asn::RRCEstablishmentCause as EstablishmentCause;

/// UE aggregate maximum bit rates, in bits per second, with distinct UL/DL values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UeAggregateBitRate {
    downlink: u64,
    uplink: u64,
}
redacted!(UeAggregateBitRate);

impl UeAggregateBitRate {
    /// Admit the ASN.1 root range (0 through 4,000,000,000,000 bits/s).
    /// Values using an ASN.1 extension range are not admitted in this subset.
    pub fn new(downlink: u64, uplink: u64) -> Result<Self, DecodeError> {
        if downlink > 4_000_000_000_000 || uplink > 4_000_000_000_000 {
            return Err(invalid("ue aggregate bit rate range"));
        }
        Ok(Self { downlink, uplink })
    }
    /// Explicit access to the downlink limit, in bits per second.
    pub const fn downlink(self) -> u64 {
        self.downlink
    }
    /// Explicit access to the uplink limit, in bits per second.
    pub const fn uplink(self) -> u64 {
        self.uplink
    }
    /// Encode the bounded root value without extensions.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_leaf(
            &asn::UEAggregateMaximumBitRate::new(
                asn::BitRate(self.downlink.into()),
                asn::BitRate(self.uplink.into()),
                None,
            ),
            ctx,
        )
    }
    /// Decode the complete bounded field; nested extensions are unsupported.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        if input.first().is_some_and(|v| v & 0xc0 != 0) {
            return Err(unsupported());
        }
        let value: asn::UEAggregateMaximumBitRate = decode_leaf(input)?;
        let downlink = u64::try_from(value.u_eaggregate_maximum_bit_rate_dl.0)
            .map_err(|_| invalid("ue aggregate bit rate range"))?;
        let uplink = u64::try_from(value.u_eaggregate_maximum_bit_rate_ul.0)
            .map_err(|_| invalid("ue aggregate bit rate range"))?;
        Self::new(downlink, uplink)
    }
}

/// Typed fields for three N3IWF NAS message outcomes.
///
/// Field access is explicit. Debug prints only the message name. Association,
/// subscription, access-network conditions and NAS security remain caller-owned.
pub enum NasMessage<'a> {
    /// Initial UE Message (initiating procedure 15).
    InitialUe {
        /// Local N3IWF UE identifier.
        ran: RanUeId,
        /// Opaque NAS message.
        nas: NasPdu<'a>,
        /// Current N3IWF IP location.
        location: N3iwfLocation,
        /// Establishment cause supplied by the caller.
        cause: EstablishmentCause,
        /// Selected PLMN, when supplied by the access procedure.
        selected_plmn: Option<PlmnId>,
        /// Whether UE context establishment is requested.
        context_requested: bool,
        /// Optional advertised slices. Admission grants no slice authorization.
        allowed_nssai: Option<AllowedNssai>,
    },
    /// Downlink NAS Transport (initiating procedure 4).
    Downlink {
        /// Peer AMF identifier.
        amf: AmfUeId,
        /// Local N3IWF identifier.
        ran: RanUeId,
        /// Opaque NAS message.
        nas: NasPdu<'a>,
        /// Applicable optional rate limit; never treated as a receiver-ignored IE.
        aggregate_bit_rate: Option<UeAggregateBitRate>,
        /// Optional advertised slices. Admission grants no slice authorization.
        allowed_nssai: Option<AllowedNssai>,
        /// Previous AMF name, without selecting or authorizing an AMF.
        old_amf: Option<AmfName>,
    },
    /// Uplink NAS Transport (initiating procedure 46).
    Uplink {
        /// Peer AMF identifier.
        amf: AmfUeId,
        /// Local N3IWF identifier.
        ran: RanUeId,
        /// Opaque NAS message.
        nas: NasPdu<'a>,
        /// Current N3IWF IP location.
        location: N3iwfLocation,
    },
}

impl fmt::Debug for NasMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InitialUe { .. } => "InitialUe([REDACTED])",
            Self::Downlink { .. } => "DownlinkNas([REDACTED])",
            Self::Uplink { .. } => "UplinkNas([REDACTED])",
        })
    }
}

/// A received typed view and value-free obligations for the enclosing procedure.
#[derive(Debug)]
pub struct AdmittedNas<'a> {
    /// Admitted core fields; no NAS delivery or procedure side effect has occurred.
    pub message: NasMessage<'a>,
    /// Count of explicitly receiver-ignored or unknown-ignore fields in the view.
    pub ignored_ie_count: usize,
    /// Unknown notify-criticality IE identifiers to include in caller-owned
    /// criticality diagnostics. No peer-provided IE values are copied here.
    pub notify_ie_ids: Vec<u16>,
}

impl NasMessage<'_> {
    /// Construct the admitted field subset as a canonical container. It has no
    /// received raw image. Applicable conditions beyond these explicit fields
    /// (for example SNPN selection) must be handled before choosing this subset.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        let output = EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        };
        let mut fields: Vec<(u16, Criticality, EncodedValue)> = Vec::new();
        let kind = match self {
            Self::InitialUe {
                ran,
                nas,
                location,
                cause,
                selected_plmn,
                context_requested,
                allowed_nssai,
            } => {
                fields.push((
                    85,
                    Criticality::reject,
                    ran.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    38,
                    Criticality::reject,
                    nas.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    121,
                    Criticality::reject,
                    location.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    90,
                    Criticality::ignore,
                    encode_leaf(cause, output).map_err(encode_error)?,
                ));
                if let Some(plmn) = selected_plmn {
                    fields.push((
                        174,
                        Criticality::ignore,
                        encode_leaf(&asn::PLMNIdentity(plmn_bytes(plmn).into()), output)
                            .map_err(encode_error)?,
                    ));
                }
                if *context_requested {
                    fields.push((
                        112,
                        Criticality::ignore,
                        encode_leaf(&asn::UEContextRequest::requested, output)
                            .map_err(encode_error)?,
                    ));
                }
                if let Some(slices) = allowed_nssai {
                    fields.push((
                        0,
                        Criticality::reject,
                        slices.encode(output).map_err(encode_error)?,
                    ));
                }
                MessageType::InitialUeMessage
            }
            Self::Downlink {
                amf,
                ran,
                nas,
                aggregate_bit_rate,
                allowed_nssai,
                old_amf,
            } => {
                fields.push((
                    10,
                    Criticality::reject,
                    amf.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    85,
                    Criticality::reject,
                    ran.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    38,
                    Criticality::reject,
                    nas.encode(output).map_err(encode_error)?,
                ));
                if let Some(rate) = aggregate_bit_rate {
                    fields.push((
                        110,
                        Criticality::ignore,
                        rate.encode(output).map_err(encode_error)?,
                    ));
                }
                if let Some(slices) = allowed_nssai {
                    fields.push((
                        0,
                        Criticality::reject,
                        slices.encode(output).map_err(encode_error)?,
                    ));
                }
                if let Some(name) = old_amf {
                    fields.push((
                        48,
                        Criticality::reject,
                        name.encode(output).map_err(encode_error)?,
                    ));
                }
                MessageType::DownlinkNasTransport
            }
            Self::Uplink {
                amf,
                ran,
                nas,
                location,
            } => {
                fields.push((
                    10,
                    Criticality::reject,
                    amf.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    85,
                    Criticality::reject,
                    ran.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    38,
                    Criticality::reject,
                    nas.encode(output).map_err(encode_error)?,
                ));
                fields.push((
                    121,
                    Criticality::ignore,
                    location.encode(output).map_err(encode_error)?,
                ));
                MessageType::UplinkNasTransport
            }
        };
        let ies: Vec<_> = fields
            .iter()
            .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
            .collect();
        let pdu = Pdu::from_protocol_ies(kind, &ies, ctx)?;
        // Use the same required-field/leaf-depth contract in both directions.
        NasMessage::from_pdu(&pdu, ctx)?;
        Ok(pdu)
    }
}

fn encode_error(_: EncodeError) -> DecodeError {
    invalid("nas message field encoding or capacity")
}

impl<'a> NasMessage<'a> {
    /// Validate the policy-filtered view of an existing PDU, including its
    /// mutable wrapper and IE criticality. Use the generic decoder first to
    /// apply unknown/duplicate selection. Source raw bytes remain untouched.
    pub fn from_pdu(pdu: &'a Pdu, ctx: DecodeContext) -> Result<AdmittedNas<'a>, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(EncodeContext {
            max_message_len: ctx.max_message_len,
            ..EncodeContext::default()
        })
        .map_err(|_| invalid("nas message container policy"))?;
        let PduKind::Initiating { message, .. } = &pdu.kind else {
            return Err(invalid("nas message outcome"));
        };
        match message {
            Message::InitialUeMessage(value) => admit(
                MessageType::InitialUeMessage,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            Message::DownlinkNasTransport(value) => admit(
                MessageType::DownlinkNasTransport,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            Message::UplinkNasTransport(value) => admit(
                MessageType::UplinkNasTransport,
                value
                    .protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id.0, ie.criticality as u8, ie.value.as_bytes())),
                ctx,
            ),
            _ => Err(invalid("unsupported nas message procedure")),
        }
    }
}

fn admit<'a>(
    kind: MessageType,
    fields: impl Iterator<Item = (u16, u8, &'a [u8])>,
    ctx: DecodeContext,
) -> Result<AdmittedNas<'a>, DecodeError> {
    let (profile, supported, ignored): (policy::IeProfile, &[u16], &[u16]) = match kind {
        MessageType::InitialUeMessage => (
            policy::INITIAL_UE_MESSAGE,
            &[85, 38, 121, 90, 174, 112, 0],
            &[201, 224, 225, 227, 259, 333, 402, 427],
        ),
        MessageType::DownlinkNasTransport => (
            policy::DOWNLINK_NAS_TRANSPORT,
            &[10, 85, 38, 110, 0, 48],
            &[
                83, 36, 31, 177, 205, 206, 209, 222, 117, 228, 226, 264, 334, 400,
            ],
        ),
        MessageType::UplinkNasTransport => (policy::UPLINK_NAS_TRANSPORT, &[10, 85, 38, 121], &[]),
        _ => return Err(invalid("unsupported nas message procedure")),
    };
    let mut amf = None;
    let mut ran = None;
    let mut nas = None;
    let mut location = None;
    let mut cause = None;
    let mut selected_plmn = None;
    let mut context_requested = false;
    let mut aggregate_bit_rate = None;
    let mut allowed_nssai = None;
    let mut old_amf = None;
    let mut ignored_ie_count = 0;
    let mut notify_ie_ids = Vec::new();
    let leaf_ctx = DecodeContext {
        max_depth: ctx.max_depth.saturating_sub(4),
        ..ctx
    };
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
                return Err(invalid("applicable or access-specific nas ie not admitted"));
            }
            match crit {
                1 => ignored_ie_count += 1,
                2 => notify_ie_ids.push(id),
                _ => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
            }
            continue;
        }
        match id {
            0 => allowed_nssai = Some(AllowedNssai::decode(value, leaf_ctx)?),
            48 => old_amf = Some(AmfName::decode(value, leaf_ctx)?),
            10 => amf = Some(AmfUeId::decode(value, leaf_ctx)?),
            85 => ran = Some(RanUeId::decode(value, leaf_ctx)?),
            38 => nas = Some(NasPdu::decode(value, leaf_ctx)?),
            121 => location = Some(N3iwfLocation::decode(value, leaf_ctx)?),
            90 => {
                bound(value, leaf_ctx, 1)?;
                cause = Some(decode_leaf(value)?);
            }
            174 => {
                bound(value, leaf_ctx, 1)?;
                selected_plmn = Some(decode_plmn(value)?);
            }
            112 => {
                bound(value, leaf_ctx, 1)?;
                let _: asn::UEContextRequest = decode_leaf(value)?;
                context_requested = true;
            }
            110 => aggregate_bit_rate = Some(UeAggregateBitRate::decode(value, leaf_ctx)?),
            _ => return Err(invalid("nas field dispatch")),
        }
    }
    let ran = ran.ok_or_else(|| invalid("missing ran ue id"))?;
    let nas = nas.ok_or_else(|| invalid("missing nas pdu"))?;
    let message = match kind {
        MessageType::InitialUeMessage => NasMessage::InitialUe {
            ran,
            nas,
            location: location.ok_or_else(|| invalid("missing user location"))?,
            cause: cause.ok_or_else(|| invalid("missing establishment cause"))?,
            selected_plmn,
            context_requested,
            allowed_nssai,
        },
        MessageType::DownlinkNasTransport => NasMessage::Downlink {
            amf: amf.ok_or_else(|| invalid("missing amf ue id"))?,
            ran,
            nas,
            aggregate_bit_rate,
            allowed_nssai,
            old_amf,
        },
        MessageType::UplinkNasTransport => NasMessage::Uplink {
            amf: amf.ok_or_else(|| invalid("missing amf ue id"))?,
            ran,
            nas,
            location: location.ok_or_else(|| invalid("missing user location"))?,
        },
        _ => return Err(invalid("nas message dispatch")),
    };
    Ok(AdmittedNas {
        message,
        ignored_ie_count,
        notify_ie_ids,
    })
}
