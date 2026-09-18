//! PDU Session Resource Notify admission and canonical construction. The caller
//! owns session/QFI correlation, GBR classification, trigger selection and all
//! resource effects. An admitted report is not proof that resources were freed.

use super::notify_fields::{NotifiedSessions, ReleasedSessions};
use super::session_lists::unique_id;
use super::*;
use crate::{Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::Encode;

/// Typed reports with at least one session list. The notified and wholly
/// released session domains must be disjoint, and every list is nonempty.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceNotify {
    /// Peer AMF UE identifier, without correlation or ownership evidence.
    pub amf: AmfUeId,
    /// Local RAN UE identifier, without an association authority claim.
    pub ran: RanUeId,
    /// Sessions with flow notification or release reports.
    pub notified: Option<NotifiedSessions>,
    /// Sessions reported wholly released, with root Causes.
    pub released: Option<ReleasedSessions>,
    /// Optional qualified N3IWF location.
    pub location: Option<N3iwfLocation>,
}
redacted!(ResourceNotify);

/// Typed fields and value-free diagnostics from the generic selected IE view.
#[derive(Debug)]
pub struct AdmittedNotify {
    /// Admitted peer reports, without local procedure or resource effects.
    pub message: ResourceNotify,
    /// Unknown-ignore IEs retained by the generic decoder.
    pub ignored_ie_count: usize,
    /// Unknown-notify identifiers, never the opaque values.
    pub notify_ie_ids: Vec<u16>,
}

impl ResourceNotify {
    /// Construct canonical reports after presence and disjointness validation.
    /// Require depth ten for released sessions, eleven for flow notifications,
    /// or twelve when notified sessions contain released flows.
    pub fn construct(&self, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
        self.validate()?;
        let mut depth = 10;
        if let Some(values) = &self.notified {
            for value in values.values() {
                depth = depth.max(7 + value.transfer.depth());
            }
        }
        crate::enforce_depth(depth, ctx)?;
        let output = output_context(ctx);
        let mut fields = vec![
            (10, Criticality::reject, self.amf.encode(output)),
            (85, Criticality::reject, self.ran.encode(output)),
        ];
        if let Some(values) = &self.notified {
            fields.push((66, Criticality::reject, values.encode(output)));
        }
        if let Some(values) = &self.released {
            fields.push((67, Criticality::ignore, values.encode(output)));
        }
        if let Some(value) = &self.location {
            fields.push((121, Criticality::ignore, value.encode(output)));
        }
        let values = fields
            .into_iter()
            .map(|(id, crit, value)| {
                value
                    .map(|value| (id, crit, value))
                    .map_err(|_| invalid("notify encoding or capacity"))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        let ies: Vec<_> = values
            .iter()
            .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value.as_bytes()))
            .collect();
        let pdu = Pdu::from_protocol_ies(MessageType::PduSessionResourceNotify, &ies, ctx)?;
        Self::from_pdu(&pdu, ctx)?;
        Ok(pdu)
    }
    /// Admit the generic decoder's selected IE view. Use the same context at
    /// both boundaries; earlier filtering cannot be undone. Metadata, complete
    /// byte length and cardinality remain authoritative before typed decoding.
    pub fn from_pdu(pdu: &Pdu, ctx: DecodeContext) -> Result<AdmittedNotify, DecodeError> {
        crate::enforce_depth(5, ctx)?;
        pdu.wire_len(output_context(ctx))
            .map_err(|_| invalid("notify container policy"))?;
        let PduKind::Initiating {
            message: Message::PduSessionResourceNotify(value),
            ..
        } = &pdu.kind
        else {
            return Err(invalid("notify outcome"));
        };
        let leaf = DecodeContext {
            max_depth: ctx.max_depth.saturating_sub(4),
            ..ctx
        };
        let (mut amf, mut ran, mut notified, mut released, mut location) =
            (None, None, None, None, None);
        let mut ignored_ie_count = 0;
        let mut notify_ie_ids = Vec::new();
        for (index, ie) in value.protocol_ies.0.iter().enumerate() {
            if index >= ctx.max_ies {
                return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
            }
            let bytes = ie.value.as_bytes();
            match ie.id {
                10 => amf = Some(AmfUeId::decode(bytes, leaf)?),
                85 => ran = Some(RanUeId::decode(bytes, leaf)?),
                66 => notified = Some(NotifiedSessions::decode(bytes, leaf)?),
                67 => released = Some(ReleasedSessions::decode(bytes, leaf)?),
                121 => location = Some(N3iwfLocation::decode(bytes, leaf)?),
                _ => match ie.criticality as u8 {
                    1 => ignored_ie_count += 1,
                    2 => notify_ie_ids.push(ie.id),
                    _ => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
                },
            }
        }
        let message = Self {
            amf: amf.ok_or_else(|| invalid("missing notify amf ue id"))?,
            ran: ran.ok_or_else(|| invalid("missing notify ran ue id"))?,
            notified,
            released,
            location,
        };
        message.validate()?;
        Ok(AdmittedNotify {
            message,
            ignored_ie_count,
            notify_ie_ids,
        })
    }
    fn validate(&self) -> Result<(), DecodeError> {
        if self.notified.is_none() && self.released.is_none() {
            return Err(invalid("missing session reports"));
        }
        let mut seen = [0; 4];
        if let Some(values) = &self.notified {
            for value in values.values() {
                unique_id(&mut seen, value.id)?;
            }
        }
        if let Some(values) = &self.released {
            for value in values.values() {
                unique_id(&mut seen, value.id)?;
            }
        }
        Ok(())
    }
}
fn output_context(ctx: DecodeContext) -> EncodeContext {
    EncodeContext {
        max_message_len: ctx.max_message_len,
        ..EncodeContext::default()
    }
}
