//! N3IWF PDU Session Resource Setup Request Transfer admission.
//!
//! This initial root subset admits one uplink tunnel and unique standardized
//! non-GBR 5QI 9 flows. Session AMBR is required for these flows (TS 38.413
//! 8.2.1.4). Other recognized optional fields and QoS profiles fail explicitly.
//! No session, QoS, tunnel or datapath state is created here.
use super::resource_fields::{
    QosFlowSetupList, SessionAggregateBitRate, SessionType, UplinkTransport,
};
use super::*;
use crate::policy;

/// Validated root transfer fields. This is a request description, not resource
/// authorization or proof that an enclosing NGAP procedure is admissible.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupRequestTransfer {
    /// Core-side endpoint for uplink traffic, distinct from a downlink endpoint.
    pub uplink: UplinkTransport,
    /// Session aggregate limits, mandatory for this non-GBR flow subset.
    pub aggregate_bit_rate: SessionAggregateBitRate,
    /// Requested session payload kind.
    pub session_type: SessionType,
    /// Unique bounded 5QI 9 flows.
    pub flows: QosFlowSetupList,
}
redacted!(SetupRequestTransfer);

/// A semantic transfer plus value-free diagnostics from the selected IE view.
#[derive(Debug)]
pub struct AdmittedRequestTransfer {
    /// Admitted fields; no backend or authorization effect occurred.
    pub transfer: SetupRequestTransfer,
    /// Unknown ignore-criticality IEs retained after configured selection.
    pub ignored_ie_count: usize,
    /// Unknown notify-criticality IDs for caller-owned criticality diagnostics.
    pub notify_ie_ids: Vec<u16>,
}

impl SetupRequestTransfer {
    /// Encode four canonical root IEs. Individual fields are bounded before
    /// their allocation and complete framing before the final buffer allocation.
    /// Diagnostics and unknown retained values are not emitted by this typed
    /// constructor. The caller may retain the original input separately.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let fields = [
            (130, self.aggregate_bit_rate.encode(ctx)?),
            (139, self.uplink.encode(ctx)?),
            (134, self.session_type.encode(ctx)?),
            (136, self.flows.encode(ctx)?),
        ];
        let mut length = 3;
        for (_, value) in &fields {
            // Every constructor is bounded; the largest complete root is
            // below 512 bytes even on a 32-bit target.
            length += 3 + constructed::open_type_len(value.as_bytes().len())?;
        }
        capacity(length, ctx)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        constructed::write_prefix(&mut bytes, fields.len());
        for (id, value) in &fields {
            constructed::write_ie(&mut bytes, *id, 0, value.as_bytes());
        }
        Ok(EncodedValue(bytes))
    }

    /// Admit a bounded root transfer with depth ten. Four enclosing container
    /// levels are subtracted before field decoding. Container count and each
    /// flow-list count separately use `max_ies`; `allocation_budget` is advisory.
    ///
    /// Shared generic policy applies first, including Drop/First/Last/Reject.
    /// Semantic admission then requires all three mandatory ASN.1 IEs plus
    /// the conditional session AMBR. A retained unknown reject-criticality IE
    /// prevents admission even under structural Preserve policy.
    pub fn decode(
        input: &[u8],
        ctx: DecodeContext,
    ) -> Result<AdmittedRequestTransfer, DecodeError> {
        bound(input, ctx, 10)?;
        if input.first().is_some_and(|v| v & 0x80 != 0) {
            return Err(unsupported());
        }
        let count = policy::preflight_ie_count(input, ctx, "resource transfer container")?;
        let mut entries = Vec::with_capacity(count);
        let mut remaining = &input[3..];
        for _ in 0..count {
            let framed = aper::ie(remaining)?;
            if framed.header[2] & 63 != 0 || framed.header[2] >> 6 > 2 {
                return Err(invalid("resource transfer criticality framing"));
            }
            entries.push(Entry {
                id: u16::from_be_bytes([framed.header[0], framed.header[1]]),
                criticality: framed.header[2] >> 6,
                value: framed.value,
            });
            remaining = framed.remainder;
        }
        if !remaining.is_empty() {
            return Err(invalid("trailing resource transfer bytes"));
        }
        let profile = policy::PDU_SESSION_RESOURCE_SETUP_REQUEST_TRANSFER;
        policy::apply_ie_policy(
            &mut entries,
            count,
            profile,
            ctx,
            |ie| ie.id,
            |ie| ie.criticality,
        )?;
        let leaf = DecodeContext {
            max_depth: ctx.max_depth.saturating_sub(4),
            ..ctx
        };
        let mut uplink = None;
        let mut aggregate_bit_rate = None;
        let mut session_type = None;
        let mut flows = None;
        let mut ignored_ie_count = 0;
        let mut notify_ie_ids = Vec::new();
        for entry in &entries {
            match entry.id {
                139 => uplink = Some(UplinkTransport::decode(&entry.value, leaf)?),
                130 => {
                    aggregate_bit_rate = Some(SessionAggregateBitRate::decode(&entry.value, leaf)?)
                }
                134 => session_type = Some(SessionType::decode(&entry.value, leaf)?),
                136 => flows = Some(QosFlowSetupList::decode(&entry.value, leaf)?),
                id if profile.recognizes(id) => return Err(unsupported()),
                _ => match entry.criticality {
                    0 => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
                    1 => ignored_ie_count += 1,
                    _ => notify_ie_ids.push(entry.id),
                },
            }
        }
        Ok(AdmittedRequestTransfer {
            transfer: Self {
                uplink: uplink.ok_or_else(|| invalid("missing uplink transport"))?,
                aggregate_bit_rate: aggregate_bit_rate
                    .ok_or_else(|| invalid("missing non-gbr session ambr"))?,
                session_type: session_type.ok_or_else(|| invalid("missing pdu session type"))?,
                flows: flows.ok_or_else(|| invalid("missing qos flow setup list"))?,
            },
            ignored_ie_count,
            notify_ie_ids,
        })
    }
}

struct Entry<'a> {
    id: u16,
    criticality: u8,
    value: Cow<'a, [u8]>,
}
