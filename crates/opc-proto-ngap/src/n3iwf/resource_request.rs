//! N3IWF PDU Session Resource Setup Request Transfer admission.
//!
//! This root subset admits a primary uplink tunnel, up to three additional
//! uplink endpoints and unique QoS flows. Session
//! AMBR is required by the default boundary. The explicitly classified boundary
//! admits its absence only when the caller classifies every requested flow as
//! GBR. Root QoS syntax does not establish that resource classification. Optional
//! root Security Indication, Network Instance and Common
//! Network Instance are admitted. Common takes precedence without hiding either
//! supplied value or relaxing its validation.
//! Data Forwarding Not Possible is receiver-ignored outside Handover Request
//! (9.3.4.1). Other recognized optional transfer fields fail explicitly.
//! No session, QoS, tunnel or datapath state is created here.
use super::network_fields::{CommonNetworkInstance, TransportNetworkInstance};
use super::qos_fields::QosResourceTypes;
use super::resource_fields::{
    QosFlowSetupList, SessionAggregateBitRate, SessionType, UplinkTransport, UplinkTransportList,
};
use super::security_fields::{NetworkInstance, SecurityIndication};
use super::*;
use crate::policy;

/// Validated root transfer fields. This is a request description, not resource
/// authorization or proof that an enclosing NGAP procedure is admissible.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupRequestTransfer {
    /// Core-side endpoint for uplink traffic, distinct from a downlink endpoint.
    pub uplink: UplinkTransport,
    /// Optional additional core-side endpoints; availability is caller-owned.
    pub additional_uplink: Option<UplinkTransportList>,
    /// Session aggregate limits. Absence requires exact caller classification
    /// through the classified encode/decode APIs and an all-GBR flow list.
    pub aggregate_bit_rate: Option<SessionAggregateBitRate>,
    /// Requested session payload kind.
    pub session_type: SessionType,
    /// Unique bounded root QoS requests; flow conditions are caller-qualified.
    pub flows: QosFlowSetupList,
    /// Optional peer security requirements; no protection is installed.
    pub security: Option<SecurityIndication>,
    /// Optional root network instance; no local network is selected.
    pub network_instance: Option<NetworkInstance>,
    /// Optional opaque common identifier; takes precedence over the numeric one.
    pub common_network_instance: Option<CommonNetworkInstance>,
}
redacted!(SetupRequestTransfer);

/// A semantic transfer plus value-free diagnostics from the selected IE view.
#[derive(Debug)]
pub struct AdmittedRequestTransfer {
    /// Admitted fields; no backend or authorization effect occurred.
    pub transfer: SetupRequestTransfer,
    /// Receiver-ignored Data Forwarding Not Possible and retained unknown-ignore IEs.
    pub ignored_ie_count: usize,
    /// Unknown notify-criticality IDs for caller-owned criticality diagnostics.
    pub notify_ie_ids: Vec<u16>,
}

impl SetupRequestTransfer {
    /// Return the request preference from TS 38.413 8.2.1.2. Both supplied
    /// fields remain available; this performs no local network selection.
    pub fn transport_network_instance(&self) -> Option<TransportNetworkInstance<'_>> {
        TransportNetworkInstance::preferred(
            self.network_instance,
            self.common_network_instance.as_ref(),
        )
    }
    /// Encode required and supplied optional root IEs in schema order.
    /// Receiver-ignored Data Forwarding Not Possible is not emitted.
    /// Individual fields are bounded before
    /// their allocation and complete framing before the final buffer allocation.
    /// Diagnostics and unknown retained values are not emitted by this typed
    /// constructor. The caller may retain the original input separately.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.encode_with_resource_types(None, ctx)
    }

    /// Encode with caller-established classification for exactly this flow set.
    /// Session AMBR may be absent only if every flow is classified GBR.
    /// Per-flow abnormal conditions remain separately reportable through
    /// `QosParameters::applicable`; this codec performs no resource allocation.
    pub fn encode_classified(
        &self,
        resource_types: &QosResourceTypes,
        ctx: EncodeContext,
    ) -> Result<EncodedValue, EncodeError> {
        self.encode_with_resource_types(Some(resource_types), ctx)
    }

    fn encode_with_resource_types(
        &self,
        resource_types: Option<&QosResourceTypes>,
        ctx: EncodeContext,
    ) -> Result<EncodedValue, EncodeError> {
        self.validate_ambr(resource_types).map_err(|_| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "session ambr or resource classification",
            })
        })?;
        let mut fields = Vec::with_capacity(8);
        if let Some(rate) = self.aggregate_bit_rate {
            fields.push((130, 0, rate.encode(ctx)?));
        }
        fields.push((139, 0, self.uplink.encode(ctx)?));
        if let Some(additional) = &self.additional_uplink {
            fields.push((126, 0, additional.encode(ctx)?));
        }
        fields.push((134, 0, self.session_type.encode(ctx)?));
        if let Some(security) = self.security {
            fields.push((138, 0, security.encode(ctx)?));
        }
        if let Some(network) = self.network_instance {
            fields.push((129, 0, network.encode(ctx)?));
        }
        fields.push((136, 0, self.flows.encode(ctx)?));
        if let Some(common) = &self.common_network_instance {
            fields.push((166, 1, common.encode(ctx)?));
        }
        let mut length = 3usize;
        for (_, _, value) in &fields {
            let framed_length = constructed::open_type_len(value.as_bytes().len())?;
            length = length
                .checked_add(3)
                .and_then(|v| v.checked_add(framed_length))
                .ok_or_else(|| EncodeError::new(EncodeErrorCode::LengthOverflow))?;
        }
        capacity(length, ctx)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        constructed::write_prefix(&mut bytes, fields.len());
        for (id, criticality, value) in &fields {
            constructed::write_ie(&mut bytes, *id, *criticality, value.as_bytes());
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
        Self::decode_with_resource_types(input, None, ctx)
    }

    /// Admit an all-GBR request without AMBR using exact caller-supplied QFI
    /// classification. Missing, duplicate or unrelated classifications fail.
    /// Shared IE policy still runs before semantic admission. Flow-specific
    /// failures are checked separately with `QosParameters::applicable` so the
    /// caller can report partial success/failure without losing the other flows.
    pub fn decode_classified(
        input: &[u8],
        resource_types: &QosResourceTypes,
        ctx: DecodeContext,
    ) -> Result<AdmittedRequestTransfer, DecodeError> {
        Self::decode_with_resource_types(input, Some(resource_types), ctx)
    }

    fn validate_ambr(&self, resource_types: Option<&QosResourceTypes>) -> Result<(), DecodeError> {
        let required = match resource_types {
            Some(types) => types.requires_session_ambr(self.flows.values())?,
            None => true,
        };
        if required && self.aggregate_bit_rate.is_none() {
            return Err(invalid("missing non-gbr session ambr"));
        }
        Ok(())
    }

    fn decode_with_resource_types(
        input: &[u8],
        resource_types: Option<&QosResourceTypes>,
        ctx: DecodeContext,
    ) -> Result<AdmittedRequestTransfer, DecodeError> {
        bound(input, ctx, 10)?;
        if input.first().is_some_and(|v| v & 0x80 != 0) {
            return Err(unsupported());
        }
        let count = policy::preflight_ie_count(input, ctx, "resource transfer container")?;
        scan(input, count, |_| {})?;
        let mut entries = Vec::with_capacity(count);
        scan(input, count, |entry| entries.push(entry))?;
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
        let mut additional_uplink = None;
        let mut aggregate_bit_rate = None;
        let mut session_type = None;
        let mut flows = None;
        let mut security = None;
        let mut network_instance = None;
        let mut common_network_instance = None;
        let mut ignored_ie_count = 0;
        let mut notify_ie_ids = Vec::new();
        for entry in &entries {
            // Unknown or receiver-ignored values are never materialized. Their
            // complete physical framing was already checked before allocation.
            if entry.id == 127 {
                ignored_ie_count += 1;
                continue;
            }
            if !profile.recognizes(entry.id) {
                match entry.criticality {
                    0 => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
                    1 => ignored_ie_count += 1,
                    _ => notify_ie_ids.push(entry.id),
                }
                continue;
            }
            if !matches!(entry.id, 139 | 126 | 130 | 134 | 136 | 138 | 129 | 166) {
                return Err(unsupported());
            }
            let framed = aper::ie(entry.wire)?;
            match entry.id {
                139 => uplink = Some(UplinkTransport::decode(&framed.value, leaf)?),
                126 => additional_uplink = Some(UplinkTransportList::decode(&framed.value, leaf)?),
                130 => {
                    aggregate_bit_rate = Some(SessionAggregateBitRate::decode(&framed.value, leaf)?)
                }
                134 => session_type = Some(SessionType::decode(&framed.value, leaf)?),
                136 => flows = Some(QosFlowSetupList::decode(&framed.value, leaf)?),
                138 => security = Some(SecurityIndication::decode(&framed.value, leaf)?),
                129 => network_instance = Some(NetworkInstance::decode(&framed.value, leaf)?),
                166 => {
                    common_network_instance =
                        Some(CommonNetworkInstance::decode(&framed.value, leaf)?)
                }
                _ => return Err(unsupported()),
            }
        }
        let admitted = AdmittedRequestTransfer {
            transfer: Self {
                uplink: uplink.ok_or_else(|| invalid("missing uplink transport"))?,
                additional_uplink,
                aggregate_bit_rate,
                session_type: session_type.ok_or_else(|| invalid("missing pdu session type"))?,
                flows: flows.ok_or_else(|| invalid("missing qos flow setup list"))?,
                security,
                network_instance,
                common_network_instance,
            },
            ignored_ie_count,
            notify_ie_ids,
        };
        admitted.transfer.validate_ambr(resource_types)?;
        Ok(admitted)
    }
}

struct Entry<'a> {
    id: u16,
    criticality: u8,
    wire: &'a [u8],
}

fn scan<'a>(
    input: &'a [u8],
    count: usize,
    mut emit: impl FnMut(Entry<'a>),
) -> Result<(), DecodeError> {
    let mut remaining = &input[3..]; // count prefix was preflighted
    for _ in 0..count {
        let (next, header) = aper::scan_ie(remaining)?;
        if header[2] & 63 != 0 || header[2] >> 6 > 2 {
            return Err(invalid("resource transfer criticality framing"));
        }
        emit(Entry {
            id: u16::from_be_bytes([header[0], header[1]]),
            criticality: header[2] >> 6,
            wire: &remaining[..remaining.len() - next.len()],
        });
        remaining = next;
    }
    if !remaining.is_empty() {
        return Err(invalid("trailing resource transfer bytes"));
    }
    Ok(())
}
