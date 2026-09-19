use super::*;
use crate::n3iwf::reset_fields::{encode_root, Sink};

/// Root mapping indication reported for one associated QoS flow.
/// It does not authorize forwarding or select a local tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosFlowMapping {
    /// The reported association applies to uplink traffic.
    Uplink,
    /// The reported association applies to downlink traffic.
    Downlink,
}

/// One flow association, preserving absence of a mapping indication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AssociatedQosFlow {
    /// Reported flow identifier; request correspondence is caller-owned.
    pub qfi: QosFlowId,
    /// Optional root mapping indication, without inferred defaults.
    pub mapping: Option<QosFlowMapping>,
}
redacted!(AssociatedQosFlow);

/// One reported downlink endpoint and its nonempty, unique flow associations.
/// A QFI may be associated with more than one reported transport bearer. This
/// type does not infer a preferred bearer or require endpoint uniqueness.
#[derive(Clone, PartialEq, Eq)]
pub struct DownlinkQosTunnel {
    downlink: DownlinkTransport,
    accepted: Vec<QosFlowId>,
    mappings: [Option<QosFlowMapping>; 64],
}
redacted!(DownlinkQosTunnel);

impl DownlinkQosTunnel {
    /// Require 1–64 unique QFIs, retaining supplied wire order and mapping.
    pub fn new(
        downlink: DownlinkTransport,
        flows: Vec<AssociatedQosFlow>,
    ) -> Result<Self, DecodeError> {
        if flows.is_empty() || flows.len() > 64 {
            return Err(invalid("resource result count"));
        }
        let mut seen = 0;
        let mut mappings = [None; 64];
        for flow in &flows {
            unique(&mut seen, flow.qfi)?;
            mappings[usize::from(flow.qfi.value())] = flow.mapping;
        }
        Ok(Self {
            downlink,
            accepted: flows.into_iter().map(|flow| flow.qfi).collect(),
            mappings,
        })
    }

    /// Explicit downlink endpoint; no local installation is established.
    pub const fn downlink(&self) -> DownlinkTransport {
        self.downlink
    }

    /// Flow associations in wire order, without allocation or inferred mapping.
    pub fn flows(&self) -> impl ExactSizeIterator<Item = AssociatedQosFlow> + '_ {
        self.accepted.iter().map(|qfi| AssociatedQosFlow {
            qfi: *qfi,
            mapping: self.mappings[usize::from(qfi.value())],
        })
    }
}

/// Root setup result with one mandatory and up to three additional downlink
/// tunnels, optional security report and optional failed QoS flows.
///
/// QFIs are unique within each tunnel and within the failed list. A failure
/// cannot also occur in any accepted association. Repeated associations across
/// different tunnels are preserved. Request correspondence, bearer selection
/// and resource effects are external; extensions remain explicitly refused.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupResponseTransfer {
    primary: DownlinkQosTunnel,
    additional: Vec<DownlinkQosTunnel>,
    failed: Vec<FailedQosFlow>,
    security: Option<SecurityResult>,
}
redacted!(SetupResponseTransfer);

impl SetupResponseTransfer {
    /// Construct a single tunnel without flow mapping indications.
    /// An entirely failed session uses `SetupFailureTransfer` instead.
    pub fn new(
        downlink: DownlinkTransport,
        accepted: Vec<QosFlowId>,
        failed: Vec<FailedQosFlow>,
    ) -> Result<Self, DecodeError> {
        if accepted.is_empty() || accepted.len() > 64 {
            return Err(invalid("resource result count"));
        }
        let mut seen = 0;
        for qfi in &accepted {
            unique(&mut seen, *qfi)?;
        }
        Self::with_tunnels(
            DownlinkQosTunnel {
                downlink,
                accepted,
                mappings: [None; 64],
            },
            Vec::new(),
            failed,
        )
    }

    /// Construct explicit per-tunnel reports. Empty additional/failed vectors
    /// denote absent optional lists; a present tunnel always has at least one
    /// flow. No request, security or installation success is inferred.
    pub fn with_tunnels(
        primary: DownlinkQosTunnel,
        additional: Vec<DownlinkQosTunnel>,
        failed: Vec<FailedQosFlow>,
    ) -> Result<Self, DecodeError> {
        if additional.len() > 3 || failed.len() > 64 {
            return Err(invalid("resource result count"));
        }
        let mut accepted = 0_u64;
        for tunnel in std::iter::once(&primary).chain(&additional) {
            for qfi in &tunnel.accepted {
                accepted |= 1_u64 << qfi.value();
            }
        }
        for flow in &failed {
            unique(&mut accepted, flow.qfi)?;
        }
        Ok(Self {
            primary,
            additional,
            failed,
            security: None,
        })
    }

    /// The mandatory downlink tunnel, including its flow mappings.
    pub const fn primary(&self) -> &DownlinkQosTunnel {
        &self.primary
    }

    /// Additional reports in wire order; an empty slice means absent.
    pub fn additional(&self) -> &[DownlinkQosTunnel] {
        &self.additional
    }

    /// The mandatory endpoint, preserving the existing single-tunnel accessor.
    pub const fn downlink(&self) -> DownlinkTransport {
        self.primary.downlink
    }

    /// Identifiers on the mandatory tunnel only, preserving the existing API.
    /// Use `primary().flows()` and `additional()` to inspect every association.
    pub fn accepted(&self) -> &[QosFlowId] {
        &self.primary.accepted
    }

    /// Explicit failure records, in received order.
    pub fn failed(&self) -> &[FailedQosFlow] {
        &self.failed
    }

    /// Bind or remove the optional peer security report.
    pub fn with_security_result(mut self, security: Option<SecurityResult>) -> Self {
        self.security = security;
        self
    }

    /// Explicit peer report; this is not proof of installed protection.
    pub const fn security_result(&self) -> Option<SecurityResult> {
        self.security
    }

    pub(in crate::n3iwf) fn required_depth(&self) -> usize {
        if self.additional.is_empty() {
            6
        } else {
            8
        }
    }

    /// Measure the complete root layout before allocating the exact output.
    /// Existing single-tunnel messages retain their canonical bytes.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_root(ctx, |out| {
            out.bits(
                u16::from(!self.additional.is_empty()) * 8
                    + u16::from(self.security.is_some()) * 4
                    + u16::from(!self.failed.is_empty()) * 2,
                5,
            )?;
            write_tunnel(out, &self.primary)?;
            if !self.additional.is_empty() {
                out.bits((self.additional.len() - 1) as u16, 2)?;
                for tunnel in &self.additional {
                    out.bits(0, 2)?;
                    write_tunnel(out, tunnel)?;
                }
            }
            if let Some(security) = self.security {
                security.write(out)?;
            }
            if !self.failed.is_empty() {
                out.bits((self.failed.len() - 1) as u16, 6)?;
                for flow in &self.failed {
                    out.bits(0, 3)?;
                    out.bits(u16::from(flow.qfi.value()), 6)?;
                    write_cause(out, flow.cause)?;
                }
            }
            Ok(())
        })
    }

    /// Preflight the entire physical layout, framing, counts and uniqueness
    /// before allocating lists. Depth is six, or eight with additional tunnels.
    /// `max_ies` bounds all flow occurrences, failures and additional items
    /// cumulatively. Mapping indications preserve their actual parent offsets.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        scan(input, ctx, false)?;
        scan(input, ctx, true)
    }
}

fn write_tunnel(out: &mut dyn Sink, value: &DownlinkQosTunnel) -> Result<(), EncodeError> {
    out.bits(0, 2)?;
    out.bits(0, 4)?;
    let address_bits = if value.downlink.address().is_ipv4() {
        32
    } else {
        128
    };
    out.bits(address_bits - 1, 8)?;
    out.align();
    match value.downlink.address() {
        IpAddr::V4(address) => write_octets(out, &address.octets())?,
        IpAddr::V6(address) => write_octets(out, &address.octets())?,
    }
    write_octets(out, &value.downlink.teid().to_be_bytes())?;
    out.bits((value.accepted.len() - 1) as u16, 6)?;
    for flow in value.flows() {
        out.bits(u16::from(flow.mapping.is_some()) * 4, 4)?;
        out.bits(u16::from(flow.qfi.value()), 6)?;
        if let Some(mapping) = flow.mapping {
            out.bits(u16::from(mapping == QosFlowMapping::Downlink), 2)?;
        }
    }
    Ok(())
}

fn read_tunnel(
    reader: &mut Reader<'_>,
    accepted_mask: &mut u64,
    materialize: bool,
) -> Result<DownlinkQosTunnel, DecodeError> {
    reader.flags(2)?;
    reader.flags(4)?;
    let address_bits = reader.bits(8)? + 1;
    if !matches!(address_bits, 32 | 128) {
        return Err(unsupported());
    }
    reader.align()?;
    let address = if address_bits == 32 {
        IpAddr::V4(std::net::Ipv4Addr::from(read_octets::<4>(reader)?))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(read_octets::<16>(reader)?))
    };
    let downlink = DownlinkTransport::new(address, u32::from_be_bytes(read_octets(reader)?));
    let count = reader.count(6, 64, 10)?;
    let mut accepted = Vec::with_capacity(if materialize { count } else { 0 });
    let mut mappings = [None; 64];
    let mut local = 0;
    for _ in 0..count {
        let flags = reader.bits(4)?;
        if flags & !4 != 0 {
            return Err(unsupported());
        }
        let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
        unique(&mut local, qfi)?;
        let mapping = if flags & 4 != 0 {
            Some(match reader.bits(2)? {
                0 => QosFlowMapping::Uplink,
                1 => QosFlowMapping::Downlink,
                _ => return Err(unsupported()),
            })
        } else {
            None
        };
        if materialize {
            accepted.push(qfi);
            mappings[usize::from(qfi.value())] = mapping;
        }
    }
    *accepted_mask |= local;
    Ok(DownlinkQosTunnel {
        downlink,
        accepted,
        mappings,
    })
}

fn scan(
    input: &[u8],
    ctx: DecodeContext,
    materialize: bool,
) -> Result<SetupResponseTransfer, DecodeError> {
    bound(input, ctx, 6)?;
    let mut reader = Reader::new(input, ctx);
    let flags = reader.bits(5)?;
    if flags & !14 != 0 {
        return Err(unsupported());
    }
    if flags & 8 != 0 {
        crate::enforce_depth(8, ctx)?;
    }
    let mut seen = 0;
    let primary = read_tunnel(&mut reader, &mut seen, materialize)?;
    let mut additional = Vec::new();
    if flags & 8 != 0 {
        let count = reader.count(2, 3, 96)?;
        if materialize {
            additional.reserve_exact(count);
        }
        for _ in 0..count {
            reader.flags(2)?;
            let tunnel = read_tunnel(&mut reader, &mut seen, materialize)?;
            if materialize {
                additional.push(tunnel);
            }
        }
    }
    let security = if flags & 4 != 0 {
        Some(SecurityResult::read(&mut reader)?)
    } else {
        None
    };
    let mut failed = Vec::new();
    if flags & 2 != 0 {
        let count = reader.count(6, 64, 14)?;
        if materialize {
            failed.reserve_exact(count);
        }
        for _ in 0..count {
            reader.flags(3)?;
            let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
            unique(&mut seen, qfi)?;
            let cause = read_cause(&mut reader)?;
            if materialize {
                failed.push(FailedQosFlow { qfi, cause });
            }
        }
    }
    reader.finish()?;
    Ok(SetupResponseTransfer {
        primary,
        additional,
        failed,
        security,
    })
}
