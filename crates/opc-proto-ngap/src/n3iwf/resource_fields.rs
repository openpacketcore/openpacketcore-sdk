//! Qualified resource-request root fields. These describe peer requests;
//! they do not assign tunnels, admit traffic or authorize QoS resources.
//!
//! Flow lists preserve both root QoS descriptors, GBR parameters and attributes.
//! Extension additions remain explicitly unsupported.
use super::modify_fields::{read_transport, write_transport};
use super::nas::UeAggregateBitRate;
use super::qos_fields::{QosFlow, QosParameters};
use super::reset_fields::encode_root;
use super::setup_fields::Reader;
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
struct TunnelEndpoint {
    address: IpAddr,
    teid: u32,
}
impl TunnelEndpoint {
    fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = if self.address.is_ipv4() { 4 } else { 16 };
        capacity(2 + length + 4, ctx)?;
        let address = match self.address {
            IpAddr::V4(value) => rasn::types::BitString::from_slice(&value.octets()),
            IpAddr::V6(value) => rasn::types::BitString::from_slice(&value.octets()),
        };
        encode_leaf(
            &asn::UPTransportLayerInformation::gTPTunnel(asn::GTPTunnel::new(
                asn::TransportLayerAddress(address),
                asn::GTPTEID(self.teid.to_be_bytes().into()),
                None,
            )),
            ctx,
        )
    }
    fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 3)?;
        let header = input
            .get(..2)
            .ok_or_else(|| invalid("truncated transport information"))?;
        // Root CHOICE, SEQUENCE extension/optional bits and address-size
        // extension must be zero before generated decoding can allocate.
        if header[0] & 0xf0 != 0 {
            return Err(unsupported());
        }
        let bit_count =
            usize::from((u16::from(header[0] & 15) << 4) | u16::from(header[1] >> 4)) + 1;
        if !matches!(bit_count, 32 | 128) {
            return Err(unsupported());
        }
        if header[1] & 15 != 0 || input.len() != 2 + bit_count / 8 + 4 {
            return Err(invalid("transport information framing"));
        }
        let asn::UPTransportLayerInformation::gTPTunnel(value) = decode_leaf(input)? else {
            return Err(unsupported());
        };
        let bytes = value.transport_layer_address.0.as_raw_slice();
        let address = match bit_count {
            32 => IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).map_err(|_| invalid("transport address size"))?,
            )),
            _ => IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(|_| invalid("transport address size"))?,
            )),
        };
        let octets: &[u8] = value.g_tp_teid.0.as_ref();
        let teid = u32::from_be_bytes(
            octets
                .try_into()
                .map_err(|_| invalid("transport teid size"))?,
        );
        Ok(Self { address, teid })
    }
}

macro_rules! directional_transport {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name(TunnelEndpoint);
        redacted!($name);
        impl $name {
            /// Bind an IP address and 32-bit TEID. All wire values, including
            /// zero, are representable; endpoint authorization is caller-owned.
            pub const fn new(address: IpAddr, teid: u32) -> Self {
                Self(TunnelEndpoint { address, teid })
            }
            /// Explicit access to the advertised IP address.
            pub const fn address(self) -> IpAddr {
                self.0.address
            }
            /// Explicit wire TEID for handoff to the caller's GTP-U boundary.
            pub const fn teid(self) -> u32 {
                self.0.teid
            }
            /// Encode the qualified generated GTP-tunnel root choice.
            pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
                self.0.encode(ctx)
            }
            /// Decode IPv4/IPv6 roots with depth three. Dual-address bit
            /// strings, choice/SEQUENCE extensions and trailing bytes fail.
            pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
                TunnelEndpoint::decode(input, ctx).map(Self)
            }
        }
    };
}
directional_transport!(
    UplinkTransport,
    "Uplink GTP tunnel advertised toward the core; distinct from a downlink endpoint."
);

/// One to three additional core-side endpoints, in peer-supplied order.
/// Repeated endpoints are preserved; matching, availability and allocation are
/// caller-owned. Root IPv4/IPv6 items carry no extension fields.
#[derive(Clone, PartialEq, Eq)]
pub struct UplinkTransportList(Vec<UplinkTransport>);
redacted!(UplinkTransportList);
impl UplinkTransportList {
    /// Validate the ASN.1 list bound without selecting an endpoint.
    pub fn new(values: Vec<UplinkTransport>) -> Result<Self, DecodeError> {
        if !(1..=3).contains(&values.len()) {
            return Err(invalid("additional uplink tunnel count"));
        }
        Ok(Self(values))
    }
    /// Explicit access to the ordered endpoint descriptions.
    pub fn values(&self) -> &[UplinkTransport] {
        &self.0
    }
    /// Measure the complete root layout before allocating the output buffer.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_root(ctx, |out| {
            out.bits((self.0.len() - 1) as u16, 2)?;
            for value in &self.0 {
                out.bits(0, 2)?;
                write_transport(out, value.address(), value.teid())?;
            }
            Ok(())
        })
    }
    /// Require depth five and bound the list with `max_ies`. Validate all
    /// flags, addresses, alignment and exact framing before allocating items.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let count = scan_uplink_list(input, ctx, |_| {})?;
        let mut values = Vec::with_capacity(count);
        scan_uplink_list(input, ctx, |value| values.push(value))?;
        Ok(Self(values))
    }
}

fn scan_uplink_list(
    input: &[u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(UplinkTransport),
) -> Result<usize, DecodeError> {
    bound(input, ctx, 5)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(2, 3, 78)?;
    for _ in 0..count {
        reader.flags(2)?;
        let (address, teid) = read_transport(&mut reader)?;
        emit(UplinkTransport::new(address, teid));
    }
    reader.finish()?;
    Ok(count)
}
directional_transport!(
    DownlinkTransport,
    "Downlink GTP tunnel advertised toward the N3IWF; distinct from an uplink endpoint."
);

/// Session-level UL/DL limits, distinct from the enclosing UE aggregate limit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionAggregateBitRate(UeAggregateBitRate);
redacted!(SessionAggregateBitRate);
impl SessionAggregateBitRate {
    /// Admit root rates from zero through 4,000,000,000,000 bits per second.
    pub fn new(downlink: u64, uplink: u64) -> Result<Self, DecodeError> {
        UeAggregateBitRate::new(downlink, uplink).map(Self)
    }
    /// Explicit downlink rate, in bits per second.
    pub const fn downlink(self) -> u64 {
        self.0.downlink()
    }
    /// Explicit uplink rate, in bits per second.
    pub const fn uplink(self) -> u64 {
        self.0.uplink()
    }
    /// Reuse the identical bounded two-BitRate root layout. Independent session
    /// vectors qualify this reuse; no UE/session policy equivalence is inferred.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.0.encode(ctx)
    }
    /// Decode the bounded root layout with depth two.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        UeAggregateBitRate::decode(input, ctx).map(Self)
    }
}

/// Root PDU session payload kind. This codec does not configure its datapath.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// IPv4 payloads.
    Ipv4,
    /// IPv6 payloads.
    Ipv6,
    /// IPv4 and IPv6 payloads.
    Ipv4v6,
    /// Ethernet payloads.
    Ethernet,
    /// Unstructured payloads.
    Unstructured,
}
redacted!(SessionType);
impl SessionType {
    /// Encode a root enumeration through the generated schema.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let value = match self {
            Self::Ipv4 => asn::PDUSessionType::ipv4,
            Self::Ipv6 => asn::PDUSessionType::ipv6,
            Self::Ipv4v6 => asn::PDUSessionType::ipv4v6,
            Self::Ethernet => asn::PDUSessionType::ethernet,
            Self::Unstructured => asn::PDUSessionType::unstructured,
        };
        encode_leaf(&value, ctx)
    }
    /// Decode a root enumeration with depth one; extensions are unsupported.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        if input.first().is_some_and(|byte| byte & 0x80 != 0) {
            return Err(unsupported());
        }
        Ok(match decode_leaf(input)? {
            asn::PDUSessionType::ipv4 => Self::Ipv4,
            asn::PDUSessionType::ipv6 => Self::Ipv6,
            asn::PDUSessionType::ipv4v6 => Self::Ipv4v6,
            asn::PDUSessionType::ethernet => Self::Ethernet,
            asn::PDUSessionType::unstructured => Self::Unstructured,
        })
    }
}

/// ASN.1 root QFI (0..=63). Allocation and reserved-value policy are external.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QosFlowId(u8);
redacted!(QosFlowId);
impl QosFlowId {
    /// Require the six-bit root range.
    pub fn new(value: u8) -> Result<Self, DecodeError> {
        if value > 63 {
            return Err(invalid("qos flow identifier range"));
        }
        Ok(Self(value))
    }
    /// Explicit wire identifier.
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// Non-GBR standardized 5QI 9 with root allocation/retention priority.
/// No flow or pre-emption action is authorized by constructing this value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NonGbrFlow {
    qfi: QosFlowId,
    priority: u8,
    may_preempt: bool,
    preemptable: bool,
}
redacted!(NonGbrFlow);
impl NonGbrFlow {
    /// Require ARP priority 1..=15; retain both pre-emption flags explicitly.
    pub fn new(
        qfi: QosFlowId,
        priority: u8,
        may_preempt: bool,
        preemptable: bool,
    ) -> Result<Self, DecodeError> {
        if !(1..=15).contains(&priority) {
            return Err(invalid("arp priority range"));
        }
        Ok(Self {
            qfi,
            priority,
            may_preempt,
            preemptable,
        })
    }
    /// Explicit flow identifier.
    pub const fn qfi(self) -> QosFlowId {
        self.qfi
    }
    /// Explicit allocation/retention priority.
    pub const fn priority(self) -> u8 {
        self.priority
    }
    /// Advertised permission to trigger pre-emption; not a local decision.
    pub const fn may_preempt(self) -> bool {
        self.may_preempt
    }
    /// Advertised vulnerability to pre-emption.
    pub const fn preemptable(self) -> bool {
        self.preemptable
    }
}

/// One through 64 unique root QoS requests, preserved in wire order.
#[derive(Clone, PartialEq, Eq)]
pub struct QosFlowSetupList(Vec<QosFlow>);
redacted!(QosFlowSetupList);
impl QosFlowSetupList {
    /// Enforce root cardinality and reject duplicate QFIs without reordering.
    /// This compatibility constructor selects the original non-GBR 5QI 9 profile.
    pub fn new(values: Vec<NonGbrFlow>) -> Result<Self, DecodeError> {
        if values.is_empty() || values.len() > 64 {
            return Err(invalid("qos flow list count"));
        }
        Self::with_profiles(values.into_iter().map(QosFlow::from).collect())
    }
    /// Admit the root QoS profiles. No flow resources are created or authorized.
    pub fn with_profiles(values: Vec<QosFlow>) -> Result<Self, DecodeError> {
        if values.is_empty() || values.len() > 64 {
            return Err(invalid("qos flow list count"));
        }
        let mut seen = 0u64;
        for value in &values {
            unique_qfi(&mut seen, value.qfi())?;
        }
        Ok(Self(values))
    }
    /// Explicit access to the admitted requests in wire order.
    pub fn values(&self) -> &[QosFlow] {
        &self.0
    }
    /// Encode the independently qualified root layout. Generated nested-list
    /// construction loses its bit offset even for a single 5QI 9 flow.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_root(ctx, |out| {
            out.bits((self.0.len() - 1) as u16, 6)?;
            for value in &self.0 {
                out.bits(u16::from(value.erab().is_some()) * 2, 3)?;
                out.bits(u16::from(value.qfi().value()), 7)?;
                value.parameters().write(out)?;
                if let Some(erab) = value.erab() {
                    out.bits(u16::from(erab), 5)?;
                }
            }
            Ok(())
        })
    }
    /// Decode root profiles with depth six (seven for a dynamic descriptor).
    /// Complete physical/count/depth/range/uniqueness preflight precedes allocation.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let count = scan_qos_flows(input, ctx, |_| {})?;
        let mut values = Vec::with_capacity(count);
        scan_qos_flows(input, ctx, |value| values.push(value))?;
        Ok(Self(values))
    }
}

fn scan_qos_flows(
    input: &[u8],
    ctx: DecodeContext,
    mut emit: impl FnMut(QosFlow),
) -> Result<usize, DecodeError> {
    bound(input, ctx, 6)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(6, 64, 41)?;
    let mut seen = 0u64;
    for _ in 0..count {
        let flags = reader.bits(3)?;
        if flags & !2 != 0 {
            return Err(unsupported());
        }
        reader.flags(1)?;
        let qfi = QosFlowId(reader.bits(6)? as u8);
        unique_qfi(&mut seen, qfi)?;
        let parameters = QosParameters::read(&mut reader, ctx, 6)?;
        let erab = if flags & 2 != 0 {
            reader.flags(1)?;
            Some(reader.bits(4)? as u8)
        } else {
            None
        };
        emit(QosFlow::new(qfi, parameters).with_erab(erab)?);
    }
    reader.finish()?;
    Ok(count)
}

fn unique_qfi(seen: &mut u64, qfi: QosFlowId) -> Result<(), DecodeError> {
    let bit = 1u64 << qfi.0;
    if *seen & bit != 0 {
        return Err(invalid("duplicate qos flow identifier"));
    }
    *seen |= bit;
    Ok(())
}
