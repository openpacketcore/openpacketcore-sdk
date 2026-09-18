//! Qualified resource-request root fields. These describe peer requests;
//! they do not assign tunnels, admit traffic or authorize QoS resources.
//!
//! The initial flow subset is standardized non-GBR 5QI 9 with root ARP.
//! Other QoS descriptors and optional flow parameters fail explicitly.
use super::nas::UeAggregateBitRate;
use super::setup_fields::{Reader, Writer};
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

/// One through 64 unique non-GBR 5QI 9 requests. Other QoS profiles need a
/// separate qualified admission boundary; they cannot silently enter this one.
#[derive(Clone, PartialEq, Eq)]
pub struct QosFlowSetupList(Vec<NonGbrFlow>);
redacted!(QosFlowSetupList);
impl QosFlowSetupList {
    /// Enforce root cardinality and reject duplicate QFIs without reordering.
    pub fn new(values: Vec<NonGbrFlow>) -> Result<Self, DecodeError> {
        if values.is_empty() || values.len() > 64 {
            return Err(invalid("qos flow list count"));
        }
        let mut seen = 0u64;
        for value in &values {
            unique_qfi(&mut seen, value.qfi)?;
        }
        Ok(Self(values))
    }
    /// Explicit access to the admitted requests in wire order.
    pub fn values(&self) -> &[NonGbrFlow] {
        &self.0
    }
    /// Encode the independently qualified root layout. Generated nested-list
    /// construction loses its bit offset even for a single 5QI 9 flow.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        // First item ends at bit 50; every following item consumes 48 bits.
        // Root constructors bound this arithmetic to at most 385 bytes.
        let length = self.0.len() * 6 + 1;
        capacity(length, ctx)?;
        let mut writer = Writer::new(length);
        writer.bits((self.0.len() - 1) as u16, 6)?;
        for value in &self.0 {
            writer.bits(0, 3)?; // item extensions/E-RAB/IE extensions
            writer.bits(u16::from(value.qfi.0), 7)?; // QFI extension bit + value
            writer.bits(0, 5)?; // QoS parameters extension and four optional flags
            writer.bits(0, 2)?; // nonDynamic5QI choice
            writer.bits(0, 5)?; // descriptor extension and four optional flags
            writer.bits(0, 1)?; // FiveQI root extension bit
            writer.align();
            writer.bits(9, 8)?;
            writer.bits(0, 2)?; // ARP extension/IE extensions
            writer.bits(u16::from(value.priority - 1), 4)?;
            writer.bits(u16::from(value.may_preempt), 2)?; // enum extension + value
            writer.bits(u16::from(value.preemptable), 2)?;
        }
        writer.finish()
    }
    /// Decode root 5QI 9 flows with depth six. Enforce `max_ies` and physical
    /// count preflight before allocation, then reject duplicate QFIs and every
    /// unsupported choice, optional field or extension.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 6)?;
        let mut reader = Reader::new(input, ctx);
        let count = reader.count(6, 64, 41)?;
        let mut values = Vec::with_capacity(count);
        let mut seen = 0u64;
        for _ in 0..count {
            reader.flags(3)?;
            reader.flags(1)?;
            let qfi = QosFlowId(reader.bits(6)? as u8);
            unique_qfi(&mut seen, qfi)?;
            reader.flags(5)?;
            reader.flags(2)?;
            reader.flags(5)?;
            reader.flags(1)?;
            reader.align()?;
            if reader.bits(8)? != 9 {
                return Err(unsupported());
            }
            reader.flags(2)?;
            let priority = reader.bits(4)? as u8 + 1;
            reader.flags(1)?;
            let may_preempt = reader.bits(1)? != 0;
            reader.flags(1)?;
            let preemptable = reader.bits(1)? != 0;
            values.push(NonGbrFlow::new(qfi, priority, may_preempt, preemptable)?);
        }
        reader.finish()?;
        Ok(Self(values))
    }
}

fn unique_qfi(seen: &mut u64, qfi: QosFlowId) -> Result<(), DecodeError> {
    let bit = 1u64 << qfi.0;
    if *seen & bit != 0 {
        return Err(invalid("duplicate qos flow identifier"));
    }
    *seen |= bit;
    Ok(())
}
