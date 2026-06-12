#![forbid(unsafe_code)]

//! Simple (non-grouped) PFCP Information Elements.
//!
//! @spec 3GPP TS29244 R18 8.2

use bytes::{BufMut, BytesMut};
use opc_protocol::{DecodeError, DecodeErrorCode, EncodeError, SpecRef};

/// Trait for simple IEs that can be decoded from a raw value buffer.
pub trait SimpleIe: Sized {
    /// Decode from the IE value bytes.
    ///
    /// `offset` is the byte offset of the value field within the message
    /// (for error reporting). `spec_ref` provides traceability.
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError>;

    /// Encode into a buffer.
    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError>;
}

// ---------------------------------------------------------------------------
// Cause (§8.2.1)
// ---------------------------------------------------------------------------

/// Cause values (TS 29.244 Table 8.2.1-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CauseValue {
    /// Reserved (0).
    Reserved = 0,
    /// Request accepted (success) (1).
    RequestAccepted = 1,
    /// Request rejected (no reason) (64).
    RequestRejected = 64,
    /// Session context not found (65).
    SessionContextNotFound = 65,
    /// Mandatory IE missing (72).
    MandatoryIeMissing = 72,
    /// Conditional IE missing (73).
    ConditionalIeMissing = 73,
    /// Invalid length (74).
    InvalidLength = 74,
    /// Mandatory IE incorrect (75).
    MandatoryIeIncorrect = 75,
    /// Invalid forwarding policy (76).
    InvalidForwardingPolicy = 76,
    /// Invalid F-TEID allocation option (77).
    InvalidFTeidAllocationOption = 77,
    /// No established PFCP association (78).
    NoEstablishedPfcpAssociation = 78,
    /// Rule creation/modification failure (79).
    RuleCreationModificationFailure = 79,
    /// PFCP entity in congestion (80).
    PfcpEntityInCongestion = 80,
    /// No resources available (81).
    NoResourcesAvailable = 81,
    /// Service not supported (82).
    ServiceNotSupported = 82,
    /// System failure (83).
    SystemFailure = 83,
    /// Redirection requested (84).
    RedirectionRequested = 84,
    /// Unknown value (any code not in the v1 registry).
    Unknown(u8),
}

impl From<u8> for CauseValue {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Reserved,
            1 => Self::RequestAccepted,
            64 => Self::RequestRejected,
            65 => Self::SessionContextNotFound,
            72 => Self::MandatoryIeMissing,
            73 => Self::ConditionalIeMissing,
            74 => Self::InvalidLength,
            75 => Self::MandatoryIeIncorrect,
            76 => Self::InvalidForwardingPolicy,
            77 => Self::InvalidFTeidAllocationOption,
            78 => Self::NoEstablishedPfcpAssociation,
            79 => Self::RuleCreationModificationFailure,
            80 => Self::PfcpEntityInCongestion,
            81 => Self::NoResourcesAvailable,
            82 => Self::ServiceNotSupported,
            83 => Self::SystemFailure,
            84 => Self::RedirectionRequested,
            other => Self::Unknown(other),
        }
    }
}

impl From<CauseValue> for u8 {
    fn from(value: CauseValue) -> Self {
        match value {
            CauseValue::Reserved => 0,
            CauseValue::RequestAccepted => 1,
            CauseValue::RequestRejected => 64,
            CauseValue::SessionContextNotFound => 65,
            CauseValue::MandatoryIeMissing => 72,
            CauseValue::ConditionalIeMissing => 73,
            CauseValue::InvalidLength => 74,
            CauseValue::MandatoryIeIncorrect => 75,
            CauseValue::InvalidForwardingPolicy => 76,
            CauseValue::InvalidFTeidAllocationOption => 77,
            CauseValue::NoEstablishedPfcpAssociation => 78,
            CauseValue::RuleCreationModificationFailure => 79,
            CauseValue::PfcpEntityInCongestion => 80,
            CauseValue::NoResourcesAvailable => 81,
            CauseValue::ServiceNotSupported => 82,
            CauseValue::SystemFailure => 83,
            CauseValue::RedirectionRequested => 84,
            CauseValue::Unknown(v) => v,
        }
    }
}

/// Cause IE (type 19).
///
/// TS 29.244 §8.2.1: one octet value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cause {
    /// Cause value.
    pub value: CauseValue,
}

impl SimpleIe for Cause {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: CauseValue::from(value[0]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.value.into());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Node ID (§8.2.38)
// ---------------------------------------------------------------------------

/// Node ID type (TS 29.244 §8.2.38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeIdType {
    /// IPv4 address (0).
    Ipv4 = 0,
    /// IPv6 address (1).
    Ipv6 = 1,
    /// FQDN (2).
    Fqdn = 2,
    /// Unknown type code.
    Unknown(u8),
}

impl From<u8> for NodeIdType {
    fn from(value: u8) -> Self {
        match value & 0x0F {
            0 => Self::Ipv4,
            1 => Self::Ipv6,
            2 => Self::Fqdn,
            other => Self::Unknown(other),
        }
    }
}

impl From<NodeIdType> for u8 {
    fn from(value: NodeIdType) -> Self {
        match value {
            NodeIdType::Ipv4 => 0,
            NodeIdType::Ipv6 => 1,
            NodeIdType::Fqdn => 2,
            NodeIdType::Unknown(v) => v & 0x0F,
        }
    }
}

/// Node ID IE (type 60).
///
/// TS 29.244 §8.2.38: first octet bits 4-1 = type; remaining octets = address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeId {
    /// Node ID type.
    pub node_id_type: NodeIdType,
    /// Raw address octets (4 for IPv4, 16 for IPv6, variable for FQDN).
    pub value: Vec<u8>,
}

impl SimpleIe for NodeId {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let node_id_type = NodeIdType::from(value[0]);
        let addr = value.get(1..).unwrap_or(&[]).to_vec();
        // Validate expected lengths for known types.
        match node_id_type {
            NodeIdType::Ipv4 if addr.len() != 4 => {
                return Err(DecodeError::new(
                    DecodeErrorCode::InvalidLength {
                        reason: "Node ID IPv4 must be 4 octets",
                    },
                    offset,
                )
                .with_spec_ref(spec_ref));
            }
            NodeIdType::Ipv6 if addr.len() != 16 => {
                return Err(DecodeError::new(
                    DecodeErrorCode::InvalidLength {
                        reason: "Node ID IPv6 must be 16 octets",
                    },
                    offset,
                )
                .with_spec_ref(spec_ref));
            }
            _ => {}
        }
        Ok(Self {
            node_id_type,
            value: addr,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.node_id_type.into());
        dst.put_slice(&self.value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// F-SEID (§8.2.40)
// ---------------------------------------------------------------------------

/// F-SEID IE (type 57).
///
/// TS 29.244 §8.2.40:
/// - octet 5: bit 2 V4, bit 1 V6, bits 8-3 spare (0)
/// - octets 6-13: SEID (8 octets)
/// - octets 14-17: IPv4 address if V4
/// - then IPv6 address (16 octets) if V6
///
/// When both V4 and V6 are set, IPv4 precedes IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FSeid {
    /// IPv4 address present.
    pub v4: bool,
    /// IPv6 address present.
    pub v6: bool,
    /// SEID (8 octets).
    pub seid: u64,
    /// IPv4 address (4 octets) if `v4`.
    pub ipv4: Option<[u8; 4]>,
    /// IPv6 address (16 octets) if `v6`.
    pub ipv6: Option<[u8; 16]>,
}

impl SimpleIe for FSeid {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        // Need at least 1 (flags) + 8 (SEID) = 9 octets.
        if value.len() < 9 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let flags = value[0];
        let v4 = (flags & 0x02) != 0; // bit 2
        let v6 = (flags & 0x01) != 0; // bit 1
                                      // Bits 8-3 are spare; senders set them to 0
                                      // and the typed re-encode canonicalizes them to 0.
        let spare = flags & 0xFC;

        let seid = u64::from_be_bytes([
            value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8],
        ]);

        let mut pos = 9usize;
        let mut ipv4 = None;
        let mut ipv6 = None;

        if v4 {
            if value.len() < pos + 4 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&value[pos..pos + 4]);
            ipv4 = Some(addr);
            pos += 4;
        }

        if v6 {
            if value.len() < pos + 16 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[pos..pos + 16]);
            ipv6 = Some(addr);
            // pos not needed beyond this point; trailing bytes are ignored for typed decode.
        }

        // Trailing octets beyond the known fields are ignored on decode for
        // forward compatibility (later releases may append fields) and are
        // NOT re-emitted by the typed encoder; see the canonicalization note
        // in CONFORMANCE.md. Use the raw layer for byte-exact forwarding.
        let _ = pos;
        let _ = spare;
        Ok(Self {
            v4,
            v6,
            seid,
            ipv4,
            ipv6,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let mut flags: u8 = 0;
        if self.v4 {
            flags |= 0x02;
        }
        if self.v6 {
            flags |= 0x01;
        }
        dst.put_u8(flags);
        dst.put_u64(self.seid);
        if let Some(ip) = self.ipv4 {
            dst.put_slice(&ip);
        }
        if let Some(ip) = self.ipv6 {
            dst.put_slice(&ip);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// F-TEID (§8.2.5)
// ---------------------------------------------------------------------------

/// F-TEID IE (type 21).
///
/// TS 29.244 §8.2.5:
/// - octet 5: bit 1 V4, bit 2 V6, bit 3 CH (choose), bit 4 CHID, bits 8-5 spare (0)
/// - octets 6-9: TEID/GRE Key if CH=0
/// - IPv4 if V4
/// - IPv6 if V6
/// - CHID if CHID=1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTeid {
    /// IPv4 address present.
    pub v4: bool,
    /// IPv6 address present.
    pub v6: bool,
    /// CH flag (choose TEID).
    pub ch: bool,
    /// CHID flag.
    pub chid: bool,
    /// TEID/GRE Key (4 octets) if CH=0.
    pub teid: Option<u32>,
    /// IPv4 address (4 octets) if V4.
    pub ipv4: Option<[u8; 4]>,
    /// IPv6 address (16 octets) if V6.
    pub ipv6: Option<[u8; 16]>,
    /// Choose ID (1 octet) if CHID=1.
    pub choose_id: Option<u8>,
}

impl SimpleIe for FTeid {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let flags = value[0];
        let v4 = (flags & 0x01) != 0; // bit 1
        let v6 = (flags & 0x02) != 0; // bit 2
        let ch = (flags & 0x04) != 0; // bit 3
        let chid = (flags & 0x08) != 0; // bit 4

        let mut pos = 1usize;
        let mut teid = None;

        if !ch {
            if value.len() < pos + 4 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            teid = Some(u32::from_be_bytes([
                value[pos],
                value[pos + 1],
                value[pos + 2],
                value[pos + 3],
            ]));
            pos += 4;
        }

        let mut ipv4 = None;
        let mut ipv6 = None;

        if v4 {
            if value.len() < pos + 4 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&value[pos..pos + 4]);
            ipv4 = Some(addr);
            pos += 4;
        }

        if v6 {
            if value.len() < pos + 16 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[pos..pos + 16]);
            ipv6 = Some(addr);
            pos += 16;
        }

        let mut choose_id = None;
        if chid {
            if value.len() < pos + 1 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            choose_id = Some(value[pos]);
            // pos not needed beyond this point.
        }

        let _ = pos;

        Ok(Self {
            v4,
            v6,
            ch,
            chid,
            teid,
            ipv4,
            ipv6,
            choose_id,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let mut flags: u8 = 0;
        if self.v4 {
            flags |= 0x01;
        }
        if self.v6 {
            flags |= 0x02;
        }
        if self.ch {
            flags |= 0x04;
        }
        if self.chid {
            flags |= 0x08;
        }
        dst.put_u8(flags);
        if let Some(t) = self.teid {
            dst.put_u32(t);
        }
        if let Some(ip) = self.ipv4 {
            dst.put_slice(&ip);
        }
        if let Some(ip) = self.ipv6 {
            dst.put_slice(&ip);
        }
        if let Some(cid) = self.choose_id {
            dst.put_u8(cid);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PDR ID (§8.2.36)
// ---------------------------------------------------------------------------

/// PDR ID IE (type 56).
///
/// TS 29.244 §8.2.36: two octets, rule id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdrId {
    /// Packet Detection Rule ID.
    pub value: u16,
}

impl SimpleIe for PdrId {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 2 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: u16::from_be_bytes([value[0], value[1]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u16(self.value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FAR ID (§8.2.50)
// ---------------------------------------------------------------------------

/// FAR ID IE (type 108).
///
/// TS 29.244 §8.2.50: four octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FarId {
    /// Forwarding Action Rule ID.
    pub value: u32,
}

impl SimpleIe for FarId {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 4 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u32(self.value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// QER ID (§8.2.37)
// ---------------------------------------------------------------------------

/// QER ID IE (type 109).
///
/// TS 29.244 §8.2.37: four octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QerId {
    /// QoS Enforcement Rule ID.
    pub value: u32,
}

impl SimpleIe for QerId {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 4 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u32(self.value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// QoS Flow Identifier (§8.2.89)
// ---------------------------------------------------------------------------

/// QoS Flow Identifier IE (type 124).
///
/// TS 29.244 §8.2.89: one octet, bits 6-1 = QFI, bits 8-7 = spare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qfi {
    /// QoS Flow Identifier (6 bits).
    pub value: u8,
}

impl SimpleIe for Qfi {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: value[0] & 0x3F,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.value & 0x3F);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Gate Status (§8.2.7)
// ---------------------------------------------------------------------------

/// Gate state for a single direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Gate is open (traffic forwarded).
    Open,
    /// Gate is closed (traffic discarded).
    Closed,
}

impl From<u8> for Gate {
    fn from(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::Open,
            _ => Self::Closed,
        }
    }
}

impl From<Gate> for u8 {
    fn from(gate: Gate) -> Self {
        match gate {
            Gate::Open => 0,
            Gate::Closed => 1,
        }
    }
}

/// Gate Status IE (type 25).
///
/// TS 29.244 §8.2.7: one octet, bits 4-3 = DL gate, bits 2-1 = UL gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateStatus {
    /// Uplink gate state.
    pub ul: Gate,
    /// Downlink gate state.
    pub dl: Gate,
}

impl SimpleIe for GateStatus {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let b = value[0];
        Ok(Self {
            ul: Gate::from(b & 0x03),
            dl: Gate::from((b >> 2) & 0x03),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let b = (u8::from(self.dl) << 2) | u8::from(self.ul);
        dst.put_u8(b);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Maximum Bit Rate (§8.2.8)
// ---------------------------------------------------------------------------

/// Maximum Bit Rate IE (type 26).
///
/// TS 29.244 §8.2.8: ten octets. The first five octets encode the uplink
/// MBR and the last five octets encode the downlink MBR, each as a 40-bit
/// unsigned integer in kilobits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mbr {
    /// Uplink maximum bitrate (kbps).
    pub ul_kbps: u64,
    /// Downlink maximum bitrate (kbps).
    pub dl_kbps: u64,
}

impl SimpleIe for Mbr {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 10 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let ul = u64::from_be_bytes([0, 0, 0, value[0], value[1], value[2], value[3], value[4]]);
        let dl = u64::from_be_bytes([0, 0, 0, value[5], value[6], value[7], value[8], value[9]]);
        Ok(Self {
            ul_kbps: ul,
            dl_kbps: dl,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let mut write_rate = |rate: u64| {
            for i in (0..5).rev() {
                dst.put_u8(((rate >> (i * 8)) & 0xFF) as u8);
            }
        };
        write_rate(self.ul_kbps);
        write_rate(self.dl_kbps);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Guaranteed Bit Rate (§8.2.9)
// ---------------------------------------------------------------------------

/// Guaranteed Bit Rate IE (type 27).
///
/// TS 29.244 §8.2.9: ten octets. The first five octets encode the uplink
/// GBR and the last five octets encode the downlink GBR, each as a 40-bit
/// unsigned integer in kilobits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gbr {
    /// Uplink guaranteed bitrate (kbps).
    pub ul_kbps: u64,
    /// Downlink guaranteed bitrate (kbps).
    pub dl_kbps: u64,
}

impl SimpleIe for Gbr {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 10 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let ul = u64::from_be_bytes([0, 0, 0, value[0], value[1], value[2], value[3], value[4]]);
        let dl = u64::from_be_bytes([0, 0, 0, value[5], value[6], value[7], value[8], value[9]]);
        Ok(Self {
            ul_kbps: ul,
            dl_kbps: dl,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let mut write_rate = |rate: u64| {
            for i in (0..5).rev() {
                dst.put_u8(((rate >> (i * 8)) & 0xFF) as u8);
            }
        };
        write_rate(self.ul_kbps);
        write_rate(self.dl_kbps);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// URR ID (§8.2.71)
// ---------------------------------------------------------------------------

/// URR ID IE (type 81).
///
/// TS 29.244 §8.2.71: four octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrrId {
    /// Usage Reporting Rule ID.
    pub value: u32,
}

impl SimpleIe for UrrId {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 4 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u32(self.value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Precedence (§8.2.20)
// ---------------------------------------------------------------------------

/// Precedence IE (type 29).
///
/// TS 29.244 §8.2.20: four octets, unsigned integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Precedence {
    /// Precedence value (lower = higher priority).
    pub value: u32,
}

impl SimpleIe for Precedence {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 4 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u32(self.value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Apply Action (§8.2.26)
// ---------------------------------------------------------------------------

/// Apply Action IE (type 44).
///
/// TS 29.244 §8.2.26: two octets, flags.
/// - bit 1: DROP
/// - bit 2: FORW
/// - bit 3: BUFF
/// - bit 4: NOCP
/// - bit 5: DUPL
/// - bit 6: IPMA
/// - bit 7: IPMD
/// - bit 8: DFRT
/// - bit 9: EDRT
/// - bit 10: BDPN
/// - bit 11: DDPN
/// - bits 16-12: spare
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyAction {
    /// DROP (bit 1).
    pub drop: bool,
    /// FORW (bit 2).
    pub forward: bool,
    /// BUFF (bit 3).
    pub buffer: bool,
    /// NOCP (bit 4).
    pub notify_cp: bool,
    /// DUPL (bit 5).
    pub duplicate: bool,
    /// IPMA (bit 6).
    pub ip_masquerade: bool,
    /// IPMD (bit 7).
    pub ip_masquerade_decap: bool,
    /// DFRT (bit 8).
    pub dfrt: bool,
    /// EDRT (bit 9).
    pub edrt: bool,
    /// BDPN (bit 10).
    pub bdpn: bool,
    /// DDPN (bit 11).
    pub ddpn: bool,
    /// Spare bits (bits 16-12) preserved for byte-exact re-encode.
    pub spare: u8,
}

impl SimpleIe for ApplyAction {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 2 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let b1 = value[0];
        let b2 = value[1];
        Ok(Self {
            drop: (b1 & 0x01) != 0,
            forward: (b1 & 0x02) != 0,
            buffer: (b1 & 0x04) != 0,
            notify_cp: (b1 & 0x08) != 0,
            duplicate: (b1 & 0x10) != 0,
            ip_masquerade: (b1 & 0x20) != 0,
            ip_masquerade_decap: (b1 & 0x40) != 0,
            dfrt: (b1 & 0x80) != 0,
            edrt: (b2 & 0x01) != 0,
            bdpn: (b2 & 0x02) != 0,
            ddpn: (b2 & 0x04) != 0,
            spare: (b2 & 0xF8) >> 3,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let mut b1: u8 = 0;
        let mut b2: u8 = (self.spare & 0x1F) << 3;
        if self.drop {
            b1 |= 0x01;
        }
        if self.forward {
            b1 |= 0x02;
        }
        if self.buffer {
            b1 |= 0x04;
        }
        if self.notify_cp {
            b1 |= 0x08;
        }
        if self.duplicate {
            b1 |= 0x10;
        }
        if self.ip_masquerade {
            b1 |= 0x20;
        }
        if self.ip_masquerade_decap {
            b1 |= 0x40;
        }
        if self.dfrt {
            b1 |= 0x80;
        }
        if self.edrt {
            b2 |= 0x01;
        }
        if self.bdpn {
            b2 |= 0x02;
        }
        if self.ddpn {
            b2 |= 0x04;
        }
        dst.put_u8(b1);
        dst.put_u8(b2);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Source Interface (§8.2.2)
// ---------------------------------------------------------------------------

/// Source Interface IE (type 20).
///
/// TS 29.244 §8.2.2: one octet, bits 4-1 = interface value, bits 8-5 = spare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceInterface {
    /// Interface value.
    /// 0 = Access, 1 = Core, 2 = SGi-LAN, 3 = CP-function, ...
    pub value: u8,
    /// Spare bits (high nibble) preserved for re-encode.
    pub spare: u8,
}

impl SimpleIe for SourceInterface {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: value[0] & 0x0F,
            spare: (value[0] & 0xF0) >> 4,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8((self.spare << 4) | (self.value & 0x0F));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Destination Interface (§8.2.3)
// ---------------------------------------------------------------------------

/// Destination Interface IE (type 42).
///
/// TS 29.244 §8.2.3: one octet, bits 4-1 = interface value, bits 8-5 = spare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationInterface {
    /// Interface value.
    pub value: u8,
    /// Spare bits (high nibble) preserved for re-encode.
    pub spare: u8,
}

impl SimpleIe for DestinationInterface {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            value: value[0] & 0x0F,
            spare: (value[0] & 0xF0) >> 4,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8((self.spare << 4) | (self.value & 0x0F));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Network Instance (§8.2.4)
// ---------------------------------------------------------------------------

/// Network Instance IE (type 22).
///
/// TS 29.244 §8.2.4: DNN encoded as an APN/DDI octet string (length variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInstance {
    /// Raw DNN octets.
    pub value: Vec<u8>,
}

impl SimpleIe for NetworkInstance {
    fn decode_value(value: &[u8], _offset: usize, _spec_ref: SpecRef) -> Result<Self, DecodeError> {
        Ok(Self {
            value: value.to_vec(),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_slice(&self.value);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UE IP Address (§8.2.62)
// ---------------------------------------------------------------------------

/// UE IP Address IE (type 93).
///
/// TS 29.244 §8.2.62:
/// - octet 5: bit 1 V4, bit 2 V6, bit 3 S/D, bit 4 IPv4D, bit 5 IPv6D,
///   bit 6 CHV4, bit 7 CHV6, bit 8 CH, bits 8-? spare
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeIpAddress {
    /// IPv4 address present.
    pub v4: bool,
    /// IPv6 address present.
    pub v6: bool,
    /// Source/Destination flag.
    pub sd: bool,
    /// IPv4D flag.
    pub ipv4d: bool,
    /// IPv6D flag.
    pub ipv6d: bool,
    /// CHV4 flag.
    pub chv4: bool,
    /// CHV6 flag.
    pub chv6: bool,
    /// CH flag.
    pub ch: bool,
    /// IPv4 address (4 octets) if V4.
    pub ipv4: Option<[u8; 4]>,
    /// IPv6 address / prefix (16 octets) if V6.
    pub ipv6: Option<[u8; 16]>,
    /// IPv4 prefix length (1 octet) if IPv4D.
    pub ipv4_prefix_length: Option<u8>,
    /// IPv6 prefix length (1 octet) if IPv6D.
    pub ipv6_prefix_length: Option<u8>,
}

impl SimpleIe for UeIpAddress {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let flags = value[0];
        let v4 = (flags & 0x01) != 0;
        let v6 = (flags & 0x02) != 0;
        let sd = (flags & 0x04) != 0;
        let ipv4d = (flags & 0x08) != 0;
        let ipv6d = (flags & 0x10) != 0;
        let chv4 = (flags & 0x20) != 0;
        let chv6 = (flags & 0x40) != 0;
        let ch = (flags & 0x80) != 0;

        let mut pos = 1usize;
        let mut ipv4 = None;
        let mut ipv6 = None;
        let mut ipv4_prefix_length = None;
        let mut ipv6_prefix_length = None;

        if v4 {
            if value.len() < pos + 4 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&value[pos..pos + 4]);
            ipv4 = Some(addr);
            pos += 4;
        }

        if v6 {
            if value.len() < pos + 16 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[pos..pos + 16]);
            ipv6 = Some(addr);
            pos += 16;
        }

        if ipv4d {
            if value.len() < pos + 1 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            ipv4_prefix_length = Some(value[pos]);
            pos += 1;
        }

        if ipv6d {
            if value.len() < pos + 1 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            ipv6_prefix_length = Some(value[pos]);
            // pos not needed beyond this point.
        }

        let _ = pos;

        Ok(Self {
            v4,
            v6,
            sd,
            ipv4d,
            ipv6d,
            chv4,
            chv6,
            ch,
            ipv4,
            ipv6,
            ipv4_prefix_length,
            ipv6_prefix_length,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let mut flags: u8 = 0;
        if self.v4 {
            flags |= 0x01;
        }
        if self.v6 {
            flags |= 0x02;
        }
        if self.sd {
            flags |= 0x04;
        }
        if self.ipv4d {
            flags |= 0x08;
        }
        if self.ipv6d {
            flags |= 0x10;
        }
        if self.chv4 {
            flags |= 0x20;
        }
        if self.chv6 {
            flags |= 0x40;
        }
        if self.ch {
            flags |= 0x80;
        }
        dst.put_u8(flags);
        if let Some(ip) = self.ipv4 {
            dst.put_slice(&ip);
        }
        if let Some(ip) = self.ipv6 {
            dst.put_slice(&ip);
        }
        if let Some(pl) = self.ipv4_prefix_length {
            dst.put_u8(pl);
        }
        if let Some(pl) = self.ipv6_prefix_length {
            dst.put_u8(pl);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Outer Header Creation (§8.2.12)
// ---------------------------------------------------------------------------

/// Outer Header Creation IE (type 84).
///
/// TS 29.244 §8.2.12:
/// - octets 5-6: Description (2 octets, flags)
/// - TEID (4 octets) if GTP-U UDP/IP or GRE
/// - IPv4 address (4 octets) if IPv4
/// - IPv6 address (16 octets) if IPv6
/// - Port number (2 octets) if UDP
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterHeaderCreation {
    /// Outer header description flags.
    pub description: u16,
    /// TEID/GRE Key (4 octets) when description indicates GTP-U or GRE.
    pub teid: Option<u32>,
    /// IPv4 address (4 octets) when IPv4 is indicated.
    pub ipv4: Option<[u8; 4]>,
    /// IPv6 address (16 octets) when IPv6 is indicated.
    pub ipv6: Option<[u8; 16]>,
    /// Port number (2 octets) when UDP is indicated.
    pub port: Option<u16>,
    /// C-TAG or S-TAG (3 octets) when applicable.
    pub c_tag: Option<[u8; 3]>,
    /// S-TAG (3 octets) when applicable.
    pub s_tag: Option<[u8; 3]>,
}

impl SimpleIe for OuterHeaderCreation {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 2 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        let description = u16::from_be_bytes([value[0], value[1]]);
        let mut pos = 2usize;

        // The Description field is two octets; octet 5 (the FIRST octet on
        // the wire) is the high byte of the big-endian u16. Per §8.2.56:
        //   octet 5 bit 1 (0x0100) = GTP-U/UDP/IPv4
        //   octet 5 bit 2 (0x0200) = GTP-U/UDP/IPv6
        //   octet 5 bit 3 (0x0400) = UDP/IPv4
        //   octet 5 bit 4 (0x0800) = UDP/IPv6
        //   octet 5 bit 5 (0x1000) = IPv4
        //   octet 5 bit 6 (0x2000) = IPv6
        //   octet 5 bit 7 (0x4000) = C-TAG
        //   octet 5 bit 8 (0x8000) = S-TAG
        //   octet 6 bit 1 (0x0001) = N19 Indication
        //   octet 6 bit 2 (0x0002) = N6 Indication
        // Field presence per §8.2.56:
        //   TEID iff a GTP-U encapsulation is requested (octet 5 bits 1-2);
        //   IPv4 address iff octet 5 bit 1, 3, or 5; IPv6 iff bit 2, 4, or 6;
        //   UDP port iff a non-GTP UDP encapsulation (octet 5 bits 3-4).
        let has_teid = (description & 0x0300) != 0;
        let has_ipv4 = (description & 0x1500) != 0;
        let has_ipv6 = (description & 0x2A00) != 0;
        let has_port = (description & 0x0C00) != 0;
        let has_c_tag = (description & 0x4000) != 0;
        let has_s_tag = (description & 0x8000) != 0;

        let mut teid = None;
        let mut ipv4 = None;
        let mut ipv6 = None;
        let mut port = None;
        let mut c_tag = None;
        let mut s_tag = None;

        if has_teid {
            if value.len() < pos + 4 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            teid = Some(u32::from_be_bytes([
                value[pos],
                value[pos + 1],
                value[pos + 2],
                value[pos + 3],
            ]));
            pos += 4;
        }

        if has_ipv4 {
            if value.len() < pos + 4 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&value[pos..pos + 4]);
            ipv4 = Some(addr);
            pos += 4;
        }

        if has_ipv6 {
            if value.len() < pos + 16 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[pos..pos + 16]);
            ipv6 = Some(addr);
            pos += 16;
        }

        if has_port {
            if value.len() < pos + 2 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            port = Some(u16::from_be_bytes([value[pos], value[pos + 1]]));
            pos += 2;
        }

        if has_c_tag {
            if value.len() < pos + 3 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref.clone()));
            }
            let mut tag = [0u8; 3];
            tag.copy_from_slice(&value[pos..pos + 3]);
            c_tag = Some(tag);
            pos += 3;
        }

        if has_s_tag {
            if value.len() < pos + 3 {
                return Err(DecodeError::new(DecodeErrorCode::Truncated, offset + pos)
                    .with_spec_ref(spec_ref));
            }
            let mut tag = [0u8; 3];
            tag.copy_from_slice(&value[pos..pos + 3]);
            s_tag = Some(tag);
            // pos not needed beyond this point.
        }

        let _ = pos;

        Ok(Self {
            description,
            teid,
            ipv4,
            ipv6,
            port,
            c_tag,
            s_tag,
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u16(self.description);
        if let Some(t) = self.teid {
            dst.put_u32(t);
        }
        if let Some(ip) = self.ipv4 {
            dst.put_slice(&ip);
        }
        if let Some(ip) = self.ipv6 {
            dst.put_slice(&ip);
        }
        if let Some(p) = self.port {
            dst.put_u16(p);
        }
        if let Some(tag) = self.c_tag {
            dst.put_slice(&tag);
        }
        if let Some(tag) = self.s_tag {
            dst.put_slice(&tag);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Outer Header Removal (§8.2.57)
// ---------------------------------------------------------------------------

/// Outer Header Removal IE (type 95).
///
/// TS 29.244 §8.2.57: one octet, description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterHeaderRemoval {
    /// Description value.
    pub description: u8,
}

impl SimpleIe for OuterHeaderRemoval {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            description: value[0],
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u8(self.description);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Recovery Time Stamp (§8.2.69)
// ---------------------------------------------------------------------------

/// Recovery Time Stamp IE (type 96).
///
/// TS 29.244 §8.2.69: four octets in the format of the first 32 bits of an
/// NTP timestamp (IETF RFC 5905), i.e. seconds since the NTP era origin
/// 1900-01-01 00:00:00 UTC. The value is carried opaquely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryTimeStamp {
    /// Seconds in NTP short format (era origin 1900-01-01, RFC 5905).
    pub seconds: u32,
}

impl SimpleIe for RecoveryTimeStamp {
    fn decode_value(value: &[u8], offset: usize, spec_ref: SpecRef) -> Result<Self, DecodeError> {
        if value.len() < 4 {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec_ref)
            );
        }
        Ok(Self {
            seconds: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
        })
    }

    fn encode_value(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_u32(self.seconds);
        Ok(())
    }
}
