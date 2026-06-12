#![forbid(unsafe_code)]

//! Grouped PFCP Information Elements.
//!
//! Grouped IEs contain a sequence of member IEs. Depth limits are enforced
//! during decode to prevent unbounded recursion on hostile input.
//!
//! @spec 3GPP TS29244 R18 7.5.2

use bytes::BytesMut;
use opc_protocol::{DecodeContext, DecodeError, EncodeContext, EncodeError};

use crate::ie::{GroupedIe, TypedIe};

// ---------------------------------------------------------------------------
// Create PDR (type 1)
// ---------------------------------------------------------------------------

/// Create PDR grouped IE (type 1).
///
/// TS 29.244 §7.5.2.1: contains PDR ID, Precedence, PDI, Outer Header Removal,
/// FAR ID, URR IDs, QER IDs, Activate Predefined Rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePdr {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for CreatePdr {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PDI (type 2)
// ---------------------------------------------------------------------------

/// PDI grouped IE (type 2).
///
/// TS 29.244 §7.5.2.2: contains Source Interface, F-TEID, Network Instance,
/// UE IP Address, and other traffic-detection parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdi {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for Pdi {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Create FAR (type 3)
// ---------------------------------------------------------------------------

/// Create FAR grouped IE (type 3).
///
/// TS 29.244 §7.5.2.3: contains FAR ID, Apply Action, Forwarding Parameters,
/// Duplicating Parameters, BAR ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFar {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for CreateFar {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Forwarding Parameters (type 4)
// ---------------------------------------------------------------------------

/// Forwarding Parameters grouped IE (type 4).
///
/// TS 29.244 §7.5.2.2.1: contains Destination Interface, Network Instance,
/// Outer Header Creation, Transport Level Marking, Forwarding Policy, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingParameters {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for ForwardingParameters {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Create URR (type 6)
// ---------------------------------------------------------------------------

/// Create URR grouped IE (type 6).
///
/// TS 29.244 §7.5.2.5: contains URR ID, Measurement Method, Reporting Triggers,
/// etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUrr {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for CreateUrr {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Create QER (type 7)
// ---------------------------------------------------------------------------

/// Create QER grouped IE (type 7).
///
/// TS 29.244 §7.5.2.4: contains QER ID, Gate Status, MBR, GBR, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateQer {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for CreateQer {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Update QER (type 14)
// ---------------------------------------------------------------------------

/// Update QER grouped IE (type 14).
///
/// TS 29.244 §7.5.4.5: contains QER ID and the subset of QoS parameters
/// that need to be modified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateQer {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for UpdateQer {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Created PDR (type 8)
// ---------------------------------------------------------------------------

/// Created PDR grouped IE (type 8).
///
/// TS 29.244 §7.5.2.6: contains PDR ID, F-TEID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedPdr {
    /// Member IEs.
    pub members: Vec<TypedIe>,
}

impl GroupedIe for CreatedPdr {
    fn decode_members(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<Self, DecodeError> {
        let members = decode_typed_ie_sequence(input, ctx, depth)?;
        Ok(Self { members })
    }

    fn encode_members(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        for member in &self.members {
            member.encode(dst, ctx)?;
        }
        Ok(())
    }
}

/// Decode a sequence of member IEs from a grouped IE value buffer,
/// enforcing depth limits for nested grouped IEs.
fn decode_typed_ie_sequence(
    input: &[u8],
    ctx: DecodeContext,
    depth: usize,
) -> Result<Vec<TypedIe>, DecodeError> {
    let mut ies = Vec::new();
    let mut offset = 0usize;

    while offset < input.len() {
        let (remaining, ie) = TypedIe::decode(&input[offset..], ctx, depth)?;
        ies.push(ie);
        offset = input.len() - remaining.len();
    }

    Ok(ies)
}
