//! Canonical 3GPP Traffic Flow Template (TFT) model and value-part codec.
//!
//! This crate owns the single product-neutral TFT representation shared by
//! GTPv2-C Bearer TFT IEs and IKEv2 TFT Notify payloads. Both transports carry
//! the value part of the TS 24.008 type-4 TFT IE, beginning with octet 3; the
//! outer IEI and length octets are deliberately outside this boundary.
//!
//! The decoder is strict and bounded. It validates operation/list cardinality,
//! fixed component lengths, spare bits, identifiers, duplicate identifiers and
//! precedence values, component combinations, parameter structure, and the
//! 255-octet TFT value limit before returning an immutable owned model.
//!
//! @spec 3GPP TS24008 R18 10.5.6.12
//! @spec 3GPP TS23060 R18 15.3.2
//! @spec 3GPP TS24302 R17 8.2.9.11
//! @req REQ-3GPP-TFT-R18-CODEC-001
//! @conformance complete-value-codec — see CONFORMANCE.md

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

mod codec;
mod error;
mod model;

pub use error::{TftError, TftErrorKind};
pub use model::{
    AuthorizationToken, FlowIdentifier, Ipv6AddressPrefix, Ipv6FlowLabel, PacketFilter,
    PacketFilterComponent, PacketFilterComponentKind, PacketFilterDirection,
    PacketFilterIdentifier, PacketFilterIdentifierList, PacketFilterList, PortRange, TftOperation,
    TftParameter, TftParameterKind, TrafficFlowTemplate, UnknownTftParameter, VlanIdentifier,
    VlanPriority, TFT_ALLOCATION_BUDGET, TFT_MAX_PACKET_FILTERS, TFT_MAX_VALUE_LEN,
    TFT_MIN_VALUE_LEN,
};
