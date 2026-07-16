//! Typed 3GPP IKEv2 multiple-bearer notifications and exchange helpers.
//!
//! This module implements the transport-neutral protocol boundary used by an
//! ePDG for TS 24.302 multiple-bearer PDN connectivity. It owns no bearer
//! admission policy, SPI allocation, Child-SA installation, retransmission
//! timer, or dataplane state.
//!
//! @spec 3GPP TS24302 R17 7.2.7, 7.4.6.3, 8.1.2.2, 8.1.2.3, 8.2.9.9-8.2.9.14
//! @spec 3GPP TS24301 R17 9.9.4.2, 9.9.4.3, 9.9.4.29, 9.9.4.30
//! @spec IETF RFC7296 1.3, 2.8, 3.10, 3.11
//! @req REQ-3GPP-TS24302-R17-MULTIPLE-BEARER-001

use core::fmt;
use std::{error::Error, num::NonZeroU32};

use bytes::BytesMut;
use opc_proto_tft::{TftError, TrafficFlowTemplate};

use crate::{
    ike_auth::{Ikev2IkeAuthPayloadBuild, IKEV2_SECURITY_PROTOCOL_ID_ESP},
    notify::{Ikev2NotifyPayload, IKEV2_NOTIFY_PROTOCOL_ID_NONE},
    payload::PayloadType,
    sa_init::Ikev2NotifyPayloadBuild,
};

mod exchange;
mod qos;

pub use exchange::{
    build_ikev2_dedicated_bearer_create_child_sa_error_response,
    build_ikev2_dedicated_bearer_create_child_sa_request,
    build_ikev2_dedicated_bearer_create_child_sa_response,
    build_ikev2_dedicated_bearer_delete_request, build_ikev2_dedicated_bearer_delete_response,
    build_ikev2_dedicated_bearer_informational_error_response,
    build_ikev2_dedicated_bearer_informational_success_response,
    build_ikev2_dedicated_bearer_modification_request,
    decode_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_request_with_context,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    decode_ikev2_dedicated_bearer_delete_request, decode_ikev2_dedicated_bearer_delete_response,
    decode_ikev2_dedicated_bearer_informational_response,
    decode_ikev2_dedicated_bearer_modification_request,
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
    validate_ikev2_dedicated_bearer_delete_response_correlation,
    validate_ikev2_dedicated_bearer_modification_response_correlation,
    validate_ikev2_dedicated_bearer_response_correlation, Ikev2DedicatedBearerCleartextPayloads,
    Ikev2DedicatedBearerCreateChildSaRequest, Ikev2DedicatedBearerCreateChildSaRequestBuild,
    Ikev2DedicatedBearerCreateChildSaResponse, Ikev2DedicatedBearerCreateChildSaResponseBuild,
    Ikev2DedicatedBearerDeleteRequest, Ikev2DedicatedBearerDeleteResponse,
    Ikev2DedicatedBearerDeleteResponseExpectation, Ikev2DedicatedBearerExchangeError,
    Ikev2DedicatedBearerInformationalResponse, Ikev2DedicatedBearerModificationRequest,
    Ikev2DedicatedBearerModificationRequestBuild, Ikev2DedicatedBearerPayloadRole,
    Ikev2DedicatedBearerPeerErrorNotify, Ikev2DedicatedBearerResponseError,
    Ikev2UnknownNonCriticalPayload,
};
pub use qos::{
    Ikev2ApnAmbrKbps, Ikev2ApnAmbrMapping, Ikev2EpsBearerBitRatesKbps, Ikev2EpsQosKbps,
    Ikev2EpsQosMapping, Ikev2QosDirection, Ikev2QosMappingError, Ikev2QosQuantization,
    Ikev2QosRateCodeTier, Ikev2QosRateField, Ikev2QosResourceType,
};

/// Private error Notify for a semantic error in a TFT operation.
///
/// @spec 3GPP TS24302 R17 8.1.2.2 table 8.1.2.2-1
pub const IKEV2_NOTIFY_SEMANTIC_ERROR_IN_THE_TFT_OPERATION: u16 = 8_241;

/// Private error Notify for a syntactical error in a TFT operation.
///
/// @spec 3GPP TS24302 R17 8.1.2.2 table 8.1.2.2-1
pub const IKEV2_NOTIFY_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION: u16 = 8_242;

/// Private error Notify for semantic errors in packet filters.
///
/// @spec 3GPP TS24302 R17 8.1.2.2 table 8.1.2.2-1
pub const IKEV2_NOTIFY_SEMANTIC_ERRORS_IN_PACKET_FILTERS: u16 = 8_244;

/// Private error Notify for syntactical errors in packet filters.
///
/// @spec 3GPP TS24302 R17 8.1.2.2 table 8.1.2.2-1
pub const IKEV2_NOTIFY_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS: u16 = 8_245;

/// Status Notify indicating support for IKEv2 multiple-bearer PDN connectivity.
///
/// @spec 3GPP TS24302 R17 8.2.9.9
pub const IKEV2_NOTIFY_MULTIPLE_BEARER_PDN_CONNECTIVITY: u16 = 42_011;

/// Status Notify carrying EPS QoS.
///
/// @spec 3GPP TS24302 R17 8.2.9.10
pub const IKEV2_NOTIFY_EPS_QOS: u16 = 42_014;

/// Status Notify carrying Extended EPS QoS.
///
/// @spec 3GPP TS24302 R17 8.2.9.10A
pub const IKEV2_NOTIFY_EXTENDED_EPS_QOS: u16 = 42_015;

/// Status Notify carrying the canonical TS 24.008 TFT value.
///
/// @spec 3GPP TS24302 R17 8.2.9.11
pub const IKEV2_NOTIFY_TFT: u16 = 42_017;

/// Status Notify identifying the ePDG-owned ESP SPI of a modified bearer.
///
/// @spec 3GPP TS24302 R17 8.2.9.12
pub const IKEV2_NOTIFY_MODIFIED_BEARER: u16 = 42_020;

/// Status Notify carrying APN-AMBR.
///
/// @spec 3GPP TS24302 R17 8.2.9.13
pub const IKEV2_NOTIFY_APN_AMBR: u16 = 42_094;

/// Status Notify carrying Extended APN-AMBR.
///
/// @spec 3GPP TS24302 R17 8.2.9.14
pub const IKEV2_NOTIFY_EXTENDED_APN_AMBR: u16 = 42_095;

const EPS_QOS_LENGTHS: [usize; 4] = [1, 5, 9, 13];
const EXTENDED_EPS_QOS_LEN: usize = 10;
const APN_AMBR_LENGTHS: [usize; 3] = [2, 4, 6];
const EXTENDED_APN_AMBR_LEN: usize = 6;
const IPSEC_SPI_LEN: usize = 4;

/// Four rate-code octets in an EPS QoS tier.
///
/// The octets retain the exact TS 24.301 representation. The base, extended,
/// and extended-2 tiers use different unit mappings, so preserving the tier as
/// part of [`Ikev2EpsQos`] avoids a lossy or ambiguous conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2EpsQosRateCodes {
    /// Maximum uplink bit-rate code.
    pub maximum_uplink: u8,
    /// Maximum downlink bit-rate code.
    pub maximum_downlink: u8,
    /// Guaranteed uplink bit-rate code.
    pub guaranteed_uplink: u8,
    /// Guaranteed downlink bit-rate code.
    pub guaranteed_downlink: u8,
}

impl Ikev2EpsQosRateCodes {
    const fn from_slice(value: &[u8]) -> Self {
        Self {
            maximum_uplink: value[0],
            maximum_downlink: value[1],
            guaranteed_uplink: value[2],
            guaranteed_downlink: value[3],
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[
            self.maximum_uplink,
            self.maximum_downlink,
            self.guaranteed_uplink,
            self.guaranteed_downlink,
        ]);
    }
}

/// Typed TS 24.301 EPS quality-of-service value part.
///
/// The value excludes the NAS IEI and NAS length octet, exactly as required by
/// the TS 24.302 EPS_QOS Notify. Optional tiers are structurally coupled: a
/// tier cannot be present unless every preceding tier is present.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ikev2EpsQos {
    qci: u8,
    base_rates: Option<Ikev2EpsQosRateCodes>,
    extended_rates: Option<Ikev2EpsQosRateCodes>,
    extended_2_rates: Option<Ikev2EpsQosRateCodes>,
}

impl Ikev2EpsQos {
    /// Construct a structurally contiguous EPS QoS value.
    ///
    /// This compatibility constructor retains caller-supplied compact codes.
    /// Strict decode and [`build_ikev2_dedicated_bearer_notify`] additionally
    /// enforce the complete Release 17 network-to-UE wire profile. The checked
    /// [`Ikev2EpsQosMapping`] API is preferred for production construction.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError`] when the QCI is reserved in the
    /// Release 17 network-to-UE profile or optional rate tiers have a gap.
    pub fn new(
        qci: u8,
        base_rates: Option<Ikev2EpsQosRateCodes>,
        extended_rates: Option<Ikev2EpsQosRateCodes>,
        extended_2_rates: Option<Ikev2EpsQosRateCodes>,
    ) -> Result<Self, Ikev2DedicatedBearerError> {
        validate_qci(qci)?;
        if extended_rates.is_some() && base_rates.is_none() {
            return Err(Ikev2DedicatedBearerError::EpsQosTierGap);
        }
        if extended_2_rates.is_some() && extended_rates.is_none() {
            return Err(Ikev2DedicatedBearerError::EpsQosTierGap);
        }
        Ok(Self {
            qci,
            base_rates,
            extended_rates,
            extended_2_rates,
        })
    }

    /// Decode a TS 24.301 EPS QoS value part.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError`] for an invalid length, QCI,
    /// resource shape, reserved code, tier relationship, or GBR relationship.
    pub fn decode_value(value: &[u8]) -> Result<Self, Ikev2DedicatedBearerError> {
        if !EPS_QOS_LENGTHS.contains(&value.len()) {
            return Err(Ikev2DedicatedBearerError::InvalidEpsQosLength {
                actual: value.len(),
            });
        }
        let qci = value[0];
        let base_rates = value.get(1..5).map(Ikev2EpsQosRateCodes::from_slice);
        let extended_rates = value.get(5..9).map(Ikev2EpsQosRateCodes::from_slice);
        let extended_2_rates = value.get(9..13).map(Ikev2EpsQosRateCodes::from_slice);
        let decoded = Self::new(qci, base_rates, extended_rates, extended_2_rates)?;
        qos::validate_eps_qos_wire_profile(&decoded)?;
        Ok(decoded)
    }

    /// Encode the retained TS 24.301 value part without validation.
    ///
    /// Production callers should use [`build_ikev2_dedicated_bearer_notify`]
    /// or an exchange builder, which revalidates the network-to-UE profile.
    pub fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_value_len());
        out.push(self.qci);
        if let Some(rates) = self.base_rates {
            rates.encode(&mut out);
        }
        if let Some(rates) = self.extended_rates {
            rates.encode(&mut out);
        }
        if let Some(rates) = self.extended_2_rates {
            rates.encode(&mut out);
        }
        out
    }

    /// QoS Class Identifier.
    pub const fn qci(&self) -> u8 {
        self.qci
    }

    /// Base bit-rate codes, when included.
    pub const fn base_rates(&self) -> Option<Ikev2EpsQosRateCodes> {
        self.base_rates
    }

    /// Extended bit-rate codes, when included.
    pub const fn extended_rates(&self) -> Option<Ikev2EpsQosRateCodes> {
        self.extended_rates
    }

    /// Extended-2 bit-rate codes, when included.
    pub const fn extended_2_rates(&self) -> Option<Ikev2EpsQosRateCodes> {
        self.extended_2_rates
    }

    /// Encoded TS 24.301 value-part length.
    pub const fn encoded_value_len(&self) -> usize {
        1 + if self.base_rates.is_some() { 4 } else { 0 }
            + if self.extended_rates.is_some() { 4 } else { 0 }
            + if self.extended_2_rates.is_some() {
                4
            } else {
                0
            }
    }
}

/// Unit code used by TS 24.301 extended bit-rate values.
///
/// Codes beyond the explicitly assigned Release 17 range can be retained in a
/// raw value. Strict decode and production builders require canonical assigned
/// network-to-UE units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2ExtendedBitRateUnit(u8);

impl Ikev2ExtendedBitRateUnit {
    /// Construct from the one-octet wire code.
    pub const fn new(wire_value: u8) -> Self {
        Self(wire_value)
    }

    /// Return the one-octet wire code.
    pub const fn wire_value(self) -> u8 {
        self.0
    }
}

/// Typed TS 24.301 Extended EPS QoS value part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2ExtendedEpsQos {
    /// Unit for both maximum bit-rate values.
    pub maximum_unit: Ikev2ExtendedBitRateUnit,
    /// Maximum uplink bit-rate multiplier.
    pub maximum_uplink: u16,
    /// Maximum downlink bit-rate multiplier.
    pub maximum_downlink: u16,
    /// Unit for both guaranteed bit-rate values.
    pub guaranteed_unit: Ikev2ExtendedBitRateUnit,
    /// Guaranteed uplink bit-rate multiplier.
    pub guaranteed_uplink: u16,
    /// Guaranteed downlink bit-rate multiplier.
    pub guaranteed_downlink: u16,
}

impl Ikev2ExtendedEpsQos {
    /// Decode the ten-octet TS 24.301 value part.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError`] when the value is not ten octets
    /// or does not carry a canonical rate above 10 Gbps.
    pub fn decode_value(value: &[u8]) -> Result<Self, Ikev2DedicatedBearerError> {
        if value.len() != EXTENDED_EPS_QOS_LEN {
            return Err(Ikev2DedicatedBearerError::InvalidExtendedEpsQosLength {
                actual: value.len(),
            });
        }
        let decoded = Self {
            maximum_unit: Ikev2ExtendedBitRateUnit::new(value[0]),
            maximum_uplink: u16::from_be_bytes([value[1], value[2]]),
            maximum_downlink: u16::from_be_bytes([value[3], value[4]]),
            guaranteed_unit: Ikev2ExtendedBitRateUnit::new(value[5]),
            guaranteed_uplink: u16::from_be_bytes([value[6], value[7]]),
            guaranteed_downlink: u16::from_be_bytes([value[8], value[9]]),
        };
        qos::validate_extended_eps_qos_wire_profile(decoded)?;
        Ok(decoded)
    }

    /// Encode the retained ten-octet TS 24.301 value part without validation.
    ///
    /// Production callers should use [`build_ikev2_dedicated_bearer_notify`]
    /// or an exchange builder.
    pub fn encode_value(self) -> [u8; EXTENDED_EPS_QOS_LEN] {
        let maximum_uplink = self.maximum_uplink.to_be_bytes();
        let maximum_downlink = self.maximum_downlink.to_be_bytes();
        let guaranteed_uplink = self.guaranteed_uplink.to_be_bytes();
        let guaranteed_downlink = self.guaranteed_downlink.to_be_bytes();
        [
            self.maximum_unit.wire_value(),
            maximum_uplink[0],
            maximum_uplink[1],
            maximum_downlink[0],
            maximum_downlink[1],
            self.guaranteed_unit.wire_value(),
            guaranteed_uplink[0],
            guaranteed_uplink[1],
            guaranteed_downlink[0],
            guaranteed_downlink[1],
        ]
    }
}

/// Paired downlink/uplink APN-AMBR code octets for one tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2ApnAmbrRateCodes {
    /// Downlink APN-AMBR code.
    pub downlink: u8,
    /// Uplink APN-AMBR code.
    pub uplink: u8,
}

/// Typed TS 24.301 APN aggregate maximum bit-rate value part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2ApnAmbr {
    base: Ikev2ApnAmbrRateCodes,
    extended: Option<Ikev2ApnAmbrRateCodes>,
    extended_2: Option<Ikev2ApnAmbrRateCodes>,
}

impl Ikev2ApnAmbr {
    /// Construct APN-AMBR with structurally contiguous optional tiers.
    ///
    /// This compatibility constructor retains caller-supplied compact codes.
    /// Strict decode and production Notify/exchange builders additionally
    /// enforce the complete Release 17 network-to-UE wire profile. The checked
    /// [`Ikev2ApnAmbrMapping`] API is preferred for production construction.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError`] if extended-2 is present without
    /// the preceding extended tier.
    pub fn new(
        base: Ikev2ApnAmbrRateCodes,
        extended: Option<Ikev2ApnAmbrRateCodes>,
        extended_2: Option<Ikev2ApnAmbrRateCodes>,
    ) -> Result<Self, Ikev2DedicatedBearerError> {
        if extended_2.is_some() && extended.is_none() {
            return Err(Ikev2DedicatedBearerError::ApnAmbrTierGap);
        }
        Ok(Self {
            base,
            extended,
            extended_2,
        })
    }

    /// Decode a TS 24.301 APN-AMBR value part.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError`] for an invalid length, reserved
    /// compact code, or non-canonical tier relationship.
    pub fn decode_value(value: &[u8]) -> Result<Self, Ikev2DedicatedBearerError> {
        if !APN_AMBR_LENGTHS.contains(&value.len()) {
            return Err(Ikev2DedicatedBearerError::InvalidApnAmbrLength {
                actual: value.len(),
            });
        }
        let pair = |offset: usize| Ikev2ApnAmbrRateCodes {
            downlink: value[offset],
            uplink: value[offset + 1],
        };
        let decoded = Self::new(
            pair(0),
            (value.len() >= 4).then(|| pair(2)),
            (value.len() == 6).then(|| pair(4)),
        )?;
        qos::validate_apn_ambr_wire_profile(decoded)?;
        Ok(decoded)
    }

    /// Encode the retained TS 24.301 value part without validation.
    ///
    /// Production callers should use [`build_ikev2_dedicated_bearer_notify`]
    /// or an exchange builder.
    pub fn encode_value(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_value_len());
        out.extend_from_slice(&[self.base.downlink, self.base.uplink]);
        if let Some(extended) = self.extended {
            out.extend_from_slice(&[extended.downlink, extended.uplink]);
        }
        if let Some(extended_2) = self.extended_2 {
            out.extend_from_slice(&[extended_2.downlink, extended_2.uplink]);
        }
        out
    }

    /// Base downlink/uplink APN-AMBR codes.
    pub const fn base(self) -> Ikev2ApnAmbrRateCodes {
        self.base
    }

    /// Extended APN-AMBR codes, when present.
    pub const fn extended(self) -> Option<Ikev2ApnAmbrRateCodes> {
        self.extended
    }

    /// Extended-2 APN-AMBR codes, when present.
    pub const fn extended_2(self) -> Option<Ikev2ApnAmbrRateCodes> {
        self.extended_2
    }

    /// Encoded value-part length.
    pub const fn encoded_value_len(self) -> usize {
        2 + if self.extended.is_some() { 2 } else { 0 }
            + if self.extended_2.is_some() { 2 } else { 0 }
    }
}

/// Typed TS 24.301 Extended APN-AMBR value part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2ExtendedApnAmbr {
    /// Unit for the downlink value.
    pub downlink_unit: Ikev2ExtendedBitRateUnit,
    /// Downlink multiplier.
    pub downlink: u16,
    /// Unit for the uplink value.
    pub uplink_unit: Ikev2ExtendedBitRateUnit,
    /// Uplink multiplier.
    pub uplink: u16,
}

impl Ikev2ExtendedApnAmbr {
    /// Decode the six-octet TS 24.301 value part.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError`] when the value is not six octets
    /// or does not carry a canonical rate above 65,280 Mbps.
    pub fn decode_value(value: &[u8]) -> Result<Self, Ikev2DedicatedBearerError> {
        if value.len() != EXTENDED_APN_AMBR_LEN {
            return Err(Ikev2DedicatedBearerError::InvalidExtendedApnAmbrLength {
                actual: value.len(),
            });
        }
        let decoded = Self {
            downlink_unit: Ikev2ExtendedBitRateUnit::new(value[0]),
            downlink: u16::from_be_bytes([value[1], value[2]]),
            uplink_unit: Ikev2ExtendedBitRateUnit::new(value[3]),
            uplink: u16::from_be_bytes([value[4], value[5]]),
        };
        qos::validate_extended_apn_ambr_wire_profile(decoded)?;
        Ok(decoded)
    }

    /// Encode the retained six-octet TS 24.301 value part without validation.
    ///
    /// Production callers should use [`build_ikev2_dedicated_bearer_notify`]
    /// or an exchange builder.
    pub fn encode_value(self) -> [u8; EXTENDED_APN_AMBR_LEN] {
        let downlink = self.downlink.to_be_bytes();
        let uplink = self.uplink.to_be_bytes();
        [
            self.downlink_unit.wire_value(),
            downlink[0],
            downlink[1],
            self.uplink_unit.wire_value(),
            uplink[0],
            uplink[1],
        ]
    }
}

/// Non-zero four-octet ESP SPI used by dedicated-bearer notifications/deletes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2DedicatedBearerEspSpi(NonZeroU32);

impl Ikev2DedicatedBearerEspSpi {
    /// Construct a non-zero ESP SPI.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError::ZeroEspSpi`] for zero.
    pub fn new(value: u32) -> Result<Self, Ikev2DedicatedBearerError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(Ikev2DedicatedBearerError::ZeroEspSpi)
    }

    /// Decode a four-octet network-order ESP SPI.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2DedicatedBearerError`] for a non-four-octet or zero SPI.
    pub fn decode(value: &[u8]) -> Result<Self, Ikev2DedicatedBearerError> {
        let octets: [u8; IPSEC_SPI_LEN] =
            value
                .try_into()
                .map_err(|_| Ikev2DedicatedBearerError::InvalidEspSpiLength {
                    actual: value.len(),
                })?;
        Self::new(u32::from_be_bytes(octets))
    }

    /// Return the numeric SPI.
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Return the four network-order SPI octets.
    pub const fn to_be_bytes(self) -> [u8; IPSEC_SPI_LEN] {
        self.get().to_be_bytes()
    }
}

impl fmt::Debug for Ikev2DedicatedBearerEspSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ikev2DedicatedBearerEspSpi")
            .field(&"<redacted>")
            .finish()
    }
}

/// TS 24.302 private error usable in Child-SA creation/modification responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2DedicatedBearerProtocolError {
    /// Semantic error in the TFT operation.
    SemanticErrorInTftOperation,
    /// Syntactical error in the TFT operation.
    SyntacticalErrorInTftOperation,
    /// Semantic error in one or more packet filters.
    SemanticErrorsInPacketFilters,
    /// Syntactical error in one or more packet filters.
    SyntacticalErrorsInPacketFilters,
}

impl Ikev2DedicatedBearerProtocolError {
    /// Return the normative private Notify Message Type.
    pub const fn notify_message_type(self) -> u16 {
        match self {
            Self::SemanticErrorInTftOperation => IKEV2_NOTIFY_SEMANTIC_ERROR_IN_THE_TFT_OPERATION,
            Self::SyntacticalErrorInTftOperation => {
                IKEV2_NOTIFY_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION
            }
            Self::SemanticErrorsInPacketFilters => IKEV2_NOTIFY_SEMANTIC_ERRORS_IN_PACKET_FILTERS,
            Self::SyntacticalErrorsInPacketFilters => {
                IKEV2_NOTIFY_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS
            }
        }
    }

    /// Decode one of the four TS 24.302 dedicated-bearer private errors.
    pub const fn from_notify_message_type(value: u16) -> Option<Self> {
        match value {
            IKEV2_NOTIFY_SEMANTIC_ERROR_IN_THE_TFT_OPERATION => {
                Some(Self::SemanticErrorInTftOperation)
            }
            IKEV2_NOTIFY_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION => {
                Some(Self::SyntacticalErrorInTftOperation)
            }
            IKEV2_NOTIFY_SEMANTIC_ERRORS_IN_PACKET_FILTERS => {
                Some(Self::SemanticErrorsInPacketFilters)
            }
            IKEV2_NOTIFY_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS => {
                Some(Self::SyntacticalErrorsInPacketFilters)
            }
            _ => None,
        }
    }
}

/// Typed TS 24.302 dedicated-bearer Notify value.
#[derive(Clone, PartialEq, Eq)]
pub enum Ikev2DedicatedBearerNotify {
    /// UE capability indication with no notification data.
    MultipleBearerPdnConnectivity,
    /// EPS_QOS value.
    EpsQos(Ikev2EpsQos),
    /// EXTENDED_EPS_QOS value.
    ExtendedEpsQos(Ikev2ExtendedEpsQos),
    /// Canonical TFT value.
    Tft(TrafficFlowTemplate),
    /// ePDG-owned ESP SPI of the modified Child SA.
    ModifiedBearer(Ikev2DedicatedBearerEspSpi),
    /// APN_AMBR value.
    ApnAmbr(Ikev2ApnAmbr),
    /// EXTENDED_APN_AMBR value.
    ExtendedApnAmbr(Ikev2ExtendedApnAmbr),
    /// One of the four dedicated-bearer private error notifications.
    ProtocolError(Ikev2DedicatedBearerProtocolError),
}

impl fmt::Debug for Ikev2DedicatedBearerNotify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultipleBearerPdnConnectivity => f.write_str("MultipleBearerPdnConnectivity"),
            Self::EpsQos(value) => f.debug_tuple("EpsQos").field(value).finish(),
            Self::ExtendedEpsQos(value) => f.debug_tuple("ExtendedEpsQos").field(value).finish(),
            Self::Tft(value) => f
                .debug_struct("Tft")
                .field("operation", &value.operation())
                .field("packet_filter_count", &value.packet_filters().len())
                .field("parameter_count", &value.parameters().len())
                .finish(),
            Self::ModifiedBearer(_) => f
                .debug_tuple("ModifiedBearer")
                .field(&"<redacted>")
                .finish(),
            Self::ApnAmbr(value) => f.debug_tuple("ApnAmbr").field(value).finish(),
            Self::ExtendedApnAmbr(value) => f.debug_tuple("ExtendedApnAmbr").field(value).finish(),
            Self::ProtocolError(value) => f.debug_tuple("ProtocolError").field(value).finish(),
        }
    }
}

impl Ikev2DedicatedBearerNotify {
    /// Return the normative Notify Message Type.
    pub const fn notify_message_type(&self) -> u16 {
        match self {
            Self::MultipleBearerPdnConnectivity => IKEV2_NOTIFY_MULTIPLE_BEARER_PDN_CONNECTIVITY,
            Self::EpsQos(_) => IKEV2_NOTIFY_EPS_QOS,
            Self::ExtendedEpsQos(_) => IKEV2_NOTIFY_EXTENDED_EPS_QOS,
            Self::Tft(_) => IKEV2_NOTIFY_TFT,
            Self::ModifiedBearer(_) => IKEV2_NOTIFY_MODIFIED_BEARER,
            Self::ApnAmbr(_) => IKEV2_NOTIFY_APN_AMBR,
            Self::ExtendedApnAmbr(_) => IKEV2_NOTIFY_EXTENDED_APN_AMBR,
            Self::ProtocolError(error) => error.notify_message_type(),
        }
    }
}

/// Decode a known TS 24.302 dedicated-bearer Notify.
///
/// Unknown Notify Message Types return `Ok(None)` and remain available to the
/// caller through the original [`Ikev2NotifyPayload`] view.
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerError`] if a known notification has an
/// invalid Protocol ID, SPI, inner length, or typed value.
pub fn decode_ikev2_dedicated_bearer_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Option<Ikev2DedicatedBearerNotify>, Ikev2DedicatedBearerError> {
    let result = match notify.notify_message_type {
        IKEV2_NOTIFY_MULTIPLE_BEARER_PDN_CONNECTIVITY => {
            validate_empty_protocol_spi(&notify)?;
            validate_empty_notification_data(&notify)?;
            Ikev2DedicatedBearerNotify::MultipleBearerPdnConnectivity
        }
        IKEV2_NOTIFY_EPS_QOS => {
            validate_empty_protocol_spi(&notify)?;
            Ikev2DedicatedBearerNotify::EpsQos(Ikev2EpsQos::decode_value(
                decode_length_prefixed_value(&notify)?,
            )?)
        }
        IKEV2_NOTIFY_EXTENDED_EPS_QOS => {
            validate_empty_protocol_spi(&notify)?;
            Ikev2DedicatedBearerNotify::ExtendedEpsQos(Ikev2ExtendedEpsQos::decode_value(
                decode_length_prefixed_value(&notify)?,
            )?)
        }
        IKEV2_NOTIFY_TFT => {
            validate_empty_protocol_spi(&notify)?;
            Ikev2DedicatedBearerNotify::Tft(TrafficFlowTemplate::decode_value(
                decode_length_prefixed_value(&notify)?,
            )?)
        }
        IKEV2_NOTIFY_MODIFIED_BEARER => {
            if notify.protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP {
                return Err(Ikev2DedicatedBearerError::InvalidNotifyProtocolId {
                    expected: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                    actual: notify.protocol_id,
                });
            }
            validate_empty_notification_data(&notify)?;
            Ikev2DedicatedBearerNotify::ModifiedBearer(Ikev2DedicatedBearerEspSpi::decode(
                notify.spi,
            )?)
        }
        IKEV2_NOTIFY_APN_AMBR => {
            validate_empty_protocol_spi(&notify)?;
            Ikev2DedicatedBearerNotify::ApnAmbr(Ikev2ApnAmbr::decode_value(
                decode_length_prefixed_value(&notify)?,
            )?)
        }
        IKEV2_NOTIFY_EXTENDED_APN_AMBR => {
            validate_empty_protocol_spi(&notify)?;
            Ikev2DedicatedBearerNotify::ExtendedApnAmbr(Ikev2ExtendedApnAmbr::decode_value(
                decode_length_prefixed_value(&notify)?,
            )?)
        }
        value => match Ikev2DedicatedBearerProtocolError::from_notify_message_type(value) {
            Some(error) => {
                validate_empty_protocol_spi(&notify)?;
                validate_empty_notification_data(&notify)?;
                Ikev2DedicatedBearerNotify::ProtocolError(error)
            }
            None => return Ok(None),
        },
    };
    Ok(Some(result))
}

/// Build a known TS 24.302 dedicated-bearer Notify payload body entry.
///
/// The returned body excludes the generic IKEv2 payload header and can be
/// passed to [`crate::build_ike_auth_cleartext_payload_chain`].
///
/// # Errors
///
/// Returns [`Ikev2DedicatedBearerError`] if a QoS/AMBR value violates the
/// Release 17 network-to-UE profile, the TFT cannot be encoded, or a one-octet
/// TS 24.302 inner length would overflow.
pub fn build_ikev2_dedicated_bearer_notify(
    value: &Ikev2DedicatedBearerNotify,
) -> Result<Ikev2IkeAuthPayloadBuild, Ikev2DedicatedBearerError> {
    let (protocol_id, spi, notification_data) = match value {
        Ikev2DedicatedBearerNotify::MultipleBearerPdnConnectivity
        | Ikev2DedicatedBearerNotify::ProtocolError(_) => {
            (IKEV2_NOTIFY_PROTOCOL_ID_NONE, Vec::new(), Vec::new())
        }
        Ikev2DedicatedBearerNotify::EpsQos(value) => {
            qos::validate_eps_qos_wire_profile(value)?;
            (
                IKEV2_NOTIFY_PROTOCOL_ID_NONE,
                Vec::new(),
                encode_length_prefixed_value(&value.encode_value())?,
            )
        }
        Ikev2DedicatedBearerNotify::ExtendedEpsQos(value) => {
            qos::validate_extended_eps_qos_wire_profile(*value)?;
            (
                IKEV2_NOTIFY_PROTOCOL_ID_NONE,
                Vec::new(),
                encode_length_prefixed_value(&value.encode_value())?,
            )
        }
        Ikev2DedicatedBearerNotify::Tft(value) => {
            let mut encoded = BytesMut::with_capacity(value.encoded_value_len()?);
            value.encode_value(&mut encoded)?;
            (
                IKEV2_NOTIFY_PROTOCOL_ID_NONE,
                Vec::new(),
                encode_length_prefixed_value(&encoded)?,
            )
        }
        Ikev2DedicatedBearerNotify::ModifiedBearer(spi) => (
            IKEV2_SECURITY_PROTOCOL_ID_ESP,
            spi.to_be_bytes().to_vec(),
            Vec::new(),
        ),
        Ikev2DedicatedBearerNotify::ApnAmbr(value) => {
            qos::validate_apn_ambr_wire_profile(*value)?;
            (
                IKEV2_NOTIFY_PROTOCOL_ID_NONE,
                Vec::new(),
                encode_length_prefixed_value(&value.encode_value())?,
            )
        }
        Ikev2DedicatedBearerNotify::ExtendedApnAmbr(value) => {
            qos::validate_extended_apn_ambr_wire_profile(*value)?;
            (
                IKEV2_NOTIFY_PROTOCOL_ID_NONE,
                Vec::new(),
                encode_length_prefixed_value(&value.encode_value())?,
            )
        }
    };
    let input = Ikev2NotifyPayloadBuild {
        protocol_id,
        spi,
        notify_message_type: value.notify_message_type(),
        notification_data,
    };
    let body = crate::build_ike_auth_notify_payload(&input)
        .map_err(|_| Ikev2DedicatedBearerError::NotifyLengthOverflow)?;
    Ok(Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body,
    })
}

fn validate_qci(qci: u8) -> Result<(), Ikev2DedicatedBearerError> {
    let standardized = matches!(
        qci,
        1..=10 | 65..=67 | 69..=76 | 79..=80 | 82..=85 | 128..=254
    );
    if standardized {
        Ok(())
    } else {
        Err(Ikev2DedicatedBearerError::InvalidQci { value: qci })
    }
}

fn validate_empty_protocol_spi(
    notify: &Ikev2NotifyPayload<'_>,
) -> Result<(), Ikev2DedicatedBearerError> {
    if notify.protocol_id != IKEV2_NOTIFY_PROTOCOL_ID_NONE {
        return Err(Ikev2DedicatedBearerError::InvalidNotifyProtocolId {
            expected: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            actual: notify.protocol_id,
        });
    }
    if notify.spi_size != 0 || !notify.spi.is_empty() {
        return Err(Ikev2DedicatedBearerError::UnexpectedNotifySpi {
            actual: notify.spi.len(),
        });
    }
    Ok(())
}

fn validate_empty_notification_data(
    notify: &Ikev2NotifyPayload<'_>,
) -> Result<(), Ikev2DedicatedBearerError> {
    if notify.notification_data.is_empty() {
        Ok(())
    } else {
        Err(Ikev2DedicatedBearerError::UnexpectedNotificationData {
            actual: notify.notification_data.len(),
        })
    }
}

fn decode_length_prefixed_value<'a>(
    notify: &Ikev2NotifyPayload<'a>,
) -> Result<&'a [u8], Ikev2DedicatedBearerError> {
    let (&declared, value) = notify
        .notification_data
        .split_first()
        .ok_or(Ikev2DedicatedBearerError::MissingInnerLength)?;
    let actual = value.len();
    if usize::from(declared) != actual {
        return Err(Ikev2DedicatedBearerError::InnerLengthMismatch { declared, actual });
    }
    Ok(value)
}

fn encode_length_prefixed_value(value: &[u8]) -> Result<Vec<u8>, Ikev2DedicatedBearerError> {
    let len =
        u8::try_from(value.len()).map_err(|_| Ikev2DedicatedBearerError::InnerLengthOverflow {
            actual: value.len(),
        })?;
    let mut out = Vec::with_capacity(value.len().saturating_add(1));
    out.push(len);
    out.extend_from_slice(value);
    Ok(out)
}

/// Structured, redaction-safe dedicated-bearer codec/exchange error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2DedicatedBearerError {
    /// A known Notify used the wrong Protocol ID.
    InvalidNotifyProtocolId {
        /// Required Protocol ID.
        expected: u8,
        /// Received Protocol ID.
        actual: u8,
    },
    /// A Notify that prohibits an SPI carried one.
    UnexpectedNotifySpi {
        /// Received SPI length.
        actual: usize,
    },
    /// A Notify that prohibits notification data carried it.
    UnexpectedNotificationData {
        /// Received notification-data length.
        actual: usize,
    },
    /// A length-prefixed 3GPP Notify omitted its inner length octet.
    MissingInnerLength,
    /// The 3GPP inner length did not match the remaining value bytes.
    InnerLengthMismatch {
        /// Declared one-octet length.
        declared: u8,
        /// Actual remaining length.
        actual: usize,
    },
    /// The value cannot fit in the 3GPP one-octet inner length.
    InnerLengthOverflow {
        /// Value length.
        actual: usize,
    },
    /// EPS QoS value length was not 1, 5, 9, or 13 octets.
    InvalidEpsQosLength {
        /// Received length.
        actual: usize,
    },
    /// EPS QoS QCI is reserved in the Release 17 network-to-UE profile.
    InvalidQci {
        /// Received QCI.
        value: u8,
    },
    /// An EPS QoS optional tier was present without its predecessor.
    EpsQosTierGap,
    /// A compact QoS/APN-AMBR rate code is reserved or non-canonical for a network sender.
    InvalidQosRateCode {
        /// Rate field containing the invalid code.
        field: Ikev2QosRateField,
        /// Compact-code tier containing the invalid code.
        tier: Ikev2QosRateCodeTier,
        /// Invalid one-octet code.
        value: u8,
    },
    /// A standardized QCI used the wrong GBR/non-GBR wire shape.
    QosResourceProfileMismatch {
        /// Standardized QCI supplied on the wire.
        qci: u8,
        /// Resource type assigned by TS 23.203.
        expected: Ikev2QosResourceType,
        /// Resource type implied by presence or absence of rate octets.
        actual: Ikev2QosResourceType,
    },
    /// Both maximum rates in a GBR EPS QoS value represent zero kbps.
    EpsQosMaximumRatesZero,
    /// A guaranteed EPS bearer rate exceeds its corresponding maximum rate.
    EpsQosGuaranteedRateExceedsMaximum {
        /// Direction containing the invalid relationship.
        direction: Ikev2QosDirection,
    },
    /// A higher compact rate tier was used without saturating its lower tier.
    QosTierSaturationRequired {
        /// Rate field containing the inconsistent tier.
        field: Ikev2QosRateField,
        /// Higher tier that requires saturated lower tiers.
        tier: Ikev2QosRateCodeTier,
    },
    /// Extended EPS QoS value was not ten octets.
    InvalidExtendedEpsQosLength {
        /// Received length.
        actual: usize,
    },
    /// An external extended-rate value used a non-canonical unit code.
    InvalidExtendedQosUnit {
        /// First field governed by the unit code.
        field: Ikev2QosRateField,
        /// Invalid unit code.
        value: u8,
    },
    /// Extended EPS QoS carried no rate above its 10 Gbps threshold.
    ExtendedEpsQosHasNoRates,
    /// Extended APN-AMBR carried no rate above its 65,280 Mbps threshold.
    ExtendedApnAmbrHasNoRates,
    /// A non-zero external rate does not exceed the threshold requiring that IE.
    ExtendedQosRateNotAboveThreshold {
        /// Rate field containing the value.
        field: Ikev2QosRateField,
    },
    /// An external rate was present without the required saturated compact-code sentinel.
    ExtendedQosSentinelRequired {
        /// Rate field whose compact-code tiers are inconsistent.
        field: Ikev2QosRateField,
    },
    /// APN-AMBR value length was not 2, 4, or 6 octets.
    InvalidApnAmbrLength {
        /// Received length.
        actual: usize,
    },
    /// APN-AMBR extended-2 codes were present without extended codes.
    ApnAmbrTierGap,
    /// Extended APN-AMBR value was not six octets.
    InvalidExtendedApnAmbrLength {
        /// Received length.
        actual: usize,
    },
    /// An ESP SPI did not contain four octets.
    InvalidEspSpiLength {
        /// Received SPI length.
        actual: usize,
    },
    /// An ESP SPI was zero.
    ZeroEspSpi,
    /// The generic Notify body length overflowed.
    NotifyLengthOverflow,
    /// Canonical TFT decode/validation/encode failed.
    Tft(TftError),
}

impl Ikev2DedicatedBearerError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidNotifyProtocolId { .. } => "ikev2_3gpp_notify_protocol_id_invalid",
            Self::UnexpectedNotifySpi { .. } => "ikev2_3gpp_notify_spi_unexpected",
            Self::UnexpectedNotificationData { .. } => "ikev2_3gpp_notify_data_unexpected",
            Self::MissingInnerLength => "ikev2_3gpp_notify_inner_length_missing",
            Self::InnerLengthMismatch { .. } => "ikev2_3gpp_notify_inner_length_mismatch",
            Self::InnerLengthOverflow { .. } => "ikev2_3gpp_notify_inner_length_overflow",
            Self::InvalidEpsQosLength { .. } => "ikev2_3gpp_eps_qos_length_invalid",
            Self::InvalidQci { .. } => "ikev2_3gpp_eps_qos_qci_invalid",
            Self::EpsQosTierGap => "ikev2_3gpp_eps_qos_tier_gap",
            Self::InvalidQosRateCode { .. } => "ikev2_3gpp_qos_rate_code_invalid",
            Self::QosResourceProfileMismatch { .. } => "ikev2_3gpp_qos_resource_profile_mismatch",
            Self::EpsQosMaximumRatesZero => "ikev2_3gpp_eps_qos_maximum_rates_zero",
            Self::EpsQosGuaranteedRateExceedsMaximum { .. } => {
                "ikev2_3gpp_eps_qos_guaranteed_exceeds_maximum"
            }
            Self::QosTierSaturationRequired { .. } => "ikev2_3gpp_qos_tier_saturation_required",
            Self::InvalidExtendedEpsQosLength { .. } => {
                "ikev2_3gpp_extended_eps_qos_length_invalid"
            }
            Self::InvalidExtendedQosUnit { .. } => "ikev2_3gpp_extended_qos_unit_invalid",
            Self::ExtendedEpsQosHasNoRates => "ikev2_3gpp_extended_eps_qos_rates_missing",
            Self::ExtendedApnAmbrHasNoRates => "ikev2_3gpp_extended_apn_ambr_rates_missing",
            Self::ExtendedQosRateNotAboveThreshold { .. } => {
                "ikev2_3gpp_extended_qos_rate_below_threshold"
            }
            Self::ExtendedQosSentinelRequired { .. } => "ikev2_3gpp_extended_qos_sentinel_required",
            Self::InvalidApnAmbrLength { .. } => "ikev2_3gpp_apn_ambr_length_invalid",
            Self::ApnAmbrTierGap => "ikev2_3gpp_apn_ambr_tier_gap",
            Self::InvalidExtendedApnAmbrLength { .. } => {
                "ikev2_3gpp_extended_apn_ambr_length_invalid"
            }
            Self::InvalidEspSpiLength { .. } => "ikev2_3gpp_esp_spi_length_invalid",
            Self::ZeroEspSpi => "ikev2_3gpp_esp_spi_zero",
            Self::NotifyLengthOverflow => "ikev2_3gpp_notify_length_overflow",
            Self::Tft(_) => "ikev2_3gpp_tft_invalid",
        }
    }
}

impl fmt::Display for Ikev2DedicatedBearerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2DedicatedBearerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tft(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TftError> for Ikev2DedicatedBearerError {
    fn from(value: TftError) -> Self {
        Self::Tft(value)
    }
}
