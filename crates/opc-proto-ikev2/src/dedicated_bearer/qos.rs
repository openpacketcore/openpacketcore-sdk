//! Checked conversion from product-neutral integer kbps into TS 24.301 QoS values.
//!
//! TS 24.301 defines a non-linear, discrete bit-rate grid. It requires the
//! network to map rates that are not explicitly represented onto an explicit
//! value, but it does not prescribe which explicit value to choose. This
//! module therefore makes that policy explicit: [`Ikev2QosQuantization::Exact`]
//! rejects a non-representable input and [`Ikev2QosQuantization::Ceiling`]
//! selects the smallest representable value that is not below the input.

use core::fmt;
use std::error::Error;

use super::{
    Ikev2ApnAmbr, Ikev2ApnAmbrRateCodes, Ikev2DedicatedBearerError, Ikev2EpsQos,
    Ikev2EpsQosRateCodes, Ikev2ExtendedApnAmbr, Ikev2ExtendedBitRateUnit, Ikev2ExtendedEpsQos,
};

const EPS_EXTENDED_THRESHOLD_KBPS: u64 = 10_000_000;
const APN_EXTENDED_THRESHOLD_KBPS: u64 = 65_280_000;
const BASE_MAX_KBPS: u64 = 8_640;
const EXTENDED_MAX_KBPS: u64 = 256_000;
const APN_EXTENDED_2_INCREMENT_KBPS: u64 = 256_000;

// TS 24.301 tables 9.9.4.30.1 and 9.9.4.29.1 use decimal SI units.
const EXTENDED_UNIT_KBPS: [u64; 21] = [
    200,
    1_000,
    4_000,
    16_000,
    64_000,
    256_000,
    1_000_000,
    4_000_000,
    16_000_000,
    64_000_000,
    256_000_000,
    1_000_000_000,
    4_000_000_000,
    16_000_000_000,
    64_000_000_000,
    256_000_000_000,
    1_000_000_000_000,
    4_000_000_000_000,
    16_000_000_000_000,
    64_000_000_000_000,
    256_000_000_000_000,
];

/// Policy used when an integer kbps value is between TS 24.301 grid points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2QosQuantization {
    /// Require the requested rate to be exactly representable.
    Exact,
    /// Select the smallest representable rate greater than or equal to the input.
    ///
    /// This is an SDK policy, not a rounding direction mandated by TS 24.301.
    Ceiling,
}

/// GBR classification carried by a QCI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2QosResourceType {
    /// Guaranteed-bit-rate bearer.
    Gbr,
    /// Non-guaranteed-bit-rate bearer.
    NonGbr,
}

/// Direction used by a structured QoS validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2QosDirection {
    /// Uplink direction.
    Uplink,
    /// Downlink direction.
    Downlink,
}

/// Rate field used by a structured QoS mapping error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2QosRateField {
    /// Maximum uplink bearer bit rate.
    MaximumUplink,
    /// Maximum downlink bearer bit rate.
    MaximumDownlink,
    /// Guaranteed uplink bearer bit rate.
    GuaranteedUplink,
    /// Guaranteed downlink bearer bit rate.
    GuaranteedDownlink,
    /// Downlink APN aggregate maximum bit rate.
    ApnAmbrDownlink,
    /// Uplink APN aggregate maximum bit rate.
    ApnAmbrUplink,
}

/// Four integer-kbps rates for a GBR bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2EpsBearerBitRatesKbps {
    /// Maximum uplink bit rate in kbps.
    pub maximum_uplink: u64,
    /// Maximum downlink bit rate in kbps.
    pub maximum_downlink: u64,
    /// Guaranteed uplink bit rate in kbps.
    pub guaranteed_uplink: u64,
    /// Guaranteed downlink bit rate in kbps.
    pub guaranteed_downlink: u64,
}

/// Product-neutral EPS QoS input expressed in integer kbps.
///
/// The variant makes the GBR/non-GBR resource type explicit. This is required
/// for operator-specific QCIs 128 through 254, whose resource type cannot be
/// inferred from the QCI number. Standardized QCIs are checked against the
/// resource type assigned by TS 23.203.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2EpsQosKbps {
    /// A GBR bearer with all four network-provided rate fields.
    Gbr {
        /// QoS Class Identifier.
        qci: u8,
        /// Maximum and guaranteed bit rates.
        rates: Ikev2EpsBearerBitRatesKbps,
    },
    /// A non-GBR bearer, for which TS 24.301 says rate fields are ignored.
    NonGbr {
        /// QoS Class Identifier.
        qci: u8,
    },
}

impl Ikev2EpsQosKbps {
    const fn qci(self) -> u8 {
        match self {
            Self::Gbr { qci, .. } | Self::NonGbr { qci } => qci,
        }
    }

    const fn resource_type(self) -> Ikev2QosResourceType {
        match self {
            Self::Gbr { .. } => Ikev2QosResourceType::Gbr,
            Self::NonGbr { .. } => Ikev2QosResourceType::NonGbr,
        }
    }
}

/// APN-AMBR input expressed in integer kbps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2ApnAmbrKbps {
    /// Downlink APN-AMBR in kbps.
    pub downlink: u64,
    /// Uplink APN-AMBR in kbps.
    pub uplink: u64,
}

/// Encoded EPS QoS values and the exact rates represented on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2EpsQosMapping {
    eps_qos: Ikev2EpsQos,
    extended_eps_qos: Option<Ikev2ExtendedEpsQos>,
    represented_rates: Option<Ikev2EpsBearerBitRatesKbps>,
}

impl Ikev2EpsQosMapping {
    /// Map integer-kbps bearer QoS into the TS 24.301 EPS QoS values.
    ///
    /// For a GBR bearer this emits all four normal rate-code octets at every
    /// required tier. A companion field that does not need a higher tier uses
    /// zero in that tier as required by TS 24.301. Rates above 10 Gbps also
    /// produce an Extended EPS QoS value; rates at or below 10 Gbps in the same
    /// unit-sharing pair use a zero multiplier.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2QosMappingError`] for an unsupported QCI, a standardized
    /// QCI/resource mismatch, invalid GBR rate relationships, an exact value
    /// that is not on the TS 24.301 grid, or a rate outside the representable
    /// extended range.
    pub fn from_kbps(
        input: Ikev2EpsQosKbps,
        quantization: Ikev2QosQuantization,
    ) -> Result<Self, Ikev2QosMappingError> {
        let qci = input.qci();
        validate_qci_resource(qci, input.resource_type())?;

        let rates = match input {
            Ikev2EpsQosKbps::NonGbr { .. } => {
                let eps_qos =
                    Ikev2EpsQos::new(qci, None, None, None).map_err(Ikev2QosMappingError::Codec)?;
                return Ok(Self {
                    eps_qos,
                    extended_eps_qos: None,
                    represented_rates: None,
                });
            }
            Ikev2EpsQosKbps::Gbr { rates, .. } => rates,
        };

        validate_gbr_rates(rates)?;
        let fields = [
            (Ikev2QosRateField::MaximumUplink, rates.maximum_uplink),
            (Ikev2QosRateField::MaximumDownlink, rates.maximum_downlink),
            (Ikev2QosRateField::GuaranteedUplink, rates.guaranteed_uplink),
            (
                Ikev2QosRateField::GuaranteedDownlink,
                rates.guaranteed_downlink,
            ),
        ];
        let mut encoded = [EncodedEpsRate::ZERO; 4];
        for (index, (field, rate)) in fields.into_iter().enumerate() {
            encoded[index] = encode_eps_rate(rate, field, quantization)?;
        }

        let include_extended = encoded.iter().any(|value| value.extended != 0);
        let include_extended_2 = encoded.iter().any(|value| value.extended_2 != 0);
        let base_rates = Some(rate_codes(&encoded, RateCodeTier::Base));
        let extended_rates = include_extended.then(|| rate_codes(&encoded, RateCodeTier::Extended));
        let extended_2_rates =
            include_extended_2.then(|| rate_codes(&encoded, RateCodeTier::Extended2));
        let eps_qos = Ikev2EpsQos::new(qci, base_rates, extended_rates, extended_2_rates)
            .map_err(Ikev2QosMappingError::Codec)?;

        let mut represented = Ikev2EpsBearerBitRatesKbps {
            maximum_uplink: encoded[0].represented_kbps,
            maximum_downlink: encoded[1].represented_kbps,
            guaranteed_uplink: encoded[2].represented_kbps,
            guaranteed_downlink: encoded[3].represented_kbps,
        };
        let extended_eps_qos = if rates_need_extended_eps(rates) {
            let maximum = encode_extended_pair(
                rates.maximum_uplink,
                rates.maximum_downlink,
                Ikev2QosRateField::MaximumUplink,
                Ikev2QosRateField::MaximumDownlink,
                EPS_EXTENDED_THRESHOLD_KBPS,
                1,
                quantization,
            )?;
            let guaranteed = encode_extended_pair(
                rates.guaranteed_uplink,
                rates.guaranteed_downlink,
                Ikev2QosRateField::GuaranteedUplink,
                Ikev2QosRateField::GuaranteedDownlink,
                EPS_EXTENDED_THRESHOLD_KBPS,
                1,
                quantization,
            )?;
            if let Some(value) = maximum.left_represented {
                represented.maximum_uplink = value;
            }
            if let Some(value) = maximum.right_represented {
                represented.maximum_downlink = value;
            }
            if let Some(value) = guaranteed.left_represented {
                represented.guaranteed_uplink = value;
            }
            if let Some(value) = guaranteed.right_represented {
                represented.guaranteed_downlink = value;
            }
            Some(Ikev2ExtendedEpsQos {
                maximum_unit: Ikev2ExtendedBitRateUnit::new(maximum.unit),
                maximum_uplink: maximum.left_multiplier,
                maximum_downlink: maximum.right_multiplier,
                guaranteed_unit: Ikev2ExtendedBitRateUnit::new(guaranteed.unit),
                guaranteed_uplink: guaranteed.left_multiplier,
                guaranteed_downlink: guaranteed.right_multiplier,
            })
        } else {
            None
        };

        Ok(Self {
            eps_qos,
            extended_eps_qos,
            represented_rates: Some(represented),
        })
    }

    /// Normal EPS QoS value to place in the EPS_QOS Notify.
    pub const fn eps_qos(&self) -> &Ikev2EpsQos {
        &self.eps_qos
    }

    /// Extended EPS QoS value required when any input rate exceeds 10 Gbps.
    pub const fn extended_eps_qos(&self) -> Option<Ikev2ExtendedEpsQos> {
        self.extended_eps_qos
    }

    /// Exact kbps values represented by the emitted fields.
    ///
    /// This is `None` for non-GBR QoS, because TS 24.301 ignores bearer rates
    /// for non-GBR QCIs.
    pub const fn represented_rates(&self) -> Option<Ikev2EpsBearerBitRatesKbps> {
        self.represented_rates
    }
}

/// Encoded APN-AMBR values and the exact rates represented on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2ApnAmbrMapping {
    apn_ambr: Ikev2ApnAmbr,
    extended_apn_ambr: Option<Ikev2ExtendedApnAmbr>,
    represented_rates: Ikev2ApnAmbrKbps,
}

impl Ikev2ApnAmbrMapping {
    /// Map integer-kbps APN-AMBR into TS 24.301 normal and extended values.
    ///
    /// A rate above 65,280 Mbps uses the normal sentinel plus Extended
    /// APN-AMBR. If only one direction exceeds that threshold, the other
    /// direction's extended unit and multiplier are both zero.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2QosMappingError`] when exact mapping is requested for a
    /// value between grid points or a value exceeds the extended range.
    pub fn from_kbps(
        input: Ikev2ApnAmbrKbps,
        quantization: Ikev2QosQuantization,
    ) -> Result<Self, Ikev2QosMappingError> {
        let downlink = encode_apn_rate(
            input.downlink,
            Ikev2QosRateField::ApnAmbrDownlink,
            quantization,
        )?;
        let uplink = encode_apn_rate(input.uplink, Ikev2QosRateField::ApnAmbrUplink, quantization)?;
        let include_extended = downlink.extended != 0 || uplink.extended != 0;
        let include_extended_2 = downlink.extended_2 != 0 || uplink.extended_2 != 0;
        let apn_ambr = Ikev2ApnAmbr::new(
            Ikev2ApnAmbrRateCodes {
                downlink: downlink.base,
                uplink: uplink.base,
            },
            include_extended.then_some(Ikev2ApnAmbrRateCodes {
                downlink: downlink.extended,
                uplink: uplink.extended,
            }),
            include_extended_2.then_some(Ikev2ApnAmbrRateCodes {
                downlink: downlink.extended_2,
                uplink: uplink.extended_2,
            }),
        )
        .map_err(Ikev2QosMappingError::Codec)?;

        let mut represented_rates = Ikev2ApnAmbrKbps {
            downlink: downlink.represented_kbps,
            uplink: uplink.represented_kbps,
        };
        let extended_apn_ambr = if input.downlink > APN_EXTENDED_THRESHOLD_KBPS
            || input.uplink > APN_EXTENDED_THRESHOLD_KBPS
        {
            let downlink_extended = encode_extended_direction(
                input.downlink,
                Ikev2QosRateField::ApnAmbrDownlink,
                APN_EXTENDED_THRESHOLD_KBPS,
                3,
                quantization,
            )?;
            let uplink_extended = encode_extended_direction(
                input.uplink,
                Ikev2QosRateField::ApnAmbrUplink,
                APN_EXTENDED_THRESHOLD_KBPS,
                3,
                quantization,
            )?;
            if let Some(value) = downlink_extended.represented {
                represented_rates.downlink = value;
            }
            if let Some(value) = uplink_extended.represented {
                represented_rates.uplink = value;
            }
            Some(Ikev2ExtendedApnAmbr {
                downlink_unit: Ikev2ExtendedBitRateUnit::new(downlink_extended.unit),
                downlink: downlink_extended.multiplier,
                uplink_unit: Ikev2ExtendedBitRateUnit::new(uplink_extended.unit),
                uplink: uplink_extended.multiplier,
            })
        } else {
            None
        };

        Ok(Self {
            apn_ambr,
            extended_apn_ambr,
            represented_rates,
        })
    }

    /// Normal APN-AMBR value to place in the APN_AMBR Notify.
    pub const fn apn_ambr(self) -> Ikev2ApnAmbr {
        self.apn_ambr
    }

    /// Extended APN-AMBR value required above 65,280 Mbps.
    pub const fn extended_apn_ambr(self) -> Option<Ikev2ExtendedApnAmbr> {
        self.extended_apn_ambr
    }

    /// Exact downlink/uplink kbps values represented by the emitted fields.
    pub const fn represented_rates(self) -> Ikev2ApnAmbrKbps {
        self.represented_rates
    }
}

/// Structured error from checked TS 24.301 bit-rate mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2QosMappingError {
    /// The QCI is reserved or unsupported by the Release 18 profile.
    UnsupportedQci {
        /// QCI supplied by the caller.
        qci: u8,
    },
    /// A standardized QCI was paired with the wrong resource type.
    StandardizedQciResourceMismatch {
        /// Standardized QCI supplied by the caller.
        qci: u8,
        /// Resource type assigned by TS 23.203.
        expected: Ikev2QosResourceType,
        /// Resource type selected by the caller's input variant.
        actual: Ikev2QosResourceType,
    },
    /// Both maximum rates in a GBR request were zero.
    ZeroMaximumRates,
    /// A guaranteed rate exceeded its maximum in the same direction.
    GuaranteedRateExceedsMaximum {
        /// Direction containing the invalid relationship.
        direction: Ikev2QosDirection,
        /// Maximum rate supplied by the caller.
        maximum_kbps: u64,
        /// Guaranteed rate supplied by the caller.
        guaranteed_kbps: u64,
    },
    /// Exact quantization was requested for a value between grid points.
    NotExactlyRepresentable {
        /// Field that cannot represent the value exactly.
        field: Ikev2QosRateField,
        /// Requested integer-kbps value.
        requested_kbps: u64,
    },
    /// The requested value exceeds the largest extended representation.
    RateOutOfRange {
        /// Field whose rate exceeds the representation.
        field: Ikev2QosRateField,
        /// Requested integer-kbps value.
        requested_kbps: u64,
    },
    /// An invariant in the underlying typed Notify codec was rejected.
    Codec(Ikev2DedicatedBearerError),
}

impl Ikev2QosMappingError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnsupportedQci { .. } => "ikev2_qos_qci_unsupported",
            Self::StandardizedQciResourceMismatch { .. } => "ikev2_qos_qci_resource_mismatch",
            Self::ZeroMaximumRates => "ikev2_qos_maximum_rates_zero",
            Self::GuaranteedRateExceedsMaximum { .. } => "ikev2_qos_guaranteed_exceeds_maximum",
            Self::NotExactlyRepresentable { .. } => "ikev2_qos_rate_not_exact",
            Self::RateOutOfRange { .. } => "ikev2_qos_rate_out_of_range",
            Self::Codec(_) => "ikev2_qos_codec_invariant",
        }
    }
}

impl fmt::Display for Ikev2QosMappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2QosMappingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodedEpsRate {
    base: u8,
    extended: u8,
    extended_2: u8,
    represented_kbps: u64,
}

impl EncodedEpsRate {
    const ZERO: Self = Self {
        base: 255,
        extended: 0,
        extended_2: 0,
        represented_kbps: 0,
    };
}

#[derive(Debug, Clone, Copy)]
enum RateCodeTier {
    Base,
    Extended,
    Extended2,
}

#[derive(Debug, Clone, Copy)]
struct EncodedExtendedPair {
    unit: u8,
    left_multiplier: u16,
    right_multiplier: u16,
    left_represented: Option<u64>,
    right_represented: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct EncodedExtendedDirection {
    unit: u8,
    multiplier: u16,
    represented: Option<u64>,
}

fn validate_qci_resource(
    qci: u8,
    actual: Ikev2QosResourceType,
) -> Result<(), Ikev2QosMappingError> {
    let expected = match qci {
        1..=4 | 65..=67 | 71..=76 | 82..=85 => Some(Ikev2QosResourceType::Gbr),
        5..=10 | 69..=70 | 79..=80 => Some(Ikev2QosResourceType::NonGbr),
        128..=254 => None,
        _ => return Err(Ikev2QosMappingError::UnsupportedQci { qci }),
    };
    match expected {
        Some(expected) if expected != actual => {
            Err(Ikev2QosMappingError::StandardizedQciResourceMismatch {
                qci,
                expected,
                actual,
            })
        }
        _ => Ok(()),
    }
}

fn validate_gbr_rates(rates: Ikev2EpsBearerBitRatesKbps) -> Result<(), Ikev2QosMappingError> {
    if rates.maximum_uplink == 0 && rates.maximum_downlink == 0 {
        return Err(Ikev2QosMappingError::ZeroMaximumRates);
    }
    for (direction, maximum, guaranteed) in [
        (
            Ikev2QosDirection::Uplink,
            rates.maximum_uplink,
            rates.guaranteed_uplink,
        ),
        (
            Ikev2QosDirection::Downlink,
            rates.maximum_downlink,
            rates.guaranteed_downlink,
        ),
    ] {
        if guaranteed > maximum {
            return Err(Ikev2QosMappingError::GuaranteedRateExceedsMaximum {
                direction,
                maximum_kbps: maximum,
                guaranteed_kbps: guaranteed,
            });
        }
    }
    Ok(())
}

fn rates_need_extended_eps(rates: Ikev2EpsBearerBitRatesKbps) -> bool {
    rates.maximum_uplink > EPS_EXTENDED_THRESHOLD_KBPS
        || rates.maximum_downlink > EPS_EXTENDED_THRESHOLD_KBPS
        || rates.guaranteed_uplink > EPS_EXTENDED_THRESHOLD_KBPS
        || rates.guaranteed_downlink > EPS_EXTENDED_THRESHOLD_KBPS
}

fn rate_codes(encoded: &[EncodedEpsRate; 4], tier: RateCodeTier) -> Ikev2EpsQosRateCodes {
    let value = |index: usize| match tier {
        RateCodeTier::Base => encoded[index].base,
        RateCodeTier::Extended => encoded[index].extended,
        RateCodeTier::Extended2 => encoded[index].extended_2,
    };
    Ikev2EpsQosRateCodes {
        maximum_uplink: value(0),
        maximum_downlink: value(1),
        guaranteed_uplink: value(2),
        guaranteed_downlink: value(3),
    }
}

fn encode_eps_rate(
    requested_kbps: u64,
    field: Ikev2QosRateField,
    quantization: Ikev2QosQuantization,
) -> Result<EncodedEpsRate, Ikev2QosMappingError> {
    if requested_kbps == 0 {
        return Ok(EncodedEpsRate::ZERO);
    }
    if requested_kbps <= BASE_MAX_KBPS {
        let (base, represented_kbps) =
            select_grid(requested_kbps, field, quantization, 1..=254, base_rate)?;
        return Ok(EncodedEpsRate {
            base,
            extended: 0,
            extended_2: 0,
            represented_kbps,
        });
    }
    if requested_kbps <= EXTENDED_MAX_KBPS {
        let (extended, represented_kbps) =
            select_grid(requested_kbps, field, quantization, 1..=250, extended_rate)?;
        return Ok(EncodedEpsRate {
            base: 254,
            extended,
            extended_2: 0,
            represented_kbps,
        });
    }
    if requested_kbps <= EPS_EXTENDED_THRESHOLD_KBPS {
        let (extended_2, represented_kbps) = select_grid(
            requested_kbps,
            field,
            quantization,
            1..=246,
            extended_2_rate,
        )?;
        return Ok(EncodedEpsRate {
            base: 254,
            extended: 250,
            extended_2,
            represented_kbps,
        });
    }
    Ok(EncodedEpsRate {
        base: 254,
        extended: 250,
        extended_2: 246,
        represented_kbps: EPS_EXTENDED_THRESHOLD_KBPS,
    })
}

fn encode_apn_rate(
    requested_kbps: u64,
    field: Ikev2QosRateField,
    quantization: Ikev2QosQuantization,
) -> Result<EncodedEpsRate, Ikev2QosMappingError> {
    if requested_kbps <= EXTENDED_MAX_KBPS {
        return encode_eps_rate(requested_kbps, field, quantization);
    }
    if requested_kbps > APN_EXTENDED_THRESHOLD_KBPS {
        return Ok(EncodedEpsRate {
            base: 254,
            extended: 250,
            extended_2: 254,
            represented_kbps: APN_EXTENDED_THRESHOLD_KBPS,
        });
    }

    let mut selected: Option<EncodedEpsRate> = None;
    for extended_2 in 1_u8..=254 {
        let increment = u64::from(extended_2) * APN_EXTENDED_2_INCREMENT_KBPS;
        let lower_requested = requested_kbps.saturating_sub(increment).max(BASE_MAX_KBPS);
        if lower_requested > EXTENDED_MAX_KBPS {
            continue;
        }
        let lower = encode_eps_rate(lower_requested, field, Ikev2QosQuantization::Ceiling)?;
        let represented_kbps = increment.saturating_add(lower.represented_kbps);
        if represented_kbps < requested_kbps || represented_kbps > APN_EXTENDED_THRESHOLD_KBPS {
            continue;
        }
        let candidate = EncodedEpsRate {
            base: lower.base,
            extended: lower.extended,
            extended_2,
            represented_kbps,
        };
        if selected
            .as_ref()
            .is_none_or(|current| candidate.represented_kbps < current.represented_kbps)
        {
            selected = Some(candidate);
        }
    }
    let selected = selected.ok_or(Ikev2QosMappingError::RateOutOfRange {
        field,
        requested_kbps,
    })?;
    if quantization == Ikev2QosQuantization::Exact && selected.represented_kbps != requested_kbps {
        return Err(Ikev2QosMappingError::NotExactlyRepresentable {
            field,
            requested_kbps,
        });
    }
    Ok(selected)
}

fn select_grid(
    requested_kbps: u64,
    field: Ikev2QosRateField,
    quantization: Ikev2QosQuantization,
    codes: core::ops::RangeInclusive<u8>,
    decode: fn(u8) -> u64,
) -> Result<(u8, u64), Ikev2QosMappingError> {
    for code in codes {
        let represented_kbps = decode(code);
        if represented_kbps >= requested_kbps {
            if quantization == Ikev2QosQuantization::Exact && represented_kbps != requested_kbps {
                return Err(Ikev2QosMappingError::NotExactlyRepresentable {
                    field,
                    requested_kbps,
                });
            }
            return Ok((code, represented_kbps));
        }
    }
    Err(Ikev2QosMappingError::RateOutOfRange {
        field,
        requested_kbps,
    })
}

const fn base_rate(code: u8) -> u64 {
    match code {
        1..=63 => code as u64,
        64..=127 => 64 + ((code as u64) - 64) * 8,
        128..=254 => 576 + ((code as u64) - 128) * 64,
        _ => 0,
    }
}

const fn extended_rate(code: u8) -> u64 {
    match code {
        1..=74 => 8_600 + (code as u64) * 100,
        75..=186 => ((code as u64) - 58) * 1_000,
        187..=250 => ((code as u64) - 122) * 2_000,
        _ => 0,
    }
}

const fn extended_2_rate(code: u8) -> u64 {
    match code {
        1..=61 => 256_000 + (code as u64) * 4_000,
        62..=161 => ((code as u64) - 11) * 10_000,
        162..=246 => ((code as u64) - 146) * 100_000,
        _ => 0,
    }
}

fn encode_extended_pair(
    left: u64,
    right: u64,
    left_field: Ikev2QosRateField,
    right_field: Ikev2QosRateField,
    threshold: u64,
    first_unit: u8,
    quantization: Ikev2QosQuantization,
) -> Result<EncodedExtendedPair, Ikev2QosMappingError> {
    if left <= threshold && right <= threshold {
        return Ok(EncodedExtendedPair {
            unit: 0,
            left_multiplier: 0,
            right_multiplier: 0,
            left_represented: None,
            right_represented: None,
        });
    }
    for unit_code in first_unit..=21 {
        let unit = unit_kbps(unit_code).ok_or(Ikev2QosMappingError::RateOutOfRange {
            field: left_field,
            requested_kbps: left,
        })?;
        let left_encoded = encode_multiplier(left, left_field, threshold, unit, quantization)?;
        let right_encoded = encode_multiplier(right, right_field, threshold, unit, quantization)?;
        if let (
            Some((left_multiplier, left_represented)),
            Some((right_multiplier, right_represented)),
        ) = (left_encoded, right_encoded)
        {
            return Ok(EncodedExtendedPair {
                unit: unit_code,
                left_multiplier,
                right_multiplier,
                left_represented,
                right_represented,
            });
        }
    }
    let (field, requested_kbps) = if left >= right {
        (left_field, left)
    } else {
        (right_field, right)
    };
    Err(match quantization {
        Ikev2QosQuantization::Exact => Ikev2QosMappingError::NotExactlyRepresentable {
            field,
            requested_kbps,
        },
        Ikev2QosQuantization::Ceiling => Ikev2QosMappingError::RateOutOfRange {
            field,
            requested_kbps,
        },
    })
}

fn encode_extended_direction(
    value: u64,
    field: Ikev2QosRateField,
    threshold: u64,
    first_unit: u8,
    quantization: Ikev2QosQuantization,
) -> Result<EncodedExtendedDirection, Ikev2QosMappingError> {
    if value <= threshold {
        return Ok(EncodedExtendedDirection {
            unit: 0,
            multiplier: 0,
            represented: None,
        });
    }
    for unit_code in first_unit..=21 {
        let unit = unit_kbps(unit_code).ok_or(Ikev2QosMappingError::RateOutOfRange {
            field,
            requested_kbps: value,
        })?;
        if let Some((multiplier, represented)) = encode_one_multiplier(value, unit, quantization) {
            return Ok(EncodedExtendedDirection {
                unit: unit_code,
                multiplier,
                represented: Some(represented),
            });
        }
    }
    Err(match quantization {
        Ikev2QosQuantization::Exact => Ikev2QosMappingError::NotExactlyRepresentable {
            field,
            requested_kbps: value,
        },
        Ikev2QosQuantization::Ceiling => Ikev2QosMappingError::RateOutOfRange {
            field,
            requested_kbps: value,
        },
    })
}

fn encode_multiplier(
    value: u64,
    _field: Ikev2QosRateField,
    threshold: u64,
    unit: u64,
    quantization: Ikev2QosQuantization,
) -> Result<Option<(u16, Option<u64>)>, Ikev2QosMappingError> {
    if value <= threshold {
        return Ok(Some((0, None)));
    }
    Ok(encode_one_multiplier(value, unit, quantization)
        .map(|(multiplier, represented)| (multiplier, Some(represented))))
}

fn encode_one_multiplier(
    value: u64,
    unit: u64,
    quantization: Ikev2QosQuantization,
) -> Option<(u16, u64)> {
    let quotient = match quantization {
        Ikev2QosQuantization::Exact if !value.is_multiple_of(unit) => return None,
        Ikev2QosQuantization::Exact => value / unit,
        Ikev2QosQuantization::Ceiling => value / unit + u64::from(!value.is_multiple_of(unit)),
    };
    let multiplier = u16::try_from(quotient).ok()?;
    Some((multiplier, quotient.saturating_mul(unit)))
}

fn unit_kbps(code: u8) -> Option<u64> {
    let index = usize::from(code.checked_sub(1)?);
    EXTENDED_UNIT_KBPS.get(index).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn must_map_eps(
        rates: Ikev2EpsBearerBitRatesKbps,
        quantization: Ikev2QosQuantization,
    ) -> Ikev2EpsQosMapping {
        match Ikev2EpsQosMapping::from_kbps(Ikev2EpsQosKbps::Gbr { qci: 1, rates }, quantization) {
            Ok(value) => value,
            Err(error) => panic!("EPS QoS mapping failed: {error:?}"),
        }
    }

    fn uniform_rates(value: u64) -> Ikev2EpsBearerBitRatesKbps {
        Ikev2EpsBearerBitRatesKbps {
            maximum_uplink: value,
            maximum_downlink: value,
            guaranteed_uplink: value,
            guaranteed_downlink: value,
        }
    }

    #[test]
    fn eps_grid_boundaries_and_gaps_use_documented_ceiling() {
        let cases = [
            (1, 1),
            (63, 63),
            (64, 64),
            (568, 568),
            (569, 576),
            (576, 576),
            (8_640, 8_640),
            (8_641, 8_700),
            (8_700, 8_700),
            (16_000, 16_000),
            (16_001, 17_000),
            (17_000, 17_000),
            (128_000, 128_000),
            (128_001, 130_000),
            (130_000, 130_000),
            (256_000, 256_000),
            (256_001, 260_000),
            (260_000, 260_000),
            (500_000, 500_000),
            (500_001, 510_000),
            (510_000, 510_000),
            (1_500_000, 1_500_000),
            (1_500_001, 1_600_000),
            (1_600_000, 1_600_000),
            (10_000_000, 10_000_000),
            (10_000_001, 10_000_200),
        ];
        for (requested, expected) in cases {
            let mapped = must_map_eps(uniform_rates(requested), Ikev2QosQuantization::Ceiling);
            assert_eq!(
                mapped.represented_rates(),
                Some(uniform_rates(expected)),
                "requested {requested}"
            );
            let exact = Ikev2EpsQosMapping::from_kbps(
                Ikev2EpsQosKbps::Gbr {
                    qci: 1,
                    rates: uniform_rates(requested),
                },
                Ikev2QosQuantization::Exact,
            );
            if requested == expected {
                assert!(exact.is_ok(), "exact boundary {requested}");
            } else {
                assert_eq!(
                    exact,
                    Err(Ikev2QosMappingError::NotExactlyRepresentable {
                        field: Ikev2QosRateField::MaximumUplink,
                        requested_kbps: requested,
                    }),
                    "exact gap {requested}"
                );
            }
        }
    }

    #[test]
    fn zero_uses_network_zero_code_and_gbr_maximum_cannot_both_be_zero() {
        let rates = Ikev2EpsBearerBitRatesKbps {
            maximum_uplink: 1,
            maximum_downlink: 0,
            guaranteed_uplink: 0,
            guaranteed_downlink: 0,
        };
        let mapped = must_map_eps(rates, Ikev2QosQuantization::Exact);
        let base = match mapped.eps_qos().base_rates() {
            Some(value) => value,
            None => panic!("GBR mapping omitted base rates"),
        };
        assert_eq!(base.maximum_downlink, 255);
        assert_eq!(base.guaranteed_uplink, 255);
        assert_eq!(base.guaranteed_downlink, 255);

        assert_eq!(
            Ikev2EpsQosMapping::from_kbps(
                Ikev2EpsQosKbps::Gbr {
                    qci: 1,
                    rates: uniform_rates(0),
                },
                Ikev2QosQuantization::Exact,
            ),
            Err(Ikev2QosMappingError::ZeroMaximumRates)
        );
    }

    #[test]
    fn normal_eps_tiers_use_zero_for_lower_tier_companions() {
        let mapped = must_map_eps(
            Ikev2EpsBearerBitRatesKbps {
                maximum_uplink: 256_001,
                maximum_downlink: 63,
                guaranteed_uplink: 8_641,
                guaranteed_downlink: 1,
            },
            Ikev2QosQuantization::Ceiling,
        );
        assert_eq!(
            mapped.eps_qos().extended_rates(),
            Some(Ikev2EpsQosRateCodes {
                maximum_uplink: 250,
                maximum_downlink: 0,
                guaranteed_uplink: 1,
                guaranteed_downlink: 0,
            })
        );
        assert_eq!(
            mapped.eps_qos().extended_2_rates(),
            Some(Ikev2EpsQosRateCodes {
                maximum_uplink: 1,
                maximum_downlink: 0,
                guaranteed_uplink: 0,
                guaranteed_downlink: 0,
            })
        );
    }

    #[test]
    fn exact_rejects_gaps_and_ceiling_reports_represented_value() {
        assert_eq!(
            Ikev2EpsQosMapping::from_kbps(
                Ikev2EpsQosKbps::Gbr {
                    qci: 1,
                    rates: uniform_rates(569),
                },
                Ikev2QosQuantization::Exact,
            ),
            Err(Ikev2QosMappingError::NotExactlyRepresentable {
                field: Ikev2QosRateField::MaximumUplink,
                requested_kbps: 569,
            })
        );
    }

    #[test]
    fn standardized_and_operator_qci_resource_types_are_checked() {
        assert!(Ikev2EpsQosMapping::from_kbps(
            Ikev2EpsQosKbps::NonGbr { qci: 9 },
            Ikev2QosQuantization::Exact,
        )
        .is_ok());
        assert!(Ikev2EpsQosMapping::from_kbps(
            Ikev2EpsQosKbps::Gbr {
                qci: 200,
                rates: uniform_rates(1_024),
            },
            Ikev2QosQuantization::Exact,
        )
        .is_ok());
        assert!(Ikev2EpsQosMapping::from_kbps(
            Ikev2EpsQosKbps::NonGbr { qci: 200 },
            Ikev2QosQuantization::Exact,
        )
        .is_ok());
        assert_eq!(
            Ikev2EpsQosMapping::from_kbps(
                Ikev2EpsQosKbps::NonGbr { qci: 1 },
                Ikev2QosQuantization::Exact,
            ),
            Err(Ikev2QosMappingError::StandardizedQciResourceMismatch {
                qci: 1,
                expected: Ikev2QosResourceType::Gbr,
                actual: Ikev2QosResourceType::NonGbr,
            })
        );
    }

    #[test]
    fn extended_eps_uses_shared_unit_and_zero_companion() {
        let rates = Ikev2EpsBearerBitRatesKbps {
            maximum_uplink: 10_000_001,
            maximum_downlink: 9_900_000,
            guaranteed_uplink: 10_000_000,
            guaranteed_downlink: 9_000_000,
        };
        let mapped = must_map_eps(rates, Ikev2QosQuantization::Ceiling);
        let extended = match mapped.extended_eps_qos() {
            Some(value) => value,
            None => panic!("extended EPS QoS was omitted"),
        };
        assert_eq!(extended.maximum_unit.wire_value(), 1);
        assert_eq!(extended.maximum_uplink, 50_001);
        assert_eq!(extended.maximum_downlink, 0);
        assert_eq!(extended.guaranteed_unit.wire_value(), 0);
        assert_eq!(extended.guaranteed_uplink, 0);
        assert_eq!(extended.guaranteed_downlink, 0);
        assert_eq!(
            mapped.represented_rates(),
            Some(Ikev2EpsBearerBitRatesKbps {
                maximum_uplink: 10_000_200,
                maximum_downlink: 9_900_000,
                guaranteed_uplink: 10_000_000,
                guaranteed_downlink: 9_000_000,
            })
        );
    }

    #[test]
    fn shared_unit_accounts_for_u16_rollover() {
        let mapped = must_map_eps(
            Ikev2EpsBearerBitRatesKbps {
                maximum_uplink: 13_107_001,
                maximum_downlink: 13_000_000,
                guaranteed_uplink: 10_000_000,
                guaranteed_downlink: 10_000_000,
            },
            Ikev2QosQuantization::Ceiling,
        );
        let extended = match mapped.extended_eps_qos() {
            Some(value) => value,
            None => panic!("extended EPS QoS was omitted"),
        };
        assert_eq!(extended.maximum_unit.wire_value(), 2);
        assert_eq!(extended.maximum_uplink, 13_108);
        assert_eq!(extended.maximum_downlink, 13_000);
    }

    #[test]
    fn apn_extended_2_boundary_and_extended_companion_are_canonical() {
        let below = match Ikev2ApnAmbrMapping::from_kbps(
            Ikev2ApnAmbrKbps {
                downlink: APN_EXTENDED_THRESHOLD_KBPS,
                uplink: 256_001,
            },
            Ikev2QosQuantization::Ceiling,
        ) {
            Ok(value) => value,
            Err(error) => panic!("APN-AMBR mapping failed: {error:?}"),
        };
        assert!(below.extended_apn_ambr().is_none());
        assert_eq!(
            below.represented_rates().downlink,
            APN_EXTENDED_THRESHOLD_KBPS
        );
        assert_eq!(below.represented_rates().uplink, 264_640);

        let above = match Ikev2ApnAmbrMapping::from_kbps(
            Ikev2ApnAmbrKbps {
                downlink: APN_EXTENDED_THRESHOLD_KBPS + 1,
                uplink: APN_EXTENDED_THRESHOLD_KBPS,
            },
            Ikev2QosQuantization::Ceiling,
        ) {
            Ok(value) => value,
            Err(error) => panic!("APN-AMBR mapping failed: {error:?}"),
        };
        let extended = match above.extended_apn_ambr() {
            Some(value) => value,
            None => panic!("extended APN-AMBR was omitted"),
        };
        assert_eq!(extended.downlink_unit.wire_value(), 3);
        assert_eq!(extended.downlink, 16_321);
        assert_eq!(extended.uplink_unit.wire_value(), 0);
        assert_eq!(extended.uplink, 0);
        assert_eq!(above.represented_rates().downlink, 65_284_000);
        assert_eq!(
            above.represented_rates().uplink,
            APN_EXTENDED_THRESHOLD_KBPS
        );
    }

    #[test]
    fn apn_shared_threshold_and_exact_grid_are_checked() {
        let exact = Ikev2ApnAmbrMapping::from_kbps(
            Ikev2ApnAmbrKbps {
                downlink: 512_000,
                uplink: 264_640,
            },
            Ikev2QosQuantization::Exact,
        );
        assert!(exact.is_ok());
        assert_eq!(
            Ikev2ApnAmbrMapping::from_kbps(
                Ikev2ApnAmbrKbps {
                    downlink: 260_000,
                    uplink: 1,
                },
                Ikev2QosQuantization::Exact,
            ),
            Err(Ikev2QosMappingError::NotExactlyRepresentable {
                field: Ikev2QosRateField::ApnAmbrDownlink,
                requested_kbps: 260_000,
            })
        );
    }

    #[test]
    fn guaranteed_rate_cannot_exceed_maximum() {
        assert_eq!(
            Ikev2EpsQosMapping::from_kbps(
                Ikev2EpsQosKbps::Gbr {
                    qci: 1,
                    rates: Ikev2EpsBearerBitRatesKbps {
                        maximum_uplink: 100,
                        maximum_downlink: 100,
                        guaranteed_uplink: 101,
                        guaranteed_downlink: 100,
                    },
                },
                Ikev2QosQuantization::Ceiling,
            ),
            Err(Ikev2QosMappingError::GuaranteedRateExceedsMaximum {
                direction: Ikev2QosDirection::Uplink,
                maximum_kbps: 100,
                guaranteed_kbps: 101,
            })
        );
    }
}
