//! Bounded Release 18 root QoS descriptions, without admission or resource effects.
//!
//! Non-dynamic and dynamic descriptors retain their explicit optional values.
//! GBR presence describes a request; it does not prove available resources.
//! Notification Control is retained for canonical encoding but has no N3IWF
//! notification authority (TS 29.413 5.3). Extension additions are rejected.

use super::reset_fields::{encode_root, Sink};
use super::resource_fields::{NonGbrFlow, QosFlowId};
use super::setup_fields::Reader;
use super::*;

/// Root non-dynamic 5QI descriptor. Optional values never acquire defaults.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NonDynamicQos {
    /// Root 5QI, 0..=255. Resource-type and reservation policy is caller-owned.
    pub five_qi: u8,
    /// Optional QoS priority, 1..=127; distinct from allocation/retention priority.
    pub priority: Option<u8>,
    /// Optional averaging window, 0..=4095 milliseconds.
    pub averaging_window: Option<u16>,
    /// Optional root maximum data burst volume, 0..=4095 bytes.
    pub maximum_data_burst: Option<u16>,
}
redacted!(NonDynamicQos);

/// Root dynamic 5QI descriptor. This is the peer's advertised profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DynamicQos {
    /// QoS priority, 1..=127.
    pub priority: u8,
    /// Packet delay budget, 0..=1023 milliseconds.
    pub packet_delay_budget: u16,
    /// Packet error-rate scalar, 0..=9.
    pub error_scalar: u8,
    /// Packet error-rate exponent, 0..=9.
    pub error_exponent: u8,
    /// Optional root 5QI.
    pub five_qi: Option<u8>,
    /// Optional delay-critical report. `Some(false)` differs from absence.
    pub delay_critical: Option<bool>,
    /// Optional averaging window, 0..=4095 milliseconds.
    pub averaging_window: Option<u16>,
    /// Optional root maximum data burst volume, 0..=4095 bytes.
    pub maximum_data_burst: Option<u16>,
}
redacted!(DynamicQos);

/// The two root QoS characteristic choices.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum QosCharacteristics {
    /// Advertised non-dynamic 5QI and optional overrides.
    NonDynamic(NonDynamicQos),
    /// Explicit dynamic QoS descriptor.
    Dynamic(DynamicQos),
}
redacted!(QosCharacteristics);

/// Caller-established QoS resource type, obtained from its admitted 5QI policy.
/// GBR parameter presence alone is not evidence of this classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosResourceType {
    /// A non-GBR flow, whose GBR information is receiver-ignored.
    NonGbr,
    /// A GBR flow (including delay-critical GBR).
    Gbr,
}

/// Caller-supplied resource classification for one exact set of requested QFIs.
/// This is local policy input, not a result inferred from peer-provided fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QosResourceTypes {
    gbr: u64,
    non_gbr: u64,
}
redacted!(QosResourceTypes);
impl QosResourceTypes {
    /// Require 1–64 distinct QFIs. Every flow in the associated request must
    /// have exactly one classification; unrelated entries are also rejected.
    pub fn new(
        values: impl IntoIterator<Item = (QosFlowId, QosResourceType)>,
    ) -> Result<Self, DecodeError> {
        let mut result = Self { gbr: 0, non_gbr: 0 };
        for (qfi, kind) in values {
            let bit = 1u64 << qfi.value();
            if (result.gbr | result.non_gbr) & bit != 0 {
                return Err(invalid("duplicate qos resource classification"));
            }
            match kind {
                QosResourceType::Gbr => result.gbr |= bit,
                QosResourceType::NonGbr => result.non_gbr |= bit,
            }
        }
        if result.gbr | result.non_gbr == 0 {
            return Err(invalid("empty qos resource classification"));
        }
        Ok(result)
    }
    /// The explicitly supplied resource type for this identifier, if present.
    pub const fn get(self, qfi: QosFlowId) -> Option<QosResourceType> {
        let bit = 1u64 << qfi.value();
        if self.gbr & bit != 0 {
            Some(QosResourceType::Gbr)
        } else if self.non_gbr & bit != 0 {
            Some(QosResourceType::NonGbr)
        } else {
            None
        }
    }
    /// Validate exact QFI coverage and return whether any flow needs Session
    /// AMBR. GBR-information presence does not affect this decision.
    pub fn requires_session_ambr(self, flows: &[QosFlow]) -> Result<bool, DecodeError> {
        let mut requested = 0u64;
        for flow in flows {
            let bit = 1u64 << flow.qfi().value();
            if requested & bit != 0 {
                return Err(invalid("duplicate qos request identifier"));
            }
            requested |= bit;
        }
        if requested != self.gbr | self.non_gbr {
            return Err(invalid("qos resource classification coverage"));
        }
        Ok(self.non_gbr != 0)
    }
}

/// A value-free per-flow abnormal-condition result. The caller selects the
/// appropriate NGAP Cause and reports this flow without discarding other flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QosConditionFailure {
    /// A caller-classified GBR flow omitted its required GBR information.
    #[error("missing gbr qos information")]
    MissingGbrInformation,
    /// A dynamic descriptor accompanying GBR information omitted Delay Critical.
    #[error("missing qos delay critical indication")]
    MissingDelayCritical,
    /// A dynamic descriptor accompanying GBR information omitted Averaging Window.
    #[error("missing qos averaging window")]
    MissingAveragingWindow,
    /// A delay-critical descriptor omitted Maximum Data Burst Volume.
    #[error("missing qos maximum data burst volume")]
    MissingMaximumDataBurst,
}

/// Applicable field view after caller-supplied resource-type checks. This does
/// not validate the classification, reserve resources or enable any procedure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ApplicableQosParameters {
    requested: QosParameters,
    resource_type: QosResourceType,
}
redacted!(ApplicableQosParameters);
impl ApplicableQosParameters {
    /// Original request, including receiver-ignored optional values.
    pub const fn requested(self) -> QosParameters {
        self.requested
    }
    /// GBR information is inapplicable for a non-GBR flow. N3IWF ignores
    /// Notification Control, so that presence flag is cleared in this view.
    pub const fn gbr(self) -> Option<GbrQosInformation> {
        match self.resource_type {
            QosResourceType::Gbr => match self.requested.gbr {
                Some(mut value) => {
                    value.notification_control = false;
                    Some(value)
                }
                None => None,
            },
            QosResourceType::NonGbr => None,
        }
    }
    /// Reflective QoS is inapplicable for a GBR flow.
    pub const fn reflective(self) -> bool {
        matches!(self.resource_type, QosResourceType::NonGbr) && self.requested.reflective
    }
    /// Additional QoS Flow Information is inapplicable for a GBR flow.
    pub const fn additional(self) -> bool {
        matches!(self.resource_type, QosResourceType::NonGbr) && self.requested.additional
    }
}

/// Root allocation/retention priority, with independent pre-emption flags.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AllocationRetentionPriority {
    priority: u8,
    may_preempt: bool,
    preemptable: bool,
}
redacted!(AllocationRetentionPriority);
impl AllocationRetentionPriority {
    /// Validate priority 1..=15; grant no permission to change local resources.
    pub fn new(priority: u8, may_preempt: bool, preemptable: bool) -> Result<Self, DecodeError> {
        if !(1..=15).contains(&priority) {
            return Err(invalid("arp priority range"));
        }
        Ok(Self {
            priority,
            may_preempt,
            preemptable,
        })
    }
    /// Explicit allocation/retention priority.
    pub const fn priority(self) -> u8 {
        self.priority
    }
    /// Reported pre-emption capability.
    pub const fn may_preempt(self) -> bool {
        self.may_preempt
    }
    /// Reported pre-emption vulnerability.
    pub const fn preemptable(self) -> bool {
        self.preemptable
    }
}

/// Root GBR parameters. All rates have the ASN.1 bound 4,000,000,000,000 bit/s.
/// Rate consistency and resource admission belong to the caller's QoS policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GbrQosInformation {
    /// Maximum downlink flow rate.
    pub maximum_downlink: u64,
    /// Maximum uplink flow rate.
    pub maximum_uplink: u64,
    /// Guaranteed downlink flow rate.
    pub guaranteed_downlink: u64,
    /// Guaranteed uplink flow rate.
    pub guaranteed_uplink: u64,
    /// Presence of root Notification Control. N3IWF ignores its requested effect.
    pub notification_control: bool,
    /// Optional maximum downlink packet loss rate, 0..=1000.
    pub maximum_packet_loss_downlink: Option<u16>,
    /// Optional maximum uplink packet loss rate, 0..=1000.
    pub maximum_packet_loss_uplink: Option<u16>,
}
redacted!(GbrQosInformation);

/// Validated root flow parameters. Accessors return data, never QoS authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QosParameters {
    characteristics: QosCharacteristics,
    arp: AllocationRetentionPriority,
    gbr: Option<GbrQosInformation>,
    reflective: bool,
    additional: bool,
}
redacted!(QosParameters);
impl QosParameters {
    /// Check flow-level conditions in TS 38.413 8.2.1.4/8.2.3.4 and 9.3.1.18.
    /// The caller establishes the resource type from its supported 5QI policy;
    /// neither presence of GBR information nor a successful codec does so.
    /// Failure is scoped to this flow, enabling partial resource failure reports.
    pub fn applicable(
        self,
        resource_type: QosResourceType,
    ) -> Result<ApplicableQosParameters, QosConditionFailure> {
        if resource_type == QosResourceType::Gbr && self.gbr.is_none() {
            return Err(QosConditionFailure::MissingGbrInformation);
        }
        if let QosCharacteristics::Dynamic(value) = self.characteristics {
            if self.gbr.is_some() {
                if value.delay_critical.is_none() {
                    return Err(QosConditionFailure::MissingDelayCritical);
                }
                if value.averaging_window.is_none() {
                    return Err(QosConditionFailure::MissingAveragingWindow);
                }
            }
            if value.delay_critical == Some(true) && value.maximum_data_burst.is_none() {
                return Err(QosConditionFailure::MissingMaximumDataBurst);
            }
        }
        Ok(ApplicableQosParameters {
            requested: self,
            resource_type,
        })
    }
    /// Validate descriptor root ranges. Cross-procedure and standardized 5QI
    /// resource-type conditions remain the caller's responsibility.
    pub fn new(
        characteristics: QosCharacteristics,
        arp: AllocationRetentionPriority,
    ) -> Result<Self, DecodeError> {
        let (priority, window, burst) = match characteristics {
            QosCharacteristics::NonDynamic(v) => {
                (v.priority, v.averaging_window, v.maximum_data_burst)
            }
            QosCharacteristics::Dynamic(v) => {
                if v.packet_delay_budget > 1023 || v.error_scalar > 9 || v.error_exponent > 9 {
                    return Err(invalid("dynamic qos range"));
                }
                (Some(v.priority), v.averaging_window, v.maximum_data_burst)
            }
        };
        if priority.is_some_and(|v| !(1..=127).contains(&v))
            || window.is_some_and(|v| v > 4095)
            || burst.is_some_and(|v| v > 4095)
        {
            return Err(invalid("qos descriptor range"));
        }
        Ok(Self {
            characteristics,
            arp,
            gbr: None,
            reflective: false,
            additional: false,
        })
    }
    /// Attach or clear GBR parameters after checking every numeric root bound.
    pub fn with_gbr(mut self, gbr: Option<GbrQosInformation>) -> Result<Self, DecodeError> {
        if let Some(v) = gbr {
            if [
                v.maximum_downlink,
                v.maximum_uplink,
                v.guaranteed_downlink,
                v.guaranteed_uplink,
            ]
            .iter()
            .any(|rate| *rate > 4_000_000_000_000)
                || v.maximum_packet_loss_downlink.is_some_and(|v| v > 1000)
                || v.maximum_packet_loss_uplink.is_some_and(|v| v > 1000)
            {
                return Err(invalid("gbr qos range"));
            }
        }
        self.gbr = gbr;
        Ok(self)
    }
    /// Preserve the presence of the two single-valued root attributes.
    pub const fn with_attributes(mut self, reflective: bool, additional: bool) -> Self {
        self.reflective = reflective;
        self.additional = additional;
        self
    }
    /// Explicit QoS descriptor.
    pub const fn characteristics(self) -> QosCharacteristics {
        self.characteristics
    }
    /// Explicit allocation/retention priority.
    pub const fn allocation_retention_priority(self) -> AllocationRetentionPriority {
        self.arp
    }
    /// Supplied GBR request parameters, if any.
    pub const fn gbr(self) -> Option<GbrQosInformation> {
        self.gbr
    }
    /// Presence of Reflective QoS Attribute.
    pub const fn reflective(self) -> bool {
        self.reflective
    }
    /// Presence of Additional QoS Flow Information.
    pub const fn additional(self) -> bool {
        self.additional
    }
    /// Encode the root with exact capacity checked before allocation.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_root(ctx, |out| self.write(out))
    }
    /// Decode a complete root. Non-dynamic needs depth four, dynamic needs five.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 4)?;
        let mut reader = Reader::new(input, ctx);
        let value = Self::read(&mut reader, ctx, 4)?;
        reader.finish()?;
        Ok(value)
    }

    pub(super) fn write(self, out: &mut dyn Sink) -> Result<(), EncodeError> {
        out.bits(
            u16::from(self.gbr.is_some()) * 8
                + u16::from(self.reflective) * 4
                + u16::from(self.additional) * 2,
            5,
        )?;
        match self.characteristics {
            QosCharacteristics::NonDynamic(v) => {
                out.bits(0, 2)?;
                out.bits(
                    u16::from(v.priority.is_some()) * 8
                        + u16::from(v.averaging_window.is_some()) * 4
                        + u16::from(v.maximum_data_burst.is_some()) * 2,
                    5,
                )?;
                write_integer(out, u16::from(v.five_qi), 8, true)?;
                if let Some(value) = v.priority {
                    write_integer(out, u16::from(value - 1), 7, false)?;
                }
                if let Some(value) = v.averaging_window {
                    write_integer(out, value, 16, true)?;
                }
                if let Some(value) = v.maximum_data_burst {
                    write_integer(out, value, 16, true)?;
                }
            }
            QosCharacteristics::Dynamic(v) => {
                out.bits(1, 2)?;
                out.bits(
                    u16::from(v.five_qi.is_some()) * 16
                        + u16::from(v.delay_critical.is_some()) * 8
                        + u16::from(v.averaging_window.is_some()) * 4
                        + u16::from(v.maximum_data_burst.is_some()) * 2,
                    6,
                )?;
                write_integer(out, u16::from(v.priority - 1), 7, false)?;
                write_integer(out, v.packet_delay_budget, 16, true)?;
                out.bits(0, 2)?;
                write_integer(out, u16::from(v.error_scalar), 4, false)?;
                write_integer(out, u16::from(v.error_exponent), 4, false)?;
                if let Some(value) = v.five_qi {
                    write_integer(out, u16::from(value), 8, true)?;
                }
                if let Some(value) = v.delay_critical {
                    out.bits(u16::from(!value), 2)?;
                }
                if let Some(value) = v.averaging_window {
                    write_integer(out, value, 16, true)?;
                }
                if let Some(value) = v.maximum_data_burst {
                    write_integer(out, value, 16, true)?;
                }
            }
        }
        out.bits(0, 2)?;
        out.bits(u16::from(self.arp.priority - 1), 4)?;
        out.bits(u16::from(self.arp.may_preempt), 2)?;
        out.bits(u16::from(self.arp.preemptable), 2)?;
        if let Some(v) = self.gbr {
            out.bits(
                u16::from(v.notification_control) * 8
                    + u16::from(v.maximum_packet_loss_downlink.is_some()) * 4
                    + u16::from(v.maximum_packet_loss_uplink.is_some()) * 2,
                5,
            )?;
            for rate in [
                v.maximum_downlink,
                v.maximum_uplink,
                v.guaranteed_downlink,
                v.guaranteed_uplink,
            ] {
                write_rate(out, rate)?;
            }
            if v.notification_control {
                out.bits(0, 1)?;
            }
            if let Some(value) = v.maximum_packet_loss_downlink {
                write_integer(out, value, 16, true)?;
            }
            if let Some(value) = v.maximum_packet_loss_uplink {
                write_integer(out, value, 16, true)?;
            }
        }
        if self.reflective {
            out.bits(0, 1)?;
        }
        if self.additional {
            out.bits(0, 1)?;
        }
        Ok(())
    }

    pub(super) fn read(
        reader: &mut Reader<'_>,
        ctx: DecodeContext,
        depth: usize,
    ) -> Result<Self, DecodeError> {
        crate::enforce_depth(depth, ctx)?;
        let flags = reader.bits(5)?;
        if flags & !14 != 0 {
            return Err(unsupported());
        }
        let characteristics = match reader.bits(2)? {
            0 => {
                let flags = reader.bits(5)?;
                if flags & !14 != 0 {
                    return Err(unsupported());
                }
                QosCharacteristics::NonDynamic(NonDynamicQos {
                    five_qi: read_integer(reader, 8, true, 255)? as u8,
                    priority: if flags & 8 != 0 {
                        Some(read_integer(reader, 7, false, 126)? as u8 + 1)
                    } else {
                        None
                    },
                    averaging_window: if flags & 4 != 0 {
                        Some(read_integer(reader, 16, true, 4095)?)
                    } else {
                        None
                    },
                    maximum_data_burst: if flags & 2 != 0 {
                        Some(read_integer(reader, 16, true, 4095)?)
                    } else {
                        None
                    },
                })
            }
            1 => {
                crate::enforce_depth(depth + 1, ctx)?;
                let flags = reader.bits(6)?;
                if flags & !30 != 0 {
                    return Err(unsupported());
                }
                let priority = read_integer(reader, 7, false, 126)? as u8 + 1;
                let packet_delay_budget = read_integer(reader, 16, true, 1023)?;
                reader.flags(2)?;
                let error_scalar = read_integer(reader, 4, false, 9)? as u8;
                let error_exponent = read_integer(reader, 4, false, 9)? as u8;
                let five_qi = if flags & 16 != 0 {
                    Some(read_integer(reader, 8, true, 255)? as u8)
                } else {
                    None
                };
                let delay_critical = if flags & 8 != 0 {
                    reader.flags(1)?;
                    Some(reader.bits(1)? == 0)
                } else {
                    None
                };
                QosCharacteristics::Dynamic(DynamicQos {
                    priority,
                    packet_delay_budget,
                    error_scalar,
                    error_exponent,
                    five_qi,
                    delay_critical,
                    averaging_window: if flags & 4 != 0 {
                        Some(read_integer(reader, 16, true, 4095)?)
                    } else {
                        None
                    },
                    maximum_data_burst: if flags & 2 != 0 {
                        Some(read_integer(reader, 16, true, 4095)?)
                    } else {
                        None
                    },
                })
            }
            _ => return Err(unsupported()),
        };
        reader.flags(2)?;
        let priority = reader.bits(4)? as u8 + 1;
        reader.flags(1)?;
        let may_preempt = reader.bits(1)? != 0;
        reader.flags(1)?;
        let preemptable = reader.bits(1)? != 0;
        let arp = AllocationRetentionPriority::new(priority, may_preempt, preemptable)?;
        let gbr = if flags & 8 != 0 {
            let flags = reader.bits(5)?;
            if flags & !14 != 0 {
                return Err(unsupported());
            }
            let maximum_downlink = read_rate(reader)?;
            let maximum_uplink = read_rate(reader)?;
            let guaranteed_downlink = read_rate(reader)?;
            let guaranteed_uplink = read_rate(reader)?;
            let notification_control = flags & 8 != 0;
            if notification_control {
                reader.flags(1)?;
            }
            Some(GbrQosInformation {
                maximum_downlink,
                maximum_uplink,
                guaranteed_downlink,
                guaranteed_uplink,
                notification_control,
                maximum_packet_loss_downlink: if flags & 4 != 0 {
                    Some(read_integer(reader, 16, true, 1000)?)
                } else {
                    None
                },
                maximum_packet_loss_uplink: if flags & 2 != 0 {
                    Some(read_integer(reader, 16, true, 1000)?)
                } else {
                    None
                },
            })
        } else {
            None
        };
        if flags & 4 != 0 {
            reader.flags(1)?;
        }
        if flags & 2 != 0 {
            reader.flags(1)?;
        }
        Ok(Self::new(characteristics, arp)?
            .with_gbr(gbr)?
            .with_attributes(flags & 4 != 0, flags & 2 != 0))
    }
}

/// A requested root QoS flow, optionally associated with an E-RAB identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QosFlow {
    qfi: QosFlowId,
    parameters: QosParameters,
    erab: Option<u8>,
}
redacted!(QosFlow);
impl QosFlow {
    /// Bind validated fields; neither QFI ownership nor resources are inferred.
    pub const fn new(qfi: QosFlowId, parameters: QosParameters) -> Self {
        Self {
            qfi,
            parameters,
            erab: None,
        }
    }
    /// Set an optional root E-RAB identifier (0..=15).
    pub fn with_erab(mut self, erab: Option<u8>) -> Result<Self, DecodeError> {
        if erab.is_some_and(|v| v > 15) {
            return Err(invalid("e-rab identifier range"));
        }
        self.erab = erab;
        Ok(self)
    }
    /// Explicit QFI.
    pub const fn qfi(self) -> QosFlowId {
        self.qfi
    }
    /// Explicit flow parameters.
    pub const fn parameters(self) -> QosParameters {
        self.parameters
    }
    /// Optional E-RAB identifier. No EPS association is inferred.
    pub const fn erab(self) -> Option<u8> {
        self.erab
    }
    /// Allocation/retention priority, independent of QoS priority.
    pub const fn priority(self) -> u8 {
        self.parameters.arp.priority
    }
    /// Reported pre-emption capability.
    pub const fn may_preempt(self) -> bool {
        self.parameters.arp.may_preempt
    }
    /// Reported pre-emption vulnerability.
    pub const fn preemptable(self) -> bool {
        self.parameters.arp.preemptable
    }

    pub(super) fn legacy(self) -> Option<NonGbrFlow> {
        let QosCharacteristics::NonDynamic(v) = self.parameters.characteristics else {
            return None;
        };
        if v.five_qi != 9
            || v.priority.is_some()
            || v.averaging_window.is_some()
            || v.maximum_data_burst.is_some()
            || self.parameters.gbr.is_some()
            || self.parameters.reflective
            || self.parameters.additional
            || self.erab.is_some()
        {
            return None;
        }
        NonGbrFlow::new(
            self.qfi,
            self.priority(),
            self.may_preempt(),
            self.preemptable(),
        )
        .ok()
    }
}
impl From<NonGbrFlow> for QosFlow {
    fn from(value: NonGbrFlow) -> Self {
        Self::new(
            value.qfi(),
            QosParameters {
                characteristics: QosCharacteristics::NonDynamic(NonDynamicQos {
                    five_qi: 9,
                    priority: None,
                    averaging_window: None,
                    maximum_data_burst: None,
                }),
                arp: AllocationRetentionPriority {
                    priority: value.priority(),
                    may_preempt: value.may_preempt(),
                    preemptable: value.preemptable(),
                },
                gbr: None,
                reflective: false,
                additional: false,
            },
        )
    }
}

fn write_integer(
    out: &mut dyn Sink,
    value: u16,
    width: usize,
    aligned: bool,
) -> Result<(), EncodeError> {
    out.bits(0, 1)?;
    if aligned {
        out.align();
    }
    out.bits(value, width)
}
fn read_integer(
    reader: &mut Reader<'_>,
    width: usize,
    aligned: bool,
    maximum: u16,
) -> Result<u16, DecodeError> {
    reader.flags(1)?;
    if aligned {
        reader.align()?;
    }
    let value = reader.bits(width)?;
    if value > maximum {
        return Err(invalid("qos integer range"));
    }
    Ok(value)
}
fn write_rate(out: &mut dyn Sink, value: u64) -> Result<(), EncodeError> {
    let octets = ((64 - value.leading_zeros()).max(1) as usize).div_ceil(8);
    out.bits((octets - 1) as u16, 4)?; // root extension + constrained octet count
    out.align();
    for shift in (0..octets).rev() {
        out.bits(((value >> (shift * 8)) & 255) as u16, 8)?;
    }
    Ok(())
}
fn read_rate(reader: &mut Reader<'_>) -> Result<u64, DecodeError> {
    reader.flags(1)?;
    let octets = usize::from(reader.bits(3)?) + 1;
    if octets > 6 {
        return Err(invalid("qos bitrate size"));
    }
    reader.align()?;
    let first = reader.bits(8)?;
    if octets > 1 && first == 0 {
        return Err(invalid("qos bitrate nonminimal"));
    }
    let mut value = u64::from(first);
    for _ in 1..octets {
        value = (value << 8) | u64::from(reader.bits(8)?);
    }
    if value > 4_000_000_000_000 {
        return Err(invalid("qos bitrate range"));
    }
    Ok(value)
}
