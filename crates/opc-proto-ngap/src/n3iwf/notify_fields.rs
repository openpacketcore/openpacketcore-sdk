//! Qualified root PDU Session Resource Notify fields. Reports neither prove
//! resource state nor authorize cleanup; callers correlate all session/QFI IDs.

use super::release::Cause;
use super::resource_fields::QosFlowId;
use super::resource_results::{cause_width, read_cause, unique};
use super::session_lists::{encode_list, preflight_results, validate_ids, SessionId};
use super::setup_fields::Reader;
use super::*;

/// Root notification status for an established GBR flow. Whether the QFI names
/// an established GBR flow must be checked against the caller's session state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NotificationCause {
    /// Reported QoS is fulfilled again.
    Fulfilled,
    /// Reported QoS is no longer fulfilled.
    NotFulfilled,
}
redacted!(NotificationCause);

/// A QFI with its reported root notification status.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotifiedQosFlow {
    /// Reported QFI, without an ownership or GBR classification claim.
    pub qfi: QosFlowId,
    /// Root notification status; extension values remain unsupported.
    pub cause: NotificationCause,
}
redacted!(NotifiedQosFlow);

/// A flow reported released, without proving that a local resource was removed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReleasedQosFlow {
    /// Reported flow identifier.
    pub qfi: QosFlowId,
    /// Explicit root release cause.
    pub cause: Cause,
}
redacted!(ReleasedQosFlow);

/// Root flow notifications and/or releases. Each present list contains 1–64
/// items, with unique QFIs across both lists. Extension fields are unsupported.
#[derive(Clone, PartialEq, Eq)]
pub struct NotifyTransfer {
    notified: Vec<NotifiedQosFlow>,
    released: Vec<ReleasedQosFlow>,
}
redacted!(NotifyTransfer);
impl NotifyTransfer {
    /// Require at least one reported flow and a unique, disjoint QFI domain.
    pub fn new(
        notified: Vec<NotifiedQosFlow>,
        released: Vec<ReleasedQosFlow>,
    ) -> Result<Self, DecodeError> {
        if notified.len() > 64 || released.len() > 64 || notified.is_empty() && released.is_empty()
        {
            return Err(invalid("notify flow count"));
        }
        let mut seen = 0;
        for qfi in notified
            .iter()
            .map(|v| v.qfi)
            .chain(released.iter().map(|v| v.qfi))
        {
            unique(&mut seen, qfi)?;
        }
        Ok(Self { notified, released })
    }
    /// Explicit notifications in received order.
    pub fn notified(&self) -> &[NotifiedQosFlow] {
        &self.notified
    }
    /// Explicit released flows in received order.
    pub fn released(&self) -> &[ReleasedQosFlow] {
        &self.released
    }
    pub(super) fn depth(&self) -> usize {
        if self.released.is_empty() {
            4
        } else {
            5
        }
    }
    fn wire_len(&self) -> usize {
        let mut bits = 4;
        if !self.notified.is_empty() {
            bits += 6 + 11 * self.notified.len();
        }
        if !self.released.is_empty() {
            bits += 6 + self
                .released
                .iter()
                .map(|v| 13 + cause_width(v.cause.class()))
                .sum::<usize>();
        }
        bits.div_ceil(8)
    }
    /// Retain independently qualified generated encoding after checking the
    /// exact output capacity, before materializing generated lists.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = self.wire_len();
        capacity(length, ctx)?;
        let notified = if self.notified.is_empty() {
            None
        } else {
            Some(asn::QosFlowNotifyList(
                self.notified
                    .iter()
                    .map(|v| {
                        asn::QosFlowNotifyItem::new(
                            asn::QosFlowIdentifier(v.qfi.value().into()),
                            match v.cause {
                                NotificationCause::Fulfilled => asn::NotificationCause::fulfilled,
                                NotificationCause::NotFulfilled => {
                                    asn::NotificationCause::not_fulfilled
                                }
                            },
                            None,
                        )
                    })
                    .collect(),
            ))
        };
        let released = if self.released.is_empty() {
            None
        } else {
            Some(asn::QosFlowListWithCause(
                self.released
                    .iter()
                    .map(|v| {
                        Ok(asn::QosFlowWithCauseItem::new(
                            asn::QosFlowIdentifier(v.qfi.value().into()),
                            v.cause.generated()?,
                            None,
                        ))
                    })
                    .collect::<Result<_, EncodeError>>()?,
            ))
        };
        encode_list(
            &asn::PDUSessionResourceNotifyTransfer::new(notified, released, None),
            length,
        )
    }
    /// Require depth four for notifications or five when releases are present.
    /// Validate all flags, cumulative counts, QFI uniqueness, root enums,
    /// padding and complete framing before allocating either output vector.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (notified_count, released_count) = scan(input, ctx, |_| {}, |_| {})?;
        let mut notified = Vec::with_capacity(notified_count);
        let mut released = Vec::with_capacity(released_count);
        scan(input, ctx, |v| notified.push(v), |v| released.push(v))?;
        Ok(Self { notified, released })
    }
}

fn scan(
    input: &[u8],
    ctx: DecodeContext,
    mut notified: impl FnMut(NotifiedQosFlow),
    mut released: impl FnMut(ReleasedQosFlow),
) -> Result<(usize, usize), DecodeError> {
    bound(input, ctx, 4)?;
    let mut reader = Reader::new(input, ctx);
    let flags = reader.bits(4)?;
    if flags & !6 != 0 {
        return Err(unsupported());
    }
    if flags == 0 {
        return Err(invalid("missing notify flow reports"));
    }
    if flags & 2 != 0 {
        crate::enforce_depth(5, ctx)?;
    }
    let (mut notified_count, mut released_count) = (0, 0);
    let mut seen = 0;
    if flags & 4 != 0 {
        notified_count = reader.count(6, 64, 11)?;
        for _ in 0..notified_count {
            reader.flags(3)?;
            let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
            unique(&mut seen, qfi)?;
            reader.flags(1)?;
            let cause = if reader.bits(1)? == 0 {
                NotificationCause::Fulfilled
            } else {
                NotificationCause::NotFulfilled
            };
            notified(NotifiedQosFlow { qfi, cause });
        }
    }
    if flags & 2 != 0 {
        released_count = reader.count(6, 64, 14)?;
        for _ in 0..released_count {
            reader.flags(3)?;
            let qfi = QosFlowId::new(reader.bits(6)? as u8)?;
            unique(&mut seen, qfi)?;
            released(ReleasedQosFlow {
                qfi,
                cause: read_cause(&mut reader)?,
            });
        }
    }
    reader.finish()?;
    Ok((notified_count, released_count))
}

/// Root report that a whole PDU session was released. Correlation and resource
/// effects remain caller-owned; extension usage/error reports are unsupported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotifyReleasedTransfer {
    /// Explicit reported Cause.
    pub cause: Cause,
}
redacted!(NotifyReleasedTransfer);
impl NotifyReleasedTransfer {
    fn wire_len(self) -> usize {
        (6 + cause_width(self.cause.class())).div_ceil(8)
    }
    /// Encode the independently qualified generated root after exact sizing.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(self.wire_len(), ctx)?;
        encode_leaf(
            &asn::PDUSessionResourceNotifyReleasedTransfer::new(self.cause.generated()?, None),
            ctx,
        )
    }
    /// Require depth three and preflight root Cause, flags, padding and exact
    /// framing before invoking the independently qualified generated decoder.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 3)?;
        let mut reader = Reader::new(input, ctx);
        reader.flags(2)?;
        read_cause(&mut reader)?;
        reader.finish()?;
        let value: asn::PDUSessionResourceNotifyReleasedTransfer = decode_leaf(input)?;
        Ok(Self {
            cause: Cause::from_generated(value.cause)?,
        })
    }
}

/// Flow notifications for one reported session.
#[derive(Clone, PartialEq, Eq)]
pub struct NotifiedSession {
    /// Session identifier without an ownership claim.
    pub id: SessionId,
    /// Typed reported flow state.
    pub transfer: NotifyTransfer,
}
redacted!(NotifiedSession);

/// A whole-session release report and its root Cause.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReleasedSession {
    /// Session identifier without a cleanup implication.
    pub id: SessionId,
    /// Reported root release cause.
    pub transfer: NotifyReleasedTransfer,
}
redacted!(ReleasedSession);

macro_rules! sessions {
    ($name:ident, $item:ident, $transfer:ident, $asn_list:ident, $asn_item:ident, $field:ident, $depth:expr, $max:expr) => {
        /// Ordered nonempty list of 1–256 unique session reports. Every nested
        /// transfer is admitted before returning; resource effects are external.
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(Vec<$item>);
        redacted!($name);
        impl $name {
            /// Enforce root count and session uniqueness.
            pub fn new(values: Vec<$item>) -> Result<Self, DecodeError> {
                validate_ids(values.iter().map(|v| v.id), values.len())?;
                Ok(Self(values))
            }
            /// Explicit reports in received order.
            pub fn values(&self) -> &[$item] {
                &self.0
            }
            /// Preserve the qualified generated list encoder, checking complete
            /// capacity before materializing generated fields or transfer bytes.
            pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
                let mut length = 1;
                for v in &self.0 {
                    length += 2 + constructed::open_type_len(v.transfer.wire_len())?;
                }
                capacity(length, ctx)?;
                let values = self
                    .0
                    .iter()
                    .map(|v| {
                        Ok(asn::$asn_item::new(
                            asn::PDUSessionID(v.id.value()),
                            v.transfer.encode(ctx)?.as_bytes().to_vec().into(),
                            None,
                        ))
                    })
                    .collect::<Result<_, EncodeError>>()?;
                encode_list(&asn::$asn_list(values), length)
            }
            /// Preflight bounded physical counts, session uniqueness, flags,
            /// padding and nested lengths before generated list materialization.
            /// Each nested transfer then receives the remaining depth budget.
            pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
                preflight_results(input, ctx, $depth, $max)?;
                let value: asn::$asn_list = decode_leaf(input)?;
                let nested = DecodeContext {
                    max_depth: ctx.max_depth.saturating_sub(3),
                    ..ctx
                };
                let values = value
                    .0
                    .iter()
                    .map(|v| {
                        Ok($item {
                            id: SessionId::new(v.p_dusession_id.0),
                            transfer: $transfer::decode(v.$field.as_ref(), nested)?,
                        })
                    })
                    .collect::<Result<_, DecodeError>>()?;
                Ok(Self(values))
            }
        }
    };
}
sessions!(
    NotifiedSessions,
    NotifiedSession,
    NotifyTransfer,
    PDUSessionResourceNotifyList,
    PDUSessionResourceNotifyItem,
    p_dusession_resource_notify_transfer,
    7,
    154
);
sessions!(
    ReleasedSessions,
    ReleasedSession,
    NotifyReleasedTransfer,
    PDUSessionResourceReleasedListNot,
    PDUSessionResourceReleasedItemNot,
    p_dusession_resource_notify_released_transfer,
    6,
    2
);
