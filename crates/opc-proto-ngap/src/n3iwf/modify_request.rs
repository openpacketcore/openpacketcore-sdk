//! Root PDU Session Resource Modify Request Transfer admission (TS 38.413
//! 8.2.3 / 9.3.4.3). The four supported fields are optional, including AMBR:
//! an existing session can retain its previous aggregate limits. Empty roots
//! and absent flow parameters are preserved without supplying defaults.
//!
//! The caller correlates sessions, bearers and QFIs, checks conditional
//! presence, constructs prescribed abnormal-condition responses and performs
//! resource changes. A typed rejection is not a protocol failure response.
//! Other recognized optional fields, QoS profiles and extensions remain
//! explicitly unsupported; this module does not admit an enclosing NGAP PDU.

use super::modify_fields::{QosFlowCauses, QosFlowModifications, UplinkModifications};
use super::resource_fields::SessionAggregateBitRate;
use super::*;
use crate::policy;

/// Optional root requests, without session existence or authorization evidence.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ModifyRequestTransfer {
    /// New session aggregate limits; absence preserves the request's omission.
    pub aggregate_bit_rate: Option<SessionAggregateBitRate>,
    /// Requested uplink endpoint and existing downlink bearer endpoint pairs.
    pub uplink_modifications: Option<UplinkModifications>,
    /// Unique QFIs with absent parameters or explicit non-GBR 5QI 9 parameters.
    pub add_or_modify: Option<QosFlowModifications>,
    /// Unique QFIs and root causes, disjoint from `add_or_modify`.
    pub release: Option<QosFlowCauses>,
}
redacted!(ModifyRequestTransfer);

/// A selected semantic transfer plus value-free unknown-IE diagnostics.
#[derive(Debug)]
pub struct AdmittedModifyRequestTransfer {
    /// Admitted request fields; no resource effect occurred.
    pub transfer: ModifyRequestTransfer,
    /// Unknown ignore-criticality IEs retained after configured selection.
    pub ignored_ie_count: usize,
    /// Unknown notify-criticality identifiers for caller-owned diagnostics.
    pub notify_ie_ids: Vec<u16>,
}

impl ModifyRequestTransfer {
    fn validate(&self) -> Result<(), DecodeError> {
        if let (Some(add), Some(release)) = (&self.add_or_modify, &self.release) {
            let identifiers = add
                .values()
                .iter()
                .fold(0u64, |seen, value| seen | (1 << value.qfi().value()));
            if release
                .values()
                .iter()
                .any(|value| identifiers & (1 << value.qfi.value()) != 0)
            {
                return Err(invalid("conflicting modify request qfi"));
            }
        }
        Ok(())
    }

    /// Encode present fields in schema order. Disjoint QFIs are checked first;
    /// each bounded field and then the complete container are capacity-checked
    /// before their allocation. Unknown values and diagnostics are not emitted.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.validate().map_err(|_| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "conflicting modify request qfi",
            })
        })?;
        let fields = [
            (
                130,
                self.aggregate_bit_rate.map(|v| v.encode(ctx)).transpose()?,
            ),
            (
                140,
                self.uplink_modifications
                    .as_ref()
                    .map(|v| v.encode(ctx))
                    .transpose()?,
            ),
            (
                135,
                self.add_or_modify
                    .as_ref()
                    .map(|v| v.encode(ctx))
                    .transpose()?,
            ),
            (
                137,
                self.release.as_ref().map(|v| v.encode(ctx)).transpose()?,
            ),
        ];
        let mut length = 3;
        let mut count = 0;
        for (_, value) in &fields {
            if let Some(value) = value {
                length += 3 + constructed::open_type_len(value.as_bytes().len())?;
                count += 1;
            }
        }
        capacity(length, ctx)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        constructed::write_prefix(&mut bytes, count);
        for (id, value) in &fields {
            if let Some(value) = value {
                constructed::write_ie(&mut bytes, *id, 0, value.as_bytes());
            }
        }
        Ok(EncodedValue(bytes))
    }

    /// Preflight the complete physical container before allocation or field
    /// materialization, then apply the shared duplicate/unknown IE policies.
    /// Retained unknown reject-criticality IEs prevent semantic admission.
    ///
    /// Depth is four for an empty root, six with AMBR, seven with identifier-only
    /// requests, eight with release causes, nine with tunnel modifications or
    /// ten with flow parameters. The container and each nested list separately
    /// use `max_ies`; `allocation_budget` remains advisory. These are SDK caller
    /// limits, not resource policy or a cumulative allocation budget.
    pub fn decode(
        input: &[u8],
        ctx: DecodeContext,
    ) -> Result<AdmittedModifyRequestTransfer, DecodeError> {
        bound(input, ctx, 4)?;
        if input.first().is_some_and(|v| v & 0x80 != 0) {
            return Err(unsupported());
        }
        let count = policy::preflight_ie_count(input, ctx, "modify request container")?;
        scan(input, count, |_| {})?;
        let mut entries = Vec::with_capacity(count);
        scan(input, count, |entry| entries.push(entry))?;
        let profile = policy::PDU_SESSION_RESOURCE_MODIFY_REQUEST_TRANSFER;
        policy::apply_ie_policy(
            &mut entries,
            count,
            profile,
            ctx,
            |ie| ie.id,
            |ie| ie.criticality,
        )?;
        let leaf = DecodeContext {
            max_depth: ctx.max_depth.saturating_sub(4),
            ..ctx
        };
        let mut transfer = Self::default();
        let mut ignored_ie_count = 0;
        let mut notify_ie_ids = Vec::new();
        for entry in &entries {
            if !profile.recognizes(entry.id) {
                match entry.criticality {
                    0 => return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)),
                    1 => ignored_ie_count += 1,
                    _ => notify_ie_ids.push(entry.id),
                }
                continue;
            }
            if !matches!(entry.id, 130 | 140 | 135 | 137) {
                return Err(unsupported());
            }
            let framed = aper::ie(entry.wire)?;
            match entry.id {
                130 => {
                    transfer.aggregate_bit_rate =
                        Some(SessionAggregateBitRate::decode(&framed.value, leaf)?)
                }
                140 => {
                    transfer.uplink_modifications =
                        Some(UplinkModifications::decode(&framed.value, leaf)?)
                }
                135 => {
                    transfer.add_or_modify =
                        Some(QosFlowModifications::decode(&framed.value, leaf)?)
                }
                137 => transfer.release = Some(QosFlowCauses::decode(&framed.value, leaf)?),
                _ => return Err(unsupported()),
            }
        }
        transfer.validate()?;
        Ok(AdmittedModifyRequestTransfer {
            transfer,
            ignored_ie_count,
            notify_ie_ids,
        })
    }
}

struct Entry<'a> {
    id: u16,
    criticality: u8,
    wire: &'a [u8],
}
fn scan<'a>(
    input: &'a [u8],
    count: usize,
    mut emit: impl FnMut(Entry<'a>),
) -> Result<(), DecodeError> {
    let mut remaining = &input[3..]; // count prefix was preflighted
    for _ in 0..count {
        let (next, header) = aper::scan_ie(remaining)?;
        if header[2] & 63 != 0 || header[2] >> 6 > 2 {
            return Err(invalid("modify request criticality framing"));
        }
        emit(Entry {
            id: u16::from_be_bytes([header[0], header[1]]),
            criticality: header[2] >> 6,
            wire: &remaining[..remaining.len() - next.len()],
        });
        remaining = next;
    }
    if !remaining.is_empty() {
        return Err(invalid("trailing modify request bytes"));
    }
    Ok(())
}
