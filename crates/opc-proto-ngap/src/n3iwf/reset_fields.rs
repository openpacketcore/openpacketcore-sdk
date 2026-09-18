//! Reset and Criticality Diagnostics root fields (TS 38.413 9.3.1.3,
//! 9.3.3.25). Independent vectors demonstrate generated count/alignment
//! defects; the bounded layouts here cover only these explicit root shapes.

use super::setup_fields::{Reader, Writer};
use super::*;

const MAX_CONNECTIONS: usize = 65536;

/// Optional peer connection identifiers, without a correlation or ownership
/// claim. An item with neither identifier is receiver-ignored, not a wildcard.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Connection {
    /// Optional peer AMF UE identifier.
    pub amf: Option<AmfUeId>,
    /// Optional local RAN UE identifier.
    pub ran: Option<RanUeId>,
}
redacted!(Connection);
impl Connection {
    /// Empty items are ignored under TS 38.413 8.7.4.4. They may be echoed or
    /// omitted from an acknowledgement; they never mean reset all.
    pub const fn is_empty(self) -> bool {
        self.amf.is_none() && self.ran.is_none()
    }
}

/// Ordered list of 1–65536 connection items, including legal empty items and
/// repetitions. Admission does not resolve IDs against any association state.
#[derive(Clone, PartialEq, Eq)]
pub struct Connections(Vec<Connection>);
redacted!(Connections);
impl Connections {
    /// Enforce the ASN.1 root count. No uniqueness rule is invented for Reset.
    pub fn new(values: Vec<Connection>) -> Result<Self, DecodeError> {
        if values.is_empty() || values.len() > MAX_CONNECTIONS {
            return Err(invalid("connection list count"));
        }
        Ok(Self(values))
    }
    /// Explicit received order, including empty and repeated items, for callers
    /// that must correlate or echo a partial-reset acknowledgement.
    pub fn values(&self) -> &[Connection] {
        &self.0
    }
    /// Receiver view that omits empty items while preserving order and repeats.
    pub fn nonempty(&self) -> impl Iterator<Item = &Connection> {
        self.0.iter().filter(|v| !v.is_empty())
    }
    /// Number of receiver-ignored empty items, without exposing identifiers.
    pub fn ignored_empty_count(&self) -> usize {
        self.0.iter().filter(|v| v.is_empty()).count()
    }
    /// Encode with exact capacity checked before output allocation. Large
    /// counts use element fragments, distinct from OCTET STRING fragments.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_root(ctx, |out| write_connections(out, &self.0))
    }
    /// Require depth three. Validate every fragment, item, integer and padding
    /// bit before allocating the result. `max_ies` bounds the cumulative count.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        decode_connections(input, ctx, false)
    }
}

/// Explicit full-interface or partial reset selection. An empty item in a
/// partial list is never promoted to an all-interface reset.
#[derive(Clone, PartialEq, Eq)]
pub enum ResetType {
    /// Reset all; this field alone authorizes no resource effect.
    All,
    /// Ordered partial list, with receiver-ignored empty items retained.
    Part(Connections),
}
redacted!(ResetType);
impl ResetType {
    /// Retain the qualified generated all-interface encoder; partial lists use
    /// the independently qualified bounded root layout and exact output size.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        match self {
            Self::All => encode_leaf(&asn::ResetType::nG_Interface(asn::ResetAll::reset_all), ctx),
            Self::Part(values) => encode_root(ctx, |out| {
                out.bits(1, 2)?;
                write_connections(out, &values.0)
            }),
        }
    }
    /// Require depth two for All and four for Part. Reject unsupported choices
    /// and extensions and preflight complete framing before materialization.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        match input.first().ok_or_else(|| invalid("missing reset type"))? >> 6 {
            0 => {
                if input != [0] {
                    return Err(invalid("reset all framing"));
                }
                let _: asn::ResetType = decode_leaf(input)?;
                Ok(Self::All)
            }
            1 => Ok(Self::Part(decode_connections(input, ctx, true)?)),
            _ => Err(unsupported()),
        }
    }
}

/// Procedure outcome named by Criticality Diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TriggeringOutcome {
    /// An initiating message.
    Initiating,
    /// A successful outcome.
    Successful,
    /// An unsuccessful outcome.
    Unsuccessful,
}
redacted!(TriggeringOutcome);

/// Permitted diagnostic IE criticality. TS 38.413 9.3.1.3 explicitly makes
/// ignore inapplicable for this item, though ASN.1 can represent it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCriticality {
    /// Reject criticality.
    Reject,
    /// Notify criticality.
    Notify,
}
redacted!(DiagnosticCriticality);

/// Root diagnostic error; extension values are unsupported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticError {
    /// The IE was not understood.
    NotUnderstood,
    /// The IE was missing.
    Missing,
}
redacted!(DiagnosticError);

/// Identifier-only diagnostic item, without the offending value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticItem {
    /// Criticality of the offending IE, restricted to reject or notify.
    pub criticality: DiagnosticCriticality,
    /// Offending IE identifier, never its opaque value.
    pub id: u16,
    /// Root error classification.
    pub error: DiagnosticError,
}
redacted!(DiagnosticItem);

/// Nonempty diagnostic list of at most 256 items. Repeated IE identifiers
/// remain in received order; the codec does not deduplicate peer reports.
#[derive(Clone, PartialEq, Eq)]
pub struct DiagnosticItems(Vec<DiagnosticItem>);
redacted!(DiagnosticItems);
impl DiagnosticItems {
    /// Enforce the ASN.1 root count. Use absent diagnostics for an empty list.
    pub fn new(values: Vec<DiagnosticItem>) -> Result<Self, DecodeError> {
        if values.is_empty() || values.len() > 256 {
            return Err(invalid("diagnostic list count"));
        }
        Ok(Self(values))
    }
    /// Explicit diagnostic metadata in received order.
    pub fn values(&self) -> &[DiagnosticItem] {
        &self.0
    }
}

/// Root Criticality Diagnostics. All root fields are optional. Whether a
/// procedure/outcome may carry particular fields is checked by its message
/// boundary; this field codec does not choose when an error must be reported.
#[derive(Clone, PartialEq, Eq)]
pub struct CriticalityDiagnostics {
    /// Procedure code; only appropriate in Error Indication diagnostics.
    pub procedure_code: Option<u8>,
    /// Triggering outcome; only appropriate in Error Indication diagnostics.
    pub triggering_outcome: Option<TriggeringOutcome>,
    /// Triggering procedure's criticality, including ignore when appropriate.
    pub procedure_criticality: Option<Criticality>,
    /// Optional nonempty diagnostic IE list.
    pub ies: Option<DiagnosticItems>,
}
redacted!(CriticalityDiagnostics);
impl CriticalityDiagnostics {
    /// Encode the qualified root layout, preserving its parent bit offset and
    /// checking exact output capacity before allocation.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_root(ctx, |out| write_diagnostics(out, self))
    }
    /// Require depth two without items, or four with items. Validate all flags,
    /// counts, enums, framing and padding before allocating an item vector.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let mut reader = Reader::new(input, ctx);
        let mut header = read_diagnostic_header(&mut reader)?;
        let mut count = 0;
        if header.1 {
            crate::enforce_depth(4, ctx)?;
            count = reader.count(8, 256, 22)?;
            for _ in 0..count {
                read_diagnostic_item(&mut reader)?;
            }
        }
        reader.finish()?;
        if count != 0 {
            let mut reader = Reader::new(input, ctx);
            read_diagnostic_header(&mut reader)?;
            reader.count(8, 256, 22)?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(read_diagnostic_item(&mut reader)?);
            }
            reader.finish()?;
            header.0.ies = Some(DiagnosticItems(values));
        }
        Ok(header.0)
    }
}

fn decode_connections(
    input: &[u8],
    ctx: DecodeContext,
    partial: bool,
) -> Result<Connections, DecodeError> {
    bound(input, ctx, if partial { 4 } else { 3 })?;
    let mut reader = Reader::new(input, ctx);
    if partial && reader.bits(2)? != 1 {
        return Err(invalid("partial reset choice"));
    }
    let count = read_connections(&mut reader, |_| {})?;
    reader.finish()?;
    let mut values = Vec::with_capacity(count);
    let mut reader = Reader::new(input, ctx);
    if partial {
        reader.bits(2)?;
    }
    read_connections(&mut reader, |v| values.push(v))?;
    reader.finish()?;
    Ok(Connections(values))
}

fn read_connections(
    reader: &mut Reader<'_>,
    mut item: impl FnMut(Connection),
) -> Result<usize, DecodeError> {
    let mut total = 0;
    loop {
        let (count, fragmented) = reader.fragment_count(MAX_CONNECTIONS - total, 4)?;
        total += count;
        for _ in 0..count {
            reader.flags(1)?;
            let has_amf = reader.bits(1)? != 0;
            let has_ran = reader.bits(1)? != 0;
            reader.flags(1)?;
            let amf = if has_amf {
                Some(AmfUeId::new(read_integer(reader, 3, 5)?)?)
            } else {
                None
            };
            let ran = if has_ran {
                Some(RanUeId::new(read_integer(reader, 2, 4)? as u32))
            } else {
                None
            };
            item(Connection { amf, ran });
        }
        if !fragmented {
            break;
        }
    }
    if total == 0 {
        return Err(invalid("connection list count"));
    }
    Ok(total)
}

fn read_integer(reader: &mut Reader<'_>, width: usize, maximum: usize) -> Result<u64, DecodeError> {
    let length = usize::from(reader.bits(width)?) + 1;
    if length > maximum {
        return Err(invalid("connection identifier length"));
    }
    reader.align()?;
    let first = reader.bits(8)?;
    if length > 1 && first == 0 {
        return Err(invalid("nonminimal connection identifier"));
    }
    let mut value = u64::from(first);
    for _ in 1..length {
        value = (value << 8) | u64::from(reader.bits(8)?);
    }
    Ok(value)
}

pub(super) fn read_diagnostic_header(
    reader: &mut Reader<'_>,
) -> Result<(CriticalityDiagnostics, bool), DecodeError> {
    reader.flags(1)?;
    let code = reader.bits(1)? != 0;
    let trigger = reader.bits(1)? != 0;
    let criticality = reader.bits(1)? != 0;
    let items = reader.bits(1)? != 0;
    reader.flags(1)?;
    let procedure_code = if code {
        reader.align()?;
        Some(reader.bits(8)? as u8)
    } else {
        None
    };
    let triggering_outcome = if trigger {
        Some(match reader.bits(2)? {
            0 => TriggeringOutcome::Initiating,
            1 => TriggeringOutcome::Successful,
            2 => TriggeringOutcome::Unsuccessful,
            _ => return Err(invalid("diagnostic trigger")),
        })
    } else {
        None
    };
    let procedure_criticality = if criticality {
        Some(match reader.bits(2)? {
            0 => Criticality::reject,
            1 => Criticality::ignore,
            2 => Criticality::notify,
            _ => return Err(invalid("diagnostic criticality")),
        })
    } else {
        None
    };
    Ok((
        CriticalityDiagnostics {
            procedure_code,
            triggering_outcome,
            procedure_criticality,
            ies: None,
        },
        items,
    ))
}

pub(super) fn read_diagnostic_item(reader: &mut Reader<'_>) -> Result<DiagnosticItem, DecodeError> {
    reader.flags(2)?;
    let criticality = match reader.bits(2)? {
        0 => DiagnosticCriticality::Reject,
        2 => DiagnosticCriticality::Notify,
        _ => return Err(invalid("diagnostic ie criticality")),
    };
    reader.align()?;
    let id = reader.bits(16)?;
    reader.flags(1)?;
    let error = if reader.bits(1)? == 0 {
        DiagnosticError::NotUnderstood
    } else {
        DiagnosticError::Missing
    };
    Ok(DiagnosticItem {
        criticality,
        id,
        error,
    })
}

// One layout pass measures without allocation; a second writes into an exact
// zeroized buffer. Both passes execute the same bounded root field traversal.
pub(super) trait Sink {
    fn bits(&mut self, value: u16, width: usize) -> Result<(), EncodeError>;
    fn align(&mut self);
}
impl Sink for Writer {
    fn bits(&mut self, value: u16, width: usize) -> Result<(), EncodeError> {
        Writer::bits(self, value, width)
    }
    fn align(&mut self) {
        Writer::align(self);
    }
}
struct Measure(usize);
impl Sink for Measure {
    fn bits(&mut self, _: u16, width: usize) -> Result<(), EncodeError> {
        self.0 = self.0.checked_add(width).ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "reset field length",
            })
        })?;
        Ok(())
    }
    fn align(&mut self) {
        self.0 = self.0.div_ceil(8) * 8;
    }
}
pub(super) fn encode_root(
    ctx: EncodeContext,
    write: impl Fn(&mut dyn Sink) -> Result<(), EncodeError>,
) -> Result<EncodedValue, EncodeError> {
    let mut measure = Measure(0);
    write(&mut measure)?;
    let length = measure.0.div_ceil(8);
    capacity(length, ctx)?;
    let mut out = Writer::new(length);
    write(&mut out)?;
    out.finish()
}

fn write_connections(out: &mut dyn Sink, mut values: &[Connection]) -> Result<(), EncodeError> {
    loop {
        out.align();
        let fragmented = values.len() >= 16384;
        let count = if fragmented {
            let blocks = (values.len() / 16384).min(4);
            out.bits(0xc0 | blocks as u16, 8)?;
            blocks * 16384
        } else {
            if values.len() < 128 {
                out.bits(values.len() as u16, 8)?;
            } else {
                out.bits(0x8000 | values.len() as u16, 16)?;
            }
            values.len()
        };
        for value in &values[..count] {
            out.bits(
                (u16::from(value.amf.is_some()) << 2) | (u16::from(value.ran.is_some()) << 1),
                4,
            )?;
            if let Some(amf) = value.amf {
                write_integer(out, amf.value(), 3)?;
            }
            if let Some(ran) = value.ran {
                write_integer(out, u64::from(ran.value()), 2)?;
            }
        }
        values = &values[count..];
        if !fragmented {
            break;
        }
    }
    Ok(())
}
fn write_integer(out: &mut dyn Sink, value: u64, width: usize) -> Result<(), EncodeError> {
    let length = ((64 - value.leading_zeros() as usize).div_ceil(8)).max(1);
    out.bits((length - 1) as u16, width)?;
    out.align();
    for index in (0..length).rev() {
        out.bits(((value >> (index * 8)) & 255) as u16, 8)?;
    }
    Ok(())
}
pub(super) fn write_diagnostics(
    out: &mut dyn Sink,
    value: &CriticalityDiagnostics,
) -> Result<(), EncodeError> {
    let flags = (u16::from(value.procedure_code.is_some()) << 4)
        | (u16::from(value.triggering_outcome.is_some()) << 3)
        | (u16::from(value.procedure_criticality.is_some()) << 2)
        | (u16::from(value.ies.is_some()) << 1);
    out.bits(flags, 6)?;
    if let Some(code) = value.procedure_code {
        out.align();
        out.bits(u16::from(code), 8)?;
    }
    if let Some(trigger) = value.triggering_outcome {
        out.bits(
            match trigger {
                TriggeringOutcome::Initiating => 0,
                TriggeringOutcome::Successful => 1,
                TriggeringOutcome::Unsuccessful => 2,
            },
            2,
        )?;
    }
    if let Some(criticality) = value.procedure_criticality {
        out.bits(criticality as u16, 2)?;
    }
    if let Some(items) = &value.ies {
        out.align();
        out.bits((items.0.len() - 1) as u16, 8)?;
        for item in &items.0 {
            out.bits(
                match item.criticality {
                    DiagnosticCriticality::Reject => 0,
                    DiagnosticCriticality::Notify => 2,
                },
                4,
            )?;
            out.align();
            out.bits(item.id, 16)?;
            out.bits(
                match item.error {
                    DiagnosticError::NotUnderstood => 0,
                    DiagnosticError::Missing => 1,
                },
                2,
            )?;
        }
    }
    Ok(())
}
