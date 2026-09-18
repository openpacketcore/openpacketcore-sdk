//! UE Context Release Complete session reports (TS 38.413 8.3.3, 9.2.2.6).
//! Reports carry identifiers and optional qualified release-response transfers;
//! the caller correlates them and performs the actual resource cleanup.

use super::resource_release::ReleaseResponseTransfer;
use super::session_lists::{encode_list, unique_id, validate_ids, SessionId};
use super::setup_fields::Reader;
use super::*;

/// One reported session; absence of a transfer differs from a present empty root.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ContextReleasedSession {
    /// Peer-reported session identifier, without an ownership claim.
    pub id: SessionId,
    /// Optional empty release-response transfer; usage extensions are unsupported.
    pub transfer: Option<ReleaseResponseTransfer>,
}
redacted!(ContextReleasedSession);

/// Nonempty list of 1–256 unique session reports in received order.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextReleasedSessions(Vec<ContextReleasedSession>);
redacted!(ContextReleasedSessions);
impl ContextReleasedSessions {
    /// Enforce the root count and unique session identifiers.
    pub fn new(values: Vec<ContextReleasedSession>) -> Result<Self, DecodeError> {
        validate_ids(values.iter().map(|v| v.id), values.len())?;
        Ok(Self(values))
    }
    /// Explicit reported values; a decoded report does not establish release.
    pub fn values(&self) -> &[ContextReleasedSession] {
        &self.0
    }
    /// Preflight exact capacity before materializing qualified generated values.
    /// The single admitted item extension is Release Response Transfer 145/ignore.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length =
            1 + 2 * self.0.len() + 8 * self.0.iter().filter(|v| v.transfer.is_some()).count();
        capacity(length, ctx)?;
        let values = self.0.iter().map(|v| {
            let extensions = v.transfer.map(|_| {
                asn::PDUSessionResourceItemCxtRelCplIEExtensions(vec![
                    asn::AnonymousPDUSessionResourceItemCxtRelCplIEExtensions::new(
                        145,
                        asn::AnonymousPDUSessionResourceItemCxtRelCplIEExtensionsCriticality::ignore,
                        // Qualified empty transfer, wrapped as an OCTET STRING.
                        rasn::types::Any::new(vec![1, 0]),
                    ),
                ])
            });
            asn::PDUSessionResourceItemCxtRelCpl::new(asn::PDUSessionID(v.id.value()), extensions)
        }).collect();
        encode_list(&asn::PDUSessionResourceListCxtRelCpl(values), length)
    }
    /// Require field depth three without transfers, or six with them. Scan all
    /// counts, flags, identifiers and nested framing before generated allocation.
    /// Exactly one 145/ignore extension is admitted per item; others reject.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        scan(input, ctx)?;
        let value: asn::PDUSessionResourceListCxtRelCpl = decode_leaf(input)?;
        Ok(Self(
            value
                .0
                .iter()
                .map(|v| ContextReleasedSession {
                    id: SessionId::new(v.p_dusession_id.0),
                    transfer: v.i_e_extensions.as_ref().map(|_| ReleaseResponseTransfer),
                })
                .collect(),
        ))
    }
    pub(super) fn message_preflight(&self, ctx: DecodeContext) -> Result<(), DecodeError> {
        crate::enforce_depth(
            if self.0.iter().any(|v| v.transfer.is_some()) {
                10
            } else {
                7
            },
            ctx,
        )?;
        if self.0.len() > ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        Ok(())
    }
}
fn scan(input: &[u8], ctx: DecodeContext) -> Result<(), DecodeError> {
    bound(input, ctx, 3)?;
    let mut reader = Reader::new(input, ctx);
    let count = reader.count(8, 256, 16)?;
    let mut seen = [0; 4];
    for _ in 0..count {
        let flags = reader.bits(2)?;
        if flags & 2 != 0 {
            return Err(unsupported());
        }
        reader.align()?;
        unique_id(&mut seen, SessionId::new(reader.bits(8)? as u8))?;
        if flags & 1 != 0 {
            crate::enforce_depth(6, ctx)?;
            if reader.bits(16)? != 0 || reader.bits(16)? != 145 || reader.bits(2)? != 1 {
                return Err(unsupported());
            }
            reader.align()?;
            let value = reader.open_octets(2)?;
            // This subset's contained transfer has one canonical zero octet.
            // Check its OCTET STRING framing as well as the outer open type.
            if value.as_ref() != [1, 0] {
                return Err(unsupported());
            }
        }
    }
    reader.finish()
}
