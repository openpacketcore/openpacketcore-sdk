//! Detached verified receipt reads. A file range is a comparison input, not
//! current application authority. Capture and final comparison run under the
//! owning State lock; every file access and decode runs after releasing it.
//!
//! This first cold-row codec uses the existing complete bounded V2 response
//! codec. It neither enables a generation format nor evicts a resident row.
//! Selection, compact indexes, and the WAL owner's current Recovery/authority
//! check are separate integration obligations; a business proof cannot replace
//! them. In particular, `copy_current` must run AFTER `ensure_readable` and the
//! same current authority checks as the original live read.

use std::io::Write;
use std::mem::size_of;
use std::sync::Arc;

use super::prefix::VerifiedPrefix;
use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use crate::fenced_transition::FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES;

// A distinct row discriminator freezes this vocabulary independently of the
// OPCNAT01/02 readers. It is not accepted by either old full-image reader.
const MAGIC: &[u8; 8] = b"OPCNRC01";
const HEADER_BYTES: usize = 8 + 56 + 8 + 32 + 8 + 4 + 4;
pub(super) const MAX_BYTES: usize = HEADER_BYTES + FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES;
// One complete input, the response decoder's bounded owned fields, and the
// old/new capacity overlap of its canonical response encoding. The additional
// 64KiB covers all fixed model/Arc/Box/identifier and timestamp work. Unlike
// a generic SessionConsensusResponse deserializer, the V2 codec cannot select
// an arbitrary nested ConsumerRecord or batch from these untrusted bytes.
const READ_BYTES: usize =
    MAX_BYTES + 4 * FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES + 64 * 1024;

// Independent output ownership: one complete boxed response plus its only
// possible allocated V2 success fields (tenant <=128, NF <=64, custom key
// type, stable ID and owner). Double their byte capacities and allow 64 bytes
// per allocation plus the Bytes control block. Scalar-only admitted errors
// allocate none. This must stay with ReceiptCopies after ResolvedReceipt and
// READ_BYTES drop; the response pointer inside NativeReceipt is insufficient.
pub(super) const OWNED_COPY_BYTES: usize = size_of::<SessionConsensusResponse>()
    + 2 * (128
        + 64
        + crate::model::SESSION_KEY_TYPE_MAX_BYTES
        + crate::model::STABLE_ID_MAX_BYTES
        + crate::model::OWNER_ID_MAX_BYTES)
    + 5 * 64
    + 16 * size_of::<usize>();

/// An untrusted range descriptor. It owns no file and is never serialized as
/// a certificate. A read ticket pins the exact admitted source separately.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReceiptRange {
    offset: u64,
    length: u32,
}

impl ReceiptRange {
    pub(super) fn new(offset: u64, length: u32) -> io::Result<Self> {
        if !(HEADER_BYTES..=MAX_BYTES).contains(&(length as usize))
            || offset.checked_add(u64::from(length)).is_none()
        {
            return Err(invalid("native cold receipt range invalid"));
        }
        Ok(Self { offset, length })
    }

    pub(super) fn offset(self) -> u64 {
        self.offset
    }

    pub(super) fn end(self) -> u64 {
        self.offset + u64::from(self.length)
    }
}

/// Only scalar fields precede the existing response bytes. The complete
/// 56-byte request ID, expiry tombstone and original response metadata remain
/// explicit; expiry does not become deletion or an inferred default.
pub(super) fn write_receipt(
    writer: &mut (impl Write + ?Sized),
    id: FencedTransitionV2RequestId,
    row: &NativeReceipt,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<usize> {
    check()?;
    let _memory = VerificationMemory::reserve(READ_BYTES)?;
    if row.cold.is_some() {
        return Err(invalid("native receipt encoder requires a resolved row"));
    }
    if !fenced_transition_v2_timestamp_is_in_range(row.retained_until) {
        return Err(invalid("native cold receipt timestamp invalid"));
    }
    let response = row
        .response
        .as_deref()
        .map(crate::sqlite::consensus::encode_fenced_transition_v2_response)
        .transpose()?;
    let length = response.as_ref().map_or(0, Vec::len);
    let timestamp = row.retained_until.as_offset_datetime();
    writer.write_all(MAGIC)?;
    writer.write_all(&id.to_bytes())?;
    writer.write_all(&row.ordinal.to_le_bytes())?;
    writer.write_all(&row.payload_digest)?;
    writer.write_all(&timestamp.unix_timestamp().to_le_bytes())?;
    writer.write_all(&timestamp.nanosecond().to_le_bytes())?;
    writer.write_all(
        &u32::try_from(length)
            .map_err(|_| invalid("native cold response length invalid"))?
            .to_le_bytes(),
    )?;
    if let Some(response) = &response {
        writer.write_all(response)?;
    }
    check()?;
    Ok(HEADER_BYTES + length)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> io::Result<[u8; N]> {
    let value = bytes
        .get(..N)
        .ok_or_else(|| invalid("native cold receipt truncated"))?
        .try_into()
        .map_err(|_| invalid("native cold receipt field invalid"))?;
    *bytes = &bytes[N..];
    Ok(value)
}

fn decode(bytes: &[u8]) -> io::Result<(FencedTransitionV2RequestId, NativeReceipt)> {
    if !(HEADER_BYTES..=MAX_BYTES).contains(&bytes.len()) {
        return Err(invalid("native cold receipt extent invalid"));
    }
    let mut remaining = bytes;
    if &take::<8>(&mut remaining)? != MAGIC {
        return Err(invalid("native cold receipt discriminator invalid"));
    }
    let id_array = take::<56>(&mut remaining)?;
    let id = receipt_id(id_array)?;
    let ordinal = u64::from_le_bytes(take(&mut remaining)?);
    let payload_digest = take(&mut remaining)?;
    let seconds = i64::from_le_bytes(take(&mut remaining)?);
    let nanoseconds = u32::from_le_bytes(take(&mut remaining)?);
    if nanoseconds >= 1_000_000_000 {
        return Err(invalid("native cold receipt timestamp invalid"));
    }
    let retained_until = time::OffsetDateTime::from_unix_timestamp(seconds)
        .and_then(|value| value.replace_nanosecond(nanoseconds))
        .map(Timestamp::from_offset_datetime)
        .map_err(|_| invalid("native cold receipt timestamp invalid"))?;
    if !fenced_transition_v2_timestamp_is_in_range(retained_until) {
        return Err(invalid("native cold receipt timestamp outside profile"));
    }
    let length = u32::from_le_bytes(take(&mut remaining)?) as usize;
    if length > FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES || remaining.len() != length {
        return Err(invalid("native cold response extent invalid"));
    }
    let response = if length == 0 {
        None
    } else {
        let response = crate::sqlite::consensus::decode_fenced_transition_v2_response(remaining)?;
        if crate::sqlite::consensus::encode_fenced_transition_v2_response(&response)? != remaining {
            return Err(invalid("native cold response is not canonical"));
        }
        Some(Arc::new(response))
    };
    Ok((
        id,
        NativeReceipt {
            ordinal,
            payload_digest,
            retained_until,
            response,
            cold: None,
        },
    ))
}

pub(super) fn receipt_id(bytes: [u8; 56]) -> io::Result<FencedTransitionV2RequestId> {
    let mut bytes = bytes.as_slice();
    let epoch = crate::fenced_transition::FencedTransitionV2HistoryEpoch::new(u64::from_be_bytes(
        take(&mut bytes)?,
    ))
    .map_err(|_| invalid("native cold receipt ID invalid"))?;
    let nonce =
        crate::fenced_transition::FencedTransitionV2CallerNonce::from_bytes(take(&mut bytes)?);
    Ok(FencedTransitionV2RequestId::from_parts(
        epoch,
        nonce,
        take(&mut bytes)?,
    ))
}

// Only fixed metadata leaves this closed arbitrary-byte decoder. The catalog
// retains its own resident index; no decoder-owned response allocation moves
// into that index or outlives the reservation below.
pub(super) fn inspect_generation_bytes(
    bytes: &[u8],
    id: FencedTransitionV2RequestId,
    identity: SessionConsensusIdentity,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<generation::facts::Row<generation::facts::Receipt>> {
    check()?;
    let _memory = VerificationMemory::reserve(READ_BYTES)?;
    let (actual, row) = decode(bytes)?;
    if actual != id {
        return Err(invalid(
            "native catalog receipt repeats a different complete ID",
        ));
    }
    let history = frontiers
        .history
        .ok_or_else(|| invalid("native catalog receipt history absent"))?;
    validation::validate_receipt(identity, &id, &row, frontiers, history)?;
    let facts = generation::facts::Receipt::of(id, &row)?;
    drop(row);
    check()?;
    Ok(facts)
}

// Closed expected-readback use by generation framing. No decoded field is
// exported. The input owner is separately reserved by that frame reader.
pub(super) fn verify_generation_bytes(
    bytes: &[u8],
    id: FencedTransitionV2RequestId,
    expected: &NativeReceipt,
    proof: &changes::BusinessProof,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    let _memory = VerificationMemory::reserve(READ_BYTES)?;
    let (decoded_id, row) = decode(bytes)?;
    if decoded_id != id || !expected.matches_decoded(id, &row)? {
        return Err(invalid(
            "native generation receipt differs from captured row",
        ));
    }
    let (identity, _, frontiers) = proof.context();
    let history = frontiers
        .history
        .ok_or_else(|| invalid("native generation receipt history absent"))?;
    validation::validate_receipt(identity, &id, &row, frontiers, history)?;
    check()
}

/// A bounded read captures both the admitted byte source and the exact live
/// predecessor. Strong ownership prevents address reuse while it is in flight.
/// The existing row is deliberately retained until integration can replace it
/// with an equally exact compact revision/index after durable selection.
pub(super) struct ReceiptReadTicket {
    source: Arc<VerifiedPrefix>,
    range: ReceiptRange,
    id: FencedTransitionV2RequestId,
    proof: Arc<changes::BusinessProof>,
    row: SharedRow<NativeReceipt>,
    _memory: VerificationMemory,
}

impl ReceiptReadTicket {
    // Bounded scalar/Arc work only: no disk, codec, cache lock, container scan,
    // or wait. The caller already owns the SDK State lock and checks authority.
    pub(super) fn capture(
        state: &NativeState,
        id: FencedTransitionV2RequestId,
        source: Arc<VerifiedPrefix>,
        range: ReceiptRange,
    ) -> io::Result<Self> {
        let proof = state.require_business_proof()?;
        if range.end() > source.identity().length {
            return Err(invalid("native cold receipt exceeds captured prefix"));
        }
        let row = state
            .receipts
            .get(&id)
            .ok_or_else(|| invalid("native cold receipt revision missing"))?;
        if row.cold_range().is_some_and(|(expected, expected_range)| {
            !Arc::ptr_eq(&expected, &source) || expected_range != range
        }) {
            return Err(invalid("native cold receipt range is not its selected row"));
        }
        let memory = VerificationMemory::reserve(
            8 * (size_of::<Self>() + size_of::<FencedTransitionV2RequestId>())
                + 256
                + OWNED_COPY_BYTES,
        )?;
        Ok(Self {
            source,
            range,
            id,
            proof: Arc::clone(proof),
            row: row.clone(),
            _memory: memory,
        })
    }

    /// Run outside State. The returned object's guard continues to own all
    /// decoded allocations until that object drops, including on cancellation,
    /// failed currentness, downstream errors and unwinding.
    pub(super) fn resolve(
        self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<ResolvedReceipt> {
        self.resolve_with(check, VerificationMemory::reserve)
    }

    fn resolve_with(
        self,
        check: &impl Fn() -> io::Result<()>,
        reserve: impl FnOnce(usize) -> io::Result<VerificationMemory>,
    ) -> io::Result<ResolvedReceipt> {
        check()?;
        let memory = reserve(READ_BYTES)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.range.length as usize)
            .map_err(|_| invalid("native cold receipt buffer allocation failed"))?;
        bytes.resize(self.range.length as usize, 0);
        self.source.read_exact_at(self.range.offset, &mut bytes)?;
        check()?;
        let (id, row) = decode(&bytes)?;
        if id != self.id || !self.row.matches_decoded(id, &row)? {
            return Err(invalid(
                "native cold receipt differs from captured revision",
            ));
        }
        let (identity, _, frontiers) = self.proof.context();
        let history = frontiers
            .history
            .ok_or_else(|| invalid("native cold receipt history missing"))?;
        validation::validate_receipt(identity, &id, &row, frontiers, history)?;
        drop(bytes);
        check()?;
        Ok(ResolvedReceipt {
            row,
            ticket: self,
            _memory: memory,
        })
    }
}

pub(super) struct ResolvedReceipt {
    // Rust drops fields in declaration order. The decoded owned response and
    // ticket/source references are destroyed before either reservation refunds.
    row: NativeReceipt,
    ticket: ReceiptReadTicket,
    _memory: VerificationMemory,
}

pub(super) struct OwnedReceipt {
    row: NativeReceipt,
    _memory: VerificationMemory,
}

impl OwnedReceipt {
    pub(super) fn row(&self) -> &NativeReceipt {
        &self.row
    }
}

impl ResolvedReceipt {
    pub(super) fn matches_revision(&self, row: &SharedRow<NativeReceipt>) -> bool {
        self.ticket.row.ptr_eq(row)
    }

    pub(super) fn copy_guarded(&self, state: &NativeState) -> io::Result<OwnedReceipt> {
        let memory = VerificationMemory::reserve(size_of::<OwnedReceipt>() + OWNED_COPY_BYTES)?;
        let row = self.copy_current(state)?;
        Ok(OwnedReceipt {
            row,
            _memory: memory,
        })
    }

    /// Business-currentness only. The WAL adapter must also recheck its owner
    /// fence and the complete current authority/Recovery state under State.
    /// Comparison uses no I/O, wait or decoding; the following bounded output
    /// copy belongs to the caller, independently of the read reservation.
    /// No borrowed decoded value or arbitrary callback can export an alias to
    /// its backing storage. In particular, ordinary StableId/response/outcome
    /// Clone would share Bytes and cannot implement this ownership boundary.
    pub(super) fn copy_current(&self, state: &NativeState) -> io::Result<NativeReceipt> {
        let current = state.require_business_proof()?;
        if !Arc::ptr_eq(current, &self.ticket.proof)
            || state
                .receipts
                .get(&self.ticket.id)
                .is_none_or(|row| !row.ptr_eq(&self.ticket.row))
        {
            return Err(invalid("native cold receipt owner revision changed"));
        }
        self.copy_owned()
    }

    /// Revalidate the exact immutable row against the complete CURRENT
    /// business context. Unrelated keys/application progress may have advanced
    /// while disk work ran. A replaced row contributes no copied response;
    /// the live tombstone/retirement/current row is interpreted under State.
    /// The adapter must first recheck its live owner and Recovery authority.
    pub(super) fn copy_matching_row(
        &self,
        state: &NativeState,
    ) -> io::Result<Option<NativeReceipt>> {
        copy_matching_receipt(
            state,
            self.ticket.id,
            &self.ticket.proof,
            &self.ticket.row,
            &self.row,
        )
    }

    fn copy_owned(&self) -> io::Result<NativeReceipt> {
        copy_receipt(&self.row)
    }
}

pub(super) fn copy_matching_receipt(
    state: &NativeState,
    id: FencedTransitionV2RequestId,
    proof: &changes::BusinessProof,
    captured: &SharedRow<NativeReceipt>,
    decoded: &NativeReceipt,
) -> io::Result<Option<NativeReceipt>> {
    let current = state.require_business_proof()?;
    let (identity, members, frontiers) = current.context();
    let (captured_identity, captured_members, _) = proof.context();
    if identity != captured_identity || members != captured_members {
        return Err(invalid("native receipt read authority changed"));
    }
    if state
        .receipts
        .get(&id)
        .is_none_or(|row| !row.ptr_eq(captured))
    {
        return Ok(None);
    }
    let history = frontiers
        .history
        .ok_or_else(|| invalid("native current receipt history absent"))?;
    if history
        .retired_through()
        .is_some_and(|floor| id.epoch().get() <= floor.get())
    {
        return Ok(None);
    }
    // The current-context validator re-encodes the fixed response. This
    // transient reservation also covers resident rows in a mixed read set,
    // which have no preceding decoder guard. Output ownership is separate.
    let _scratch = VerificationMemory::reserve(READ_BYTES)?;
    validation::validate_receipt(identity, &id, decoded, frontiers, history)?;
    copy_receipt(decoded).map(Some)
}

fn copy_receipt(row: &NativeReceipt) -> io::Result<NativeReceipt> {
    if row.cold.is_some() {
        return Err(invalid("native receipt copy is unresolved"));
    }
    Ok(NativeReceipt {
        ordinal: row.ordinal,
        payload_digest: row.payload_digest,
        retained_until: row.retained_until,
        response: row
            .response
            .as_deref()
            .map(copy_response)
            .transpose()?
            .map(Arc::new),
        cold: None,
    })
}

// The decoded V2 vocabulary has one success shape and scalar-only errors.
// Keep that restriction explicit so extending the general response enum can
// never silently introduce a shared allocation across this output boundary.
pub(super) fn copy_response(
    response: &SessionConsensusResponse,
) -> io::Result<SessionConsensusResponse> {
    let result = match &response.result {
        Ok(SessionMutationOutcome::FencedTransition(outcome)) => Ok(
            SessionMutationOutcome::FencedTransition(copy_outcome(outcome)?),
        ),
        Err(
            error @ (StoreError::TopologyAuthorityRevoked
            | StoreError::NotFound
            | StoreError::StaleFence
            | StoreError::CasConflict
            | StoreError::InvalidSessionTtl
            | StoreError::InvalidRecordExpiry
            | StoreError::LeaseHeld
            | StoreError::LeaseExpired
            | StoreError::PayloadTooLarge { .. }
            | StoreError::FencedTransitionStorageExhausted),
        ) => Err(error.clone()),
        _ => return Err(invalid("native cold output response outside V2 profile")),
    };
    Ok(SessionConsensusResponse {
        result,
        sequence: response.sequence,
        digest: response.digest,
        logical_time: response.logical_time,
        raft_log_index: response.raft_log_index,
    })
}

pub(super) fn copy_outcome(
    outcome: &FencedTransitionOutcome,
) -> io::Result<FencedTransitionOutcome> {
    let lease = outcome.lease();
    let key = lease.key();
    let copied_key = SessionKey {
        tenant: key.tenant.clone(),
        nf_kind: key.nf_kind.clone(),
        key_type: key.key_type.clone(),
        // Both decoder -> read scratch and read scratch -> caller output
        // need independent ownership. Clone would retain the Bytes backing.
        stable_id: crate::model::StableId::try_from(key.stable_id.as_bytes())
            .map_err(|_| invalid("native cold output identifier invalid"))?,
    };
    let copied_lease = LeaseGuard::new(
        copied_key,
        lease.owner().clone(),
        lease.fence(),
        lease.acquired_at(),
        lease.expires_at(),
        lease.credential_id(),
    );
    FencedTransitionOutcome::new(
        copied_lease,
        outcome.committed_generation(),
        outcome.mutation(),
        outcome.recorded_at(),
    )
    .map_err(|_| invalid("native cold output outcome invalid"))
}

#[cfg(test)]
#[path = "cold_tests.rs"]
mod tests;
