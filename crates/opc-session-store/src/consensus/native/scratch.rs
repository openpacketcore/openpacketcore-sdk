//! Temporary verification work for detached, process-certified captures.
//!
//! These are allocation reservations, not new durable row or batch limits.
//! Cold parsing and resident-row ownership have separate lifetimes and must
//! retain their own reservations when the persistence path is integrated.

use super::*;
use crate::consensus::types::MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS;
use crate::consensus::verified_snapshot::VerificationMemory;
use std::mem::size_of;

// Per closed V2 request shape, 128 key slots cover all nested object fields.
// Each 512-byte slot covers a decoded field name and even a separate B-tree
// node; the traversal retains only keys of currently open maps. This also
// exceeds the fixed model/Arc/Box descriptors and bounded identifier storage.
// Count the public 256-request profile, never the benchmark's batch of eight.
const REQUEST_METADATA: usize = 128 * 512;
const CONTEXT_METADATA: usize = 64 * 1024;

// These two boundary fixtures each deliberately consume most of the one
// process budget. Serialize only their construction/verification in the test
// harness; production keeps the original shared reservation and denial rules.
#[cfg(test)]
pub(super) static LARGE_ROW_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn add(left: usize, right: usize) -> io::Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| invalid("native verification scratch overflow"))
}
fn mul(left: usize, right: usize) -> io::Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| invalid("native verification scratch overflow"))
}

fn log_bytes(row: &log::NativeLogEntry) -> io::Result<usize> {
    if row.is_cold() {
        return Ok(CONTEXT_METADATA);
    }
    let row = row.resident()?;
    let mut count = 0;
    let mut largest_payload = 0;
    let mut request = |request: &FencedTransitionV2Request| {
        count += 1;
        if let Some(record) = request.mutation().record() {
            largest_payload = largest_payload.max(record.payload.len());
        }
    };
    if let EntryPayload::Normal(command) = &row.entry.payload {
        let intent = match &command.intent {
            SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
            intent => intent,
        };
        match intent {
            SessionMutationIntent::AdvanceLogicalTime => {}
            SessionMutationIntent::MaintainFencedTransitionV2History { .. } => {
                count = 1;
            }
            SessionMutationIntent::ActivateFencedTransitionCapability { .. } => {
                count = 1;
            }
            SessionMutationIntent::ActivateProtectedRosterProfileV2 { .. } => {
                count = 1;
            }
            SessionMutationIntent::RosterAdmission(value)
            | SessionMutationIntent::RosterAdmissionV2(value) => {
                count = 1;
                largest_payload = value
                    .native_read_allocation_bytes()
                    .ok_or_else(|| invalid("native roster command allocation overflow"))?;
            }
            SessionMutationIntent::RosterTerminal(value) => {
                count = 1;
                largest_payload = value
                    .native_read_allocation_bytes()
                    .ok_or_else(|| invalid("native roster command allocation overflow"))?;
            }
            SessionMutationIntent::RosterTerminalV2(value) => {
                count = 1;
                largest_payload = value
                    .native_read_allocation_bytes()
                    .ok_or_else(|| invalid("native roster command allocation overflow"))?;
            }
            SessionMutationIntent::FencedTransition(value)
            | SessionMutationIntent::ActivateFencedTransition { request: value, .. } => {
                count = 1;
                largest_payload = value
                    .mutation()
                    .record()
                    .map_or(0, |record| record.payload.len());
            }
            SessionMutationIntent::CompareAndSet(op) => {
                count = 1;
                largest_payload = op.new_record.payload.len();
            }
            SessionMutationIntent::DeleteFenced(_)
            | SessionMutationIntent::RefreshTtl { .. }
            | SessionMutationIntent::AcquireLease { .. }
            | SessionMutationIntent::RenewLease { .. }
            | SessionMutationIntent::ReleaseLease(_)
            | SessionMutationIntent::BindConsumerRequest { .. }
            | SessionMutationIntent::ReadConsumerRecord { .. } => {
                count = 1;
            }
            SessionMutationIntent::FencedTransitionV2(value)
            | SessionMutationIntent::ActivateFencedTransitionV2 { request: value, .. } => {
                request(value)
            }
            SessionMutationIntent::FencedTransitionV2Batch(requests) => {
                if requests.len() > MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS {
                    return Err(invalid(
                        "native captured batch exceeds its admitted profile",
                    ));
                }
                for value in requests {
                    request(value);
                }
            }
            _ => return Err(invalid("native private log command is not implemented")),
        }
    }
    log_peak(row.encoded.len(), count, largest_payload)
}

pub(super) fn log_peak(
    encoded: usize,
    requests: usize,
    largest_payload: usize,
) -> io::Result<usize> {
    // Callers first establish this allocation shape through either a captured
    // immutable revision with complete predecessor/target stamp equations, or
    // the borrowing arbitrary-byte generation JSON preflight. Both shapes have
    // one authority envelope, bounded model
    // fields, at most the public batch count, and opaque numeric byte arrays.
    // Two input widths cover retained decoded bytes, String parsing backing,
    // payload chunk/final overlap and their growth descriptors. The fixed
    // request charge covers small/empty arrays and model/container overhead.
    // Roster capsule JSON consumes at least two input bytes per decoded byte.
    // Its bounded binary body/canonical copies therefore fit these same input
    // widths; eight member/proof descriptors and their fixed signing models
    // fit the per-request metadata. Native ownership copies do not re-encode
    // those bodies, and retained capacities are counted after decoder drop.
    let retained = mul(encoded, 2)?;
    // Vec growth can temporarily own the old and new allocations: <3N for
    // one N-byte encoding. The canonical JSON buffer is explicitly dropped
    // before the raw-key audit. Request-body commitment encoding is no wider
    // than its JSON row apart from the separately charged fixed descriptors.
    let encoding = mul(encoded, 3)?;
    // Envelope decode copies at most P bytes. Bound-AAD's owned fields and
    // parser backing use <=2P; its canonical Vec's old/new growth uses <=3P.
    // These do not overlap the outer canonical JSON buffer. The same bound
    // covers envelope validation during payload deserialization. No payload
    // validity or <=1MiB assumption is made: conflict bodies retain the
    // original 16MiB log-row acceptance boundary.
    let envelope = mul(largest_payload, 6)?;
    let metadata = add(CONTEXT_METADATA, mul(requests.max(1), REQUEST_METADATA)?)?;
    add(add(retained, encoding.max(envelope))?, metadata)
}

pub(super) fn log_owned(entry: &Entry<SessionRaftTypeConfig>) -> io::Result<usize> {
    // Count the actual independent copy while the original whole-decoder
    // reservation still covers it. No parser maps, canonical JSON, raw input
    // or destroyed context is retained by this result. Existing model helpers
    // count String/Vec capacities, record Boxes and aligned payload ArcInner
    // storage. owned::key constructs the exact independent Box backing those
    // helpers require; no decoder-owned Bytes or Arc can escape with a refund.
    fn request(value: &FencedTransitionV2Request) -> io::Result<usize> {
        value
            .log_row_reuse_allocation_bytes()
            .ok_or_else(|| invalid("native owned request allocation overflow"))
    }
    fn key(value: &SessionKey) -> io::Result<usize> {
        value
            .log_row_reuse_allocation_bytes()
            .ok_or_else(|| invalid("native owned key allocation overflow"))
    }
    fn lease(value: &LeaseGuard) -> io::Result<usize> {
        value
            .log_row_reuse_allocation_bytes()
            .ok_or_else(|| invalid("native owned lease allocation overflow"))
    }
    fn record(value: &StoredSessionRecord) -> io::Result<usize> {
        add(
            add(
                key(&value.key)?,
                add(
                    value.owner.allocation_capacity(),
                    value.state_type.allocation_capacity(),
                )?,
            )?,
            value
                .payload
                .log_row_reuse_allocation_bytes()
                .ok_or_else(|| invalid("native owned payload allocation overflow"))?,
        )
    }
    fn intent(value: &SessionMutationIntent, allow_authorized: bool) -> io::Result<usize> {
        match value {
            SessionMutationIntent::AdvanceLogicalTime => Ok(0),
            SessionMutationIntent::MaintainFencedTransitionV2History { .. } if allow_authorized => {
                Ok(0)
            }
            SessionMutationIntent::BindConsumerRequest { .. } => Ok(0),
            SessionMutationIntent::ActivateFencedTransitionCapability { .. } => Ok(0),
            SessionMutationIntent::ActivateProtectedRosterProfileV2 { .. } => Ok(0),
            SessionMutationIntent::RosterAdmission(value)
            | SessionMutationIntent::RosterAdmissionV2(value)
                if !allow_authorized =>
            {
                value
                    .native_read_allocation_bytes()
                    .ok_or_else(|| invalid("native owned roster admission allocation overflow"))
            }
            SessionMutationIntent::RosterTerminal(value) if !allow_authorized => value
                .native_read_allocation_bytes()
                .ok_or_else(|| invalid("native owned roster terminal allocation overflow")),
            SessionMutationIntent::RosterTerminalV2(value) if !allow_authorized => value
                .native_read_allocation_bytes()
                .ok_or_else(|| invalid("native owned roster V2 terminal allocation overflow")),
            SessionMutationIntent::FencedTransition(value)
            | SessionMutationIntent::ActivateFencedTransition { request: value, .. } => {
                let lease_bytes = match value.lease() {
                    crate::FencedTransitionLease::Acquire {
                        key: value, owner, ..
                    } => add(key(value)?, owner.allocation_capacity())?,
                    crate::FencedTransitionLease::Renew { lease: value, .. } => lease(value)?,
                };
                let mutation = value
                    .mutation()
                    .record()
                    .map(|value| add(size_of::<StoredSessionRecord>(), record(value)?))
                    .transpose()?
                    .unwrap_or(0);
                add(
                    size_of::<crate::FencedTransitionRequest>(),
                    add(lease_bytes, mutation)?,
                )
            }
            SessionMutationIntent::ReadConsumerRecord { key: value } => key(value),
            SessionMutationIntent::CompareAndSet(value) => add(
                size_of::<crate::backend::CompareAndSet>() + 4 * size_of::<usize>(),
                add(
                    add(key(&value.key)?, lease(&value.lease)?)?,
                    record(&value.new_record)?,
                )?,
            ),
            SessionMutationIntent::DeleteFenced(value)
            | SessionMutationIntent::ReleaseLease(value)
            | SessionMutationIntent::RenewLease { lease: value, .. }
            | SessionMutationIntent::RefreshTtl { lease: value, .. } => lease(value),
            SessionMutationIntent::AcquireLease {
                key: value, owner, ..
            } => add(key(value)?, owner.allocation_capacity()),
            SessionMutationIntent::FencedTransitionV2(value)
            | SessionMutationIntent::ActivateFencedTransitionV2 { request: value, .. } => {
                add(size_of::<FencedTransitionV2Request>(), request(value)?)
            }
            SessionMutationIntent::FencedTransitionV2Batch(requests) => {
                if requests.len() > MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS {
                    return Err(invalid("native owned batch exceeds public profile"));
                }
                let mut bytes = mul(requests.capacity(), size_of::<FencedTransitionV2Request>())?;
                for value in requests {
                    bytes = add(bytes, request(value)?)?;
                }
                Ok(bytes)
            }
            SessionMutationIntent::Authorized { mutation, .. } if allow_authorized => {
                add(size_of::<SessionMutationIntent>(), intent(mutation, false)?)
            }
            _ => Err(invalid("native owned log requires its command codec")),
        }
    }
    fn tree<T>(count: usize) -> io::Result<usize> {
        // Scalar-ID B-trees only. Charge even a separate full node for each
        // element, including unused slots and child pointers; EmptyNode adds
        // no heap allocation. This is retained container capacity, not the
        // arbitrary JSON key-auditor's per-request allowance.
        mul(
            add(count, 1)?,
            mul(8, add(size_of::<T>(), 4 * size_of::<usize>())?)?,
        )
    }
    let owned = match &entry.payload {
        EntryPayload::Blank => 0,
        EntryPayload::Normal(command) => intent(&command.intent, true)?,
        EntryPayload::Membership(membership) => {
            let configs = membership.get_joint_config();
            let mut bytes = mul(
                configs.capacity(),
                size_of::<BTreeSet<SessionConsensusNodeId>>(),
            )?;
            for config in configs {
                bytes = add(bytes, tree::<SessionConsensusNodeId>(config.len())?)?;
            }
            add(
                bytes,
                tree::<(SessionConsensusNodeId, EmptyNode)>(membership.nodes().count())?,
            )?
        }
    };
    add(size_of::<generation::decode::OwnedLog>(), owned)
}

fn run_reserved(
    bytes: usize,
    check: &impl Fn() -> io::Result<()>,
    reserve: impl FnOnce(usize) -> io::Result<VerificationMemory>,
    verify: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    let _memory = reserve(bytes)?;
    // Every decoded/encoded temporary is created and destroyed inside this
    // closure before the guard refunds, including errors and unwinding.
    verify()?;
    check()
}

pub(super) fn log(
    row: &log::NativeLogEntry,
    check: &impl Fn() -> io::Result<()>,
    verify: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    run_reserved(log_bytes(row)?, check, VerificationMemory::reserve, verify)
}

pub(super) fn key(
    row: &NativeKeyState,
    check: &impl Fn() -> io::Result<()>,
    verify: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let payload = row.record.as_ref().map_or(0, |record| record.payload.len());
    run_reserved(
        add(mul(payload, 6)?, CONTEXT_METADATA)?,
        check,
        VerificationMemory::reserve,
        verify,
    )
}

pub(super) fn receipt(
    check: &impl Fn() -> io::Result<()>,
    verify: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let bytes = add(
        mul(
            crate::fenced_transition::FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES,
            3,
        )?,
        CONTEXT_METADATA,
    )?;
    run_reserved(bytes, check, VerificationMemory::reserve, verify)
}

pub(super) fn small(
    check: &impl Fn() -> io::Result<()>,
    verify: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Fixed membership/frontiers and notification TTL validation. The latter
    // first bounds its iterative worklist to 256 (reference, depth) pairs.
    // Include old/new Vec growth and both sequential validator worklists.
    let work = mul(
        crate::backend::MAX_REPLICATION_OPERATIONS_PER_ENTRY,
        6 * size_of::<(&crate::backend::ReplicationOp, usize)>(),
    )?;
    run_reserved(
        add(work, CONTEXT_METADATA)?,
        check,
        VerificationMemory::reserve,
        verify,
    )
}

#[cfg(test)]
#[path = "scratch_tests.rs"]
mod tests;
