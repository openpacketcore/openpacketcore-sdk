//! A read captures only requested cold revisions. All file/cache/codec work
//! runs after the adapter releases State. Final copies are checked against
//! the current owner under State before a status or apply can consume them.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use std::mem::size_of;
use std::sync::Arc;

pub(crate) struct ReceiptReads {
    rows: HashMap<FencedTransitionV2RequestId, cold::ReceiptReadTicket>,
    resident: HashMap<FencedTransitionV2RequestId, ResidentReceiptRead>,
}

pub(crate) struct ResolvedReceipts {
    rows: HashMap<FencedTransitionV2RequestId, cold::ResolvedReceipt>,
    resident: HashMap<FencedTransitionV2RequestId, ResidentReceiptRead>,
}

struct ResidentReceiptRead {
    proof: Arc<changes::BusinessProof>,
    row: SharedRow<NativeReceipt>,
    _memory: VerificationMemory,
}

pub(crate) struct ReceiptCopies {
    proof: Arc<changes::BusinessProof>,
    rows: HashMap<FencedTransitionV2RequestId, NativeReceipt>,
    // These containers are apply/read scratch. Each response is the existing
    // codec's independent output copy, not an alias into decoded scratch.
    _memory: VerificationMemory,
}

impl ReceiptReads {
    fn capture(
        state: &NativeState,
        ids: impl IntoIterator<Item = FencedTransitionV2RequestId>,
        resolved: Option<&ResolvedReceipts>,
    ) -> io::Result<Self> {
        let proof = state.require_business_proof()?;
        let mut rows = HashMap::new();
        let mut resident = HashMap::new();
        for id in ids {
            if rows.contains_key(&id) || resident.contains_key(&id) {
                continue;
            }
            let Some(row) = state.receipts.get(&id) else {
                continue;
            };
            if !row.retained() {
                continue;
            }
            if let Some(resolved) = resolved {
                if resolved.covers(id, row)? {
                    continue;
                }
            }
            let Some((source, range)) = row.cold_range() else {
                if row.response.is_some() {
                    // A mixed read releases State. Keep resident revisions
                    // too: durable relocation can make them cold meanwhile,
                    // without changing their logical row revision.
                    let memory = VerificationMemory::reserve(
                        8 * (size_of::<ResidentReceiptRead>()
                            + size_of::<FencedTransitionV2RequestId>())
                            + 256
                            + cold::OWNED_COPY_BYTES,
                    )?;
                    resident.try_reserve(1).map_err(|_| {
                        invalid("native resident receipt capture allocation failed")
                    })?;
                    resident.insert(
                        id,
                        ResidentReceiptRead {
                            proof: Arc::clone(proof),
                            row: row.clone(),
                            _memory: memory,
                        },
                    );
                }
                continue;
            };
            // The ticket reserves before either map grows. Its guard covers
            // old/new capture and resolved-map bucket overlap until copied.
            let ticket = cold::ReceiptReadTicket::capture(state, id, source, range)?;
            rows.try_reserve(1)
                .map_err(|_| invalid("native receipt read capture allocation failed"))?;
            rows.insert(id, ticket);
        }
        Ok(Self { rows, resident })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(crate) fn resolve(
        self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<ResolvedReceipts> {
        let mut rows = HashMap::new();
        for (id, ticket) in self.rows {
            check()?;
            let resolved = ticket.resolve(check)?;
            rows.try_reserve(1)
                .map_err(|_| invalid("native resolved receipt map allocation failed"))?;
            rows.insert(id, resolved);
        }
        check()?;
        Ok(ResolvedReceipts {
            rows,
            resident: self.resident,
        })
    }
}

impl ResolvedReceipts {
    fn covers(
        &self,
        id: FencedTransitionV2RequestId,
        row: &SharedRow<NativeReceipt>,
    ) -> io::Result<bool> {
        let matches = self
            .rows
            .get(&id)
            .map(|resolved| resolved.matches_revision(row))
            .or_else(|| {
                self.resident
                    .get(&id)
                    .map(|resident| resident.row.ptr_eq(row))
            });
        match matches {
            Some(true) => Ok(true),
            // Within one live owner a complete request ID binds once. Its
            // retained revision may relocate, expire or retire; it cannot
            // become another retained revision. Authority replacement must
            // invalidate the adapter's owner before reaching this check.
            Some(false) => Err(invalid("native retained receipt revision was replaced")),
            None => Ok(false),
        }
    }

    pub(crate) fn capture_missing(
        &self,
        state: &NativeState,
        requests: &[FencedTransitionV2Request],
    ) -> io::Result<ReceiptReads> {
        ReceiptReads::capture(
            state,
            requests.iter().map(FencedTransitionV2Request::request_id),
            Some(self),
        )
    }

    pub(crate) fn extend(&mut self, additional: Self) -> io::Result<()> {
        // Every additional detached pass contains a previously unseen cold
        // ID. A request cohort therefore takes at most its distinct ID count
        // of passes; neither relocation nor unrelated commits restart it.
        if additional.rows.is_empty() {
            return Err(invalid("native receipt resolution made no progress"));
        }
        if additional
            .rows
            .keys()
            .chain(additional.resident.keys())
            .any(|id| self.rows.contains_key(id) || self.resident.contains_key(id))
        {
            return Err(invalid("native receipt resolution repeated an ID"));
        }
        self.rows
            .try_reserve(additional.rows.len())
            .map_err(|_| invalid("native resolved receipt extension allocation failed"))?;
        self.resident
            .try_reserve(additional.resident.len())
            .map_err(|_| invalid("native resident receipt extension allocation failed"))?;
        self.rows.extend(additional.rows);
        self.resident.extend(additional.resident);
        Ok(())
    }

    pub(crate) fn copy_current(&self, state: &NativeState) -> io::Result<ReceiptCopies> {
        let proof = Arc::clone(state.require_business_proof()?);
        let count = self
            .rows
            .len()
            .checked_add(self.resident.len())
            .ok_or_else(|| invalid("native receipt output count overflow"))?;
        let bytes = count
            .checked_mul(
                8 * (size_of::<(FencedTransitionV2RequestId, NativeReceipt)>() + 1)
                    + cold::OWNED_COPY_BYTES,
            )
            .and_then(|bytes| bytes.checked_add(size_of::<ReceiptCopies>()))
            .ok_or_else(|| invalid("native receipt output reservation overflow"))?;
        let memory = VerificationMemory::reserve(bytes)?;
        let mut rows = HashMap::new();
        rows.try_reserve(count)
            .map_err(|_| invalid("native receipt output map allocation failed"))?;
        for (id, resolved) in &self.rows {
            if let Some(row) = resolved.copy_matching_row(state)? {
                rows.insert(*id, row);
            }
        }
        for (id, resident) in &self.resident {
            if let Some(row) = cold::copy_matching_receipt(
                state,
                *id,
                &resident.proof,
                &resident.row,
                &resident.row,
            )? {
                rows.insert(*id, row);
            }
        }
        Ok(ReceiptCopies {
            proof,
            rows,
            _memory: memory,
        })
    }
}

impl ReceiptCopies {
    pub(super) fn require_current(&self, state: &NativeState) -> io::Result<()> {
        if !Arc::ptr_eq(&self.proof, state.require_business_proof()?) {
            return Err(invalid("native resolved receipt apply predecessor changed"));
        }
        Ok(())
    }

    pub(super) fn get(&self, id: &FencedTransitionV2RequestId) -> Option<&NativeReceipt> {
        self.rows.get(id)
    }
}

fn entry_requests(entry: &Entry<SessionRaftTypeConfig>) -> &[FencedTransitionV2Request] {
    let EntryPayload::Normal(command) = &entry.payload else {
        return &[];
    };
    let intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
        intent => intent,
    };
    match intent {
        SessionMutationIntent::FencedTransitionV2(request)
        | SessionMutationIntent::ActivateFencedTransitionV2 { request, .. } => {
            std::slice::from_ref(request)
        }
        SessionMutationIntent::FencedTransitionV2Batch(requests) => requests,
        _ => &[],
    }
}

impl NativeState {
    pub(crate) fn capture_receipt_reads(
        &self,
        requests: &[FencedTransitionV2Request],
    ) -> io::Result<ReceiptReads> {
        ReceiptReads::capture(
            self,
            requests.iter().map(FencedTransitionV2Request::request_id),
            None,
        )
    }

    pub(crate) fn capture_apply_reads(
        &self,
        entries: &[Entry<SessionRaftTypeConfig>],
    ) -> io::Result<ReceiptReads> {
        ReceiptReads::capture(
            self,
            entries
                .iter()
                .flat_map(entry_requests)
                .map(FencedTransitionV2Request::request_id),
            None,
        )
    }

    pub(crate) fn status_with_receipts(
        &self,
        request: &FencedTransitionV2Request,
        receipts: &ReceiptCopies,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        receipts.require_current(self).map_err(|_| unavailable())?;
        self.status_using(request, Some(receipts))
    }

    pub(crate) fn apply_with_receipts(
        &mut self,
        entries: &[Entry<SessionRaftTypeConfig>],
        receipts: &ReceiptCopies,
    ) -> io::Result<NativeApplied> {
        receipts.require_current(self)?;
        let delta = self.prepare_using(entries, Some(receipts))?;
        changes::Publication::prepare(delta)?.publish(self)
    }
}
