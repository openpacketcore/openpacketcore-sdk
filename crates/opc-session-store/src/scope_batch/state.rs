//! Bounded transactional planning, shared by native and SQLite replicated apply.

use super::*;
use crate::scope_storage::{batch_key, child_key, claim_key, ClaimOwner, ClaimRow, ScopeRow};
use std::collections::HashMap;

pub(crate) struct ScopeBatchPlan {
    pub(crate) checkpoint: ScopeBatchCheckpoint,
    pub(crate) rows: HashMap<SessionKey, ScopeRow>,
}

impl ScopeBatchCheckpoint {
    pub(crate) fn empty(scope: ScopeId) -> Self {
        Self {
            scope,
            revision: 0,
            birth_floor: 0,
            counters: [0; SCOPE_COUNTERS],
            lanes: std::array::from_fn(|_| ScopeBatchLaneCheckpoint::default()),
        }
    }

    pub(crate) fn outcome(&self, lane: u8) -> Option<&ScopeBatchOutcome> {
        match self.receipt(lane)?.terminal() {
            ScopeBatchTerminal::Applied(outcome) => Some(outcome),
            ScopeBatchTerminal::Cancelled => None,
        }
    }

    pub(crate) fn receipt(&self, lane: u8) -> Option<&ScopeBatchReceipt> {
        self.lanes.get(usize::from(lane))?.receipt.as_ref()
    }

    pub(crate) fn lane_floors(
        &self,
    ) -> Result<[(u64, u64, [u8; 32]); SCOPE_BATCH_LANES], ScopeBatchError> {
        let mut floors = [(0, 0, [0; 32]); SCOPE_BATCH_LANES];
        for (entry, lane) in floors.iter_mut().zip(&self.lanes) {
            *entry = (
                lane.sequence,
                lane.floor,
                Sha256::digest(
                    postcard::to_allocvec(lane).map_err(|_| ScopeBatchError::FormatMismatch)?,
                )
                .into(),
            );
        }
        Ok(floors)
    }

    pub(crate) fn validate_stored(&self) -> Result<(), ScopeBatchError> {
        if self.revision == 0 {
            // AdmitInitial commits this canonical header with authority. Its
            // presence distinguishes an unused ledger from missing floors.
            return if *self == Self::empty(self.scope.clone()) {
                Ok(())
            } else {
                Err(ScopeBatchError::FormatMismatch)
            };
        }
        if !(1..=COUNTER_MAX).contains(&self.revision)
            || self.birth_floor > COUNTER_MAX
            || self.counters.iter().any(|value| *value > COUNTER_MAX)
        {
            return Err(ScopeBatchError::FormatMismatch);
        }
        let mut transitions = 0_u64;
        let mut revisions = HashSet::new();
        let mut ids = HashSet::new();
        for (index, lane) in self.lanes.iter().enumerate() {
            if lane.sequence == 0 {
                if *lane != ScopeBatchLaneCheckpoint::default() {
                    return Err(ScopeBatchError::FormatMismatch);
                }
                continue;
            }
            lane.frontier()?.validate()?;
            let receipt = lane
                .receipt
                .as_ref()
                .ok_or(ScopeBatchError::FormatMismatch)?;
            receipt
                .validate()
                .map_err(|_| ScopeBatchError::FormatMismatch)?;
            transitions = transitions
                .checked_add(lane.sequence)
                .ok_or(ScopeBatchError::FormatMismatch)?;
            if receipt.attempt.stamp.scope() != &self.scope
                || !ids.insert(receipt.attempt.request_id)
                || !revisions.insert(receipt.revision)
                || lane.sequence > self.revision
                || receipt.attempt.lane != index as u8
                || !(lane.sequence..=self.revision).contains(&receipt.revision)
            {
                return Err(ScopeBatchError::FormatMismatch);
            }
            if let ScopeBatchTerminal::Applied(outcome) = &receipt.terminal {
                if outcome
                    .counters
                    .iter()
                    .zip(self.counters)
                    .any(|(old, current)| *old > current)
                    || (outcome.revision == self.revision && outcome.counters != self.counters)
                    || outcome.rows.iter().any(|row| row.birth > self.birth_floor)
                {
                    return Err(ScopeBatchError::FormatMismatch);
                }
            }
        }
        if transitions != self.revision || !revisions.contains(&self.revision) {
            return Err(ScopeBatchError::FormatMismatch);
        }
        Ok(())
    }

    /// The caller must first establish through a full-round authority read
    /// that the old stamp has been superseded. This function only reads receipts.
    pub(crate) fn resolve(
        &self,
        request: &ScopeBatchRequest,
    ) -> Result<ScopeBatchResolution, ScopeBatchError> {
        match self.lookup(&request.attempt()?, true)? {
            ScopeBatchLookup::Applied(outcome) => Ok(ScopeBatchResolution::Applied(outcome)),
            ScopeBatchLookup::Cancelled | ScopeBatchLookup::NotApplied => {
                Ok(ScopeBatchResolution::NotApplied)
            }
            ScopeBatchLookup::Pruned => Ok(ScopeBatchResolution::Unknown),
            ScopeBatchLookup::NotRecorded => Err(ScopeBatchError::FormatMismatch),
        }
    }

    /// The fencing argument is supplied only by a validated same-cut read.
    pub(crate) fn lookup(
        &self,
        attempt: &ScopeBatchAttempt,
        permanently_fenced: bool,
    ) -> Result<ScopeBatchLookup, ScopeBatchError> {
        self.validate_stored()?;
        attempt.validate()?;
        if attempt.stamp.scope() != &self.scope {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        // A retained ID may not be rebound even to a different lane or stamp.
        if self
            .lanes
            .iter()
            .filter_map(|lane| lane.receipt.as_ref())
            .any(|receipt| {
                receipt.attempt.request_id == attempt.request_id && receipt.attempt != *attempt
            })
        {
            return Err(ScopeBatchError::IdempotencyConflict);
        }
        let lane = &self.lanes[usize::from(attempt.lane)];
        match lane
            .frontier()?
            .lookup(&attempt.key()?, permanently_fenced)?
        {
            lane::LaneLookup::Retained => match &lane
                .receipt
                .as_ref()
                .ok_or(ScopeBatchError::FormatMismatch)?
                .terminal
            {
                ScopeBatchTerminal::Applied(outcome) => {
                    Ok(ScopeBatchLookup::Applied(outcome.clone()))
                }
                ScopeBatchTerminal::Cancelled => Ok(ScopeBatchLookup::Cancelled),
            },
            lane::LaneLookup::NotApplied => Ok(ScopeBatchLookup::NotApplied),
            lane::LaneLookup::NotRecorded => Ok(ScopeBatchLookup::NotRecorded),
            lane::LaneLookup::Pruned => Ok(ScopeBatchLookup::Pruned),
        }
    }

    pub(crate) fn replay(&self, request: &ScopeBatchRequest) -> Result<bool, ScopeBatchError> {
        match self.lookup(&request.attempt()?, false)? {
            ScopeBatchLookup::Applied(_) => return Ok(true),
            ScopeBatchLookup::Cancelled => return Err(ScopeBatchError::Cancelled),
            _ => {}
        }
        if request
            .expected_revision
            .is_some_and(|revision| revision != self.revision)
        {
            return Err(ScopeBatchError::RevisionConflict);
        }
        if self.lanes[usize::from(request.lane)]
            .frontier()?
            .next_sequence()?
            != request.sequence
        {
            return Err(ScopeBatchError::SequenceConflict);
        }
        Ok(false)
    }

    fn record_terminal(
        &mut self,
        attempt: ScopeBatchAttempt,
        revision: u64,
        terminal: ScopeBatchTerminal,
    ) -> Result<(), ScopeBatchError> {
        if revision != next(self.revision)? {
            return Err(ScopeBatchError::RevisionConflict);
        }
        let lane = &mut self.lanes[usize::from(attempt.lane)];
        let frontier = lane.frontier()?.advance(attempt.key()?)?;
        lane.sequence = frontier.sequence;
        lane.floor = frontier.discarded_through;
        lane.receipt = Some(ScopeBatchReceipt {
            attempt,
            revision,
            terminal,
        });
        self.revision = revision;
        self.validate_stored()
    }
}

impl ScopeBatchLaneCheckpoint {
    fn frontier(&self) -> Result<lane::LaneFrontier, ScopeBatchError> {
        Ok(lane::LaneFrontier {
            sequence: self.sequence,
            discarded_through: self.floor,
            retained: self
                .receipt
                .as_ref()
                .map(|receipt| receipt.attempt.key())
                .transpose()?,
        })
    }
}

impl From<lane::LaneProtocolError> for ScopeBatchError {
    fn from(error: lane::LaneProtocolError) -> Self {
        match error {
            lane::LaneProtocolError::InvalidAttempt
            | lane::LaneProtocolError::SequenceExhausted => Self::InvalidRequest,
            lane::LaneProtocolError::Corrupt => Self::FormatMismatch,
            lane::LaneProtocolError::IdempotencyConflict => Self::IdempotencyConflict,
            lane::LaneProtocolError::SequenceConflict => Self::SequenceConflict,
        }
    }
}

impl ScopeBatchCancelCommand {
    pub(crate) fn plan(
        &self,
        authority: &ScopeState,
        checkpoint: &ScopeBatchCheckpoint,
    ) -> Result<ScopeBatchPlan, ScopeBatchError> {
        self.validate()?;
        checkpoint.validate_authority(authority)?;
        match checkpoint.lookup(&self.attempt, false)? {
            ScopeBatchLookup::Applied(_) | ScopeBatchLookup::Cancelled => {
                return Ok(ScopeBatchPlan {
                    checkpoint: checkpoint.clone(),
                    rows: HashMap::new(),
                });
            }
            _ => {}
        }
        authority.check_stamp(&self.attempt.stamp)?;
        let mut successor = checkpoint.clone();
        successor.record_terminal(
            self.attempt.clone(),
            next(checkpoint.revision)?,
            ScopeBatchTerminal::Cancelled,
        )?;
        let rows = HashMap::from([(
            batch_key(&successor.scope)?,
            ScopeRow::Batch(Box::new(successor.clone())),
        )]);
        Ok(ScopeBatchPlan {
            checkpoint: successor,
            rows,
        })
    }
}

impl ScopeBatchCommand {
    pub(crate) fn plan(
        &self,
        authority: &ScopeState,
        checkpoint: &ScopeBatchCheckpoint,
        read: impl Fn(&SessionKey) -> Result<Option<ScopeRow>, ScopeBatchError>,
    ) -> Result<ScopeBatchPlan, ScopeBatchError> {
        self.validate()?;
        checkpoint.validate_authority(authority)?;
        if checkpoint.replay(&self.request)? {
            return Ok(ScopeBatchPlan {
                checkpoint: checkpoint.clone(),
                rows: HashMap::new(),
            });
        }
        let scope = self.request.scope();
        if authority.view.scope() != scope {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        authority.check_stamp(&self.request.stamp)?;
        let namespace = self.request.namespace();
        let revision = next(checkpoint.revision)?;
        let mut conflicts = ScopeBatchConflicts::default();
        let mut predecessors = Vec::with_capacity(self.request.operations.len());
        for op in &self.request.operations {
            let predecessor = match read(&child_key(namespace, op.key())?)? {
                Some(ScopeRow::Child(row))
                    if row.namespace == *namespace && row.key == op.key() =>
                {
                    Some(row)
                }
                None => None,
                _ => return Err(ScopeBatchError::FormatMismatch),
            };
            let live = predecessor.as_ref().filter(|row| row.value.is_some());
            if live.map(|row| row.revision) != op.expected() {
                conflicts.children.push(op.key());
            }
            predecessors.push(predecessor);
        }
        for condition in &self.request.child_conditions {
            let live = match read(&child_key(namespace, condition.key())?)? {
                Some(ScopeRow::Child(row))
                    if row.namespace == *namespace && row.key == condition.key() =>
                {
                    row.value.is_some().then_some(row.revision)
                }
                None => None,
                _ => return Err(ScopeBatchError::FormatMismatch),
            };
            if !condition.matches(condition.key(), live) {
                conflicts.children.push(condition.key());
            }
        }
        for condition in &self.request.claim_conditions {
            let (revision, owner) = match read(&claim_key(namespace, condition.key())?)? {
                Some(ScopeRow::Claim(row))
                    if row.namespace == *namespace && row.key == condition.key() =>
                {
                    let owner = row
                        .owner
                        .map(|owner| ScopeClaimOwner::new(owner.child, owner.birth))
                        .transpose()
                        .map_err(|_| ScopeBatchError::FormatMismatch)?;
                    (Some(row.revision), owner)
                }
                None => (None, None),
                _ => return Err(ScopeBatchError::FormatMismatch),
            };
            if !condition.matches(condition.key(), revision, owner) {
                conflicts.claims.push(condition.key());
            } else if let Some(owner) = owner {
                match read(&child_key(namespace, owner.child())?)? {
                    Some(ScopeRow::Child(row))
                        if row.namespace == *namespace
                            && row.key == owner.child()
                            && row.value.is_some()
                            && row.revision.birth() == owner.birth()
                            && row.claims.contains(&condition.key()) => {}
                    _ => return Err(ScopeBatchError::FormatMismatch),
                }
            }
        }
        let mut compared_claims: HashSet<_> = self
            .request
            .claim_conditions
            .iter()
            .map(|condition| condition.key())
            .collect();
        for claims in predecessors
            .iter()
            .flatten()
            .map(|row| row.claims.as_slice())
            .chain(self.request.operations.iter().map(|op| op.claims()))
        {
            compared_claims.extend(claims.iter().copied());
        }
        if compared_claims.len() > MAX_SCOPE_BATCH_CHILDREN * MAX_SCOPE_CHILD_CLAIMS {
            return Err(ScopeBatchError::InvalidRequest);
        }
        for counter in &self.request.counters {
            if checkpoint.counters[usize::from(counter.counter)] != counter.expected {
                conflicts.counters.push(counter.counter);
            }
        }
        if conflicts != ScopeBatchConflicts::default() {
            return Err(ScopeBatchError::Conflict(conflicts));
        }

        // Every effect below is detached. No backend row is changed until all
        // child, claim, counter and bounded-counter predicates have succeeded.
        let mut rows = HashMap::new();
        for predecessor in predecessors
            .iter()
            .flatten()
            .filter(|row| row.value.is_some())
        {
            for claim in &predecessor.claims {
                let key = claim_key(namespace, *claim)?;
                let Some(ScopeRow::Claim(mut row)) = read(&key)? else {
                    return Err(ScopeBatchError::FormatMismatch);
                };
                if row.namespace != *namespace
                    || row.owner
                        != Some(ClaimOwner {
                            child: predecessor.key,
                            birth: predecessor.revision.birth,
                        })
                {
                    return Err(ScopeBatchError::FormatMismatch);
                }
                row.owner = None;
                row.revision = revision;
                rows.insert(key, ScopeRow::Claim(row));
            }
        }
        let mut successor = checkpoint.clone();
        let mut versions = Vec::with_capacity(self.request.operations.len());
        for op in &self.request.operations {
            let version = match op.expected() {
                Some(before) => ScopeChildRevision::new(before.birth, next(before.generation)?)?,
                None => {
                    successor.birth_floor = next(successor.birth_floor)?;
                    ScopeChildRevision::new(successor.birth_floor, 1)?
                }
            };
            let owner = ClaimOwner {
                child: op.key(),
                birth: version.birth,
            };
            for claim in op.claims() {
                let key = claim_key(namespace, *claim)?;
                let current = match rows.get(&key) {
                    Some(row) => Some(row.clone()),
                    None => read(&key)?,
                };
                let occupied = match current {
                    Some(ScopeRow::Claim(row))
                        if row.namespace == *namespace && row.key == *claim =>
                    {
                        row.owner.is_some()
                    }
                    None => false,
                    _ => return Err(ScopeBatchError::FormatMismatch),
                };
                if occupied {
                    if !conflicts.claims.contains(claim) {
                        conflicts.claims.push(*claim);
                    }
                    continue;
                }
                rows.insert(
                    key,
                    ScopeRow::Claim(ClaimRow {
                        namespace: namespace.clone(),
                        key: *claim,
                        revision,
                        owner: Some(owner),
                    }),
                );
            }
            let value = match op {
                ScopeChildMutation::Create { value, .. }
                | ScopeChildMutation::CompareAndSet { value, .. } => Some(value.clone()),
                ScopeChildMutation::Delete { .. } => None,
            };
            rows.insert(
                child_key(namespace, op.key())?,
                ScopeRow::Child(ScopeChildRecord {
                    namespace: namespace.clone(),
                    key: op.key(),
                    revision: version,
                    batch_revision: revision,
                    value,
                    claims: op.claims().to_vec(),
                }),
            );
            versions.push(version);
        }
        if !conflicts.claims.is_empty() {
            return Err(ScopeBatchError::Conflict(conflicts));
        }
        for counter in &self.request.counters {
            successor.counters[usize::from(counter.counter)] = counter.next;
        }
        let outcome = ScopeBatchOutcome {
            request_digest: self.request.digest()?,
            lane: self.request.lane,
            sequence: self.request.sequence,
            revision,
            rows: versions,
            counters: successor.counters,
        };
        successor.record_terminal(
            self.request.attempt()?,
            revision,
            ScopeBatchTerminal::Applied(Box::new(outcome)),
        )?;
        rows.insert(
            batch_key(scope)?,
            ScopeRow::Batch(Box::new(successor.clone())),
        );
        Ok(ScopeBatchPlan {
            checkpoint: successor,
            rows,
        })
    }
}

fn next(value: u64) -> Result<u64, ScopeBatchError> {
    value
        .checked_add(1)
        .filter(|value| *value <= COUNTER_MAX)
        .ok_or(ScopeBatchError::InvalidRequest)
}
