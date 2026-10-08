//! Bounded transactional planning, shared by native and SQLite replicated apply.

use super::*;
use crate::scope_storage::{batch_key, child_key, claim_key, ClaimOwner, ClaimRow, ScopeRow};
use std::collections::HashMap;

pub(crate) struct ScopeBatchPlan {
    pub(crate) checkpoint: ScopeBatchCheckpoint,
    pub(crate) rows: HashMap<SessionKey, ScopeRow>,
}

impl ScopeBatchCheckpoint {
    pub(crate) fn empty(scope: ScopeLeaseId) -> Self {
        Self {
            scope,
            revision: 0,
            birth_floor: 0,
            counters: [0; SCOPE_COUNTERS],
            lanes: std::array::from_fn(|_| ScopeBatchLaneCheckpoint::default()),
        }
    }

    pub(crate) fn outcome(&self, lane: u8) -> Option<&ScopeBatchOutcome> {
        self.lanes.get(usize::from(lane))?.outcome.as_ref()
    }

    pub(crate) fn validate_stored(&self) -> Result<(), ScopeBatchError> {
        let lane = &self.lanes[0];
        let outcome = lane
            .outcome
            .as_ref()
            .ok_or(ScopeBatchError::FormatMismatch)?;
        if !(1..=COUNTER_MAX).contains(&self.revision)
            || self.birth_floor > COUNTER_MAX
            || lane.last_request_id == [0; 16]
            || lane.sequence != self.revision
            || lane.floor != lane.sequence - 1
            || self.lanes[1..]
                .iter()
                .any(|lane| *lane != ScopeBatchLaneCheckpoint::default())
            || self.counters.iter().any(|value| *value > COUNTER_MAX)
            || outcome.lane != 0
            || outcome.sequence != lane.sequence
            || outcome.revision != self.revision
            || outcome.counters != self.counters
            || outcome.request_digest != lane.last_digest
            || outcome.rows.len() > MAX_SCOPE_BATCH_CHILDREN
            || outcome.rows.iter().any(|row| {
                row.birth == 0
                    || row.birth > self.birth_floor
                    || !(1..=COUNTER_MAX).contains(&row.generation)
            })
        {
            return Err(ScopeBatchError::FormatMismatch);
        }
        Ok(())
    }

    pub(crate) fn replay(&self, request: &ScopeBatchRequest) -> Result<bool, ScopeBatchError> {
        if request.scope() != &self.scope {
            return Err(ScopeLeaseError::Unauthorized.into());
        }
        let lane = self
            .lanes
            .get(usize::from(request.lane))
            .ok_or(ScopeBatchError::InvalidRequest)?;
        let digest = request.digest()?;
        if request.request_id == lane.last_request_id {
            return if digest == lane.last_digest {
                Ok(true)
            } else {
                Err(ScopeBatchError::IdempotencyConflict)
            };
        }
        if request.expected_revision != self.revision {
            return Err(ScopeBatchError::RevisionConflict);
        }
        Ok(false)
    }
}

impl ScopeBatchCommand {
    pub(crate) fn plan(
        &self,
        authority: &ScopeState,
        checkpoint: &ScopeBatchCheckpoint,
        apply_time: opc_types::Timestamp,
        read: impl Fn(&SessionKey) -> Result<Option<ScopeRow>, ScopeBatchError>,
    ) -> Result<ScopeBatchPlan, ScopeBatchError> {
        self.validate()?;
        if checkpoint.replay(&self.request)? {
            return Ok(ScopeBatchPlan {
                checkpoint: checkpoint.clone(),
                rows: HashMap::new(),
            });
        }
        let scope = self.request.scope();
        if authority.view.scope() != scope {
            return Err(ScopeLeaseError::Unauthorized.into());
        }
        let current = authority
            .view
            .permit()
            .ok_or(ScopeLeaseError::StalePermit)?;
        let supplied = &self.request.permit;
        if current.scope() != supplied.scope()
            || current.execution() != supplied.execution()
            || current.selection() != supplied.selection()
            || current.grant_epoch() != supplied.grant_epoch()
            || authority.view.selection() != supplied.selection()
            || authority.view.selected() != Some(supplied.execution())
        {
            return Err(ScopeLeaseError::StalePermit.into());
        }
        // The trusted interval alone can only be made more conservative by
        // the replicated application clock. A command delayed past the stop
        // deadline cannot acquire authority from its old preparation time.
        if self.bounds.latest().max(apply_time) >= current.stop_at() {
            return Err(ScopeLeaseError::Expired.into());
        }
        let revision = next(checkpoint.revision)?;
        let mut conflicts = ScopeBatchConflicts::default();
        let mut predecessors = Vec::with_capacity(self.request.operations.len());
        for op in &self.request.operations {
            let predecessor = match read(&child_key(scope, op.key())?)? {
                Some(ScopeRow::Child(row)) if row.scope == *scope && row.key == op.key() => {
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
                let key = claim_key(scope, *claim)?;
                let Some(ScopeRow::Claim(mut row)) = read(&key)? else {
                    return Err(ScopeBatchError::FormatMismatch);
                };
                if row.scope != *scope
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
                let key = claim_key(scope, *claim)?;
                let current = match rows.get(&key) {
                    Some(row) => Some(row.clone()),
                    None => read(&key)?,
                };
                let occupied = match current {
                    Some(ScopeRow::Claim(row)) if row.scope == *scope && row.key == *claim => {
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
                        scope: scope.clone(),
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
                child_key(scope, op.key())?,
                ScopeRow::Child(ScopeChildRecord {
                    scope: scope.clone(),
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
        successor.revision = revision;
        let lane = &mut successor.lanes[usize::from(self.request.lane)];
        lane.sequence = self.request.sequence;
        lane.floor = lane.sequence - 1;
        lane.last_request_id = self.request.request_id;
        lane.last_digest = self.request.digest()?;
        lane.outcome = Some(ScopeBatchOutcome {
            request_digest: lane.last_digest,
            lane: self.request.lane,
            sequence: lane.sequence,
            revision,
            rows: versions,
            counters: successor.counters,
        });
        successor.validate_stored()?;
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
