//! One reply window and fixed terminal summaries owned by the retained cut.

use super::cursor::{CursorCodec, CursorPhase, CursorState, ScopeScanCursor};
use super::engine::{self, InspectedItem, InventoryError, InventorySource};
use super::integrity::InventoryFloors;
use super::progress::{InventoryTotals, PageBoundary, PageLimits};
use super::replay::{PageAttempt, ReplyAdmission, ReplyWindow, ReplyWindowError};
use super::{ScopeCut, ScopeScanError};
use crate::scope_authority::ScopeAuthorityStamp;
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};

pub(crate) enum ReplyBody {
    Data {
        items: Vec<InspectedItem>,
        next: ScopeScanCursor,
    },
    WorkBudget {
        next: ScopeScanCursor,
    },
    Complete {
        totals: InventoryTotals,
        manifest: Option<ScopeScanCursor>,
    },
}

/// One immutable response. Its item verdicts are final only at its exact cut.
pub struct ScopeScanReply {
    pub(crate) cut: ScopeCut,
    pub(crate) body: ReplyBody,
}
impl ScopeScanReply {
    /// Exact immutable observation shared by every item in this reply.
    pub fn cut(&self) -> &ScopeCut {
        &self.cut
    }
}
impl fmt::Debug for ScopeScanReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanReply(<redacted>)")
    }
}

pub(crate) struct PageProtocol {
    codec: CursorCodec,
    window: ReplyWindow<ScopeScanReply>,
    terminal_inventory: Option<(PageAttempt, Arc<ScopeScanReply>)>,
    terminal_manifest: Option<(PageAttempt, Arc<ScopeScanReply>)>,
    cut: ScopeCut,
    floors: InventoryFloors,
    limits: PageLimits,
}
impl PageProtocol {
    pub(crate) fn lookup<S: InventorySource>(
        &self,
        key: super::ScopeScanLookupKey,
        source: &mut S,
    ) -> Result<super::ScopeScanLookup, ScopeScanError> {
        let key = match key {
            super::ScopeScanLookupKey::Child(key) => {
                crate::scope_storage::child_key(&self.cut.namespace, key)
            }
            super::ScopeScanLookupKey::Claim(key) => {
                crate::scope_storage::claim_key(&self.cut.namespace, key)
            }
        }
        .map_err(|_| ScopeScanError::InvalidCursor)?;
        let item = engine::lookup(source, &self.cut.namespace, self.floors, &key)
            .map_err(inventory_error)?;
        Ok(super::ScopeScanLookup {
            cut: self.cut.clone(),
            item,
        })
    }

    pub(crate) fn new(
        cut: ScopeCut,
        stamp: &ScopeAuthorityStamp,
        birth_floor: u64,
        limits: PageLimits,
    ) -> Result<(Self, ScopeScanCursor), ScopeScanError> {
        let codec = CursorCodec::new(&cut, stamp, limits)?;
        let initial = codec.seal(&CursorState {
            phase: CursorPhase::Inventory,
            attempt: 0,
            rows: limits.rows,
            after: None,
            totals: InventoryTotals::default(),
        })?;
        let floors = InventoryFloors {
            batch_revision: cut.batch_revision,
            birth: birth_floor,
        };
        Ok((
            Self {
                codec,
                window: ReplyWindow::new(),
                terminal_inventory: None,
                terminal_manifest: None,
                cut,
                floors,
                limits,
            },
            initial,
        ))
    }
    pub(crate) fn page<S: InventorySource>(
        &mut self,
        cursor: &ScopeScanCursor,
        source: &mut S,
    ) -> Result<Arc<ScopeScanReply>, ScopeScanError> {
        let state = self.codec.open(cursor)?;
        let attempt = PageAttempt {
            number: state.attempt,
            binding: Sha256::digest(cursor.as_bytes()).into(),
        };
        // Only the two fixed, payload-free terminal summaries survive a
        // successor acknowledgement. No old data page or failure list does.
        for (accepted, reply) in [
            self.terminal_inventory.as_ref(),
            self.terminal_manifest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if accepted.number == attempt.number {
                return if *accepted == attempt {
                    Ok(Arc::clone(reply))
                } else {
                    Err(ScopeScanError::InvalidCursor)
                };
            }
        }
        let token = match self.window.begin(attempt).map_err(window_error)? {
            ReplyAdmission::Replay(reply) => return Ok(reply),
            ReplyAdmission::Pending => return Err(ScopeScanError::Unavailable),
            ReplyAdmission::Build(token) => token,
        };
        let body = match self.build(&state, source) {
            Ok(body) => body,
            Err(error) => {
                self.window.cancel(&token);
                return Err(error);
            }
        };
        let has_successor = !matches!(&body, ReplyBody::Complete { manifest: None, .. });
        let terminal = matches!(&body, ReplyBody::Complete { .. });
        let reply = Arc::new(ScopeScanReply {
            cut: self.cut.clone(),
            body,
        });
        self.window
            .publish(&token, Arc::clone(&reply), has_successor)
            .map_err(window_error)?;
        if terminal {
            if matches!(
                state.phase,
                CursorPhase::Inventory | CursorPhase::InventoryFinalize
            ) {
                self.terminal_inventory = Some((attempt, Arc::clone(&reply)));
            } else {
                self.terminal_manifest = Some((attempt, Arc::clone(&reply)));
            }
        }
        Ok(reply)
    }

    fn build<S: InventorySource>(
        &self,
        state: &CursorState,
        source: &mut S,
    ) -> Result<ReplyBody, ScopeScanError> {
        if matches!(
            state.phase,
            CursorPhase::InventoryFinalize | CursorPhase::ManifestFinalize
        ) {
            return self.complete(state);
        }
        let page = engine::page(
            source,
            &self.cut.namespace,
            self.floors,
            PageLimits {
                rows: state.rows,
                ..self.limits
            },
            state.after.clone(),
            state.totals,
            state.phase == CursorPhase::Manifest,
        )
        .map_err(inventory_error)?;
        match page.boundary {
            PageBoundary::NoProgress => {
                let mut next = self.successor(state)?;
                next.rows = (next.rows / 2).max(1);
                Ok(ReplyBody::WorkBudget {
                    next: self.codec.seal(&next)?,
                })
            }
            PageBoundary::Continue { after, totals } => {
                let mut next = self.successor(state)?;
                next.after = Some(after);
                next.totals = totals;
                Ok(ReplyBody::Data {
                    items: page.items,
                    next: self.codec.seal(&next)?,
                })
            }
            PageBoundary::Complete { after, totals } => {
                let complete = CursorState {
                    after,
                    totals,
                    ..state.clone()
                };
                if page.items.is_empty() {
                    self.complete(&complete)
                } else {
                    // A separate finalization request releases the last data
                    // payload before retaining a replayable terminal summary.
                    let mut next = self.successor(&complete)?;
                    next.phase = match state.phase {
                        CursorPhase::Inventory => CursorPhase::InventoryFinalize,
                        CursorPhase::Manifest => CursorPhase::ManifestFinalize,
                        _ => return Err(ScopeScanError::InvalidCursor),
                    };
                    Ok(ReplyBody::Data {
                        items: page.items,
                        next: self.codec.seal(&next)?,
                    })
                }
            }
        }
    }

    fn successor(&self, state: &CursorState) -> Result<CursorState, ScopeScanError> {
        Ok(CursorState {
            attempt: state
                .attempt
                .checked_add(1)
                .ok_or(ScopeScanError::RestartRequired)?,
            ..state.clone()
        })
    }

    fn complete(&self, state: &CursorState) -> Result<ReplyBody, ScopeScanError> {
        let inventory = matches!(
            state.phase,
            CursorPhase::Inventory | CursorPhase::InventoryFinalize
        );
        if !inventory {
            let Some((_, original)) = &self.terminal_inventory else {
                return Err(ScopeScanError::InvalidCursor);
            };
            let ReplyBody::Complete { totals, .. } = &original.body else {
                return Err(ScopeScanError::InvalidCursor);
            };
            if *totals != state.totals {
                return Err(ScopeScanError::RestartRequired);
            }
        }
        let manifest = if inventory && state.totals.failures > 0 {
            let next = CursorState {
                phase: CursorPhase::Manifest,
                after: None,
                totals: InventoryTotals::default(),
                ..self.successor(state)?
            };
            Some(self.codec.seal(&next)?)
        } else {
            None
        };
        Ok(ReplyBody::Complete {
            totals: state.totals,
            manifest,
        })
    }
}
fn window_error(error: ReplyWindowError) -> ScopeScanError {
    match error {
        ReplyWindowError::InvalidRequest => ScopeScanError::InvalidCursor,
        ReplyWindowError::Closed | ReplyWindowError::CounterExhausted => {
            ScopeScanError::RestartRequired
        }
    }
}
pub(crate) fn inventory_error(error: InventoryError) -> ScopeScanError {
    match error {
        InventoryError::InvalidPosition | InventoryError::InvalidLimits => {
            ScopeScanError::InvalidCursor
        }
        InventoryError::Interrupted
        | InventoryError::WorkBudget
        | InventoryError::CountOverflow => ScopeScanError::Unavailable,
    }
}
#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
