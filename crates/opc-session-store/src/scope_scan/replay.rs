//! One exact, bounded reply retained until its successor acknowledges it.
//! Cursor authentication, current local admission and reply byte bounds are
//! checked by the facade before this non-authoritative per-view state is used.

use std::{fmt, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PageAttempt {
    pub(crate) number: u64,
    /// Digest of the complete authenticated cursor/request, including limits.
    pub(crate) binding: [u8; 32],
}

/// A unique in-process builder. Reusing an attempt after cancellation produces
/// a new token, so an old worker cannot publish or cancel its replacement.
pub(crate) struct BuildToken {
    generation: u64,
    attempt: PageAttempt,
}

pub(crate) enum ReplyAdmission<R> {
    Build(BuildToken),
    Pending,
    Replay(Arc<R>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyWindowError {
    InvalidRequest,
    Closed,
    CounterExhausted,
}

pub(crate) struct ReplyWindow<R> {
    expected: Option<u64>,
    generation: u64,
    inflight: Option<(u64, PageAttempt)>,
    cached: Option<(PageAttempt, Arc<R>)>,
    closed: bool,
}

impl<R> ReplyWindow<R> {
    pub(crate) fn new() -> Self {
        Self {
            expected: Some(0),
            generation: 0,
            inflight: None,
            cached: None,
            closed: false,
        }
    }
    pub(crate) fn begin(
        &mut self,
        attempt: PageAttempt,
    ) -> Result<ReplyAdmission<R>, ReplyWindowError> {
        if self.closed {
            return Err(ReplyWindowError::Closed);
        }
        if let Some((accepted, reply)) = &self.cached {
            if accepted.number == attempt.number {
                return if *accepted == attempt {
                    Ok(ReplyAdmission::Replay(Arc::clone(reply)))
                } else {
                    Err(ReplyWindowError::InvalidRequest)
                };
            }
        }
        if self.expected != Some(attempt.number) {
            return Err(ReplyWindowError::InvalidRequest);
        }
        if let Some((_, accepted)) = self.inflight {
            return if accepted == attempt {
                Ok(ReplyAdmission::Pending)
            } else {
                Err(ReplyWindowError::InvalidRequest)
            };
        }
        let Some(generation) = self.generation.checked_add(1) else {
            self.invalidate();
            return Err(ReplyWindowError::CounterExhausted);
        };
        // Only an accepted successor acknowledges the old reply. Invalid
        // future attempts must not evict a reply that the client has not seen.
        self.cached = None;
        self.generation = generation;
        self.inflight = Some((generation, attempt));
        Ok(ReplyAdmission::Build(BuildToken {
            generation,
            attempt,
        }))
    }
    pub(crate) fn publish(
        &mut self,
        token: &BuildToken,
        reply: Arc<R>,
        has_successor: bool,
    ) -> Result<(), ReplyWindowError> {
        if self.closed {
            return Err(ReplyWindowError::Closed);
        }
        if !self.owns(token) {
            return Err(ReplyWindowError::InvalidRequest);
        }
        let next = if has_successor {
            let Some(next) = token.attempt.number.checked_add(1) else {
                self.invalidate();
                return Err(ReplyWindowError::CounterExhausted);
            };
            Some(next)
        } else {
            None
        };
        self.cached = Some((token.attempt, reply));
        self.expected = next;
        self.inflight = None;
        Ok(())
    }
    pub(crate) fn cancel(&mut self, token: &BuildToken) -> bool {
        if self.closed || !self.owns(token) {
            return false;
        }
        self.inflight = None;
        true
    }
    pub(crate) fn invalidate(&mut self) {
        self.closed = true;
        self.expected = None;
        self.inflight = None;
        self.cached = None;
    }
    fn owns(&self, token: &BuildToken) -> bool {
        self.inflight == Some((token.generation, token.attempt))
    }
}

impl fmt::Debug for BuildToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BuildToken(<redacted>)")
    }
}

#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;
